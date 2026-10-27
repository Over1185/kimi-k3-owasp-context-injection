"""
Escenario: endpoint de subida de archivos con manejo seguro de errores.

Medidas aplicadas (OWASP Top 10:2025):
- A02: no se exponen trazas de error ni detalles internos al cliente.
- A05/A06: lista blanca de extensiones y tipos MIME, nombre de archivo
  saneado y nombre de almacenamiento aleatorio (previene path traversal
  y subida de archivos peligrosos).
- A09: los eventos de seguridad se registran sin datos sensibles.
- A10: excepciones manejadas de forma explícita, sin `except` genéricos.

Nota: este fragmento académico no incluye autenticación. En un entorno
real, protege este endpoint verificando la identidad y el rol del
usuario antes de permitir la subida (A01 - Broken Access Control).
"""

import logging
import re
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, status

logger = logging.getLogger(__name__)

app = FastAPI(debug=False)

# --- Configuración de seguridad -------------------------------------------
UPLOAD_DIR = Path("uploads")
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
CHUNK_SIZE = 1024 * 1024  # lectura por bloques de 1 MB

ALLOWED_EXTENSIONS = {".txt", ".csv", ".pdf", ".png", ".jpg", ".jpeg"}
ALLOWED_CONTENT_TYPES = {
    "text/plain",
    "text/csv",
    "application/pdf",
    "image/png",
    "image/jpeg",
}

# Solo letras, números, guiones, guiones bajos y puntos en el nombre original.
_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]")


@app.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_file(file: UploadFile) -> dict:
    """Recibe un archivo, lo valida y lo almacena de forma segura."""
    # 1. El archivo debe tener nombre
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El archivo debe tener un nombre.",
        )

    # 2. Sanear el nombre (elimina rutas y caracteres peligrosos)
    original_name = _SAFE_CHARS.sub("_", Path(file.filename).name)
    extension = Path(original_name).suffix.lower()

    # 3. Lista blanca de extensiones (evita ejecutables o scripts)
    if extension not in ALLOWED_EXTENSIONS:
        logger.info("Subida rechazada: extensión no permitida (%s).", extension)
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Tipo de archivo no permitido.",
        )

    # 4. Lista blanca de tipos de contenido declarados
    if file.content_type not in ALLOWED_CONTENT_TYPES:
        logger.info(
            "Subida rechazada: content-type no permitido (%s).", file.content_type
        )
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Tipo de contenido no permitido.",
        )

    # 5. Rechazo temprano si el tamaño declarado excede el límite
    if file.size is not None and file.size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="El archivo supera el tamaño máximo permitido (5 MB).",
        )

    # 6. Nombre aleatorio: evita colisiones y path traversal
    stored_name = f"{uuid.uuid4().hex}{extension}"
    destination = (UPLOAD_DIR / stored_name).resolve()

    # Defensa en profundidad: el destino debe permanecer dentro del directorio
    if UPLOAD_DIR.resolve() not in destination.parents:
        logger.warning("Intento de escritura fuera del directorio de subidas.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nombre de archivo no válido.",
        )

    bytes_written = 0
    try:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        with destination.open("wb") as buffer:
            while chunk := await file.read(CHUNK_SIZE):
                bytes_written += len(chunk)
                # 7. Límite real aplicado durante la lectura por bloques
                if bytes_written > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="El archivo supera el tamaño máximo permitido (5 MB).",
                    )
                buffer.write(chunk)
    except HTTPException:
        destination.unlink(missing_ok=True)  # eliminar archivo parcial
        raise
    except OSError:
        destination.unlink(missing_ok=True)
        # A09: la traza queda en el log del servidor, no en la respuesta
        logger.exception("Error de E/S al guardar la subida.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No se pudo procesar el archivo. Inténtelo de nuevo.",
        ) from None
    finally:
        await file.close()

    # 8. Rechazar archivos vacíos
    if bytes_written == 0:
        destination.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El archivo está vacío.",
        )

    logger.info("Subida aceptada: %s (%d bytes).", stored_name, bytes_written)
    return {
        "mensaje": "Archivo subido correctamente.",
        "archivo": stored_name,
        "tamano_bytes": bytes_written,
    }
