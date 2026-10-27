"""
Endpoint seguro de subida de archivos (FastAPI).

Medidas aplicadas según OWASP Top 10:2025 y el checklist del proyecto:
- A01: se exige autenticación (token Bearer) antes de aceptar el archivo.
- Validación estricta de extensión, content-type y tamaño máximo.
- Sanitización del nombre de archivo para evitar path traversal.
- Nombre de almacenamiento generado con aleatoriedad segura (secrets).
- A09: logging de eventos de seguridad sin datos sensibles.
- A10: manejo explícito de excepciones; no se exponen trazas al cliente.
"""

import logging
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, UploadFile, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MiB
ALLOWED_EXTENSIONS = {".txt", ".csv", ".pdf", ".png", ".jpg", ".jpeg"}
ALLOWED_CONTENT_TYPES = {
    "text/plain",
    "text/csv",
    "application/pdf",
    "image/png",
    "image/jpeg",
}
CHUNK_SIZE = 64 * 1024  # 64 KiB

logger = logging.getLogger("scenario.upload")
logging.basicConfig(level=logging.INFO)

app = FastAPI(debug=False)  # A02: modo debug desactivado
bearer_scheme = HTTPBearer(auto_error=True)


# ---------------------------------------------------------------------------
# Autenticación (A01/A07)
# ---------------------------------------------------------------------------

# En un entorno real este valor vendría de una variable de entorno / gestor de
# secretos; nunca debe incluirse un secreto real en el código fuente (A04).
import os

EXPECTED_TOKEN = os.environ.get("UPLOAD_API_TOKEN", "")


def require_authenticated_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> str:
    """Verifica el token Bearer en cada solicitud."""
    if not EXPECTED_TOKEN or not secrets.compare_digest(
        credentials.credentials, EXPECTED_TOKEN
    ):
        # A09: se registra el intento fallido sin exponer el token recibido.
        logger.warning("Intento de subida con credenciales inválidas")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas.",
        )
    return "authenticated-user"


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def sanitize_filename(filename: str) -> str:
    """
    Devuelve un nombre de archivo seguro:
    - elimina componentes de ruta (path traversal);
    - conserva solo caracteres seguros.
    """
    name = Path(filename).name  # descarta cualquier directorio
    safe = "".join(c for c in name if c.isalnum() or c in ("-", "_", "."))
    return safe.strip(".") or "upload"


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@app.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_file(
    file: UploadFile,
    user: str = Depends(require_authenticated_user),
) -> dict:
    # --- Validación de extensión y content-type ---------------------------
    safe_name = sanitize_filename(file.filename or "")
    extension = Path(safe_name).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        logger.info("Subida rechazada: extensión no permitida (%s)", extension)
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Tipo de archivo no permitido.",
        )

    if file.content_type not in ALLOWED_CONTENT_TYPES:
        logger.info(
            "Subida rechazada: content-type no permitido (%s)", file.content_type
        )
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Content-Type no permitido.",
        )

    # --- Preparación del destino ------------------------------------------
    try:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        # A10: excepción esperable manejada explícitamente; sin traza al cliente.
        logger.exception("No se pudo preparar el directorio de subidas")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno al procesar la subida.",
        )

    # Nombre final aleatorio: evita colisiones y sobrescritura de archivos.
    stored_name = f"{secrets.token_hex(8)}{extension}"
    destination = (UPLOAD_DIR / stored_name).resolve()

    # Defensa adicional contra path traversal: el destino debe quedar dentro
    # del directorio de subidas.
    if not destination.is_relative_to(UPLOAD_DIR.resolve()):
        logger.warning("Intento de escritura fuera del directorio permitido")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nombre de archivo no válido.",
        )

    # --- Escritura por chunks con límite de tamaño -------------------------
    total_bytes = 0
    try:
        with destination.open("wb") as out:
            while chunk := await file.read(CHUNK_SIZE):
                total_bytes += len(chunk)
                if total_bytes > MAX_FILE_SIZE:
                    raise ValueError("size-limit")
                out.write(chunk)
    except ValueError:
        # Archivo demasiado grande: se elimina el archivo parcial.
        destination.unlink(missing_ok=True)
        logger.info("Subida rechazada: tamaño máximo excedido")
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="El archivo supera el tamaño máximo permitido (5 MiB).",
        )
    except OSError:
        destination.unlink(missing_ok=True)
        logger.exception("Error de E/S al guardar el archivo")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno al guardar el archivo.",
        )
    finally:
        await file.close()

    # A09: evento de seguridad registrado sin contenido sensible.
    logger.info(
        "Archivo aceptado: usuario=%s nombre_original=%s bytes=%d",
        user,
        safe_name,
        total_bytes,
    )

    return {
        "message": "Archivo subido correctamente.",
        "filename": stored_name,
        "size": total_bytes,
    }
