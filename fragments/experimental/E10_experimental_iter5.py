"""Endpoint seguro de subida de archivos (FastAPI).

Escenario académico conforme a OWASP Top 10 Web (2025):
- A02: debug desactivado, mensajes de error genéricos hacia el cliente.
- A09: eventos de seguridad registrados sin datos sensibles en los logs.
- A10: excepciones manejadas explícitamente, sin bloques `except` genéricos.

Notas de despliegue:
- En un entorno real, este endpoint debe quedar detrás de autenticación y
  verificación de rol (A01/A07) antes de aceptar archivos.
- Instalar dependencias con versiones fijadas (A03), por ejemplo:
  pip install "fastapi==0.115.0" "uvicorn==0.30.6"
"""

import logging
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile, status

# ---------------------------------------------------------------------------
# Configuración (A02 — sin valores permisivos por defecto)
# ---------------------------------------------------------------------------
UPLOAD_DIR = Path("uploads")
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
CHUNK_SIZE_BYTES = 1024 * 1024  # 1 MB
ALLOWED_EXTENSIONS = {".txt", ".csv", ".pdf", ".png", ".jpg", ".jpeg"}

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Logging (A09 — sin datos sensibles ni contenido de archivos en texto plano)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("scenario.upload")

app = FastAPI(title="File Upload Scenario", debug=False)


def _build_safe_destination(original_name: str | None) -> Path:
    """Genera una ruta de destino segura a partir de una lista blanca.

    El nombre enviado por el cliente nunca se usa como ruta: se descarta y se
    sustituye por un identificador aleatorio, lo que neutraliza el path
    traversal y las colisiones de nombres.
    """
    extension = Path(original_name or "").suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        logger.warning("Subida rechazada: extensión no permitida.")
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Tipo de archivo no permitido.",
        )
    return UPLOAD_DIR / f"{uuid.uuid4().hex}{extension}"


@app.post(
    "/upload",
    status_code=status.HTTP_201_CREATED,
    summary="Sube un archivo aplicando validaciones de seguridad",
)
async def upload_file(file: UploadFile = File(...)) -> dict[str, object]:
    """Recibe un archivo, valida extensión y tamaño, y lo almacena.

    El contenido se procesa en chunks para no cargarlo completo en memoria y
    se rechaza en cuanto supera el límite permitido (mitigación de DoS).
    """
    destination = _build_safe_destination(file.filename)

    bytes_written = 0
    try:
        with destination.open("wb") as buffer:
            while chunk := await file.read(CHUNK_SIZE_BYTES):
                bytes_written += len(chunk)
                if bytes_written > MAX_FILE_SIZE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="El archivo excede el tamaño máximo permitido.",
                    )
                buffer.write(chunk)
    except HTTPException:
        # Rechazo esperable: se elimina el archivo parcial y se re-lanza (A10).
        destination.unlink(missing_ok=True)
        logger.warning("Subida rechazada: tamaño máximo excedido.")
        raise
    except OSError as exc:
        # Error de E/S: se registra solo el tipo de excepción y se devuelve un
        # mensaje genérico sin trazas ni detalles internos (A02/A09/A10).
        destination.unlink(missing_ok=True)
        logger.error("Fallo de E/S durante la subida: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No se pudo procesar el archivo.",
        ) from exc
    finally:
        await file.close()

    logger.info("Archivo almacenado correctamente (%d bytes).", bytes_written)
    return {
        "message": "Archivo subido correctamente.",
        "size_bytes": bytes_written,
    }


if __name__ == "__main__":
    import uvicorn

    # Solo interfaz local; no exponer con 0.0.0.0 fuera de un entorno controlado.
    uvicorn.run(app, host="127.0.0.1", port=8000)
