"""Endpoint seguro de subida de archivos (FastAPI).

Aplica las directrices OWASP Top 10:2025 definidas en este repositorio:
- A01 (Broken Access Control): no se confía en el nombre de archivo enviado
  por el cliente; se genera uno aleatorio (mitiga path traversal).
- A02 (Security Misconfiguration): las respuestas de error no exponen trazas
  ni detalles internos; la app se ejecuta con debug desactivado.
- A09 (Security Logging): los eventos se registran sin datos sensibles
  (no se registran nombres de archivo del cliente ni contenido).
- A10 (Mishandling of Exceptional Conditions): solo se capturan excepciones
  explícitas y esperables; no hay `except` genéricos ni vacíos.

Requiere: fastapi, uvicorn y python-multipart (fijar versiones con pin, A03).
"""

from __future__ import annotations

import logging
import re
import secrets
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, status

logger = logging.getLogger("scenario.upload")
logging.basicConfig(level=logging.INFO)

app = FastAPI(debug=False)

UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MiB
CHUNK_SIZE = 64 * 1024  # 64 KiB
ALLOWED_EXTENSIONS = {".txt", ".csv", ".pdf", ".png", ".jpg", ".jpeg"}
_EXTENSION_RE = re.compile(r"^\.[a-z0-9]{1,10}$")


def _validated_extension(filename: str | None) -> str:
    """Valida la extensión contra una allowlist.

    Nunca devuelve partes de la ruta enviada por el cliente.
    """
    if not filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nombre de archivo no válido.",
        )
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS or not _EXTENSION_RE.fullmatch(suffix):
        logger.warning("Subida rechazada: extensión no permitida.")
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Tipo de archivo no permitido.",
        )
    return suffix


@app.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_file(file: UploadFile) -> dict:
    extension = _validated_extension(file.filename)

    # El nombre almacenado es aleatorio; el del cliente se descarta (A01).
    stored_name = f"{secrets.token_hex(16)}{extension}"
    destination = UPLOAD_DIR / stored_name

    total = 0
    try:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        with destination.open("wb") as buffer:
            while chunk := await file.read(CHUNK_SIZE):
                total += len(chunk)
                if total > MAX_FILE_SIZE:
                    logger.warning("Subida rechazada: tamaño máximo excedido.")
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="El archivo supera el tamaño máximo permitido.",
                    )
                buffer.write(chunk)
    except HTTPException:
        # Error de validación ya comunicado al cliente: limpiar y relanzar.
        destination.unlink(missing_ok=True)
        raise
    except OSError as exc:
        # Error de E/S esperable (disco, permisos): no exponer detalles (A02).
        destination.unlink(missing_ok=True)
        logger.error("Error de E/S al guardar archivo: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No se pudo procesar el archivo.",
        ) from exc
    finally:
        await file.close()

    if total == 0:
        destination.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El archivo está vacío.",
        )

    logger.info("Archivo almacenado correctamente (%d bytes).", total)
    return {"filename": stored_name, "size_bytes": total}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
