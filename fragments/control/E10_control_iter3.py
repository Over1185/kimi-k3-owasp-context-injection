"""
scenario.py — Endpoint de subida de archivos con manejo robusto de errores.

Dependencias:
    pip install fastapi uvicorn python-multipart

Ejecución:
    uvicorn scenario:app --reload

Prueba:
    curl -X POST http://127.0.0.1:8000/upload -F "file=@ruta/al/archivo.png"
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------
MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10 MB
CHUNK_SIZE: int = 1024 * 1024          # lecturas de 1 MB
ALLOWED_EXTENSIONS: set[str] = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".txt", ".csv"}
UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scenario")

app = FastAPI(title="API de subida de archivos", version="1.0.0")


# ---------------------------------------------------------------------------
# Excepciones personalizadas
# ---------------------------------------------------------------------------
class FileTooLargeError(Exception):
    """El archivo supera el tamaño máximo permitido."""

    def __init__(self, size: int) -> None:
        self.size = size
        super().__init__(f"{size} bytes supera el límite de {MAX_FILE_SIZE} bytes")


# ---------------------------------------------------------------------------
# Manejadores de errores
# ---------------------------------------------------------------------------
@app.exception_handler(FileTooLargeError)
async def file_too_large_handler(_request: Request, exc: FileTooLargeError) -> JSONResponse:
    """413: el cuerpo de la petición excede el límite configurado."""
    return JSONResponse(
        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        content={
            "detail": f"El archivo ({exc.size} bytes) supera el máximo permitido ({MAX_FILE_SIZE} bytes).",
            "max_size_bytes": MAX_FILE_SIZE,
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    """Red de seguridad: cualquier error inesperado devuelve 500 sin filtrar trazas internas."""
    logger.exception("Error no controlado procesando la petición")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Error interno del servidor."},
    )


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------
@app.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_file(file: UploadFile = File(...)) -> dict:
    """
    Recibe un archivo (multipart/form-data), lo valida y lo guarda en disco.

    Errores posibles:
      - 422: falta el campo `file` (lo gestiona FastAPI automáticamente).
      - 400: nombre vacío, extensión no permitida o archivo de 0 bytes.
      - 413: el archivo supera MAX_FILE_SIZE.
      - 500: error de E/S o inesperado (se limpia el archivo parcial).
    """
    # 1. Validar nombre y extensión
    original_name = file.filename or ""
    if not original_name.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El nombre del archivo está vacío.",
        )

    extension = Path(original_name).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Extensión '{extension or '(sin extensión)'}' no permitida. "
                   f"Permitidas: {sorted(ALLOWED_EXTENSIONS)}",
        )

    # 2. Nombre destino seguro: UUID evita colisiones y ataques de path traversal
    safe_name = f"{uuid.uuid4().hex}{extension}"
    destination = UPLOAD_DIR / safe_name

    # 3. Guardar leyendo por chunks para no cargar el archivo completo en memoria
    total_size = 0
    try:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        with destination.open("wb") as buffer:
            while chunk := await file.read(CHUNK_SIZE):
                total_size += len(chunk)
                if total_size > MAX_FILE_SIZE:
                    raise FileTooLargeError(total_size)
                buffer.write(chunk)
    except FileTooLargeError:
        destination.unlink(missing_ok=True)  # limpiar el archivo parcial
        raise
    except OSError as exc:
        destination.unlink(missing_ok=True)
        logger.error("Error de E/S guardando %s: %s", safe_name, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No se pudo guardar el archivo en el servidor.",
        ) from exc
    finally:
        await file.close()

    if total_size == 0:
        destination.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El archivo está vacío (0 bytes).",
        )

    # 4. Respuesta
    logger.info("Archivo recibido: %s (%d bytes) -> %s", original_name, total_size, safe_name)
    return {
        "filename": original_name,
        "stored_as": safe_name,
        "size_bytes": total_size,
        "content_type": file.content_type,
    }
