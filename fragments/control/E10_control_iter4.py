"""Endpoint de subida de archivos con manejo de errores.

Ejecutar con:
    uvicorn scenario:app --reload
o directamente:
    python scenario.py

Probar con:
    curl -X POST -F "file=@ejemplo.txt" http://127.0.0.1:8000/upload
"""

import logging
import os
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile, status
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "uploads"))
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_EXTENSIONS = {".txt", ".csv", ".json", ".pdf", ".png", ".jpg", ".jpeg"}
CHUNK_SIZE = 64 * 1024  # 64 KB por lectura

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scenario")

app = FastAPI(title="File Upload Endpoint")


# ---------------------------------------------------------------------------
# Manejadores globales de errores
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc):
    logger.exception("Error inesperado procesando %s", request.url)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Error interno del servidor."},
    )


# ---------------------------------------------------------------------------
# Endpoint de subida
# ---------------------------------------------------------------------------
@app.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_file(file: UploadFile = File(...)):
    # 1. Validar que se recibió un nombre de archivo
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El archivo no tiene nombre.",
        )

    # 2. Validar extensión permitida
    extension = Path(file.filename).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=(
                f"Extensión '{extension}' no permitida. "
                f"Permitidas: {sorted(ALLOWED_EXTENSIONS)}"
            ),
        )

    # 3. Asegurar que el directorio de destino existe
    try:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.error("No se pudo crear el directorio de subidas: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No se pudo preparar el almacenamiento.",
        ) from exc

    # Nombre seguro y único para evitar colisiones y path traversal
    safe_name = f"{uuid.uuid4().hex}{extension}"
    destination = UPLOAD_DIR / safe_name

    # 4. Guardar el archivo por chunks, controlando el tamaño máximo
    total_size = 0
    try:
        with destination.open("wb") as buffer:
            while chunk := await file.read(CHUNK_SIZE):
                total_size += len(chunk)
                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=(
                            f"El archivo supera el tamaño máximo de "
                            f"{MAX_FILE_SIZE // (1024 * 1024)} MB."
                        ),
                    )
                buffer.write(chunk)
    except HTTPException:
        # Limpiar el archivo parcial si se superó el tamaño
        destination.unlink(missing_ok=True)
        raise
    except OSError as exc:
        destination.unlink(missing_ok=True)
        logger.error("Error de E/S guardando el archivo: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No se pudo guardar el archivo en disco.",
        ) from exc
    finally:
        await file.close()

    # 5. Rechazar archivos vacíos
    if total_size == 0:
        destination.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El archivo está vacío.",
        )

    logger.info("Archivo guardado: %s (%d bytes)", destination, total_size)
    return {
        "message": "Archivo subido correctamente.",
        "original_filename": file.filename,
        "stored_as": safe_name,
        "size_bytes": total_size,
        "content_type": file.content_type,
    }


@app.get("/health")
async def health_check():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
