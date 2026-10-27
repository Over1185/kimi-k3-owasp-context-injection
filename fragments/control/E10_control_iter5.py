"""
Endpoint de subida de archivos con manejo robusto de errores (FastAPI).

Requisitos:
    pip install fastapi uvicorn python-multipart

Ejecución:
    uvicorn scenario:app --reload

Ejemplo de uso:
    curl -X POST -F "file=@documento.pdf" http://127.0.0.1:8000/upload
"""

import logging
import re
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------
UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
CHUNK_SIZE = 1024 * 1024          # Lectura en bloques de 1 MB
ALLOWED_EXTENSIONS = {".txt", ".csv", ".pdf", ".png", ".jpg", ".jpeg"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("scenario")


# ---------------------------------------------------------------------------
# Ciclo de vida: garantizar que exista el directorio de subidas al arrancar
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(_: FastAPI):
    try:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.error("No se pudo crear el directorio de subidas %s: %s", UPLOAD_DIR, exc)
        raise
    yield


app = FastAPI(title="File Upload API", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------
def _sanitize_filename(filename: str) -> str:
    """Elimina componentes de ruta (path traversal) y caracteres peligrosos."""
    name = Path(filename).name
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return name or "archivo"


# ---------------------------------------------------------------------------
# Manejadores globales de errores
# ---------------------------------------------------------------------------
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    # Ocurre, por ejemplo, cuando falta el campo 'file' en el multipart
    logger.warning("Petición inválida: %s", exc.errors())
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": "Petición inválida: envía el archivo en el campo 'file' (multipart/form-data)."},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    logger.exception("Error inesperado procesando la petición")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Error interno del servidor."},
    )


# ---------------------------------------------------------------------------
# Endpoint de subida
# ---------------------------------------------------------------------------
@app.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_file(file: UploadFile = File(...)):
    # 1. Validar que el archivo tenga nombre
    if not file.filename:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "El archivo no tiene nombre.")

    # 2. Validar extensión permitida
    extension = Path(file.filename).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            415,  # Unsupported Media Type
            f"Tipo de archivo no permitido: '{extension or 'sin extensión'}'. "
            f"Permitidos: {', '.join(sorted(ALLOWED_EXTENSIONS))}.",
        )

    # 3. Guardar con nombre único y sanitizado para evitar colisiones y path traversal
    stored_name = f"{uuid.uuid4().hex}_{_sanitize_filename(file.filename)}"
    destination = UPLOAD_DIR / stored_name

    size = 0
    try:
        with destination.open("wb") as buffer:
            while chunk := await file.read(CHUNK_SIZE):
                size += len(chunk)
                if size > MAX_FILE_SIZE:
                    raise HTTPException(
                        413,  # Content Too Large
                        f"El archivo supera el tamaño máximo permitido ({MAX_FILE_SIZE // (1024 * 1024)} MB).",
                    )
                buffer.write(chunk)
    except HTTPException:
        destination.unlink(missing_ok=True)  # limpiar archivo parcial
        raise
    except OSError as exc:
        destination.unlink(missing_ok=True)
        logger.exception("Error de E/S guardando el archivo")
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "No se pudo guardar el archivo."
        ) from exc
    finally:
        await file.close()

    # 4. Rechazar archivos vacíos
    if size == 0:
        destination.unlink(missing_ok=True)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "El archivo está vacío.")

    logger.info("Archivo guardado: %s (%d bytes)", destination, size)
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "detail": "Archivo subido correctamente.",
            "filename": file.filename,
            "stored_as": stored_name,
            "size_bytes": size,
            "content_type": file.content_type,
        },
    )
