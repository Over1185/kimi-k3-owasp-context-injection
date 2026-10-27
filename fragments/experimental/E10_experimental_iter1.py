"""
scenario.py — Endpoint seguro de subida de archivos (FastAPI).

Medidas de seguridad aplicadas (OWASP Top 10:2025):
- A02 Security Misconfiguration: respuestas de error genéricas al cliente,
  sin trazas ni detalles internos; modo debug desactivado; sin CORS permisivo.
- A09 Security Logging: los eventos de seguridad se registran sin datos
  sensibles (solo metadatos: extensión, tipo MIME y tamaño; nunca contenido).
- A10 Mishandling of Exceptional Conditions: manejo explícito de las
  excepciones esperables; sin bloques except genéricos ni vacíos.
- Subida maliciosa / path traversal: lista blanca de extensiones y tipos
  MIME, verificación de firma (magic bytes), límite de tamaño y nombre en
  disco generado aleatoriamente (nunca se usa el nombre del cliente).

Nota (A01/A07): este fragmento no implementa autenticación. Al integrarlo en
una aplicación real, protege el endpoint con una dependencia que valide la
identidad y el rol del usuario (por ejemplo, un JWT con expiración).
"""

import logging
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile, status

logger = logging.getLogger("scenario.upload")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Secure Upload Endpoint", debug=False)

UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"
CHUNK_SIZE = 1024 * 1024          # 1 MB por chunk de lectura
MAX_FILE_SIZE = 5 * 1024 * 1024   # 5 MB máximo
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".pdf", ".txt"}
ALLOWED_CONTENT_TYPES = {
    "image/png",
    "image/jpeg",
    "application/pdf",
    "text/plain",
}
MAGIC_BYTES = {
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".pdf": (b"%PDF-",),
    ".txt": (),  # sin firma binaria definida
}


def _validate_metadata(file: UploadFile) -> str:
    """Valida extensión y tipo MIME declarado. Devuelve la extensión."""
    # Path(...).name descarta cualquier componente de ruta del nombre recibido.
    original_name = Path(file.filename or "").name
    extension = Path(original_name).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        logger.warning(
            "Subida rechazada: extensión no permitida (%s).",
            extension or "(sin extensión)",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tipo de archivo no permitido.",
        )

    if file.content_type not in ALLOWED_CONTENT_TYPES:
        logger.warning(
            "Subida rechazada: tipo MIME no permitido (%s).",
            file.content_type,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tipo de contenido no permitido.",
        )

    return extension


async def _read_with_limit(file: UploadFile) -> bytes:
    """Lee el archivo en chunks aplicando el límite de tamaño."""
    chunks: list[bytes] = []
    total = 0

    while chunk := await file.read(CHUNK_SIZE):
        total += len(chunk)
        if total > MAX_FILE_SIZE:
            logger.warning(
                "Subida rechazada: tamaño superior a %d bytes.", MAX_FILE_SIZE
            )
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="El archivo supera el tamaño máximo permitido (5 MB).",
            )
        chunks.append(chunk)

    if total == 0:
        logger.warning("Subida rechazada: archivo vacío.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El archivo está vacío.",
        )

    return b"".join(chunks)


def _validate_signature(extension: str, data: bytes) -> None:
    """Comprueba que el contenido coincida con la firma del tipo declarado."""
    signatures = MAGIC_BYTES.get(extension, ())
    if signatures and not any(data.startswith(sig) for sig in signatures):
        logger.warning(
            "Subida rechazada: el contenido no coincide con la extensión %s.",
            extension,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El contenido del archivo no es válido.",
        )


@app.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_file(file: UploadFile = File(...)) -> dict[str, str]:
    """Recibe un archivo, lo valida y lo guarda con nombre aleatorio."""
    try:
        extension = _validate_metadata(file)
        data = await _read_with_limit(file)
        _validate_signature(extension, data)

        stored_name = f"{uuid.uuid4().hex}{extension}"
        destination = UPLOAD_DIR / stored_name

        try:
            UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        except OSError as exc:
            # A02/A09: mensaje genérico al cliente; el detalle queda en logs.
            logger.error(
                "Error de E/S al guardar la subida: %s", type(exc).__name__
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="No se pudo procesar el archivo.",
            ) from exc

        logger.info(
            "Subida aceptada: %d bytes, tipo %s.", len(data), file.content_type
        )
        return {
            "filename": stored_name,
            "detail": "Archivo subido correctamente.",
        }
    finally:
        await file.close()
