"""Endpoint de subida de archivos con manejo de errores.

Aplicación Flask en un único archivo.

Uso:
    pip install flask
    python scenario.py

Probar:
    curl -F "file=@ejemplo.txt" http://127.0.0.1:5000/upload

Nota: en tiempo de ejecución se crea la carpeta "uploads/" junto a este
archivo para almacenar los ficheros recibidos.
"""

from __future__ import annotations

import os
import uuid

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"txt", "csv", "pdf", "png", "jpg", "jpeg", "gif"}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
# Flask rechaza automáticamente cuerpos mayores con un 413.
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------
def allowed_file(filename: str) -> bool:
    """Comprueba que el nombre tenga una extensión permitida.

    Ojo: validar la extensión no garantiza el contenido real del archivo;
    para producción convendría inspeccionar también el tipo MIME o la
    cabecera (magic bytes).
    """
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def error_response(message: str, status_code: int):
    """Construye una respuesta de error JSON uniforme."""
    response = jsonify(ok=False, error=message)
    response.status_code = status_code
    return response


# ---------------------------------------------------------------------------
# Manejadores de error
# ---------------------------------------------------------------------------
@app.errorhandler(RequestEntityTooLarge)
def handle_request_entity_too_large(error):
    """El cuerpo de la petición supera MAX_CONTENT_LENGTH."""
    limit_mb = MAX_CONTENT_LENGTH // (1024 * 1024)
    return error_response(f"El archivo supera el límite de {limit_mb} MB.", 413)


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    """Red de seguridad: cualquier excepción no controlada devuelve JSON 500."""
    # Los errores HTTP normales (404, 405, ...) se devuelven tal cual.
    if isinstance(error, HTTPException):
        return error
    app.logger.exception("Error inesperado: %s", error)
    return error_response("Error interno del servidor.", 500)


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------
@app.post("/upload")
def upload_file():
    # 1. La petición debe ser multipart/form-data.
    content_type = request.content_type or ""
    if not content_type.startswith("multipart/form-data"):
        return error_response(
            "Content-Type debe ser multipart/form-data.", 415
        )

    # 2. Debe incluir el campo "file".
    if "file" not in request.files:
        return error_response("Falta el campo 'file' en la petición.", 400)

    file = request.files["file"]

    # 3. Nombre vacío: el cliente envió el campo sin seleccionar archivo.
    if file.filename is None or file.filename.strip() == "":
        return error_response("No se seleccionó ningún archivo.", 400)

    # 4. Extensión permitida.
    if not allowed_file(file.filename):
        allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
        return error_response(
            f"Extensión no permitida. Extensiones válidas: {allowed}.", 400
        )

    # 5. Guardar con nombre saneado y único para evitar colisiones y
    #    ataques de path traversal.
    safe_name = secure_filename(file.filename)
    unique_name = f"{uuid.uuid4().hex}_{safe_name}"
    destination = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)

    try:
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        file.save(destination)
    except OSError as exc:
        # Disco lleno, permisos insuficientes, ruta inválida, etc.
        app.logger.exception("No se pudo guardar el archivo")
        detail = exc.strerror or str(exc)
        return error_response(f"No se pudo guardar el archivo: {detail}.", 500)

    return (
        jsonify(
            ok=True,
            filename=unique_name,
            original_filename=file.filename,
            size=os.path.getsize(destination),
        ),
        201,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
