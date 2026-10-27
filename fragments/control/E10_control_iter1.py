"""Endpoint de subida de archivos con manejo de errores (Flask).

Uso:
    pip install flask
    python scenario.py

    curl -X POST -F "file=@ejemplo.txt" http://127.0.0.1:5000/upload
"""

import logging
import os
import uuid

from flask import Flask, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

# --- Configuración -----------------------------------------------------------
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")
ALLOWED_EXTENSIONS = {"txt", "csv", "pdf", "png", "jpg", "jpeg", "gif"}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename: str) -> bool:
    """Comprueba que el nombre tenga una extensión permitida."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# --- Endpoint ----------------------------------------------------------------
@app.route("/upload", methods=["POST"])
def upload_file():
    # 1. La petición no incluye la parte 'file' (multipart incorrecto).
    if "file" not in request.files:
        return jsonify({"error": "Falta la parte 'file' en la petición multipart."}), 400

    file = request.files["file"]

    # 2. El campo existe pero el usuario no seleccionó ningún archivo.
    if file.filename == "":
        return jsonify({"error": "No se seleccionó ningún archivo."}), 400

    # 3. Extensión no permitida.
    if not allowed_file(file.filename):
        permitidas = ", ".join(sorted(ALLOWED_EXTENSIONS))
        return jsonify({"error": f"Tipo de archivo no permitido. Válidos: {permitidas}."}), 400

    # 4. Guardar el archivo con nombre sanitizado y único.
    try:
        safe_name = secure_filename(file.filename)
        unique_name = f"{uuid.uuid4().hex}_{safe_name}"
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
        file.save(save_path)
    except OSError:
        logger.exception("Error de E/S al guardar el archivo subido")
        return jsonify({"error": "No se pudo guardar el archivo en el servidor."}), 500

    return jsonify({
        "message": "Archivo subido correctamente.",
        "filename": unique_name,
        "size_bytes": os.path.getsize(save_path),
    }), 201


# --- Manejadores de errores --------------------------------------------------
@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    return jsonify({"error": "El archivo supera el tamaño máximo permitido (16 MB)."}), 413


@app.errorhandler(404)
def handle_not_found(error):
    return jsonify({"error": "Recurso no encontrado."}), 404


@app.errorhandler(405)
def handle_method_not_allowed(error):
    return jsonify({"error": "Método no permitido. Usa POST en /upload."}), 405


@app.errorhandler(500)
def handle_internal_error(error):
    logger.exception("Error interno no controlado")
    return jsonify({"error": "Error interno del servidor."}), 500


if __name__ == "__main__":
    app.run(debug=True)
