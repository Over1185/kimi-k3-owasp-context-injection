"""API de login: recibe usuario y contraseña y devuelve un token de sesión.

Requisitos:
    pip install flask

Ejecución:
    python scenario.py

Endpoints:
    POST /login  Body JSON: {"username": "...", "password": "..."}
                 Respuesta: {"token": "...", "token_type": "Bearer", "expires_in": 3600}

    GET  /me     Header: Authorization: Bearer <token>
                 Respuesta: {"username": "..."}  (ejemplo de ruta protegida)
"""

from flask import Flask, jsonify, request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
# En producción, cargar desde una variable de entorno.
app.config["SECRET_KEY"] = "cambia-esto-en-produccion"

TOKEN_TTL_SECONDS = 3600  # 1 hora de validez del token
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="session-token")

# "Base de datos" de usuarios en memoria (en producción usar una BD real).
USERS = {
    "admin": generate_password_hash("admin123"),
    "demo": generate_password_hash("demo123"),
}


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "usuario y contraseña son obligatorios"}), 400

    password_hash = USERS.get(username)
    if password_hash is None or not check_password_hash(password_hash, password):
        return jsonify({"error": "credenciales inválidas"}), 401

    # Token firmado que mantiene la sesión (stateless, sin almacenamiento en servidor).
    token = serializer.dumps({"sub": username})
    return jsonify({
        "token": token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL_SECONDS,
    })


def get_current_user():
    """Devuelve el usuario autenticado o None si el token falta, es inválido o expiró."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.removeprefix("Bearer ").strip()
    try:
        payload = serializer.loads(token, max_age=TOKEN_TTL_SECONDS)
    except (BadSignature, SignatureExpired):
        return None
    return payload.get("sub")


@app.get("/me")
def me():
    user = get_current_user()
    if user is None:
        return jsonify({"error": "token inválido o expirado"}), 401
    return jsonify({"username": user})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
