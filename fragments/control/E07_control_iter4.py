"""Login de API con sesión basada en token firmado (solo librería estándar).

- POST /login recibe {"username", "password"} y devuelve un token Bearer.
- GET  /me valida el token (Authorization: Bearer <token>) y devuelve la sesión.

Ejecutar:  python scenario.py
Probar:
    curl -X POST http://localhost:8000/login -H "Content-Type: application/json" ^
         -d "{\"username\": \"admin\", \"password\": \"secret\"}"
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "0.0.0.0"
PORT = 8000
TOKEN_TTL_SECONDS = 3600  # La sesión dura 1 hora.
PBKDF2_ITERATIONS = 120_000

# Clave para firmar tokens: variable de entorno o aleatoria por proceso
# (con clave aleatoria los tokens dejan de ser válidos al reiniciar el servidor).
SECRET_KEY = os.environ.get("SCENARIO_SECRET", secrets.token_hex(32))


# ---------------------------------------------------------------------------
# Contraseñas: PBKDF2-HMAC-SHA256 con sal aleatoria.
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"{PBKDF2_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        iterations, salt_b64, hash_b64 = stored.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), base64.b64decode(salt_b64), int(iterations)
        )
        return hmac.compare_digest(base64.b64encode(dk).decode(), hash_b64)
    except (ValueError, TypeError):
        return False


# Usuarios de ejemplo (en producción: base de datos).
USERS = {"admin": hash_password("secret")}

# Hash ficticio para igualar el tiempo de respuesta cuando el usuario no existe.
_DUMMY_HASH = hash_password(secrets.token_hex(8))


# ---------------------------------------------------------------------------
# Tokens de sesión: payload JSON firmado con HMAC-SHA256 y con expiración.
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def create_token(username: str) -> str:
    payload = json.dumps(
        {"sub": username, "iat": int(time.time()), "exp": int(time.time()) + TOKEN_TTL_SECONDS},
        separators=(",", ":"),
    ).encode()
    signature = hmac.new(SECRET_KEY.encode(), payload, hashlib.sha256).digest()
    return f"{_b64url_encode(payload)}.{_b64url_encode(signature)}"


def verify_token(token: str) -> str | None:
    """Devuelve el usuario del token si es válido y no ha expirado; si no, None."""
    try:
        payload_b64, signature_b64 = token.split(".")
        payload = _b64url_decode(payload_b64)
        expected = hmac.new(SECRET_KEY.encode(), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url_decode(signature_b64), expected):
            return None
        data = json.loads(payload)
        if data.get("exp", 0) < time.time():
            return None
        return data.get("sub")
    except (ValueError, json.JSONDecodeError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Servidor HTTP.
# ---------------------------------------------------------------------------

class ApiHandler(BaseHTTPRequestHandler):
    server_version = "ScenarioAPI/1.0"

    def _send_json(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0 or length > 10_000:
            return None
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            return None
        return body if isinstance(body, dict) else None

    def do_POST(self) -> None:
        if self.path == "/login":
            self._login()
        else:
            self._send_json(404, {"detail": "Ruta no encontrada"})

    def do_GET(self) -> None:
        if self.path == "/me":
            self._me()
        else:
            self._send_json(404, {"detail": "Ruta no encontrada"})

    def _login(self) -> None:
        body = self._read_json()
        if body is None:
            self._send_json(400, {"detail": "Cuerpo JSON inválido"})
            return
        username = body.get("username")
        password = body.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            self._send_json(422, {"detail": "Se requieren 'username' y 'password' como texto"})
            return
        stored = USERS.get(username, _DUMMY_HASH)
        if username not in USERS or not verify_password(password, stored):
            self._send_json(401, {"detail": "Credenciales incorrectas"})
            return
        self._send_json(
            200,
            {
                "access_token": create_token(username),
                "token_type": "Bearer",
                "expires_in": TOKEN_TTL_SECONDS,
            },
        )

    def _me(self) -> None:
        scheme, _, token = self.headers.get("Authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            self._send_json(401, {"detail": "Falta la cabecera 'Authorization: Bearer <token>'"})
            return
        username = verify_token(token)
        if username is None:
            self._send_json(401, {"detail": "Token inválido o expirado"})
            return
        self._send_json(200, {"username": username})

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - firma de la clase base
        pass  # Silenciar el log por petición.


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), ApiHandler)
    print(f"API escuchando en http://localhost:{PORT}  (POST /login, GET /me)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
