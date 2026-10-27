"""Login de API en un único archivo (solo biblioteca estándar de Python).

Endpoints:
    POST /login  Recibe {"username", "password"} y devuelve un token firmado.
    GET  /me     Valida el token (cabecera "Authorization: Bearer <token>").

El token es un JWT HS256 (header.payload.signature) con caducidad, firmado
con HMAC-SHA256. Al reiniciar el servidor se genera una clave nueva y los
tokens anteriores quedan invalidados; para que persistan entre reinicios,
define la variable de entorno SCENARIO_SECRET.

Ejecución:
    python scenario.py

Prueba:
    curl -X POST http://localhost:8000/login ^
         -H "Content-Type: application/json" ^
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
TOKEN_TTL_SECONDS = 3600  # 1 hora de sesión
MAX_BODY_BYTES = 10_000
PBKDF2_ITERATIONS = 100_000

# Clave de firma: de entorno o aleatoria por arranque.
SECRET_KEY = os.environ.get("SCENARIO_SECRET") or secrets.token_hex(32)


# --------------------------------------------------------------------------
# Contraseñas (PBKDF2-HMAC-SHA256)
# --------------------------------------------------------------------------

def _hash_password(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return base64.urlsafe_b64encode(salt + dk).decode()


def _verify_password(password: str, stored: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(stored.encode())
    except ValueError:
        return False
    salt, dk = raw[:16], raw[16:]
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PBKDF2_ITERATIONS
    )
    return hmac.compare_digest(candidate, dk)


# Usuarios de demostración (¡cambiar en producción!). Formato: usuario -> hash.
USERS = {
    "admin": _hash_password("secret", b"scenario-demo-salt"),
}


# --------------------------------------------------------------------------
# Tokens JWT HS256
# --------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_token(username: str) -> str:
    header = _b64url_encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()
    )
    now = int(time.time())
    payload = _b64url_encode(
        json.dumps(
            {"sub": username, "iat": now, "exp": now + TOKEN_TTL_SECONDS},
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{payload}"
    signature = _b64url_encode(
        hmac.new(SECRET_KEY.encode(), signing_input.encode(), hashlib.sha256).digest()
    )
    return f"{signing_input}.{signature}"


def verify_token(token: str) -> dict | None:
    """Devuelve los claims si el token es válido y no ha expirado; si no, None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header, payload, signature = parts
    signing_input = f"{header}.{payload}"
    expected = _b64url_encode(
        hmac.new(SECRET_KEY.encode(), signing_input.encode(), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        claims = json.loads(_b64url_decode(payload))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(claims, dict) or claims.get("exp", 0) < time.time():
        return None
    return claims


# --------------------------------------------------------------------------
# Servidor HTTP
# --------------------------------------------------------------------------

class ApiHandler(BaseHTTPRequestHandler):
    server_version = "ScenarioAPI/1.0"

    def _send_json(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY_BYTES:
            return None
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return body if isinstance(body, dict) else None

    def do_POST(self) -> None:  # noqa: N802 - nombre impuesto por BaseHTTPRequestHandler
        if self.path != "/login":
            self._send_json(404, {"error": "not found"})
            return

        body = self._read_json()
        if body is None:
            self._send_json(400, {"error": "cuerpo JSON inválido"})
            return

        username = body.get("username")
        password = body.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            self._send_json(400, {"error": "username y password son obligatorios"})
            return

        stored = USERS.get(username)
        if stored is None or not _verify_password(password, stored):
            # Misma respuesta para usuario inexistente y contraseña incorrecta.
            self._send_json(401, {"error": "credenciales inválidas"})
            return

        self._send_json(
            200,
            {
                "access_token": create_token(username),
                "token_type": "Bearer",
                "expires_in": TOKEN_TTL_SECONDS,
            },
        )

    def do_GET(self) -> None:  # noqa: N802 - nombre impuesto por BaseHTTPRequestHandler
        if self.path != "/me":
            self._send_json(404, {"error": "not found"})
            return

        auth = self.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
        claims = verify_token(token) if token else None
        if claims is None:
            self._send_json(401, {"error": "token inválido o expirado"})
            return

        self._send_json(200, {"username": claims["sub"], "expires_at": claims["exp"]})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), ApiHandler)
    print(f"API escuchando en http://localhost:{PORT}")
    print('Prueba el login con: {"username": "admin", "password": "secret"}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
