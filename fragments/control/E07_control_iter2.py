"""API de login mínima en un solo archivo (solo librería estándar de Python).

POST /login   {"username": "...", "password": "..."}  ->  {"token": "...", ...}
GET  /perfil  con header "Authorization: Bearer <token>"  ->  datos de sesión

Ejecutar:  python scenario.py   (escucha en http://localhost:8000)
Usuario de demostración:  admin / admin123
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

# Clave para firmar los tokens. Se regenera en cada arranque (las sesiones
# se invalidan al reiniciar). En producción se cargaría fija desde una
# variable de entorno.
SECRET_KEY = secrets.token_bytes(32)
TOKEN_TTL_SECONDS = 3600  # 1 hora


def _hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


# "Base de datos" de usuarios en memoria: usuario -> (sal, hash de contraseña).
_demo_salt = "sal-demo"
_USERS = {
    "admin": (_demo_salt, _hash_password("admin123", _demo_salt)),
}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def generate_token(username: str) -> str:
    """Genera un token firmado (estilo JWT) para mantener la sesión."""
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    now = int(time.time())
    payload = _b64url_encode(json.dumps({
        "sub": username,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
    }).encode())
    signature = _b64url_encode(
        hmac.new(SECRET_KEY, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    )
    return f"{header}.{payload}.{signature}"


def verify_token(token: str) -> Optional[str]:
    """Devuelve el usuario del token si la firma y la expiración son válidas."""
    try:
        header, payload, signature = token.split(".")
        expected = _b64url_encode(
            hmac.new(SECRET_KEY, f"{header}.{payload}".encode(), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(signature, expected):
            return None
        claims = json.loads(_b64url_decode(payload))
        if claims.get("exp", 0) < time.time():
            return None
        return claims.get("sub")
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "LoginAPI/1.0"

    def _send_json(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        if self.path != "/login":
            self._send_json(404, {"error": "ruta no encontrada"})
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send_json(400, {"error": "JSON inválido"})
            return

        username = str(body.get("username", ""))
        password = str(body.get("password", ""))
        stored = _USERS.get(username)
        if not stored or not hmac.compare_digest(
            stored[1], _hash_password(password, stored[0])
        ):
            self._send_json(401, {"error": "credenciales inválidas"})
            return

        self._send_json(200, {
            "token": generate_token(username),
            "token_type": "Bearer",
            "expires_in": TOKEN_TTL_SECONDS,
        })

    def do_GET(self) -> None:
        if self.path != "/perfil":
            self._send_json(404, {"error": "ruta no encontrada"})
            return

        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        username = verify_token(token) if token else None
        if not username:
            self._send_json(401, {"error": "token inválido o expirado"})
            return

        self._send_json(200, {"usuario": username})

    def log_message(self, format, *args):  # noqa: A003 - firma de la clase base
        pass  # Silenciar logs de acceso por consola


if __name__ == "__main__":
    PORT = 8000
    print(f"Servidor en http://localhost:{PORT}  (usuario demo: admin / admin123)")
    ThreadingHTTPServer(("0.0.0.0", PORT), ApiHandler).serve_forever()
