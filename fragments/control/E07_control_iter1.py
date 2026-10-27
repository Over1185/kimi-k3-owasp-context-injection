"""API mínima de login en un solo archivo.

Uso:
    python scenario.py

POST /login
Content-Type: application/json
{"username": "admin", "password": "admin"}

Respuesta 200:
{"access_token": "...", "token_type": "Bearer", "expires_in": 3600}
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "3600"))
API_USERNAME = os.getenv("API_USERNAME", "admin")
API_PASSWORD = os.getenv("API_PASSWORD", "admin")
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
MAX_BODY_BYTES = 10_000


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json_response(handler: BaseHTTPRequestHandler, status: HTTPStatus, payload: dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status.value)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any] | None:
    content_type = handler.headers.get("Content-Type", "")
    if "application/json" not in content_type.lower():
        return None

    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        return None

    if length <= 0 or length > MAX_BODY_BYTES:
        return None

    try:
        payload = json.loads(handler.rfile.read(length).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

    return payload if isinstance(payload, dict) else None


def _credentials_are_valid(username: str, password: str) -> bool:
    return hmac.compare_digest(username, API_USERNAME) and hmac.compare_digest(password, API_PASSWORD)


def _create_access_token(username: str) -> tuple[str, int]:
    now = int(time.time())
    expires_in = SESSION_TTL_SECONDS
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + expires_in,
        "jti": secrets.token_urlsafe(8),
    }
    payload_part = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature_part = _b64url(
        hmac.new(SECRET_KEY.encode("utf-8"), payload_part.encode("ascii"), hashlib.sha256).digest()
    )
    return f"{payload_part}.{signature_part}", expires_in


class LoginHandler(BaseHTTPRequestHandler):
    server_version = "ScenarioLogin/1.0"

    def do_POST(self) -> None:
        if urlsplit(self.path).path != "/login":
            _json_response(self, HTTPStatus.NOT_FOUND, {"detail": "Not found"})
            return

        payload = _read_json(self)
        if payload is None:
            _json_response(self, HTTPStatus.BAD_REQUEST, {"detail": "Expected JSON body"})
            return

        username = payload.get("username")
        password = payload.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            _json_response(self, HTTPStatus.BAD_REQUEST, {"detail": "username and password must be strings"})
            return

        if not _credentials_are_valid(username, password):
            _json_response(self, HTTPStatus.UNAUTHORIZED, {"detail": "Invalid credentials"})
            return

        token, expires_in = _create_access_token(username)
        _json_response(
            self,
            HTTPStatus.OK,
            {"access_token": token, "token_type": "Bearer", "expires_in": expires_in},
        )

    def log_message(self, format: str, *args: Any) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), LoginHandler)
    print(f"Login API listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
