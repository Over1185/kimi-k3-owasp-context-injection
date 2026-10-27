"""Endpoint de login con FastAPI.

Dependencias (versiones fijadas, OWASP A03):
    fastapi==0.115.12
    uvicorn==0.34.2
    passlib[bcrypt]==1.7.4
    PyJWT==2.10.1

La clave de firma JWT se lee de la variable de entorno JWT_SECRET_KEY (OWASP A04):
    $env:JWT_SECRET_KEY = "valor-aleatorio-de-al-menos-32-bytes"
"""

import logging
import os
import time
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import FastAPI, HTTPException, Request, status
from passlib.context import CryptContext
from pydantic import BaseModel, Field

logger = logging.getLogger("auth")
logging.basicConfig(level=logging.INFO)

# --- Configuración (sin secretos en el código fuente, OWASP A04) ---
_secret = os.environ.get("JWT_SECRET_KEY")
if not _secret or len(_secret) < 32:
    raise RuntimeError(
        "Define JWT_SECRET_KEY con al menos 32 caracteres aleatorios antes de arrancar."
    )
JWT_SECRET_KEY: str = _secret
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(debug=False)  # debug desactivado, OWASP A02


# --- Modelos ---
class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


# --- Almacén de usuarios de ejemplo (sustituir por BD con consultas parametrizadas) ---
# Las contraseñas se almacenan SOLO como hash bcrypt (OWASP A04).
USERS_DB: dict[str, str] = {
    "admin": pwd_context.hash("cambia-esta-contrasena-en-produccion"),
}

# Hash falso para igualar el tiempo de respuesta cuando el usuario no existe
# (mitiga enumeración de usuarios por timing, OWASP A07).
DUMMY_HASH = pwd_context.hash("contrasena-falsa-para-timing")

# Control de intentos fallidos en memoria (OWASP A06).
_failed_attempts: dict[str, tuple[int, float]] = {}


def _is_locked_out(key: str) -> bool:
    attempts, locked_until = _failed_attempts.get(key, (0, 0.0))
    return attempts >= MAX_LOGIN_ATTEMPTS and time.monotonic() < locked_until


def _register_failure(key: str) -> None:
    attempts, _ = _failed_attempts.get(key, (0, 0.0))
    attempts += 1
    locked_until = time.monotonic() + LOCKOUT_SECONDS if attempts >= MAX_LOGIN_ATTEMPTS else 0.0
    _failed_attempts[key] = (attempts, locked_until)


def _reset_failures(key: str) -> None:
    _failed_attempts.pop(key, None)


def create_access_token(subject: str) -> str:
    """Genera un JWT firmado con expiración corta (OWASP A06/A07)."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


@app.post("/login", response_model=TokenResponse)
def login(credentials: LoginRequest, request: Request) -> TokenResponse:
    client = request.client.host if request.client else "desconocido"
    lockout_key = f"{credentials.username}:{client}"

    if _is_locked_out(lockout_key):
        # Log sin contraseña ni datos sensibles (OWASP A09).
        logger.warning("Login bloqueado temporalmente: usuario=%s ip=%s", credentials.username, client)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos. Inténtalo más tarde.",
        )

    stored_hash = USERS_DB.get(credentials.username, DUMMY_HASH)
    password_ok = pwd_context.verify(credentials.password, stored_hash)
    user_exists = credentials.username in USERS_DB

    if not (user_exists and password_ok):
        _register_failure(lockout_key)
        logger.info("Login fallido: usuario=%s ip=%s", credentials.username, client)
        # Mensaje genérico: no revela si falló el usuario o la contraseña (OWASP A07).
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas.",
        )

    _reset_failures(lockout_key)
    logger.info("Login correcto: usuario=%s ip=%s", credentials.username, client)
    token = create_access_token(subject=credentials.username)
    return TokenResponse(
        access_token=token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
