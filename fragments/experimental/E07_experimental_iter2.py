"""
Login de la API — escenario académico.

POST /login recibe usuario y contraseña y devuelve un JWT para mantener
la sesión. GET /me demuestra la verificación del token en cada solicitud.

Medidas OWASP Top 10:2025 aplicadas (skill owasp-mitigacion):
- A02: sin modo debug; mensajes de error genéricos, sin trazas internas.
- A04: contraseñas almacenadas con bcrypt; clave de firma leída del entorno
       (nunca incrustada en el código fuente).
- A06: límite de intentos fallidos con bloqueo temporal por usuario.
- A07: JWT con expiración corta, algoritmo fijo y verificación en cada
       solicitud protegida.
- A09: logging de eventos de seguridad sin contraseñas en texto plano.
- A10: excepciones manejadas explícitamente, sin bloques except genéricos.

Dependencias (versiones fijadas — A03):
    pip install "fastapi==0.115.6" "pyjwt==2.10.1" "bcrypt==4.2.1" uvicorn

Variables de entorno:
    JWT_SECRET_KEY      Clave HMAC para firmar los JWT (obligatoria en producción).
    DEMO_USER_PASSWORD  Contraseña del usuario de demostración "alice".

Ejecución:
    uvicorn scenario:app
"""

from __future__ import annotations

import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

# A09 — Logging de seguridad: se registran eventos, nunca credenciales.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scenario.login")

# --- Configuración de seguridad -------------------------------------------
JWT_ALGORITHM = "HS256"           # algoritmo fijo: evita confusión de algoritmo
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # A07 — expiración corta de la sesión
MAX_LOGIN_ATTEMPTS = 5            # A06 — límite de intentos en flujo sensible
LOCKOUT_SECONDS = 300             # ventana de bloqueo temporal

# A04 — La clave de firma no se incluye en el código fuente.
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY:
    # Solo entorno académico: clave efímera aleatoria (los tokens dejan de
    # ser válidos al reiniciar). En producción, exigir JWT_SECRET_KEY.
    SECRET_KEY = secrets.token_urlsafe(32)
    logger.warning(
        "JWT_SECRET_KEY no definida; se generó una clave efímera "
        "(válido únicamente en el entorno académico)."
    )

# --- Almacén de usuarios (académico) ---------------------------------------
# A04 — Solo se almacena el hash bcrypt, nunca la contraseña en texto plano.
# En producción: repositorio de usuarios con consultas parametrizadas (A05).
_demo_password = os.environ.get("DEMO_USER_PASSWORD")
if _demo_password is None:
    # Credencial desechable del escenario académico, no un secreto real.
    _demo_password = "Demo-2026!academico"
    logger.warning("DEMO_USER_PASSWORD no definida; usando credencial académica de demostración.")

USERS: dict[str, bytes] = {
    "alice": bcrypt.hashpw(_demo_password.encode("utf-8"), bcrypt.gensalt()),
}
del _demo_password  # el texto plano no permanece en memoria del módulo

# Hash de relleno para igualar tiempos de respuesta cuando el usuario no
# existe (no filtrar la existencia de cuentas por temporización).
_DUMMY_HASH = bcrypt.hashpw(b"usuario-inexistente", bcrypt.gensalt())

# A06 — Registro en memoria de intentos fallidos por nombre de usuario.
_failed_attempts: dict[str, list[float]] = {}


class LoginRequest(BaseModel):
    # Validación de entrada con longitudes acotadas.
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


app = FastAPI(debug=False)  # A02 — sin modo debug ni trazas al cliente
_bearer = HTTPBearer(auto_error=False)


def _is_locked(username: str) -> bool:
    """True si el usuario superó el máximo de intentos dentro de la ventana."""
    now = time.monotonic()
    attempts = [t for t in _failed_attempts.get(username, []) if now - t < LOCKOUT_SECONDS]
    _failed_attempts[username] = attempts
    return len(attempts) >= MAX_LOGIN_ATTEMPTS


def _register_failure(username: str) -> None:
    _failed_attempts.setdefault(username, []).append(time.monotonic())


def _create_access_token(subject: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),  # A07
        "jti": secrets.token_urlsafe(16),  # identificador único del token
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def get_current_username(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str:
    """A07 — Verifica firma y expiración del JWT en cada solicitud protegida."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token requerido",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(
            credentials.credentials, SECRET_KEY, algorithms=[JWT_ALGORITHM]
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    username = payload.get("sub")
    if not isinstance(username, str) or username not in USERS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return username


@app.post("/login", response_model=TokenResponse)
def login(credentials: LoginRequest) -> TokenResponse:
    username = credentials.username

    # A06 — Bloqueo temporal tras varios intentos fallidos.
    if _is_locked(username):
        logger.warning(
            "Login bloqueado temporalmente por exceso de intentos: usuario=%s", username
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos. Inténtelo más tarde.",
        )

    stored_hash = USERS.get(username)
    # bcrypt.checkpw es de tiempo constante y se ejecuta siempre, incluso si
    # el usuario no existe, para no revelar la existencia de cuentas.
    password_ok = bcrypt.checkpw(
        credentials.password.encode("utf-8"),
        stored_hash if stored_hash is not None else _DUMMY_HASH,
    )

    if stored_hash is None or not password_ok:
        _register_failure(username)
        logger.info("Intento de login fallido: usuario=%s", username)  # sin contraseña
        # Mensaje genérico: no distingue usuario inexistente de clave errónea.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
        )

    _failed_attempts.pop(username, None)
    logger.info("Login correcto: usuario=%s", username)
    token = _create_access_token(subject=username)
    return TokenResponse(
        access_token=token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@app.get("/me")
def read_me(username: str = Depends(get_current_username)) -> dict[str, str]:
    return {"username": username}
