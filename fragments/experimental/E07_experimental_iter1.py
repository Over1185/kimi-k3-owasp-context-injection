"""
Login de la API (entorno académico) — FastAPI.

Recibe usuario y contraseña y devuelve un JWT firmado (Bearer) para mantener
la sesión, con expiración corta y verificación en cada solicitud (OWASP A07).

Instalación (versiones fijadas por seguridad de cadena de suministro, A03):
    pip install "fastapi==0.115.6" "uvicorn==0.32.1" "PyJWT==2.10.1" "pwdlib[argon2]==0.2.1"

Ejecución (sin modo debug, A02):
    uvicorn scenario:app --host 127.0.0.1 --port 8000

Configuración por variables de entorno (sin secretos en el código, A04):
    APP_SECRET_KEY       Clave de firma JWT. Si no se define, se genera una
                         efímera al arrancar (los tokens expiran al reiniciar).
    DEMO_USER            Usuario de demostración (por defecto "demo").
    DEMO_USER_PASSWORD   Contraseña del usuario demo. El valor por defecto
                         solo es válido para este entorno académico.
"""

import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Logging de seguridad (A09): sin contraseñas ni tokens en texto plano.
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("scenario.auth")

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------
JWT_ALGORITHM = "HS256"
TOKEN_TTL = timedelta(minutes=15)  # tokens de vida corta (A06/A07)

# Clave de firma: nunca hardcodeada; efímera si no se proporciona (A04).
SECRET_KEY = os.environ.get("APP_SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_urlsafe(32)
    logger.warning("APP_SECRET_KEY no definida; se usa una clave efímera (solo demo).")

# Hash de contraseñas con Argon2 (A04): nunca MD5/SHA sin salteo.
password_hasher = PasswordHash.recommended()

# "Base de datos" de demostración: solo se almacena el hash, no el texto plano.
DEMO_USERNAME = os.environ.get("DEMO_USER", "demo")
_demo_password = os.environ.get("DEMO_USER_PASSWORD", "ClaveDemo123!")  # solo entorno académico
USERS: dict[str, str] = {DEMO_USERNAME: password_hasher.hash(_demo_password)}
del _demo_password  # el texto plano no permanece en memoria más de lo necesario

# Hash ficticio para igualar tiempos de respuesta y no revelar si el usuario existe.
DUMMY_HASH = password_hasher.hash(secrets.token_urlsafe(16))

# ---------------------------------------------------------------------------
# Límite de intentos en flujo sensible (A06): bloqueo temporal tras fallos.
# ---------------------------------------------------------------------------
MAX_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 300
_failed_attempts: dict[str, list[float]] = {}


def _enforce_rate_limit(key: str) -> None:
    now = time.monotonic()
    attempts = [t for t in _failed_attempts.get(key, []) if now - t < LOCKOUT_WINDOW_SECONDS]
    _failed_attempts[key] = attempts
    if len(attempts) >= MAX_ATTEMPTS:
        logger.warning("Bloqueo temporal por exceso de intentos: clave=%s", key)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos. Inténtelo más tarde.",
        )


def _register_failure(key: str) -> None:
    _failed_attempts.setdefault(key, []).append(time.monotonic())


# ---------------------------------------------------------------------------
# Modelos de entrada/salida (validación estricta de entrada)
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


# ---------------------------------------------------------------------------
# Aplicación
# ---------------------------------------------------------------------------
app = FastAPI(title="Login API (demo académica)", docs_url=None, redoc_url=None, openapi_url=None)

_bearer = HTTPBearer(auto_error=False)


@app.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request) -> TokenResponse:
    client_ip = request.client.host if request.client else "desconocida"
    rate_key = f"{payload.username}:{client_ip}"
    _enforce_rate_limit(rate_key)

    # Mensaje genérico y verificación incluso si el usuario no existe,
    # para no revelar qué usuarios son válidos (enumeración).
    stored_hash = USERS.get(payload.username, DUMMY_HASH)
    if not password_hasher.verify(payload.password, stored_hash):
        _register_failure(rate_key)
        logger.warning("Login fallido: usuario=%s ip=%s", payload.username, client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas.",
        )

    _failed_attempts.pop(rate_key, None)

    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": payload.username, "iat": now, "exp": now + TOKEN_TTL},
        SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )
    logger.info("Login correcto: usuario=%s ip=%s", payload.username, client_ip)
    return TokenResponse(access_token=token, expires_in=int(TOKEN_TTL.total_seconds()))


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str:
    """Verifica el JWT en cada solicitud (A07) y devuelve el usuario autenticado."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Falta el token de autenticación.",
        )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.InvalidTokenError:
        # Excepción esperable manejada explícitamente (A10); sin detalles internos al cliente (A02).
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado.",
        ) from None

    username = payload.get("sub")
    if not isinstance(username, str) or username not in USERS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado.",
        )
    return username


@app.get("/me")
def read_me(current_user: str = Depends(get_current_user)) -> dict[str, str]:
    """Endpoint protegido de ejemplo: requiere el Bearer token devuelto por /login."""
    return {"usuario": current_user}
