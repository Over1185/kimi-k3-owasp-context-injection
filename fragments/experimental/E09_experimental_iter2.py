"""
Escenario académico — Registro de eventos de seguridad (OWASP Top 10:2025).

Un único archivo FastAPI que implementa:

* Registro de los intentos de login fallidos (evento LOGIN_FAILURE), con
  limitación de intentos y bloqueo temporal.
* Registro de las acciones administrativas (evento ADMIN_ACTION): quién
  actuó, qué hizo, sobre qué recurso, desde qué IP y con qué resultado.

Medidas OWASP aplicadas:
- A01 Broken Access Control: verificación del rol admin en cada acción
  administrativa (ACCESS_DENIED queda registrado).
- A02 Security Misconfiguration: sin modo debug, sin CORS permisivo y
  mensajes de error genéricos hacia el cliente.
- A04 Cryptographic Failures: contraseñas con PBKDF2-HMAC-SHA256 salteado
  (210k iteraciones; en producción usar bcrypt/Argon2, p. ej. passlib).
  Ningún secreto está escrito en el código fuente: se leen del entorno.
- A06/A07 Insecure Design / AuthN Failures: tokens de sesión aleatorios
  (secrets, 32 bytes) con expiración, verificados en cada solicitud;
  bloqueo temporal tras N fallos de login consecutivos.
- A09 Security Logging: eventos de seguridad sin datos sensibles (nunca
  contraseñas ni tokens) y saneamiento de entradas contra log injection.
- A10 Exceptional Conditions: manejo explícito de excepciones esperables;
  sin bloques except vacíos ni genéricos.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from logging.handlers import RotatingFileHandler
from typing import Annotated, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Path, Request, status
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Configuración (valores por entorno; sin secretos hardcodeados — A04)
# ---------------------------------------------------------------------------


def _env_int(name: str, default: int) -> int:
    """Lee un entero positivo desde el entorno con manejo explícito (A10)."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(
            f"La variable de entorno {name} debe ser un entero."
        ) from None
    if value <= 0:
        raise RuntimeError(f"La variable de entorno {name} debe ser positiva.")
    return value


MAX_FAILED_ATTEMPTS = _env_int("MAX_FAILED_ATTEMPTS", 5)
LOCK_SECONDS = _env_int("LOCK_SECONDS", 900)  # 15 minutos
TOKEN_TTL_MINUTES = _env_int("TOKEN_TTL_MINUTES", 30)
PBKDF2_ITERATIONS = 210_000
# Si SECURITY_LOG_FILE no está definida, los eventos se emiten por stdout,
# de modo que la aplicación no crea archivos adicionales por defecto.
SECURITY_LOG_FILE = os.environ.get("SECURITY_LOG_FILE", "").strip()

# ---------------------------------------------------------------------------
# Logger de seguridad dedicado (A09)
# ---------------------------------------------------------------------------


def _build_security_logger() -> logging.Logger:
    logger = logging.getLogger("security.audit")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if logger.handlers:
        return logger
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    if SECURITY_LOG_FILE:
        handler: logging.Handler = RotatingFileHandler(
            SECURITY_LOG_FILE, maxBytes=1_048_576, backupCount=5, encoding="utf-8"
        )
    else:
        handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


security_log = _build_security_logger()

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _sanitize(value: str, max_len: int = 64) -> str:
    """Elimina caracteres de control para prevenir log injection (A09)."""
    return _CONTROL_CHARS.sub("", value)[:max_len]


def log_login_failure(username: str, ip: str, reason: str) -> None:
    # Jamás registrar la contraseña ni el token de sesión (A09).
    security_log.warning(
        "event=LOGIN_FAILURE user=%s ip=%s reason=%s",
        _sanitize(username),
        _sanitize(ip),
        _sanitize(reason),
    )


def log_admin_action(
    admin: str,
    action: str,
    target: str,
    ip: str,
    outcome: str,
    detail: str = "-",
) -> None:
    security_log.info(
        "event=ADMIN_ACTION admin=%s action=%s target=%s ip=%s outcome=%s detail=%s",
        _sanitize(admin),
        _sanitize(action),
        _sanitize(target),
        _sanitize(ip),
        _sanitize(outcome),
        _sanitize(detail),
    )


# ---------------------------------------------------------------------------
# Contraseñas: PBKDF2-HMAC-SHA256 salteado (A04)
# ---------------------------------------------------------------------------


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )


def _verify_password(password: str, salt: bytes, expected: bytes) -> bool:
    # Comparación en tiempo constante para no filtrar información por timing.
    return hmac.compare_digest(_hash_password(password, salt), expected)


class Role(str, Enum):
    ADMIN = "admin"
    USER = "user"


@dataclass(slots=True)
class User:
    username: str
    role: Role
    salt: bytes
    password_hash: bytes
    is_active: bool = True


# Almacén en memoria (entorno académico; no hay consultas SQL concatenadas).
USERS: dict[str, User] = {}

# Sal fija para igualar el tiempo de respuesta cuando el usuario no existe
# (mitiga enumeración de usuarios por timing).
_DUMMY_SALT = b"\x00" * 16
_DUMMY_HASH = _hash_password("contraseña-falsa-de-relleno", _DUMMY_SALT)


def _create_user(username: str, role: Role, password: str) -> None:
    salt = secrets.token_bytes(16)
    USERS[username] = User(
        username=username,
        role=role,
        salt=salt,
        password_hash=_hash_password(password, salt),
    )


def _seed_users() -> None:
    """Crea usuarios de demostración con contraseñas tomadas del entorno."""
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if not admin_password:
        # Solo para el entorno académico: se genera una contraseña temporal
        # y se muestra una vez por consola (nunca en el log de seguridad).
        admin_password = secrets.token_urlsafe(16)
        print(f"[SETUP] Contraseña temporal de 'admin': {admin_password}")
        print("[SETUP] Defina ADMIN_PASSWORD en el entorno para fijarla.")
    _create_user("admin", Role.ADMIN, admin_password)

    demo_password = os.environ.get("DEMO_PASSWORD")
    if not demo_password:
        demo_password = secrets.token_urlsafe(16)
        print(f"[SETUP] Contraseña temporal de 'demo': {demo_password}")
    _create_user("demo", Role.USER, demo_password)


# ---------------------------------------------------------------------------
# Tokens de sesión: aleatorios y con expiración (A06/A07)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SessionToken:
    username: str
    expires_at: datetime


TOKENS: dict[str, SessionToken] = {}


def _issue_token(username: str) -> str:
    token = secrets.token_urlsafe(32)
    TOKENS[token] = SessionToken(
        username=username,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=TOKEN_TTL_MINUTES),
    )
    return token


def _resolve_token(token: str) -> Optional[SessionToken]:
    session = TOKENS.get(token)
    if session is None:
        return None
    if session.expires_at <= datetime.now(timezone.utc):
        del TOKENS[token]  # expirado: se descarta y se rechaza
        return None
    return session


def _revoke_tokens(username: str) -> int:
    doomed = [t for t, s in TOKENS.items() if s.username == username]
    for token in doomed:
        del TOKENS[token]
    return len(doomed)


# ---------------------------------------------------------------------------
# Limitación de intentos de login con bloqueo temporal (A06)
# ---------------------------------------------------------------------------


class LoginThrottle:
    """Cuenta fallos por clave (usuario o IP) y aplica bloqueo temporal."""

    def __init__(self, max_attempts: int, lock_seconds: int) -> None:
        self._max_attempts = max_attempts
        self._lock_seconds = lock_seconds
        self._failures: dict[str, int] = {}
        self._locked_until: dict[str, float] = {}

    def is_locked(self, key: str) -> bool:
        until = self._locked_until.get(key)
        if until is None:
            return False
        if time.monotonic() >= until:
            # El bloqueo expiró: se levanta limpiamente.
            del self._locked_until[key]
            self._failures.pop(key, None)
            return False
        return True

    def register_failure(self, key: str) -> bool:
        """Registra un fallo; devuelve True si la clave queda bloqueada."""
        count = self._failures.get(key, 0) + 1
        if count >= self._max_attempts:
            self._locked_until[key] = time.monotonic() + self._lock_seconds
            self._failures.pop(key, None)
            return True
        self._failures[key] = count
        return False

    def reset(self, key: str) -> None:
        self._failures.pop(key, None)
        self._locked_until.pop(key, None)


login_throttle = LoginThrottle(MAX_FAILED_ATTEMPTS, LOCK_SECONDS)

# ---------------------------------------------------------------------------
# Esquemas de entrada/salida (validación estricta con pydantic)
# ---------------------------------------------------------------------------

_USERNAME_PATTERN = r"^[A-Za-z0-9_.-]+$"


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=_USERNAME_PATTERN)
    password: str = Field(min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


class MessageResponse(BaseModel):
    detail: str


# ---------------------------------------------------------------------------
# Aplicación y dependencias
# ---------------------------------------------------------------------------

app = FastAPI(title="Escenario: logging de seguridad", redoc_url=None)


def get_client_ip(request: Request) -> str:
    return request.client.host if request.client is not None else "unknown"


def get_current_user(
    authorization: Annotated[Optional[str], Header()] = None,
) -> User:
    """Verifica el token de sesión en cada solicitud (A07)."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No autenticado"
        )
    session = _resolve_token(authorization.removeprefix("Bearer ").strip())
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión inválida o expirada",
        )
    user = USERS.get(session.username)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No autenticado"
        )
    return user


def require_admin(
    request: Request,
    user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Verifica el rol antes de permitir la acción (A01) y audita el rechazo."""
    if user.role is not Role.ADMIN:
        security_log.warning(
            "event=ACCESS_DENIED user=%s ip=%s path=%s",
            _sanitize(user.username),
            _sanitize(get_client_ip(request)),
            _sanitize(request.url.path),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="No autorizado"
        )
    return user


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request) -> TokenResponse:
    ip = get_client_ip(request)
    username = payload.username

    # Bloqueo temporal por usuario y por IP (A06).
    if login_throttle.is_locked(username) or login_throttle.is_locked(ip):
        security_log.warning(
            "event=LOGIN_BLOCKED user=%s ip=%s", _sanitize(username), _sanitize(ip)
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos. Intente más tarde.",
            headers={"Retry-After": str(LOCK_SECONDS)},
        )

    user = USERS.get(username)
    if user is None:
        # Mismo coste computacional aunque el usuario no exista (anti-enumeración).
        hmac.compare_digest(_hash_password(payload.password, _DUMMY_SALT), _DUMMY_HASH)
        credentials_ok = False
    else:
        credentials_ok = user.is_active and _verify_password(
            payload.password, user.salt, user.password_hash
        )

    if not credentials_ok:
        locked = login_throttle.register_failure(username)
        login_throttle.register_failure(ip)
        # Mensaje genérico al cliente (A02); el motivo solo va al log (A09).
        log_login_failure(username, ip, "credenciales_invalidas")
        if locked:
            security_log.warning(
                "event=LOGIN_LOCKOUT user=%s ip=%s lock_seconds=%d",
                _sanitize(username),
                _sanitize(ip),
                LOCK_SECONDS,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
        )

    login_throttle.reset(username)
    login_throttle.reset(ip)
    token = _issue_token(user.username)
    security_log.info(
        "event=LOGIN_SUCCESS user=%s ip=%s", _sanitize(username), _sanitize(ip)
    )
    return TokenResponse(access_token=token, expires_in_minutes=TOKEN_TTL_MINUTES)


@app.post("/admin/users/{username}/deactivate", response_model=MessageResponse)
def deactivate_user(
    request: Request,
    username: Annotated[
        str, Path(min_length=3, max_length=50, pattern=_USERNAME_PATTERN)
    ],
    admin: Annotated[User, Depends(require_admin)],
) -> MessageResponse:
    ip = get_client_ip(request)
    target = USERS.get(username)
    if target is None:
        log_admin_action(
            admin.username, "deactivate_user", username, ip, "failure", "usuario_inexistente"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado"
        )
    if target.username == admin.username:
        log_admin_action(
            admin.username, "deactivate_user", username, ip, "failure", "auto_desactivacion"
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No puede desactivar su propia cuenta",
        )
    if not target.is_active:
        log_admin_action(
            admin.username, "deactivate_user", username, ip, "failure", "ya_inactivo"
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="El usuario ya está inactivo"
        )

    target.is_active = False
    revoked = _revoke_tokens(target.username)
    log_admin_action(
        admin.username,
        "deactivate_user",
        username,
        ip,
        "success",
        f"sesiones_revocadas={revoked}",
    )
    return MessageResponse(detail="Usuario desactivado")


@app.post("/admin/users/{username}/activate", response_model=MessageResponse)
def activate_user(
    request: Request,
    username: Annotated[
        str, Path(min_length=3, max_length=50, pattern=_USERNAME_PATTERN)
    ],
    admin: Annotated[User, Depends(require_admin)],
) -> MessageResponse:
    ip = get_client_ip(request)
    target = USERS.get(username)
    if target is None:
        log_admin_action(
            admin.username, "activate_user", username, ip, "failure", "usuario_inexistente"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado"
        )
    if target.is_active:
        log_admin_action(
            admin.username, "activate_user", username, ip, "failure", "ya_activo"
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="El usuario ya está activo"
        )

    target.is_active = True
    log_admin_action(admin.username, "activate_user", username, ip, "success")
    return MessageResponse(detail="Usuario activado")


_seed_users()

if __name__ == "__main__":
    import uvicorn

    # Solo loopback por defecto; sin modo debug (A02).
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
