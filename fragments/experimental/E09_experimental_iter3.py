"""
scenario.py — Escenario académico FastAPI: registro de eventos de seguridad.

Implementa (OWASP Top 10:2025, skill "owasp-mitigacion"):
- A01 Broken Access Control: verificación de rol antes de acciones de admin.
- A04 Cryptographic Failures: contraseñas con scrypt + sal (stdlib); las
  credenciales de la demo se leen de variables de entorno, nunca del código.
- A06 Insecure Design: tokens de sesión aleatorios con expiración y bloqueo
  temporal tras N intentos fallidos de login.
- A07 Authentication Failures: el token se verifica en cada solicitud.
- A09 Security Logging and Alerting Failures: se registran los eventos de
  seguridad (login fallido/exitoso, bloqueo, acceso denegado, acción de
  admin) SIN datos sensibles: jamás se registran contraseñas ni tokens.
- A10 Mishandling of Exceptional Conditions: excepciones explícitas, sin
  bloques except genéricos ni trazas expuestas al cliente.

Requisitos: fastapi y uvicorn instalados (versiones fijadas en el entorno).
Variables de entorno obligatorias para la demo:
    DEMO_USER_PASSWORD   contraseña del usuario de prueba "usuario"
    DEMO_ADMIN_PASSWORD  contraseña del usuario de prueba "admin"

Ejecución: uvicorn scenario:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass

from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Logger dedicado a eventos de seguridad (A09).
# En producción se redirigiría a un colector central / SIEM.
# Regla de oro: NUNCA registrar contraseñas, hashes ni tokens de sesión.
# ---------------------------------------------------------------------------
security_logger = logging.getLogger("security.audit")
security_logger.setLevel(logging.INFO)
if not security_logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s [security] %(message)s")
    )
    security_logger.addHandler(_handler)
security_logger.propagate = False

# ---------------------------------------------------------------------------
# Hash de contraseñas con scrypt (A04): memoria-dura, con sal aleatoria.
# ---------------------------------------------------------------------------
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    """Devuelve 'sal_hex$digest_hex' usando scrypt con sal aleatoria."""
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Verificación en tiempo constante. False si el formato es inválido."""
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
            dklen=_SCRYPT_DKLEN,
        )
    except ValueError:
        return False
    return secrets.compare_digest(digest, bytes.fromhex(digest_hex))


# ---------------------------------------------------------------------------
# Usuarios de la demo. Las contraseñas llegan por entorno (A04: sin secretos
# en el código fuente) y se almacenan únicamente como hash.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class User:
    username: str
    password_hash: str
    role: str  # "user" | "admin"


def _load_demo_users() -> dict[str, User]:
    try:
        user_pw = os.environ["DEMO_USER_PASSWORD"]
        admin_pw = os.environ["DEMO_ADMIN_PASSWORD"]
    except KeyError as exc:
        raise RuntimeError(
            f"Falta la variable de entorno {exc.args[0]}; "
            "defínela antes de iniciar la aplicación."
        ) from exc
    return {
        "usuario": User("usuario", hash_password(user_pw), "user"),
        "admin": User("admin", hash_password(admin_pw), "admin"),
    }


USERS = _load_demo_users()

# ---------------------------------------------------------------------------
# Sesiones en memoria (A06/A07): token opaco aleatorio con expiración.
# ---------------------------------------------------------------------------
_SESSION_TTL_SECONDS = 15 * 60


@dataclass
class Session:
    username: str
    role: str
    expires_at: float  # reloj monotónico


_SESSIONS: dict[str, Session] = {}
_sessions_lock = threading.Lock()


def _create_session(user: User) -> str:
    token = secrets.token_urlsafe(32)
    with _sessions_lock:
        _SESSIONS[token] = Session(
            username=user.username,
            role=user.role,
            expires_at=time.monotonic() + _SESSION_TTL_SECONDS,
        )
    return token

# ---------------------------------------------------------------------------
# Límite de intentos fallidos (A06): bloqueo temporal por par IP+usuario.
# ---------------------------------------------------------------------------
_MAX_FAILED_ATTEMPTS = 5
_LOCKOUT_SECONDS = 300


@dataclass
class _Attempts:
    failures: int = 0
    locked_until: float = 0.0


_failed_attempts: dict[str, _Attempts] = {}
_attempts_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Modelos de entrada (validación estricta con pydantic).
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class AdminActionRequest(BaseModel):
    action: str = Field(min_length=1, max_length=64)
    target: str = Field(min_length=1, max_length=256)


# ---------------------------------------------------------------------------
# Utilidades y dependencias.
# ---------------------------------------------------------------------------


def _client_ip(request: Request) -> str:
    # Tras un proxy inverso, configurar cabeceras de proxy de confianza.
    return request.client.host if request.client else "unknown"


def get_current_session(request: Request) -> Session:
    """Verifica el token Bearer en cada solicitud (A07)."""
    auth = request.headers.get("Authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de sesión requerido.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    with _sessions_lock:
        session = _SESSIONS.get(token)
        if session is not None and session.expires_at <= time.monotonic():
            del _SESSIONS[token]
            session = None
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión inválida o expirada.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return session


def require_admin(
    request: Request,
    session: Session = Depends(get_current_session),
) -> Session:
    """Solo administradores (A01). Los intentos denegados también se registran."""
    if session.role != "admin":
        security_logger.warning(
            "event=admin_access_denied user=%s ip=%s path=%s",
            session.username,
            _client_ip(request),
            request.url.path,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requiere rol de administrador.",
        )
    return session


# ---------------------------------------------------------------------------
# Aplicación y endpoints. debug permanece desactivado (A02).
# ---------------------------------------------------------------------------
app = FastAPI(title="Escenario: logging de seguridad", debug=False)


@app.post("/login")
def login(payload: LoginRequest, request: Request) -> dict:
    ip = _client_ip(request)
    key = f"{ip}|{payload.username}"

    with _attempts_lock:
        attempts = _failed_attempts.get(key)
        locked = attempts is not None and attempts.locked_until > time.monotonic()
    if locked:
        security_logger.warning(
            "event=login_locked_out user=%s ip=%s", payload.username, ip
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos fallidos. Intente más tarde.",
        )

    user = USERS.get(payload.username)
    if user is None or not verify_password(payload.password, user.password_hash):
        # A09: se registra el intento fallido SIN la contraseña probada.
        # El detalle al cliente es genérico para no permitir enumerar usuarios.
        with _attempts_lock:
            entry = _failed_attempts.setdefault(key, _Attempts())
            entry.failures += 1
            if entry.failures >= _MAX_FAILED_ATTEMPTS:
                entry.locked_until = time.monotonic() + _LOCKOUT_SECONDS
                entry.failures = 0
        security_logger.warning(
            "event=login_failed user=%s ip=%s reason=invalid_credentials",
            payload.username,
            ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas.",
        )

    with _attempts_lock:
        _failed_attempts.pop(key, None)

    token = _create_session(user)
    security_logger.info("event=login_success user=%s ip=%s", user.username, ip)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": _SESSION_TTL_SECONDS,
    }


@app.post("/admin/actions")
def perform_admin_action(
    payload: AdminActionRequest,
    request: Request,
    session: Session = Depends(require_admin),
) -> dict:
    """Ejecuta y registra una acción administrativa (A01 + A09)."""
    ip = _client_ip(request)
    security_logger.info(
        "event=admin_action user=%s ip=%s action=%s target=%s",
        session.username,
        ip,
        payload.action,
        payload.target,
    )
    # Aquí iría la lógica real de la acción administrativa.
    return {
        "detail": "Acción registrada.",
        "action": payload.action,
        "target": payload.target,
    }
