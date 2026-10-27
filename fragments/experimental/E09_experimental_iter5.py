"""scenario.py — Registro de eventos de seguridad (OWASP A09).

Fragmento académico FastAPI que registra:
  1. Intentos de login fallidos (con alerta al superar un umbral de intentos).
  2. Acciones realizadas por usuarios con rol administrador.

Decisiones de seguridad aplicadas (OWASP Top 10:2025):
  - A01: las acciones de administración verifican el rol antes de ejecutarse.
  - A04: las contraseñas se almacenan con PBKDF2-HMAC-SHA256 salteado e iterado.
  - A06: tokens aleatorios de longitud suficiente y límite de intentos de login.
  - A07: los tokens de sesión son opacos, tienen expiración y se verifican en
         cada solicitud.
  - A09: los eventos de seguridad se registran en formato JSON estructurado,
         sin contraseñas, tokens ni datos sensibles en texto plano.
  - A10: no se usan bloques except genéricos ni vacíos; los errores se
         comunican al cliente con mensajes genéricos (sin trazas internas).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Logger de auditoría (A09): un evento JSON por línea, con rotación de archivo
# ---------------------------------------------------------------------------

AUDIT_LOG_FILE = Path(__file__).with_name("security.log")


class JsonFormatter(logging.Formatter):
    """Formatea cada registro como una línea JSON apta para un SIEM."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        event = getattr(record, "event", None)
        if isinstance(event, dict):
            payload["event"] = event
        return json.dumps(payload, ensure_ascii=False)


def build_audit_logger() -> logging.Logger:
    logger = logging.getLogger("security.audit")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = RotatingFileHandler(
            AUDIT_LOG_FILE, maxBytes=1_000_000, backupCount=5, encoding="utf-8"
        )
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    return logger


audit_logger = build_audit_logger()

# Claves que jamás deben aparecer en un log (defensa en profundidad).
_FORBIDDEN_LOG_KEYS = {"password", "passwd", "token", "secret", "authorization"}


def log_security_event(event_type: str, *, level: int = logging.INFO, **fields: object) -> None:
    """Registra un evento de seguridad descartando cualquier dato sensible."""
    safe_fields = {
        key: value for key, value in fields.items() if key.lower() not in _FORBIDDEN_LOG_KEYS
    }
    audit_logger.log(
        level, event_type, extra={"event": {"type": event_type, **safe_fields}}
    )


# ---------------------------------------------------------------------------
# Almacenamiento de credenciales (A04)
# ---------------------------------------------------------------------------

PBKDF2_ITERATIONS = 200_000


def hash_password(password: str, salt: bytes) -> bytes:
    """Deriva un hash de contraseña con PBKDF2-HMAC-SHA256 salteado."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )


@dataclass
class UserRecord:
    username: str
    salt: bytes
    password_hash: bytes
    role: str
    disabled: bool = False


def _create_user(username: str, password: str, role: str) -> UserRecord:
    salt = secrets.token_bytes(16)
    return UserRecord(
        username=username,
        salt=salt,
        password_hash=hash_password(password, salt),
        role=role,
    )


# NOTA: credenciales de demostración exclusivamente para el entorno académico.
# En un sistema real provienen de una base de datos y nunca se fijan en código.
USERS: dict[str, UserRecord] = {
    "admin": _create_user("admin", "Cambia-Esta-Clave!2026", "admin"),
    "usuario": _create_user("usuario", "Clave-Demo!2026", "user"),
}

# Sal fija para homogeneizar el tiempo de respuesta cuando el usuario no existe
# (mitiga la enumeración de usuarios por canal lateral de temporización).
_DUMMY_SALT = b"\x00" * 16

# ---------------------------------------------------------------------------
# Sesiones: tokens opacos, aleatorios y con expiración (A06 / A07)
# ---------------------------------------------------------------------------

TOKEN_TTL = timedelta(minutes=15)


@dataclass
class Session:
    username: str
    role: str
    expires_at: datetime


ACTIVE_SESSIONS: dict[str, Session] = {}


def get_current_user(request: Request) -> UserRecord:
    """Verifica el token Bearer en cada solicitud (A07)."""
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Autenticación requerida"
        )
    session = ACTIVE_SESSIONS.get(token)
    if session is None or session.expires_at <= datetime.now(timezone.utc):
        ACTIVE_SESSIONS.pop(token, None)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Sesión inválida o expirada"
        )
    user = USERS.get(session.username)
    if user is None or user.disabled:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Cuenta no disponible")
    return user


def require_admin(user: UserRecord = Depends(get_current_user)) -> UserRecord:
    """Exige rol administrador antes de cualquier acción privilegiada (A01)."""
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Permisos insuficientes")
    return user


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "desconocida"


# ---------------------------------------------------------------------------
# Aplicación y modelos de entrada
# ---------------------------------------------------------------------------

app = FastAPI(title="Scenario — Auditoría de seguridad")


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class RoleChangeRequest(BaseModel):
    new_role: str = Field(pattern="^(admin|user)$")


# ---------------------------------------------------------------------------
# 1) Login con registro de intentos fallidos (A09) y límite de intentos (A06)
# ---------------------------------------------------------------------------

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW = timedelta(minutes=10)
FAILED_ATTEMPTS: dict[str, list[datetime]] = {}


@app.post("/login")
def login(credentials: LoginRequest, request: Request) -> dict[str, object]:
    client_ip = _client_ip(request)
    username = credentials.username
    now = datetime.now(timezone.utc)

    recent_attempts = [
        ts for ts in FAILED_ATTEMPTS.get(username, []) if now - ts < LOCKOUT_WINDOW
    ]
    if len(recent_attempts) >= MAX_FAILED_ATTEMPTS:
        log_security_event(
            "LOGIN_BLOQUEADO",
            level=logging.WARNING,
            username=username,
            ip=client_ip,
            motivo="umbral de intentos fallidos superado",
        )
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos. Inténtelo más tarde.",
        )

    user = USERS.get(username)
    if user is None:
        # Homogeneiza el tiempo de respuesta para usuarios inexistentes.
        hash_password(credentials.password, _DUMMY_SALT)
        password_ok = False
    elif user.disabled:
        password_ok = False
    else:
        candidate = hash_password(credentials.password, user.salt)
        password_ok = hmac.compare_digest(candidate, user.password_hash)

    if not password_ok:
        recent_attempts.append(now)
        FAILED_ATTEMPTS[username] = recent_attempts
        # El log registra el evento sin la contraseña ni datos sensibles (A09).
        log_security_event(
            "LOGIN_FALLIDO",
            level=logging.WARNING,
            username=username,
            ip=client_ip,
            intentos_recientes=len(recent_attempts),
            motivo="credenciales inválidas o cuenta no disponible",
        )
        # Respuesta genérica: no revela si el usuario existe (A02).
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas"
        )

    FAILED_ATTEMPTS.pop(username, None)
    token = secrets.token_urlsafe(32)
    ACTIVE_SESSIONS[token] = Session(
        username=user.username, role=user.role, expires_at=now + TOKEN_TTL
    )
    log_security_event("LOGIN_EXITOSO", username=username, ip=client_ip)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": int(TOKEN_TTL.total_seconds()),
    }


# ---------------------------------------------------------------------------
# 2) Acciones de administrador con registro de auditoría (A01 / A09)
# ---------------------------------------------------------------------------


@app.post("/admin/users/{target_username}/role")
def change_user_role(
    target_username: str,
    body: RoleChangeRequest,
    request: Request,
    admin: UserRecord = Depends(require_admin),
) -> dict[str, str]:
    client_ip = _client_ip(request)
    target = USERS.get(target_username)
    if target is None:
        log_security_event(
            "ACCION_ADMIN",
            level=logging.WARNING,
            admin=admin.username,
            accion="cambiar_rol",
            objetivo=target_username,
            ip=client_ip,
            resultado="objetivo_no_encontrado",
        )
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")

    previous_role = target.role
    target.role = body.new_role
    log_security_event(
        "ACCION_ADMIN",
        admin=admin.username,
        accion="cambiar_rol",
        objetivo=target_username,
        ip=client_ip,
        rol_anterior=previous_role,
        rol_nuevo=body.new_role,
        resultado="ok",
    )
    return {"detail": "Rol actualizado"}


@app.post("/admin/users/{target_username}/disable")
def disable_user(
    target_username: str,
    request: Request,
    admin: UserRecord = Depends(require_admin),
) -> dict[str, str]:
    client_ip = _client_ip(request)
    target = USERS.get(target_username)
    if target is None:
        log_security_event(
            "ACCION_ADMIN",
            level=logging.WARNING,
            admin=admin.username,
            accion="deshabilitar_usuario",
            objetivo=target_username,
            ip=client_ip,
            resultado="objetivo_no_encontrado",
        )
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")

    target.disabled = True
    # Revoca las sesiones activas del usuario deshabilitado.
    for token, session in list(ACTIVE_SESSIONS.items()):
        if session.username == target_username:
            ACTIVE_SESSIONS.pop(token, None)

    log_security_event(
        "ACCION_ADMIN",
        admin=admin.username,
        accion="deshabilitar_usuario",
        objetivo=target_username,
        ip=client_ip,
        resultado="ok",
    )
    return {"detail": "Usuario deshabilitado"}
