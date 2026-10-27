"""
scenario.py
===========

Registro de eventos de seguridad (OWASP A09 — Security Logging and Alerting
Failures) para dos tipos de sucesos:

1. Intentos de login fallidos (incluido el bloqueo temporal por exceso de
   intentos).
2. Acciones realizadas por administradores (pista de auditoría).

Decisiones de seguridad aplicadas (OWASP Top 10:2025):

- A01 Broken Access Control: el rol se verifica en cada endpoint de
  administración; los accesos denegados también se registran.
- A02 Security Misconfiguration: respuestas de error genéricas; las trazas
  internas nunca llegan al cliente. Documentación interactiva deshabilitada.
- A04 Cryptographic Failures: contraseñas con PBKDF2-HMAC-SHA256
  (sal aleatoria, 600 000 iteraciones). Las credenciales demo se leen de
  variables de entorno (ADMIN_PASSWORD / ANALISTA_PASSWORD); si no existen,
  la cuenta queda deshabilitada con una contraseña aleatoria desconocida.
  Nunca hay secretos en claro en el código fuente.
- A06 Insecure Design: límite de intentos fallidos con bloqueo temporal por
  par (usuario, IP).
- A07 Authentication Failures: tokens de sesión aleatorios
  (secrets.token_urlsafe) con expiración, verificados en cada solicitud.
- A09 Security Logging: eventos estructurados en JSON (un evento por línea),
  lo que escapa saltos de línea y evita la inyección/forja de entradas de
  log. Jamás se registran contraseñas ni tokens.
- A10 Mishandling of Exceptional Conditions: sin bloques ``except`` genéricos
  que oculten errores; el manejador global de FastAPI registra
  explícitamente el tipo de excepción y devuelve un mensaje genérico.

Nota de alcance (entorno académico): el almacén de usuarios y sesiones es en
memoria, por lo que no hay consultas a base de datos (A05 no aplica). Los
logs se emiten por stdout para no crear archivos adicionales.
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import Depends, FastAPI, HTTPException, Path, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Constantes de seguridad
# ---------------------------------------------------------------------------

PBKDF2_ITERATIONS = 600_000          # Recomendación OWASP para PBKDF2-HMAC-SHA256
SESSION_TTL_SECONDS = 15 * 60        # Expiración de sesión (A07)
MAX_FAILED_ATTEMPTS = 5              # Límite de intentos (A06)
FAILED_ATTEMPTS_WINDOW_SECONDS = 10 * 60
LOCKOUT_SECONDS = 15 * 60

# ---------------------------------------------------------------------------
# Logger de seguridad estructurado (A09)
# ---------------------------------------------------------------------------


class SecurityJsonFormatter(logging.Formatter):
    """Serializa cada evento como una línea JSON.

    Al pasar por ``json.dumps``, los valores controlados por el cliente (p.
    ej. el nombre de usuario) quedan escapados y no pueden inyectar líneas
    falsas en el registro.
    """

    def format(self, record: logging.LogRecord) -> str:
        event = record.msg if isinstance(record.msg, dict) else {"message": record.getMessage()}
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            **event,
        }
        return json.dumps(payload, ensure_ascii=False)


security_logger = logging.getLogger("security.audit")
security_logger.setLevel(logging.INFO)
_security_handler = logging.StreamHandler()  # stdout: no se crean archivos extra
_security_handler.setFormatter(SecurityJsonFormatter())
security_logger.addHandler(_security_handler)
security_logger.propagate = False


def log_security_event(event_type: str, **fields: object) -> None:
    """Registra un evento de seguridad sin datos sensibles.

    Reglas: nunca incluir contraseñas, tokens de sesión ni hashes.
    """
    log_security_event_allowed = {"username", "client_ip", "reason", "path", "action",
                                  "target", "outcome", "detail", "exception_type"}
    safe_fields = {k: v for k, v in fields.items() if k in log_security_event_allowed}
    security_logger.info({"event": event_type, **safe_fields})


# ---------------------------------------------------------------------------
# Usuarios y contraseñas (A04)
# ---------------------------------------------------------------------------


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)


@dataclass
class UserRecord:
    username: str
    role: str  # "admin" | "user"
    salt: bytes
    password_hash: bytes


def _bootstrap_users() -> "dict[str, UserRecord]":
    users: "dict[str, UserRecord]" = {}
    for username, role, env_var in (
        ("admin", "admin", "ADMIN_PASSWORD"),
        ("analista", "user", "ANALISTA_PASSWORD"),
    ):
        password = os.environ.get(env_var)
        if password is None:
            # Cuenta deshabilitada: contraseña aleatoria que nadie conoce.
            password = secrets.token_urlsafe(32)
        salt = secrets.token_bytes(16)
        users[username] = UserRecord(username, role, salt, _hash_password(password, salt))
    return users


USERS = _bootstrap_users()

# ---------------------------------------------------------------------------
# Sesiones con expiración (A07)
# ---------------------------------------------------------------------------


@dataclass
class Session:
    username: str
    role: str
    expires_at: float


SESSIONS: "dict[str, Session]" = {}

# ---------------------------------------------------------------------------
# Limitador de intentos fallidos (A06)
# ---------------------------------------------------------------------------


class LoginRateLimiter:
    """Bloqueo temporal por par (usuario, IP) tras N fallos consecutivos."""

    def __init__(self) -> None:
        self._failures: "dict[tuple[str, str], list[float]]" = {}
        self._locked_until: "dict[tuple[str, str], float]" = {}
        self._lock = threading.Lock()

    def is_locked(self, key: "tuple[str, str]") -> bool:
        with self._lock:
            until = self._locked_until.get(key, 0.0)
            if time.time() < until:
                return True
            self._locked_until.pop(key, None)
            return False

    def register_failure(self, key: "tuple[str, str]") -> bool:
        """Registra un fallo. Devuelve True si la clave acaba de bloquearse."""
        now = time.time()
        with self._lock:
            attempts = [t for t in self._failures.get(key, [])
                        if now - t < FAILED_ATTEMPTS_WINDOW_SECONDS]
            attempts.append(now)
            self._failures[key] = attempts
            if len(attempts) >= MAX_FAILED_ATTEMPTS:
                self._locked_until[key] = now + LOCKOUT_SECONDS
                self._failures.pop(key, None)
                return True
            return False

    def reset(self, key: "tuple[str, str]") -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)


LOGIN_LIMITER = LoginRateLimiter()

# ---------------------------------------------------------------------------
# Esquemas de entrada (validación estricta: también protege los logs)
# ---------------------------------------------------------------------------

_USERNAME_PATTERN = r"^[a-zA-Z0-9_.-]{1,64}$"


class LoginRequest(BaseModel):
    username: str = Field(pattern=_USERNAME_PATTERN)
    password: str = Field(min_length=1, max_length=128)


class RoleUpdateRequest(BaseModel):
    new_role: Literal["admin", "user"]


# ---------------------------------------------------------------------------
# Aplicación y dependencias
# ---------------------------------------------------------------------------

app = FastAPI(title="Security Logging Scenario", docs_url=None, redoc_url=None, openapi_url=None)
bearer_scheme = HTTPBearer(auto_error=False)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def get_current_session(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Session:
    """Verifica el token en cada solicitud, incluida su expiración (A07)."""
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Autenticación requerida")
    session = SESSIONS.get(credentials.credentials)
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sesión inválida o expirada")
    if session.expires_at < time.time():
        SESSIONS.pop(credentials.credentials, None)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sesión inválida o expirada")
    return session


def require_admin(request: Request, session: Session = Depends(get_current_session)) -> Session:
    """Verifica el rol antes de cualquier acción de administración (A01)."""
    if session.role != "admin":
        log_security_event(
            "access_denied",
            username=session.username,
            client_ip=_client_ip(request),
            path=request.url.path,
            reason="admin_role_required",
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permisos insuficientes")
    return session


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post("/login")
def login(payload: LoginRequest, request: Request) -> dict:
    ip = _client_ip(request)
    key = (payload.username, ip)

    if LOGIN_LIMITER.is_locked(key):
        log_security_event("login_blocked", username=payload.username, client_ip=ip,
                           reason="too_many_failures")
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "Demasiados intentos. Inténtelo más tarde.")

    user = USERS.get(payload.username)
    # Comparación en tiempo constante aunque el usuario no exista, para no
    # revelar qué nombres de usuario son válidos.
    salt = user.salt if user else b"\x00" * 16
    expected = user.password_hash if user else b"\x00" * 32
    candidate = _hash_password(payload.password, salt)

    if user is None or not hmac.compare_digest(candidate, expected):
        just_locked = LOGIN_LIMITER.register_failure(key)
        # A09: se registra el intento fallido SIN la contraseña.
        log_security_event("login_failed", username=payload.username, client_ip=ip,
                           reason="invalid_credentials")
        if just_locked:
            log_security_event("account_locked", username=payload.username, client_ip=ip,
                               detail=f"locked_for_seconds={LOCKOUT_SECONDS}")
        # Mensaje genérico: no revela si el usuario existe (A02).
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciales inválidas")

    LOGIN_LIMITER.reset(key)
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = Session(user.username, user.role, time.time() + SESSION_TTL_SECONDS)
    log_security_event("login_success", username=user.username, client_ip=ip)
    return {"access_token": token, "token_type": "bearer", "expires_in": SESSION_TTL_SECONDS}


@app.post("/logout")
def logout(request: Request, session: Session = Depends(get_current_session)) -> dict:
    SESSIONS.pop(request.headers["authorization"].removeprefix("Bearer "), None)
    log_security_event("logout", username=session.username, client_ip=_client_ip(request))
    return {"detail": "Sesión cerrada"}


@app.post("/admin/users/{username}/role")
def change_user_role(
    request: Request,
    payload: RoleUpdateRequest,
    username: str = Path(pattern=_USERNAME_PATTERN),
    admin: Session = Depends(require_admin),
) -> dict:
    ip = _client_ip(request)
    target = USERS.get(username)

    if target is None:
        outcome = "target_not_found"
    elif username == admin.username:
        outcome = "self_modification_denied"
    else:
        target.role = payload.new_role
        # Revoca las sesiones activas del objetivo para que el nuevo rol
        # surta efecto de inmediato.
        for token, s in list(SESSIONS.items()):
            if s.username == username:
                SESSIONS.pop(token, None)
        outcome = "success"

    # A09: auditoría de la acción administrativa, sin datos sensibles.
    log_security_event(
        "admin_action",
        username=admin.username,
        client_ip=ip,
        action="change_role",
        target=username,
        outcome=outcome,
        detail=f"new_role={payload.new_role}",
    )
    if outcome == "target_not_found":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuario no encontrado")
    if outcome == "self_modification_denied":
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Un administrador no puede modificarse a sí mismo")
    return {"detail": "Rol actualizado"}


@app.delete("/admin/users/{username}")
def delete_user(
    request: Request,
    username: str = Path(pattern=_USERNAME_PATTERN),
    admin: Session = Depends(require_admin),
) -> dict:
    ip = _client_ip(request)

    if username not in USERS:
        outcome = "target_not_found"
    elif username == admin.username:
        outcome = "self_modification_denied"
    else:
        USERS.pop(username)
        for token, s in list(SESSIONS.items()):
            if s.username == username:
                SESSIONS.pop(token, None)
        outcome = "success"

    log_security_event(
        "admin_action",
        username=admin.username,
        client_ip=ip,
        action="delete_user",
        target=username,
        outcome=outcome,
    )
    if outcome == "target_not_found":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuario no encontrado")
    if outcome == "self_modification_denied":
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Un administrador no puede eliminarse a sí mismo")
    return {"detail": "Usuario eliminado"}


# ---------------------------------------------------------------------------
# Manejo global de errores (A02/A10): log explícito, respuesta genérica
# ---------------------------------------------------------------------------


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    log_security_event(
        "unhandled_error",
        path=request.url.path,
        exception_type=type(exc).__name__,
    )
    return JSONResponse(status_code=500, content={"detail": "Error interno"})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
