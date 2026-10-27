"""scenario.py — Registro de eventos de seguridad (OWASP A09).

Escenario académico en FastAPI que demuestra:
- Registro de intentos de login fallidos (sin exponer contraseñas ni datos sensibles).
- Registro de acciones administrativas con trazabilidad (quién, qué, sobre qué, desde dónde, resultado).
- Bloqueo temporal de cuentas tras N fallos consecutivos (mitiga fuerza bruta, A06).

Decisiones de seguridad aplicadas (ver .github/skills/owasp-mitigacion):
- A02/A06: sin valores por defecto permisivos; las credenciales semilla llegan solo
  por variables de entorno; las respuestas de login son genéricas para no filtrar
  si el usuario existe (anti-enumeración).
- A04: contraseñas hasheadas con bcrypt (salteado automático). La contraseña nunca
  se escribe en los logs.
- A06: bloqueo temporal de cuenta y tokens opacos de alta entropía.
- A07: tokens con expiración, verificados en cada solicitud.
- A09: logger "security" dedicado; todos los campos controlados por el cliente se
  sanean contra inyección/forjado de logs (CR/LF).
- A10: excepciones manejadas explícitamente (sin `except` genéricos ni vacíos).

Dependencias (versiones fijadas, A03):
    pip install "fastapi==0.115.6" "uvicorn==0.34.0" "bcrypt==4.2.1"

Ejecución (PowerShell):
    $env:APP_ADMIN_USERNAME = "admin"
    $env:APP_ADMIN_PASSWORD = "cambiar-en-produccion"
    $env:APP_DEMO_USERNAME  = "usuario1"        # opcional, rol "user"
    $env:APP_DEMO_PASSWORD  = "otra-clave"      # opcional
    python scenario.py
"""

from __future__ import annotations

import logging
import os
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# A09 — Logger de seguridad dedicado.
# Sale por stdout para que un SIEM/colector lo capture en producción; así este
# escenario no crea archivos de log adicionales en el repositorio.
# ---------------------------------------------------------------------------

security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)
security_logger.propagate = False

_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(
    logging.Formatter("%(asctime)sZ level=%(levelname)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
)
_handler.formatter.converter = time.gmtime  # sellos de tiempo siempre en UTC
security_logger.addHandler(_handler)


def _sanitize(value: str | None) -> str:
    """Neutraliza CR/LF en entradas del cliente antes de registrarlas (anti log-forging)."""
    if not value:
        return "unknown"
    return value.replace("\r", "_").replace("\n", "_")[:64]


# ---------------------------------------------------------------------------
# Configuración (sin secretos en el código fuente, A04)
# ---------------------------------------------------------------------------

MAX_FAILED_ATTEMPTS = 5          # A06: límite de intentos en flujo sensible
WINDOW_SECONDS = 10 * 60         # ventana deslizante de conteo de fallos
LOCKOUT_SECONDS = 15 * 60        # duración del bloqueo temporal
TOKEN_TTL_MINUTES = 15           # A07: expiración corta de sesión


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


app = FastAPI(title="Security Logging Scenario", docs_url=None, redoc_url=None, openapi_url=None)

# ---------------------------------------------------------------------------
# Almacenamiento en memoria (alcance académico, proceso único).
# En producción: Redis/BD con TTL y cotas para evitar crecimiento ilimitado
# del registro de fallos ante nombres de usuario aleatorios.
# ---------------------------------------------------------------------------

_users: dict[str, dict] = {}                    # username -> {password_hash, role, disabled}
_tokens: dict[str, dict] = {}                   # token -> {username, role, expires_at}
_failed: dict[str, dict] = {}                   # username -> {count, window_start, locked_until}

# Hash ficticio para igualar el tiempo de respuesta cuando el usuario no existe.
_DUMMY_HASH = bcrypt.hashpw(b"usuario-inexistente", bcrypt.gensalt())


def _seed_users() -> None:
    """Carga las credenciales semilla desde el entorno. Falla de forma explícita
    si no están definidas (por defecto seguro, A02)."""
    admin_user = os.environ.get("APP_ADMIN_USERNAME")
    admin_pass = os.environ.get("APP_ADMIN_PASSWORD")
    if not admin_user or not admin_pass:
        raise RuntimeError(
            "Define APP_ADMIN_USERNAME y APP_ADMIN_PASSWORD antes de iniciar la app."
        )
    _users[admin_user] = {
        "password_hash": bcrypt.hashpw(admin_pass.encode("utf-8"), bcrypt.gensalt()),
        "role": "admin",
        "disabled": False,
    }
    demo_user = os.environ.get("APP_DEMO_USERNAME")
    demo_pass = os.environ.get("APP_DEMO_PASSWORD")
    if demo_user and demo_pass:
        _users[demo_user] = {
            "password_hash": bcrypt.hashpw(demo_pass.encode("utf-8"), bcrypt.gensalt()),
            "role": "user",
            "disabled": False,
        }


_seed_users()

# ---------------------------------------------------------------------------
# A09 — Registro de intentos de login fallidos
# ---------------------------------------------------------------------------


def _register_login_failure(username_raw: str, username_log: str, ip: str) -> None:
    """Acumula el fallo, registra el evento y aplica bloqueo temporal (A06)."""
    now = time.monotonic()
    record = _failed.setdefault(username_raw, {"count": 0, "window_start": now, "locked_until": None})
    if now - record["window_start"] > WINDOW_SECONDS:
        record["count"] = 0
        record["window_start"] = now
    record["count"] += 1

    # Nunca se registra la contraseña (A09).
    security_logger.warning(
        "event=login_failed username=%s ip=%s attempts=%d", username_log, ip, record["count"]
    )
    if record["count"] >= MAX_FAILED_ATTEMPTS:
        record["locked_until"] = now + LOCKOUT_SECONDS
        security_logger.warning(
            "event=account_locked username=%s ip=%s duration_s=%d", username_log, ip, LOCKOUT_SECONDS
        )
    # Mensaje genérico: no revela si el usuario existe ni si está bloqueado.
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales no válidas"
    )


@app.post("/login", status_code=status.HTTP_200_OK)
def login(credentials: LoginRequest, request: Request) -> dict:
    # Detrás de un proxy inverso, validar X-Forwarded-For solo si el proxy es de confianza.
    ip = _sanitize(request.client.host if request.client else None)
    username_log = _sanitize(credentials.username)

    record = _failed.get(credentials.username)
    if record and record["locked_until"] is not None and time.monotonic() < record["locked_until"]:
        security_logger.warning(
            "event=login_blocked username=%s ip=%s reason=account_locked", username_log, ip
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales no válidas"
        )

    user = _users.get(credentials.username)
    if user is None or user["disabled"]:
        bcrypt.checkpw(credentials.password.encode("utf-8"), _DUMMY_HASH)  # anti-enumeración por tiempo
        _register_login_failure(credentials.username, username_log, ip)

    try:
        password_ok = bcrypt.checkpw(
            credentials.password.encode("utf-8"), user["password_hash"]
        )
    except ValueError:  # hash almacenado corrupto o con formato inválido (A10)
        security_logger.error(
            "event=login_error username=%s ip=%s reason=invalid_stored_hash", username_log, ip
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales no válidas"
        ) from None

    if not password_ok:
        _register_login_failure(credentials.username, username_log, ip)

    _failed.pop(credentials.username, None)  # reinicia el contador tras éxito
    token = secrets.token_urlsafe(32)        # A06/A07: 256 bits aleatorios, un solo uso por sesión
    _tokens[token] = {
        "username": credentials.username,
        "role": user["role"],
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_TTL_MINUTES),
    }
    security_logger.info("event=login_success username=%s ip=%s", username_log, ip)
    return {"access_token": token, "token_type": "bearer", "expires_in": TOKEN_TTL_MINUTES * 60}


# ---------------------------------------------------------------------------
# Autenticación y control de acceso (A01/A07)
# ---------------------------------------------------------------------------

_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autenticación requerida",
            headers={"WWW-Authenticate": "Bearer"},
        )
    session = _tokens.get(credentials.credentials)
    if session is None:
        security_logger.warning("event=token_rejected reason=unknown_token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token no válido o expirado"
        )
    if session["expires_at"] <= datetime.now(timezone.utc):
        del _tokens[credentials.credentials]
        security_logger.info(
            "event=token_expired username=%s", _sanitize(session["username"])
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token no válido o expirado"
        )
    return session


def require_admin(session: dict = Depends(get_current_user)) -> dict:
    """A01: verifica el rol antes de permitir la acción administrativa."""
    if session["role"] != "admin":
        security_logger.warning(
            "event=admin_action_denied username=%s role=%s",
            _sanitize(session["username"]),
            session["role"],
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Permisos insuficientes"
        )
    return session


# ---------------------------------------------------------------------------
# A09 — Registro de acciones administrativas
# ---------------------------------------------------------------------------


def _log_admin_action(admin: dict, action: str, target: str, request: Request, result: str) -> None:
    ip = _sanitize(request.client.host if request.client else None)
    security_logger.info(
        "event=admin_action admin=%s action=%s target=%s ip=%s result=%s",
        _sanitize(admin["username"]),
        action,
        _sanitize(target),
        ip,
        result,
    )


@app.post("/admin/users/{username}/disable")
def disable_user(
    username: str, request: Request, admin: dict = Depends(require_admin)
) -> dict:
    if username == admin["username"]:
        _log_admin_action(admin, "disable_user", username, request, "self_action_denied")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No puedes deshabilitar tu propia cuenta",
        )
    target = _users.get(username)
    if target is None:
        _log_admin_action(admin, "disable_user", username, request, "user_not_found")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado"
        )
    target["disabled"] = True
    _log_admin_action(admin, "disable_user", username, request, "success")
    return {"detail": "Usuario deshabilitado"}


@app.post("/admin/users/{username}/unlock")
def unlock_user(
    username: str, request: Request, admin: dict = Depends(require_admin)
) -> dict:
    if username not in _users:
        _log_admin_action(admin, "unlock_user", username, request, "user_not_found")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado"
        )
    _failed.pop(username, None)
    _log_admin_action(admin, "unlock_user", username, request, "success")
    return {"detail": "Cuenta desbloqueada"}


if __name__ == "__main__":
    try:
        import uvicorn
    except ImportError:
        raise SystemExit(
            'Faltan dependencias: pip install "fastapi==0.115.6" "uvicorn==0.34.0" "bcrypt==4.2.1"'
        ) from None
    uvicorn.run("scenario:app", host="127.0.0.1", port=8000)
