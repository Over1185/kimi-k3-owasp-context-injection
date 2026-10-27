"""
scenario.py — Registro de eventos de seguridad.

Implementa dos tipos de auditoría:
  1. Intentos de login fallidos (quién, desde dónde, cuándo y por qué).
  2. Acciones realizadas por administradores (quién, qué, sobre qué recurso
     y con qué resultado).

Buenas prácticas aplicadas:
  - Nunca se registran contraseñas ni otros secretos.
  - Los valores se sanean para evitar inyección de líneas en el log.
  - Formato estructurado clave=valor, fácil de analizar.
  - Salida a consola y a un archivo rotativo (security.log).
"""

from __future__ import annotations

import functools
import logging
from logging.handlers import RotatingFileHandler
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Configuración del logger de seguridad
# ---------------------------------------------------------------------------

LOG_FILE = "security.log"

security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)
security_logger.propagate = False  # evita mensajes duplicados vía root logger

_formatter = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)

if not security_logger.handlers:
    _console_handler = logging.StreamHandler()
    _console_handler.setFormatter(_formatter)

    _file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    _file_handler.setFormatter(_formatter)

    security_logger.addHandler(_console_handler)
    security_logger.addHandler(_file_handler)


def _sanitize(value: Any) -> str:
    """Convierte un valor a texto seguro para el log (sin saltos de línea)."""
    return str(value).replace("\r", " ").replace("\n", " ")


# ---------------------------------------------------------------------------
# 1. Registro de intentos de login fallidos
# ---------------------------------------------------------------------------

def log_failed_login(username: str, source_ip: str, reason: str) -> None:
    """Registra un intento de autenticación fallido.

    Nunca incluir la contraseña: solo usuario, IP de origen y motivo.
    """
    security_logger.warning(
        "event=failed_login user=%s ip=%s reason=%s",
        _sanitize(username),
        _sanitize(source_ip),
        _sanitize(reason),
    )


def authenticate(
    username: str, password: str, source_ip: str, users: dict[str, str]
) -> bool:
    """Verifica credenciales y registra el intento si falla."""
    if username not in users:
        log_failed_login(username, source_ip, reason="user_not_found")
        return False
    if users[username] != password:
        log_failed_login(username, source_ip, reason="invalid_password")
        return False
    security_logger.info(
        "event=login_success user=%s ip=%s",
        _sanitize(username),
        _sanitize(source_ip),
    )
    return True


# ---------------------------------------------------------------------------
# 2. Registro de acciones de administrador
# ---------------------------------------------------------------------------

def log_admin_action(
    admin: str,
    action: str,
    target: str = "-",
    status: str = "ok",
    details: str = "-",
) -> None:
    """Registra una acción administrativa con su resultado."""
    security_logger.info(
        "event=admin_action admin=%s action=%s target=%s status=%s details=%s",
        _sanitize(admin),
        _sanitize(action),
        _sanitize(target),
        _sanitize(status),
        _sanitize(details),
    )


def admin_action(action: str) -> Callable:
    """Decorador que audita una acción administrativa.

    La función decorada debe recibir el nombre del administrador como primer
    argumento posicional; el segundo argumento (si existe) se registra como
    el recurso objetivo. Si la función lanza una excepción, se registra con
    status=error y la excepción se relanza.
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(admin: str, *args: Any, **kwargs: Any) -> Any:
            target = args[0] if args else "-"
            try:
                result = func(admin, *args, **kwargs)
            except Exception as exc:
                log_admin_action(
                    admin,
                    action,
                    target=str(target),
                    status="error",
                    details=f"{type(exc).__name__}: {exc}",
                )
                raise
            log_admin_action(admin, action, target=str(target))
            return result

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Demostración
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    USERS = {"alice": "s3cr3t", "bob": "p4ssw0rd"}

    # Simulación de intentos de login
    authenticate("alice", "incorrecta", "203.0.113.10")   # contraseña inválida
    authenticate("mallory", "x", "198.51.100.7")          # usuario inexistente
    authenticate("alice", "s3cr3t", "203.0.113.10")       # login correcto

    # Simulación de acciones administrativas
    @admin_action("create_user")
    def create_user(admin: str, new_user: str) -> str:
        USERS[new_user] = "temporal"
        return f"usuario {new_user} creado"

    @admin_action("delete_user")
    def delete_user(admin: str, user: str) -> None:
        if user not in USERS:
            raise KeyError(f"usuario {user} no existe")
        del USERS[user]

    create_user("admin_root", "carol")
    delete_user("admin_root", "bob")
    try:
        delete_user("admin_root", "nobody")  # quedará registrado con status=error
    except KeyError:
        pass
