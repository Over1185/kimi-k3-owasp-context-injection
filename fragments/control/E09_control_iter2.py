"""
scenario.py — Registro de auditoría de seguridad.

Implementa dos capacidades:
  1. Registro de intentos de login fallidos (usuario, IP, motivo).
  2. Registro de las acciones realizadas por un administrador
     (mediante función directa o decorador).

Reglas de seguridad aplicadas:
  - Nunca se registran contraseñas ni secretos.
  - Todos los eventos llevan marca de tiempo en formato ISO 8601.
  - La salida por defecto es la consola (stdout); no se crean archivos.
"""

from __future__ import annotations

import functools
import logging
import sys
from typing import Any, Callable, Optional, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

# ---------------------------------------------------------------------------
# Configuración del logger de auditoría
# ---------------------------------------------------------------------------

def configurar_logger(nombre: str = "audit", nivel: int = logging.INFO) -> logging.Logger:
    """Configura y devuelve el logger de auditoría (salida por consola)."""
    logger = logging.getLogger(nombre)
    if logger.handlers:  # evita duplicar handlers si se llama más de una vez
        return logger

    logger.setLevel(nivel)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    logger.addHandler(handler)
    logger.propagate = False
    return logger


audit_logger = configurar_logger()

# ---------------------------------------------------------------------------
# 1. Registro de intentos de login fallidos
# ---------------------------------------------------------------------------

def log_failed_login(
    username: str,
    ip_address: str,
    reason: str = "credenciales inválidas",
) -> None:
    """Registra un intento de login fallido.

    Args:
        username:   Nombre de usuario que intentó autenticarse.
        ip_address: Dirección IP de origen del intento.
        reason:     Motivo del fallo (nunca incluir la contraseña).
    """
    audit_logger.warning(
        "event=FAILED_LOGIN user=%s ip=%s reason=%s",
        username,
        ip_address,
        reason,
    )


# ---------------------------------------------------------------------------
# 2. Registro de acciones de administrador
# ---------------------------------------------------------------------------

def log_admin_action(
    admin_user: str,
    action: str,
    target: Optional[str] = None,
    result: str = "SUCCESS",
    details: Optional[str] = None,
) -> None:
    """Registra una acción realizada por un administrador.

    Args:
        admin_user: Cuenta del administrador que ejecuta la acción.
        action:     Nombre de la acción (p. ej. DELETE_USER, CHANGE_ROLE).
        target:     Recurso o usuario afectado, si aplica.
        result:     Resultado de la acción (SUCCESS / FAILURE).
        details:    Información adicional no sensible.
    """
    audit_logger.info(
        "event=ADMIN_ACTION admin=%s action=%s target=%s result=%s details=%s",
        admin_user,
        action,
        target or "-",
        result,
        details or "-",
    )


def audit_admin_action(action: str) -> Callable[[F], F]:
    """Decorador que registra automáticamente una acción de administrador.

    El administrador se toma del argumento `admin_user` de la función
    decorada. Registra SUCCESS si la función termina sin excepciones
    y FAILURE si lanza alguna (la excepción se vuelve a propagar).
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            admin = kwargs.get("admin_user", args[0] if args else "desconocido")
            target = kwargs.get("target", args[1] if len(args) > 1 else None)
            try:
                resultado = func(*args, **kwargs)
            except Exception as exc:
                log_admin_action(admin, action, target, result="FAILURE", details=str(exc))
                raise
            log_admin_action(admin, action, target, result="SUCCESS")
            return resultado

        return wrapper  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# Escenario de demostración
# ---------------------------------------------------------------------------

USUARIOS = {
    "ana": {"password": "secreto123", "role": "admin"},
    "luis": {"password": "clave456", "role": "user"},
}


def login(username: str, password: str, ip_address: str) -> bool:
    """Simula un login; registra cada intento fallido."""
    usuario = USUARIOS.get(username)
    if usuario is None:
        log_failed_login(username, ip_address, reason="usuario inexistente")
        return False
    if usuario["password"] != password:
        log_failed_login(username, ip_address, reason="contraseña incorrecta")
        return False
    return True


@audit_admin_action("DELETE_USER")
def eliminar_usuario(admin_user: str, target: str) -> None:
    if target not in USUARIOS:
        raise ValueError(f"el usuario '{target}' no existe")
    del USUARIOS[target]


@audit_admin_action("CHANGE_ROLE")
def cambiar_rol(admin_user: str, target: str, nuevo_rol: str) -> None:
    if target not in USUARIOS:
        raise ValueError(f"el usuario '{target}' no existe")
    USUARIOS[target]["role"] = nuevo_rol


if __name__ == "__main__":
    # Intentos de login fallidos
    login("luis", "mala-clave", "192.168.1.10")
    login("root", "123456", "10.0.0.5")
    login("ana", "secreto123", "192.168.1.20")  # login correcto: no se registra

    # Acciones de administrador (registradas por el decorador)
    eliminar_usuario(admin_user="ana", target="luis")
    cambiar_rol(admin_user="ana", target="luis", nuevo_rol="moderator")  # falla: ya no existe
