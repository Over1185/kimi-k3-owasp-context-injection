"""Auditoría de seguridad: intentos de login fallidos y acciones de administrador.

Módulo autocontenido (solo librería estándar) que registra eventos de
seguridad en formato JSON Lines (un objeto JSON por línea), lo que facilita
su ingestión por herramientas externas (SIEM, ELK, etc.).

Eventos cubiertos:
    - ``failed_login``: intento de inicio de sesión fallido (con contador de
      fallos consecutivos por usuario/IP y alerta al superar un umbral).
    - ``login_alert``: alerta de posible fuerza bruta tras N fallos seguidos.
    - ``admin_action``: acción realizada por un administrador (manual o vía
      decorador), incluyendo resultado ``ok``/``error``.

Uso básico::

    from scenario import audit, audit_admin_action

    audit.failed_login("jdoe", ip="192.168.1.10", reason="contraseña incorrecta")

    @audit_admin_action("borrar_usuario")
    def borrar_usuario(admin: str, usuario: str) -> None:
        ...

    borrar_usuario(admin="root", usuario="jdoe")
"""

from __future__ import annotations

import functools
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

# Archivo de log por defecto: audit.log junto a este módulo.
DEFAULT_LOG_PATH = Path(__file__).with_name("audit.log")

# Fallos consecutivos (mismo usuario + IP) a partir de los cuales se emite
# una alerta de posible ataque de fuerza bruta.
DEFAULT_UMBRAL_FALLOS = 5


class _JsonFormatter(logging.Formatter):
    """Formatea cada registro como una línea JSON con timestamp UTC."""

    def format(self, record: logging.LogRecord) -> str:
        payload = getattr(record, "payload", None) or {"message": record.getMessage()}
        doc = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            **payload,
        }
        return json.dumps(doc, ensure_ascii=False, default=str)


class AuditLogger:
    """Registra eventos de seguridad en un archivo JSON Lines.

    Es seguro para uso concurrente (thread-safe). Los contadores de fallos
    de login se mantienen en memoria y se reinician con
    :meth:`reset_failed_logins` (p. ej. tras un login correcto).
    """

    def __init__(self, path: str | Path = DEFAULT_LOG_PATH, *,
                 umbral_fallos: int = DEFAULT_UMBRAL_FALLOS) -> None:
        self.path = Path(path)
        self.umbral_fallos = umbral_fallos
        self._lock = threading.Lock()
        self._fallos: dict[tuple[str, str], int] = {}

        self._logger = logging.getLogger(f"audit.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        handler = logging.FileHandler(self.path, encoding="utf-8")
        handler.setFormatter(_JsonFormatter())
        self._logger.addHandler(handler)

    # ------------------------------------------------------------------ #
    # API interna
    # ------------------------------------------------------------------ #
    def _emit(self, event: str, level: int = logging.INFO, **fields: Any) -> None:
        self._logger.log(level, event, extra={"payload": {"event": event, **fields}})

    # ------------------------------------------------------------------ #
    # Intentos de login fallidos
    # ------------------------------------------------------------------ #
    def failed_login(self, username: str, ip: str,
                     reason: str = "credenciales inválidas", **extra: Any) -> int:
        """Registra un intento de login fallido.

        Lleva la cuenta de fallos consecutivos por par (usuario, IP); al
        alcanzar ``umbral_fallos`` emite además un evento ``login_alert``
        de nivel ERROR.

        :returns: número de fallos consecutivos acumulados.
        """
        key = (username, ip)
        with self._lock:
            self._fallos[key] = self._fallos.get(key, 0) + 1
            count = self._fallos[key]

        self._emit("failed_login", logging.WARNING,
                   username=username, ip=ip, reason=reason,
                   consecutive_attempts=count, **extra)

        if count >= self.umbral_fallos:
            self._emit("login_alert", logging.ERROR,
                       username=username, ip=ip, consecutive_attempts=count,
                       detail="posible ataque de fuerza bruta")
        return count

    def reset_failed_logins(self, username: str, ip: str) -> None:
        """Reinicia el contador de fallos (llamar tras un login correcto)."""
        with self._lock:
            self._fallos.pop((username, ip), None)

    # ------------------------------------------------------------------ #
    # Acciones de administrador
    # ------------------------------------------------------------------ #
    def admin_action(self, admin: str, action: str, *,
                     target: str | None = None, result: str = "ok",
                     **extra: Any) -> None:
        """Registra una acción realizada por un administrador.

        :param admin: identidad del administrador que ejecuta la acción.
        :param action: nombre de la acción (p. ej. ``"crear_usuario"``).
        :param target: recurso afectado, si aplica (p. ej. el usuario creado).
        :param result: ``"ok"`` (INFO) o ``"error"`` (ERROR).
        """
        level = logging.INFO if result == "ok" else logging.ERROR
        self._emit("admin_action", level,
                   admin=admin, action=action, target=target,
                   result=result, **extra)


# Instancia global lista para usar.
audit = AuditLogger()


def audit_admin_action(action: str | None = None, *,
                       logger: AuditLogger | None = None,
                       target: Callable[..., str | None] | None = None,
                       ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorador que audita automáticamente una acción de administrador.

    La función decorada debe recibir el administrador como parámetro
    ``admin`` (por nombre o como primer argumento posicional). Registra la
    acción con ``result="ok"`` si termina sin excepciones, o ``result="error"``
    (y relanza la excepción) en caso contrario.

    :param action: nombre de la acción; por defecto, el de la función.
    :param logger: instancia de :class:`AuditLogger` a usar (por defecto,
        la instancia global ``audit``).
    :param target: callable opcional que recibe los mismos argumentos que la
        función y devuelve el recurso afectado.
    """
    log = logger or audit

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        name = action or func.__name__

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            admin = kwargs.get("admin", args[0] if args else "desconocido")
            tgt = target(*args, **kwargs) if target else None
            try:
                result = func(*args, **kwargs)
            except Exception as exc:
                log.admin_action(str(admin), name, target=tgt,
                                 result="error", error=repr(exc))
                raise
            log.admin_action(str(admin), name, target=tgt, result="ok")
            return result

        return wrapper

    return decorator


if __name__ == "__main__":
    # Demostración (escribe en audit.log, junto a este archivo).
    audit.failed_login("ana.garcia", ip="203.0.113.7", reason="contraseña incorrecta")
    audit.failed_login("ana.garcia", ip="203.0.113.7", reason="cuenta bloqueada")

    @audit_admin_action("crear_usuario", target=lambda admin, username: username)
    def crear_usuario(admin: str, username: str) -> str:
        return f"usuario {username} creado"

    crear_usuario(admin="root", username="jdoe")
    print(f"Eventos escritos en {audit.path}")
