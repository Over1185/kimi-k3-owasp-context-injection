"""
scenario.py — Auditoría de seguridad.

Módulo autocontenido (solo biblioteca estándar) que registra en formato
JSON Lines dentro de ``security_audit.log``:

  1. Intentos de login fallidos: usuario, IP de origen, motivo del fallo,
     instante UTC y número de fallos consecutivos. Si se supera un umbral,
     se emite un evento adicional de alerta.
  2. Acciones de administrador: quién la ejecuta, qué acción, sobre qué
     recurso y con qué resultado (success / denied / error).

Al ejecutarlo como script se lanza una pequeña simulación de demostración.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOG_FILE = Path(__file__).with_name("security_audit.log")
PBKDF2_ITERATIONS = 100_000


# ---------------------------------------------------------------------------
# Capa de registro (audit log)
# ---------------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    """Formatea cada registro como una línea JSON con timestamp UTC."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
        }
        payload.update(getattr(record, "event", {}))
        return json.dumps(payload, ensure_ascii=False)


class AuditLogger:
    """Punto único de escritura de eventos de seguridad."""

    def __init__(self, log_file: Path = LOG_FILE, alert_threshold: int = 3) -> None:
        self.alert_threshold = alert_threshold
        self._failures: dict[tuple[str, str], int] = {}

        self._logger = logging.getLogger("security_audit")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        if not self._logger.handlers:
            handler = logging.FileHandler(log_file, encoding="utf-8")
            handler.setFormatter(JsonFormatter())
            self._logger.addHandler(handler)

    def _emit(self, level: int, event: str, **fields: Any) -> None:
        self._logger.log(level, event, extra={"event": {"event": event, **fields}})

    # -- Logins -----------------------------------------------------------

    def log_failed_login(self, username: str, ip: str, reason: str) -> None:
        key = (username, ip)
        self._failures[key] = self._failures.get(key, 0) + 1
        self._emit(
            logging.WARNING,
            "login_failed",
            username=username,
            ip=ip,
            reason=reason,
            consecutive_failures=self._failures[key],
        )
        if self._failures[key] >= self.alert_threshold:
            self._emit(
                logging.CRITICAL,
                "login_failure_alert",
                username=username,
                ip=ip,
                attempts=self._failures[key],
                message="Posible ataque de fuerza bruta",
            )

    def log_login_success(self, username: str, ip: str) -> None:
        self._failures.pop((username, ip), None)
        self._emit(logging.INFO, "login_success", username=username, ip=ip)

    # -- Acciones de administrador ----------------------------------------

    def log_admin_action(
        self,
        admin: str,
        action: str,
        target: str | None = None,
        result: str = "success",
        **details: Any,
    ) -> None:
        level = logging.INFO if result == "success" else logging.WARNING
        self._emit(
            level,
            "admin_action",
            admin=admin,
            action=action,
            target=target,
            result=result,
            details=details or None,
        )


# ---------------------------------------------------------------------------
# Autenticación
# ---------------------------------------------------------------------------

@dataclass
class User:
    username: str
    salt: bytes
    password_hash: bytes
    role: str = "user"


class UserStore:
    """Almacén en memoria con contraseñas hasheadas (PBKDF2-HMAC-SHA256)."""

    def __init__(self, audit: AuditLogger) -> None:
        self.audit = audit
        self._users: dict[str, User] = {}

    @staticmethod
    def _hash(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )

    def add_user(self, username: str, password: str, role: str = "user") -> None:
        salt = os.urandom(16)
        self._users[username] = User(username, salt, self._hash(password, salt), role)

    def get(self, username: str) -> User | None:
        return self._users.get(username)

    def remove_user(self, username: str) -> None:
        if username not in self._users:
            raise KeyError(f"El usuario '{username}' no existe")
        del self._users[username]

    def authenticate(self, username: str, password: str, ip: str) -> User | None:
        """Devuelve el usuario si las credenciales son válidas.

        Cada fallo queda registrado en el audit log con su motivo interno.
        """
        user = self._users.get(username)
        if user is None:
            self.audit.log_failed_login(username, ip, reason="user_not_found")
            return None
        candidate = self._hash(password, user.salt)
        if not hmac.compare_digest(user.password_hash, candidate):
            self.audit.log_failed_login(username, ip, reason="wrong_password")
            return None
        self.audit.log_login_success(username, ip)
        return user


# ---------------------------------------------------------------------------
# Operaciones de administración (auditadas)
# ---------------------------------------------------------------------------

class AdminService:
    """Operaciones privilegiadas; cada ejecución queda registrada."""

    def __init__(self, store: UserStore, audit: AuditLogger) -> None:
        self.store = store
        self.audit = audit

    def _require_admin(self, actor: User, action: str) -> None:
        if actor.role != "admin":
            self.audit.log_admin_action(
                actor.username, action, result="denied", reason="not_admin"
            )
            raise PermissionError(
                f"'{actor.username}' no tiene privilegios de administrador"
            )

    def create_user(
        self, actor: User, username: str, password: str, role: str = "user"
    ) -> None:
        self._require_admin(actor, "create_user")
        self.store.add_user(username, password, role)
        self.audit.log_admin_action(
            actor.username, "create_user", target=username, role=role
        )

    def delete_user(self, actor: User, username: str) -> None:
        self._require_admin(actor, "delete_user")
        try:
            self.store.remove_user(username)
        except KeyError as exc:
            self.audit.log_admin_action(
                actor.username, "delete_user", target=username,
                result="error", error=str(exc),
            )
            raise
        self.audit.log_admin_action(actor.username, "delete_user", target=username)

    def change_role(self, actor: User, username: str, new_role: str) -> None:
        self._require_admin(actor, "change_role")
        target = self.store.get(username)
        if target is None:
            self.audit.log_admin_action(
                actor.username, "change_role", target=username,
                result="error", error="user_not_found",
            )
            raise KeyError(f"El usuario '{username}' no existe")
        old_role = target.role
        target.role = new_role
        self.audit.log_admin_action(
            actor.username, "change_role", target=username,
            old_role=old_role, new_role=new_role,
        )


# ---------------------------------------------------------------------------
# Demostración
# ---------------------------------------------------------------------------

def main() -> None:
    audit = AuditLogger()
    store = UserStore(audit)
    admin_service = AdminService(store, audit)

    store.add_user("root", "s3cret-admin", role="admin")
    store.add_user("ana", "clave-correcta")

    # 1) Intentos de login fallidos (el 3.º dispara la alerta por umbral)
    store.authenticate("ana", "mala-clave", ip="192.168.1.10")
    store.authenticate("ana", "otra-mala", ip="192.168.1.10")
    store.authenticate("ana", "tercera-mala", ip="192.168.1.10")
    store.authenticate("desconocido", "x", ip="10.0.0.5")
    store.authenticate("ana", "clave-correcta", ip="192.168.1.10")

    # 2) Acciones de administrador legítimas
    admin = store.authenticate("root", "s3cret-admin", ip="192.168.1.1")
    assert admin is not None
    admin_service.create_user(admin, "luis", "temporal-123")
    admin_service.change_role(admin, "luis", "moderator")
    admin_service.delete_user(admin, "luis")

    # 3) Intento de acción privilegiada sin permisos (queda registrado)
    ana = store.authenticate("ana", "clave-correcta", ip="192.168.1.10")
    assert ana is not None
    try:
        admin_service.delete_user(ana, "root")
    except PermissionError as exc:
        print(f"Acceso denegado: {exc}")

    print(f"\nContenido de {LOG_FILE.name}:\n")
    print(LOG_FILE.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
