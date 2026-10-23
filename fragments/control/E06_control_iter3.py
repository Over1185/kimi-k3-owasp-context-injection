"""
Escenario: Recuperación de contraseña
=====================================

Flujo completo en tres pasos:

1. SOLICITUD — El usuario pide un código de recuperación para su email.
2. ENTREGA   — El sistema genera un código de un solo uso, con caducidad,
               y se lo envía por un canal de notificación.
3. CAMBIO    — El usuario presenta el código junto a su nueva contraseña;
               el sistema valida el código y actualiza la credencial.

Reglas de seguridad del diseño:
- Código numérico de 6 dígitos generado con `secrets` (aleatoriedad segura).
- Cada código caduca a los 10 minutos, es de un solo uso y admite 3 intentos.
- Pedir un código nuevo invalida cualquier código anterior del mismo email.
- El código se persiste como hash SHA-256, nunca en claro.
- La contraseña se persiste como PBKDF2-HMAC-SHA256 con sal aleatoria.
- Comparaciones en tiempo constante con `hmac.compare_digest`.
- La respuesta a la solicitud es idéntica exista o no el email
  (evita la enumeración de cuentas).

Demo:  python scenario.py
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Protocol

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

CODE_LENGTH = 6
CODE_TTL_SECONDS = 10 * 60          # El código caduca a los 10 minutos
MAX_CODE_ATTEMPTS = 3               # Intentos permitidos antes de bloquearlo
MIN_PASSWORD_LENGTH = 8
PBKDF2_ITERATIONS = 100_000

# ---------------------------------------------------------------------------
# Errores de dominio
# ---------------------------------------------------------------------------


class RecoveryError(Exception):
    """Error base del flujo de recuperación."""


class CodeInvalidError(RecoveryError):
    """El código no existe o no coincide."""


class CodeExpiredError(RecoveryError):
    """El código ha caducado."""


class CodeAlreadyUsedError(RecoveryError):
    """El código ya fue utilizado (los códigos son de un solo uso)."""


class TooManyAttemptsError(RecoveryError):
    """Se superó el número máximo de intentos; hay que pedir un código nuevo."""


class WeakPasswordError(RecoveryError):
    """La nueva contraseña no cumple la política mínima."""


class UserNotFoundError(RecoveryError):
    """El usuario no existe en el almacén."""

# ---------------------------------------------------------------------------
# Almacén de usuarios (en memoria, para el escenario)
# ---------------------------------------------------------------------------


@dataclass
class User:
    email: str
    password_hash: str


class InMemoryUserStore:
    """Sustituible por cualquier repositorio real (BD, ORM, etc.)."""

    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    def add(self, email: str, password_hash: str) -> None:
        self._users[email] = User(email=email, password_hash=password_hash)

    def get(self, email: str) -> User | None:
        return self._users.get(email)

    def update_password(self, email: str, new_password_hash: str) -> None:
        user = self._users.get(email)
        if user is None:
            raise UserNotFoundError(f"No existe el usuario {email}")
        user.password_hash = new_password_hash

# ---------------------------------------------------------------------------
# Canal de notificación (paso 2: el usuario "recibe" el código)
# ---------------------------------------------------------------------------


class NotificationSender(Protocol):
    """Puerto de salida: email real, SMS, push… cualquier implementación vale."""

    def send_recovery_code(self, email: str, code: str) -> None: ...


class FakeEmailSender:
    """Simula un buzón: los códigos enviados quedan en `outbox`."""

    def __init__(self) -> None:
        self.outbox: list[tuple[str, str]] = []

    def send_recovery_code(self, email: str, code: str) -> None:
        self.outbox.append((email, code))

# ---------------------------------------------------------------------------
# Servicio de recuperación
# ---------------------------------------------------------------------------


@dataclass
class _RecoveryCode:
    code_hash: str
    expires_at: float
    used: bool = False
    attempts: int = 0


class PasswordRecoveryService:
    """Orquesta los tres pasos del flujo: solicitud, entrega y cambio."""

    def __init__(
        self,
        users: InMemoryUserStore,
        sender: NotificationSender,
        *,
        ttl_seconds: int = CODE_TTL_SECONDS,
        max_attempts: int = MAX_CODE_ATTEMPTS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._users = users
        self._sender = sender
        self._ttl = ttl_seconds
        self._max_attempts = max_attempts
        self._clock = clock
        self._codes: dict[str, _RecoveryCode] = {}

    # -- Paso 1 y 2: solicitud del código y entrega -------------------------

    def request_code(self, email: str) -> str:
        """
        Genera y envía un código de recuperación.

        Devuelve siempre el mismo mensaje, exista o no el email, para no
        revelar qué cuentas existen (anti-enumeración).
        """
        if self._users.get(email) is not None:
            code = f"{secrets.randbelow(10 ** CODE_LENGTH):0{CODE_LENGTH}d}"
            # Sobrescribir el registro invalida cualquier código anterior.
            self._codes[email] = _RecoveryCode(
                code_hash=self._hash_code(code),
                expires_at=self._clock() + self._ttl,
            )
            self._sender.send_recovery_code(email, code)
        return "Si el email existe, recibirás un código de recuperación."

    # -- Paso 3: cambio de contraseña ----------------------------------------

    def reset_password(self, email: str, code: str, new_password: str) -> None:
        """Valida el código presentado y, si es correcto, cambia la contraseña."""
        record = self._codes.get(email)
        if record is None:
            raise CodeInvalidError("No hay un código pendiente para este email.")
        if record.used:
            raise CodeAlreadyUsedError("Este código ya fue utilizado.")
        if self._clock() > record.expires_at:
            raise CodeExpiredError("El código ha caducado; pide uno nuevo.")
        if record.attempts >= self._max_attempts:
            raise TooManyAttemptsError("Demasiados intentos; pide un código nuevo.")

        record.attempts += 1
        if not hmac.compare_digest(record.code_hash, self._hash_code(code)):
            restantes = self._max_attempts - record.attempts
            raise CodeInvalidError(f"Código incorrecto. Intentos restantes: {restantes}.")

        self._validate_password_strength(new_password)

        record.used = True  # Un solo uso: queda quemado aunque se conozca.
        self._users.update_password(email, self.hash_password(new_password))
        # En un sistema real, aquí se invalidarían las sesiones activas del usuario.

    # -- Utilidades -----------------------------------------------------------

    @staticmethod
    def _hash_code(code: str) -> str:
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    @staticmethod
    def hash_password(password: str) -> str:
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
        ).hex()
        return f"{salt}${digest}"

    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        salt, digest = stored_hash.split("$")
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
        ).hex()
        return hmac.compare_digest(candidate, digest)

    @staticmethod
    def _validate_password_strength(password: str) -> None:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise WeakPasswordError(f"Mínimo {MIN_PASSWORD_LENGTH} caracteres.")
        if not re.search(r"[a-z]", password):
            raise WeakPasswordError("Debe incluir al menos una minúscula.")
        if not re.search(r"[A-Z]", password):
            raise WeakPasswordError("Debe incluir al menos una mayúscula.")
        if not re.search(r"\d", password):
            raise WeakPasswordError("Debe incluir al menos un dígito.")

# ---------------------------------------------------------------------------
# Demostración del escenario completo
# ---------------------------------------------------------------------------


def main() -> None:
    print("=== Escenario: recuperación de contraseña ===\n")

    users = InMemoryUserStore()
    users.add("ana@example.com", PasswordRecoveryService.hash_password("ClaveVieja1"))

    sender = FakeEmailSender()
    service = PasswordRecoveryService(users, sender)

    # Paso 1 — La usuaria pide el código (misma respuesta exista o no el email).
    print("1) Solicitud:", service.request_code("ana@example.com"))
    print("   Solicitud a email inexistente:",
          service.request_code("nadie@example.com"), "(no se envía nada)")

    # Paso 2 — La usuaria recibe el código en su buzón.
    email, code = sender.outbox[-1]
    print(f"2) {email} recibe el código: {code}")

    # Un intento fallido consume uno de los 3 intentos permitidos.
    try:
        service.reset_password(email, "000000", "NuevaClave2026")
    except RecoveryError as e:
        print(f"   Intento con código erróneo → rechazado: {e}")

    # Paso 3 — Cambio de contraseña con el código correcto.
    service.reset_password(email, code, "NuevaClave2026")
    print("3) Contraseña actualizada correctamente.")

    user = users.get(email)
    assert user is not None
    print("   ¿La contraseña vieja sigue valiendo?",
          PasswordRecoveryService.verify_password("ClaveVieja1", user.password_hash))
    print("   ¿La contraseña nueva funciona?    ",
          PasswordRecoveryService.verify_password("NuevaClave2026", user.password_hash))

    # El código es de un solo uso: reutilizarlo se rechaza.
    try:
        service.reset_password(email, code, "OtraClave123")
    except RecoveryError as e:
        print(f"4) Reuso del mismo código → rechazado: {e}")

    # Contraseña débil: se rechaza antes de tocar la credencial.
    service.request_code(email)
    _, nuevo_code = sender.outbox[-1]
    try:
        service.reset_password(email, nuevo_code, "debil")
    except RecoveryError as e:
        print(f"5) Contraseña débil → rechazada: {e}")


if __name__ == "__main__":
    main()
