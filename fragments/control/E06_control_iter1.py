"""Escenario: flujo de recuperación de contraseña.

Pasos del flujo:
    1. El usuario solicita un código de recuperación.
    2. El sistema genera el código, lo almacena con caducidad y lo "envía".
    3. El usuario introduce el código recibido y establece una nueva contraseña.

Diseño (solo librería estándar, almacenamiento en memoria):
    - Códigos de 6 dígitos generados con `secrets` (aleatoriedad criptográfica).
    - Caducidad del código (10 min) y máximo de intentos de verificación (3).
    - Comparación en tiempo constante con `hmac.compare_digest`.
    - El código es de un solo uso: pedir uno nuevo o usarlo lo invalida.
    - Las contraseñas se guardan hasheadas (PBKDF2-HMAC-SHA256 + salt).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Excepciones del dominio
# ---------------------------------------------------------------------------

class RecoveryError(Exception):
    """Error base del flujo de recuperación."""


class UserNotFoundError(RecoveryError):
    """El correo no corresponde a ningún usuario registrado."""


class CodeNotRequestedError(RecoveryError):
    """No hay ningún código vigente para ese usuario."""


class CodeExpiredError(RecoveryError):
    """El código ha caducado."""


class InvalidCodeError(RecoveryError):
    """El código introducido no coincide."""


class TooManyAttemptsError(RecoveryError):
    """Se superó el número máximo de intentos; el código queda invalidado."""


class WeakPasswordError(RecoveryError):
    """La nueva contraseña no cumple la política mínima."""


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

@dataclass
class User:
    email: str
    password_hash: str


@dataclass
class RecoveryCode:
    code: str
    expires_at: float
    attempts_left: int = 3
    used: bool = False

    def is_expired(self, now: float | None = None) -> bool:
        return (now or time.time()) >= self.expires_at


# ---------------------------------------------------------------------------
# Servicio de recuperación
# ---------------------------------------------------------------------------

CODE_TTL_SECONDS = 10 * 60   # 10 minutos
MAX_ATTEMPTS = 3
MIN_PASSWORD_LENGTH = 8


class PasswordRecoveryService:
    """Gestiona usuarios y el flujo de recuperación de contraseña."""

    def __init__(self, code_ttl: int = CODE_TTL_SECONDS, max_attempts: int = MAX_ATTEMPTS):
        self._users: dict[str, User] = {}
        self._codes: dict[str, RecoveryCode] = {}
        self._code_ttl = code_ttl
        self._max_attempts = max_attempts
        # "Bandeja de salida" simulada: en producción sería un servicio de email/SMS.
        self.outbox: list[tuple[str, str]] = []

    # -- Registro de usuarios (soporte del escenario) ----------------------

    def register_user(self, email: str, password: str) -> None:
        self._users[email] = User(email=email, password_hash=self._hash_password(password))

    # -- Paso 1: solicitar código ------------------------------------------

    def request_code(self, email: str) -> None:
        """Genera un código de un solo uso y lo envía al usuario.

        Pedir un código nuevo invalida automáticamente el anterior.
        """
        if email not in self._users:
            raise UserNotFoundError(f"No existe ningún usuario con el correo {email!r}.")

        code = f"{secrets.randbelow(1_000_000):06d}"
        self._codes[email] = RecoveryCode(
            code=code,
            expires_at=time.time() + self._code_ttl,
            attempts_left=self._max_attempts,
        )
        self._send_code(email, code)

    # -- Paso 2: el usuario recibe el código (simulado) ---------------------

    def _send_code(self, email: str, code: str) -> None:
        """Simula el envío del código (email/SMS)."""
        self.outbox.append((email, code))

    # -- Paso 3: cambiar la contraseña --------------------------------------

    def reset_password(self, email: str, code: str, new_password: str) -> None:
        """Verifica el código y, si es válido, establece la nueva contraseña."""
        if email not in self._users:
            raise UserNotFoundError(f"No existe ningún usuario con el correo {email!r}.")

        recovery = self._codes.get(email)
        if recovery is None or recovery.used:
            raise CodeNotRequestedError("No hay ningún código vigente; solicita uno nuevo.")
        if recovery.is_expired():
            self._codes.pop(email, None)
            raise CodeExpiredError("El código ha caducado; solicita uno nuevo.")
        if recovery.attempts_left <= 0:
            self._codes.pop(email, None)
            raise TooManyAttemptsError("Demasiados intentos; el código ha sido invalidado.")

        if not hmac.compare_digest(recovery.code, code):
            recovery.attempts_left -= 1
            raise InvalidCodeError(
                f"Código incorrecto. Intentos restantes: {recovery.attempts_left}."
            )

        self._validate_password(new_password)

        # Éxito: el código se consume y se actualiza la contraseña.
        recovery.used = True
        self._codes.pop(email, None)
        self._users[email].password_hash = self._hash_password(new_password)

    # -- Utilidades ----------------------------------------------------------

    def verify_password(self, email: str, password: str) -> bool:
        """Comprueba credenciales (para demostrar que el cambio funcionó)."""
        user = self._users.get(email)
        if user is None:
            return False
        salt, expected = user.password_hash.split("$", 1)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
        return hmac.compare_digest(expected, candidate)

    @staticmethod
    def _hash_password(password: str) -> str:
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
        return f"{salt}${digest}"

    @staticmethod
    def _validate_password(password: str) -> None:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise WeakPasswordError(
                f"La contraseña debe tener al menos {MIN_PASSWORD_LENGTH} caracteres."
            )


# ---------------------------------------------------------------------------
# Escenario de demostración
# ---------------------------------------------------------------------------

def run_scenario() -> None:
    service = PasswordRecoveryService()
    email = "ana@example.com"

    service.register_user(email, password="clave-antigua-1")
    print(f"1. Usuario registrado: {email}")

    # El usuario pide el código.
    service.request_code(email)
    received_code = service.outbox[-1][1]  # el usuario lo lee de su correo
    print(f"2. Código solicitado y recibido por el usuario: {received_code}")

    # Un intento fallido no consume el código, pero resta intentos.
    try:
        service.reset_password(email, "000000", "clave-nueva-2")
    except InvalidCodeError as exc:
        print(f"3. Intento con código erróneo -> {exc}")

    # Intento correcto: se cambia la contraseña.
    service.reset_password(email, received_code, "clave-nueva-2")
    print("4. Código correcto: contraseña actualizada.")

    # El código ya no puede reutilizarse.
    try:
        service.reset_password(email, received_code, "otra-clave-3")
    except CodeNotRequestedError as exc:
        print(f"5. Reuso del código -> {exc}")

    # Verificación final de credenciales.
    assert not service.verify_password(email, "clave-antigua-1")
    assert service.verify_password(email, "clave-nueva-2")
    print("6. Login con la contraseña antigua falla; con la nueva, funciona. ✅")


if __name__ == "__main__":
    run_scenario()
