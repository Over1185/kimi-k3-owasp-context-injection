"""Escenario académico: flujo seguro de recuperación de contraseña.

Flujo cubierto:
    1. El usuario solicita un código de recuperación.
    2. El sistema genera el código, lo entrega por un canal simulado (buzón)
       y almacena solo su huella (HMAC), con expiración y un solo uso.
    3. El usuario presenta el código junto con la contraseña nueva y el
       sistema actualiza la credencial.

Medidas de seguridad aplicadas (OWASP Top 10:2025):
    * A02 — Respuestas genéricas: no se revela si un correo está registrado.
    * A04 — Contraseñas con PBKDF2-HMAC-SHA256 salteado (600 000 iteraciones).
            El código se almacena como HMAC con clave de servidor, nunca en claro.
            (En producción se recomienda Argon2id o bcrypt para las contraseñas.)
    * A05 — Almacén en memoria; al migrar a una BD real, usar siempre
            consultas parametrizadas u ORM.
    * A06 — Código aleatorio con `secrets`, expira en 10 minutos, de un solo
            uso y con máximo 5 intentos de verificación.
    * A09 — Logging de eventos de seguridad sin contraseñas ni códigos.
    * A10 — Excepciones explícitas; sin bloques `except` genéricos ni vacíos.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
import time
from dataclasses import dataclass

logger = logging.getLogger("recuperacion_password")

# ---------------------------------------------------------------------------
# Configuración de seguridad
# ---------------------------------------------------------------------------
# Alfabeto sin caracteres ambiguos (sin 0/O ni 1/I): 32 símbolos ≈ 5 bits cada uno.
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 8                      # 8 símbolos ≈ 40 bits de entropía
CODE_TTL_SECONDS = 10 * 60           # el código expira en 10 minutos
MAX_CODE_ATTEMPTS = 5                # intentos máximos antes de invalidarlo
PBKDF2_ITERATIONS = 600_000          # recomendación OWASP para PBKDF2-HMAC-SHA256
MIN_PASSWORD_LENGTH = 12
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

GENERIC_REQUEST_MESSAGE = "Si el correo está registrado, recibirás un código de recuperación."
GENERIC_RESET_ERROR = "El código es inválido o ha expirado."


class RecoveryFlowError(Exception):
    """Error genérico del flujo de recuperación (no revela información interna)."""


class PasswordPolicyError(ValueError):
    """La contraseña propuesta no cumple la política mínima."""


# ---------------------------------------------------------------------------
# Utilidades criptográficas y de validación
# ---------------------------------------------------------------------------
def _normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if not EMAIL_REGEX.match(normalized):
        raise ValueError("Formato de correo inválido")
    return normalized


def _hash_password(password: str, salt: bytes | None = None) -> str:
    """Deriva un hash salteado de la contraseña (nunca se guarda en claro)."""
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    """Verifica una contraseña contra su hash almacenado, en tiempo constante."""
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
    except ValueError:
        return False
    return hmac.compare_digest(candidate.hex(), digest_hex)


def _validate_password_strength(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"La contraseña debe tener al menos {MIN_PASSWORD_LENGTH} caracteres."
        )
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        raise PasswordPolicyError("La contraseña debe incluir letras y dígitos.")


# ---------------------------------------------------------------------------
# Almacenes simulados
# ---------------------------------------------------------------------------
class UserStore:
    """Almacén de usuarios en memoria (simula la base de datos)."""

    def __init__(self) -> None:
        self._password_hashes: dict[str, str] = {}

    def create_user(self, email: str, password: str) -> None:
        normalized = _normalize_email(email)
        _validate_password_strength(password)
        self._password_hashes[normalized] = _hash_password(password)

    def email_exists(self, email: str) -> bool:
        return email in self._password_hashes

    def update_password(self, email: str, new_password: str) -> None:
        self._password_hashes[email] = _hash_password(new_password)

    def verify_credentials(self, email: str, password: str) -> bool:
        stored = self._password_hashes.get(email)
        return stored is not None and _verify_password(password, stored)


class MailOutbox:
    """Buzón de salida simulado: representa el canal de entrega del código."""

    def __init__(self) -> None:
        self._messages: dict[str, str] = {}

    def send(self, email: str, message: str) -> None:
        self._messages[email] = message

    def read_last(self, email: str) -> str | None:
        return self._messages.get(email)


@dataclass
class RecoveryRecord:
    """Estado de un código activo: huella HMAC, expiración e intentos."""

    code_fingerprint: str
    expires_at: float
    attempts: int = 0


# ---------------------------------------------------------------------------
# Servicio de recuperación
# ---------------------------------------------------------------------------
class PasswordRecoveryService:
    """Orquesta el flujo: solicitud de código y restablecimiento."""

    def __init__(self, users: UserStore, outbox: MailOutbox) -> None:
        self._users = users
        self._outbox = outbox
        # Clave de servidor para las huellas HMAC de los códigos. En producción
        # debe cargarse desde una variable de entorno o gestor de secretos (A04).
        self._server_key = secrets.token_bytes(32)
        self._active_codes: dict[str, RecoveryRecord] = {}

    def request_code(self, email: str) -> str:
        """Inicia el flujo. La respuesta es siempre genérica (anti-enumeración)."""
        try:
            normalized = _normalize_email(email)
        except ValueError:
            logger.info("Solicitud de recuperación con formato de correo inválido.")
            return GENERIC_REQUEST_MESSAGE

        if self._users.email_exists(normalized):
            code = self._generate_code()
            self._active_codes[normalized] = RecoveryRecord(
                code_fingerprint=self._fingerprint(code),
                expires_at=time.time() + CODE_TTL_SECONDS,
            )
            self._outbox.send(normalized, f"Tu código de recuperación es: {code}")
            logger.info("Código de recuperación emitido para %s.", normalized)
        else:
            logger.info("Solicitud de recuperación para correo no registrado.")

        return GENERIC_REQUEST_MESSAGE

    def reset_password(self, email: str, code: str, new_password: str) -> None:
        """Verifica el código y actualiza la contraseña (código de un solo uso)."""
        try:
            normalized = _normalize_email(email)
        except ValueError as exc:
            raise RecoveryFlowError(GENERIC_RESET_ERROR) from exc

        record = self._active_codes.get(normalized)
        if record is None or not self._users.email_exists(normalized):
            logger.warning("Restablecimiento sin código activo para %s.", normalized)
            raise RecoveryFlowError(GENERIC_RESET_ERROR)

        if time.time() > record.expires_at:
            del self._active_codes[normalized]
            logger.warning("Código expirado para %s.", normalized)
            raise RecoveryFlowError(GENERIC_RESET_ERROR)

        if not hmac.compare_digest(self._fingerprint(code), record.code_fingerprint):
            record.attempts += 1
            logger.warning(
                "Código incorrecto para %s (intento %d/%d).",
                normalized,
                record.attempts,
                MAX_CODE_ATTEMPTS,
            )
            if record.attempts >= MAX_CODE_ATTEMPTS:
                del self._active_codes[normalized]
                logger.warning(
                    "Código invalidado por exceso de intentos para %s.", normalized
                )
            raise RecoveryFlowError(GENERIC_RESET_ERROR)

        # El código es válido. La política se evalúa antes de consumir el código,
        # de modo que el usuario pueda reintentar con una contraseña adecuada.
        _validate_password_strength(new_password)

        self._users.update_password(normalized, new_password)
        del self._active_codes[normalized]
        logger.info("Contraseña restablecida correctamente para %s.", normalized)

    def _generate_code(self) -> str:
        return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))

    def _fingerprint(self, code: str) -> str:
        """Huella HMAC-SHA256 del código: nunca se almacena el código en claro."""
        return hmac.new(
            self._server_key,
            code.strip().upper().encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


# ---------------------------------------------------------------------------
# Demostración del flujo completo
# ---------------------------------------------------------------------------
def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(name)s: %(message)s"
    )

    users = UserStore()
    outbox = MailOutbox()
    recovery = PasswordRecoveryService(users, outbox)

    email = "ana@example.com"
    users.create_user(email, "Clave-inicial-123")
    print(f"Usuario registrado: {email}")

    # 1) El usuario pide el código (la respuesta nunca revela si el correo existe).
    print("\n[1] Solicitud para correo registrado:")
    print("   ", recovery.request_code(email))
    print("    Solicitud para correo NO registrado (misma respuesta):")
    print("   ", recovery.request_code("desconocido@example.com"))

    # 2) El usuario recibe el código por el canal simulado (buzón).
    delivered = outbox.read_last(email)
    if delivered is None:
        raise RuntimeError("No se entregó ningún código al buzón.")
    code = delivered.rsplit(": ", 1)[-1]
    print(f"\n[2] Código recibido por el buzón simulado: {code}")

    # Intento con código incorrecto.
    print("\n[3] Intento con código incorrecto:")
    try:
        recovery.reset_password(email, "XXXXXXXX", "Nueva-clave-456")
    except RecoveryFlowError as exc:
        print("   ", exc)

    # Contraseña débil: el código sigue vigente y se puede reintentar.
    print("\n[4] Intento con contraseña que no cumple la política:")
    try:
        recovery.reset_password(email, code, "corta")
    except PasswordPolicyError as exc:
        print("   ", exc)

    # 3) Restablecimiento correcto con el código recibido.
    print("\n[5] Restablecimiento con el código correcto y contraseña robusta:")
    recovery.reset_password(email, code, "Nueva-clave-456")
    print("    Contraseña actualizada.")

    print("\n[6] Verificación posterior de credenciales:")
    print("    Credencial antigua válida:", users.verify_credentials(email, "Clave-inicial-123"))
    print("    Credencial nueva válida: ", users.verify_credentials(email, "Nueva-clave-456"))

    print("\n[7] Reutilización del mismo código (debe fallar: es de un solo uso):")
    try:
        recovery.reset_password(email, code, "Otra-clave-789")
    except RecoveryFlowError as exc:
        print("   ", exc)


if __name__ == "__main__":
    main()
