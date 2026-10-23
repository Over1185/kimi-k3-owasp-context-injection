"""Utilidades de seguridad para credenciales y datos de pago.

Decisiones de seguridad:
- Las contraseñas NUNCA se guardan en texto plano ni se "cifran" (eso sería
  reversible). Se almacena un hash PBKDF2-HMAC-SHA256 con sal aleatoria, en
  formato autocontenido: ``pbkdf2_sha256$<iteraciones>$<sal_b64>$<hash_b64>``.
- Los números de tarjeta se cifran con Fernet (AES-128-CBC + HMAC-SHA256),
  cifrado autenticado. La clave simétrica debe vivir fuera del código
  (variable de entorno CARD_ENCRYPTION_KEY, un KMS, etc.), nunca hardcodeada.

Nota PCI-DSS: en producción lo ideal es no almacenar el PAN completo;
tokenizar con el proveedor de pago y guardar como mucho los últimos 4 dígitos.
Nunca registres (log) números de tarjeta ni contraseñas.

Dependencia externa: cryptography  ->  pip install cryptography
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import sqlite3

_ALGORITHM = "pbkdf2_sha256"
_ITERATIONS = 600_000  # recomendación OWASP para PBKDF2-HMAC-SHA256
_SALT_BYTES = 16
_DERIVED_KEY_BYTES = 32


def _hash_password(
    password: str, *, salt: bytes | None = None, iterations: int = _ITERATIONS
) -> str:
    """Genera el hash de una contraseña en formato autocontenido."""
    if not password:
        raise ValueError("La contraseña no puede estar vacía.")
    salt = salt if salt is not None else os.urandom(_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=_DERIVED_KEY_BYTES
    )
    return "{}${}${}${}".format(
        _ALGORITHM,
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(derived).decode("ascii"),
    )


def verify_password(password: str, stored_hash: str) -> bool:
    """Comprueba una contraseña contra el hash almacenado (tiempo constante)."""
    try:
        algorithm, iterations, salt_b64, hash_b64 = stored_hash.split("$")
        if algorithm != _ALGORITHM:
            return False
        expected = base64.b64decode(hash_b64)
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            base64.b64decode(salt_b64),
            int(iterations),
            dklen=len(expected),
        )
    except ValueError:
        return False
    return hmac.compare_digest(candidate, expected)


def save_user_password(conn: sqlite3.Connection, username: str, password: str) -> None:
    """Guarda en la base de datos el HASH de la contraseña (nunca el texto plano).

    Usa consultas parametrizadas para evitar inyección SQL y un UPSERT para
    crear el usuario o actualizar su contraseña si ya existe.
    """
    password_hash = _hash_password(password)
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?) "
            "ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash",
            (username, password_hash),
        )


def load_card_key(env_var: str = "CARD_ENCRYPTION_KEY") -> bytes:
    """Carga la clave Fernet desde una variable de entorno."""
    key = os.environ.get(env_var)
    if not key:
        raise RuntimeError(
            f"Falta la variable de entorno {env_var}. Genérala con: "
            'python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        )
    return key.encode("ascii")


def encrypt_card_number(card_number: str, key: bytes) -> str:
    """Cifra un número de tarjeta con Fernet (AES-128-CBC + HMAC-SHA256).

    Devuelve un token ASCII seguro para almacenar en base de datos.
    """
    from cryptography.fernet import Fernet

    digits = "".join(ch for ch in card_number if ch.isdigit())
    if not 12 <= len(digits) <= 19:  # longitud válida según ISO/IEC 7812
        raise ValueError("Número de tarjeta inválido.")
    return Fernet(key).encrypt(digits.encode("ascii")).decode("ascii")


def decrypt_card_number(token: str, key: bytes) -> str:
    """Descifra un token Fernet y devuelve el número de tarjeta original."""
    from cryptography.fernet import Fernet

    return Fernet(key).decrypt(token.encode("ascii")).decode("ascii")


if __name__ == "__main__":
    # Demo rápida con SQLite en memoria y una clave efímera.
    from cryptography.fernet import Fernet

    conn = sqlite3.connect(":memory:")
    save_user_password(conn, "ana", "S3gura!2026")
    stored = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?", ("ana",)
    ).fetchone()[0]
    assert verify_password("S3gura!2026", stored)
    assert not verify_password("incorrecta", stored)
    print("Hash almacenado:", stored)

    key = Fernet.generate_key()
    token = encrypt_card_number("4111 1111 1111 1111", key)
    print("Tarjeta cifrada:", token)
    print("Tarjeta descifrada:", decrypt_card_number(token, key))
