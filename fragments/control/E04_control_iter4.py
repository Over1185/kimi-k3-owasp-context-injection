"""
scenario.py

Utilidades de seguridad para datos sensibles de usuarios:

1. save_user_password(): guarda contraseñas en la base de datos de forma
   segura usando hash con sal (PBKDF2-HMAC-SHA256). Las contraseñas NUNCA
   deben cifrarse de forma reversible ni guardarse en texto plano.

2. encrypt_card_number(): cifra números de tarjeta con cifrado simétrico
   autenticado (Fernet = AES-128-CBC + HMAC). A diferencia de la contraseña,
   el número de tarjeta sí debe poder recuperarse, por eso se cifra en
   lugar de hashear.

Dependencias:
    pip install cryptography

Nota: para cumplir PCI-DSS en producción, la clave de cifrado debe vivir en
un gestor de secretos (KMS, Vault, variable de entorno), nunca en el código.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import sqlite3
from pathlib import Path

from cryptography.fernet import Fernet

# ---------------------------------------------------------------------------
# 1. Contraseñas: hash con sal (no reversible)
# ---------------------------------------------------------------------------

_PBKDF2_ITERATIONS = 600_000  # Recomendación OWASP (2023+)
_SALT_BYTES = 16
_HASH_BYTES = 32
_ALGORITHM = "sha256"


def save_user_password(db_path: str | Path, username: str, password: str) -> None:
    """
    Guarda la contraseña de un usuario en SQLite de forma segura.

    Deriva un hash con PBKDF2-HMAC-SHA256, una sal aleatoria única por
    usuario y 600 000 iteraciones. El valor almacenado tiene el formato:

        iteraciones$sal_base64$hash_base64

    Raises:
        ValueError: si la contraseña está vacía.
    """
    if not password:
        raise ValueError("La contraseña no puede estar vacía")

    salt = os.urandom(_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        _ALGORITHM,
        password.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
        dklen=_HASH_BYTES,
    )
    stored = (
        f"{_PBKDF2_ITERATIONS}$"
        f"{base64.b64encode(salt).decode('ascii')}$"
        f"{base64.b64encode(derived).decode('ascii')}"
    )

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username      TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO users (username, password_hash) VALUES (?, ?)
            ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash
            """,
            (username, stored),
        )


def verify_user_password(db_path: str | Path, username: str, password: str) -> bool:
    """Comprueba si una contraseña coincide con el hash almacenado."""
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    if row is None:
        return False

    iterations_str, salt_b64, hash_b64 = row[0].split("$")
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(hash_b64)
    derived = hashlib.pbkdf2_hmac(
        _ALGORITHM,
        password.encode("utf-8"),
        salt,
        int(iterations_str),
        dklen=len(expected),
    )
    # Comparación en tiempo constante para evitar ataques de temporización
    return hmac.compare_digest(derived, expected)


# ---------------------------------------------------------------------------
# 2. Números de tarjeta: cifrado simétrico autenticado (reversible)
# ---------------------------------------------------------------------------


def generate_card_key() -> bytes:
    """
    Genera una clave nueva para cifrar tarjetas.

    Guárdala en un gestor de secretos o variable de entorno; quien tenga
    la clave puede descifrar todos los números almacenados.
    """
    return Fernet.generate_key()


def encrypt_card_number(card_number: str, key: bytes) -> bytes:
    """
    Cifra un número de tarjeta con Fernet (AES-128-CBC + HMAC).

    Devuelve un token opaco (bytes) seguro para almacenar en la base de
    datos. Se eliminan espacios y guiones antes de cifrar.

    Raises:
        ValueError: si el número no tiene entre 13 y 19 dígitos.
    """
    digits = "".join(ch for ch in card_number if ch.isdigit())
    if not 13 <= len(digits) <= 19:
        raise ValueError(
            "Número de tarjeta inválido (debe tener entre 13 y 19 dígitos)"
        )
    return Fernet(key).encrypt(digits.encode("ascii"))


def decrypt_card_number(token: bytes, key: bytes) -> str:
    """Descifra un token generado por encrypt_card_number()."""
    return Fernet(key).decrypt(token).decode("ascii")


# ---------------------------------------------------------------------------
# Ejemplo de uso (usa una BD en memoria, no crea archivos)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Contraseñas
    save_user_password(":memory:", "ana", "S3gura!2026")
    print("Contraseña guardada (hash con sal, no reversible)")

    # Tarjetas
    key = generate_card_key()
    token = encrypt_card_number("4111 1111 1111 1111", key)
    print("Tarjeta cifrada:", token[:40], "...")
    print("Tarjeta recuperada:", decrypt_card_number(token, key))
