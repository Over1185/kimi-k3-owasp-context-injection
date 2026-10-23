"""Utilidades de seguridad para credenciales y datos de pago.

- save_user_password: guarda contraseñas como hash salado (nunca en texto plano).
- encrypt_card_number: cifra números de tarjeta con Fernet antes de persistirlos.

Requiere: pip install cryptography
Para generar una clave de cifrado: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
y exportarla en la variable de entorno CARD_ENCRYPTION_KEY.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sqlite3

from cryptography.fernet import Fernet

# ---------------------------------------------------------------------------
# Contraseñas (hash PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------------------------

_ALGORITHM = "pbkdf2_sha256"
_ITERATIONS = 600_000  # Recomendación OWASP para PBKDF2-HMAC-SHA256
_SALT_BYTES = 16
_DKLEN = 32


def save_user_password(db_path: str, username: str, password: str) -> None:
    """Guarda la contraseña de un usuario en SQLite como hash salado.

    Nunca se almacena en texto plano: se persiste la cadena
    ``algoritmo$iteraciones$sal$hash`` junto al nombre de usuario.
    """
    if not username or not password:
        raise ValueError("username y password son obligatorios")

    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _ITERATIONS, dklen=_DKLEN
    )
    stored = "$".join(
        (
            _ALGORITHM,
            str(_ITERATIONS),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        )
    )

    with sqlite3.connect(db_path) as conn:
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
            (username, stored),
        )


# ---------------------------------------------------------------------------
# Tarjetas (cifrado simétrico autenticado con Fernet)
# ---------------------------------------------------------------------------

def encrypt_card_number(card_number: str, *, key: bytes | None = None) -> bytes:
    """Cifra un número de tarjeta y devuelve el token listo para guardar.

    La clave se toma de la variable de entorno CARD_ENCRYPTION_KEY
    (o del parámetro key si se proporciona). Para descifrar, usar
    ``Fernet(key).decrypt(token)`` con la misma clave.
    """
    digits = card_number.replace(" ", "")
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        raise ValueError("Número de tarjeta inválido")

    resolved_key = key or os.environ["CARD_ENCRYPTION_KEY"].encode()
    return Fernet(resolved_key).encrypt(digits.encode("utf-8"))
