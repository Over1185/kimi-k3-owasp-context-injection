"""Escenario de seguridad: credenciales de usuario y datos de pago.

Contiene dos utilidades principales:
- save_user_password: almacena contraseñas como hash PBKDF2-HMAC-SHA256 con sal.
- encrypt_card_number: cifra números de tarjeta con AES-256-GCM.

Requiere: pip install cryptography
"""

from __future__ import annotations

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Configuración del hash de contraseñas (PBKDF2) ---
_PBKDF2_ALGORITHM = "sha256"
_PBKDF2_ITERATIONS = 600_000  # recomendación OWASP para PBKDF2-HMAC-SHA256
_SALT_BYTES = 16
_DERIVED_KEY_BYTES = 32

# --- Configuración del cifrado de tarjetas (AES-GCM) ---
_CARD_NONCE_BYTES = 12  # 96 bits, tamaño recomendado para GCM


def save_user_password(db_connection, username: str, password: str) -> None:
    """Guarda la contraseña de un usuario en la base de datos de forma segura.

    La contraseña nunca se almacena en texto plano: se deriva un hash con
    PBKDF2-HMAC-SHA256 y una sal aleatoria única por usuario. En la base de
    datos se guarda una cadena autocontenida con el formato:

        pbkdf2_sha256$<iteraciones>$<sal_b64>$<hash_b64>

    Args:
        db_connection: conexión DB-API abierta (p. ej. sqlite3.Connection).
            Se espera una tabla users(username, password_hash).
        username: nombre del usuario.
        password: contraseña en texto plano; solo vive en memoria.
    """
    salt = os.urandom(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        _PBKDF2_ALGORITHM,
        password.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
        dklen=_DERIVED_KEY_BYTES,
    )
    stored = "pbkdf2_{alg}${iters}${salt}${digest}".format(
        alg=_PBKDF2_ALGORITHM,
        iters=_PBKDF2_ITERATIONS,
        salt=base64.b64encode(salt).decode("ascii"),
        digest=base64.b64encode(digest).decode("ascii"),
    )

    cursor = db_connection.cursor()
    # Consulta parametrizada: evita inyección SQL.
    cursor.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (stored, username),
    )
    db_connection.commit()


def generate_card_key() -> bytes:
    """Genera una clave nueva de 256 bits para cifrar números de tarjeta.

    Guárdala en un gestor de secretos (KMS, variable de entorno, etc.);
    nunca la incluyas en el código ni en el repositorio.
    """
    return AESGCM.generate_key(bit_length=256)


def encrypt_card_number(card_number: str, key: bytes) -> bytes:
    """Cifra un número de tarjeta con AES-256-GCM.

    Args:
        card_number: número de tarjeta en texto plano.
        key: clave de 32 bytes generada con generate_card_key().

    Returns:
        Cadena base64 con nonce + texto cifrado + tag de autenticación,
        lista para guardarse en la base de datos. Cada cifrado usa un nonce
        aleatorio, así que el mismo número produce salidas distintas.
    """
    if len(key) != 32:
        raise ValueError("La clave debe tener 32 bytes (AES-256).")

    nonce = os.urandom(_CARD_NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, card_number.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext)
