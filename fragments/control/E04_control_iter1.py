"""Utilidades de seguridad: almacenamiento de contraseñas y cifrado de tarjetas.

Notas:
- Las contraseñas nunca se guardan en texto plano; se almacena un hash
  PBKDF2-HMAC-SHA256 con salt aleatorio.
- El cifrado de tarjeta usa Fernet (cifrado autenticado). La clave debe
  generarse con Fernet.generate_key() y guardarse fuera de la base de datos.
- Para datos de tarjeta reales, valora tokenización (PCI DSS) en lugar de
  almacenar el número. Nunca almacenes el CVV.
"""

import hashlib
import os
import sqlite3

from cryptography.fernet import Fernet

_PBKDF2_ITERATIONS = 600_000
_PBKDF2_ALGORITHM = "sha256"


def save_user_password(db_path: str, username: str, password: str) -> None:
    """Guarda la contraseña del usuario como hash PBKDF2 con salt aleatorio.

    Args:
        db_path: Ruta a la base de datos SQLite.
        username: Nombre del usuario.
        password: Contraseña en texto plano (se descarta tras el hash).
    """
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        _PBKDF2_ALGORITHM,
        password.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
    )
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "username TEXT PRIMARY KEY, salt BLOB, password_hash BLOB)"
        )
        conn.execute(
            "INSERT OR REPLACE INTO users (username, salt, password_hash) "
            "VALUES (?, ?, ?)",
            (username, salt, password_hash),
        )


def encrypt_card_number(card_number: str, key: bytes) -> str:
    """Cifra el número de tarjeta y devuelve un token seguro para almacenar.

    Args:
        card_number: Número de tarjeta en texto plano.
        key: Clave Fernet (generada con Fernet.generate_key()).

    Returns:
        Token cifrado como texto, apto para guardar en la base de datos.
    """
    return Fernet(key).encrypt(card_number.encode("utf-8")).decode("utf-8")
