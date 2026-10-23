"""Utilidades de seguridad: almacenamiento de contraseñas y cifrado de tarjetas.

Decisiones de seguridad (OWASP Top 10:2025, ver AGENTS.md):
- A04: contraseñas con bcrypt (coste 12); nunca MD5/SHA1/SHA256 sin sal.
- A04: cifrado de tarjetas con Fernet (AES-128-CBC + HMAC) y la clave se
  obtiene de la variable de entorno CARD_ENCRYPTION_KEY, nunca del código.
  Generarla una vez con: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
- A05: consultas SQL parametrizadas (placeholders), sin concatenación.
- A09: los logs registran el evento sin incluir contraseñas ni tarjetas.
- A10: excepciones manejadas explícitamente; sin bloques except genéricos.

Dependencias (fijar versión exacta en requirements.txt, p. ej.):
    bcrypt==4.2.1
    cryptography==43.0.3
"""

from __future__ import annotations

import logging
import os
import sqlite3

import bcrypt
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

# Factor de coste recomendado por OWASP para bcrypt.
_BCRYPT_ROUNDS = 12

# Variable de entorno que contiene la clave de cifrado de tarjetas.
_ENV_CLAVE_TARJETA = "CARD_ENCRYPTION_KEY"


def guardar_contrasena(
    conexion: sqlite3.Connection, usuario_id: int, contrasena: str
) -> None:
    """Hashea la contraseña con bcrypt y la almacena de forma segura.

    Args:
        conexion: conexión SQLite abierta (o compatible con DB-API).
        usuario_id: identificador interno del usuario (nunca del cliente
            sin validar; ver A01 Broken Access Control).
        contrasena: contraseña en texto plano recibida del usuario.

    Raises:
        ValueError: si la contraseña está vacía.
        RuntimeError: si falla la operación contra la base de datos.
    """
    if not contrasena:
        raise ValueError("La contraseña no puede estar vacía.")

    hash_bytes = bcrypt.hashpw(
        contrasena.encode("utf-8"), bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
    )

    try:
        with conexion:
            # Consulta parametrizada: los valores nunca se concatenan (A05).
            conexion.execute(
                "UPDATE usuarios SET password_hash = ? WHERE id = ?",
                (hash_bytes.decode("utf-8"), usuario_id),
            )
    except sqlite3.Error as exc:
        # No se expone el detalle interno; se registra solo el evento (A09).
        logger.error(
            "Fallo al actualizar la contraseña del usuario id=%s", usuario_id
        )
        raise RuntimeError("No se pudo guardar la contraseña.") from exc

    logger.info("Contraseña actualizada para el usuario id=%s", usuario_id)


def _obtener_clave_cifrado() -> bytes:
    """Lee la clave de cifrado desde el entorno (nunca hardcodeada, A04)."""
    clave = os.environ.get(_ENV_CLAVE_TARJETA)
    if not clave:
        raise RuntimeError(
            f"La variable de entorno {_ENV_CLAVE_TARJETA} no está definida."
        )
    return clave.encode("utf-8")


def cifrar_numero_tarjeta(numero_tarjeta: str) -> bytes:
    """Cifra el número de tarjeta con Fernet (cifrado autenticado).

    Args:
        numero_tarjeta: número de tarjeta en texto plano (solo dígitos).

    Returns:
        Token cifrado en bytes, apto para almacenarse como BLOB o texto
        base64 en la base de datos.

    Raises:
        ValueError: si el número está vacío o contiene caracteres no
            numéricos.
        RuntimeError: si la clave de cifrado no está configurada.
    """
    if not numero_tarjeta or not numero_tarjeta.isdigit():
        raise ValueError("El número de tarjeta debe contener solo dígitos.")

    fernet = Fernet(_obtener_clave_cifrado())
    return fernet.encrypt(numero_tarjeta.encode("utf-8"))
