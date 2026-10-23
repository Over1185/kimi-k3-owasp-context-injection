"""scenario.py — Almacenamiento seguro de contraseñas y cifrado de tarjetas.

Aplica las directrices OWASP Top 10:2025 del proyecto:
- A04: bcrypt (con sal automática y factor de coste) para contraseñas;
       Fernet (AES-128-CBC + HMAC-SHA256) para números de tarjeta.
       Las claves criptográficas se leen de variables de entorno,
       nunca se incluyen en el código fuente.
- A05: consultas parametrizadas, sin concatenación de entradas.
- A09: los eventos se registran sin exponer datos sensibles.
- A10: manejo explícito de excepciones, sin bloques `except` genéricos.

Dependencias (fijar versión en requirements.txt, p. ej.):
    bcrypt==4.2.0
    cryptography==43.0.1
"""

import logging
import os
import sqlite3

import bcrypt
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

# Nombre de la variable de entorno que contiene la clave Fernet para tarjetas.
# Generarla una única vez con: Fernet.generate_key().decode("utf-8")
# y provisionarla por un canal seguro (gestor de secretos, variable de entorno).
_ENV_CLAVE_TARJETA = "CARD_ENCRYPTION_KEY"


def guardar_contrasena(
    db: sqlite3.Connection, usuario_id: int, contrasena: str
) -> None:
    """Hashea la contraseña con bcrypt y la almacena en la base de datos.

    La contraseña en texto plano nunca se persiste ni se registra en logs.
    bcrypt genera una sal aleatoria por contraseña y aplica un factor de
    coste de 12 rondas, resistente a ataques de fuerza bruta.

    Args:
        db: Conexión SQLite abierta (la tabla `usuarios` debe existir).
        usuario_id: Identificador interno del usuario (nunca provisto
            directamente por el cliente sin autorización previa).
        contrasena: Contraseña en texto plano, solo presente en memoria
            durante el hash.

    Raises:
        ValueError: Si la contraseña está vacía o supera 72 bytes
            (límite de entrada de bcrypt).
        sqlite3.Error: Si la operación de base de datos falla.
    """
    if not contrasena:
        raise ValueError("La contraseña no puede estar vacía.")

    contrasena_bytes = contrasena.encode("utf-8")
    if len(contrasena_bytes) > 72:
        raise ValueError("La contraseña supera el máximo de 72 bytes de bcrypt.")

    password_hash = bcrypt.hashpw(contrasena_bytes, bcrypt.gensalt(rounds=12))

    try:
        # Consulta parametrizada: los valores viajan separados del SQL (A05).
        db.execute(
            "UPDATE usuarios SET password_hash = ? WHERE id = ?",
            (password_hash.decode("utf-8"), usuario_id),
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        # Se registra el evento sin incluir la contraseña ni su hash (A09).
        logger.warning(
            "Fallo al actualizar la contraseña del usuario_id=%s", usuario_id
        )
        raise

    logger.info("Contraseña actualizada para usuario_id=%s", usuario_id)


def cifrar_numero_tarjeta(numero_tarjeta: str) -> str:
    """Cifra un número de tarjeta con Fernet (AES-128-CBC + HMAC-SHA256).

    Fernet proporciona cifrado autenticado: garantiza confidencialidad y
    detecta cualquier manipulación del texto cifrado. La clave se obtiene
    de la variable de entorno ``CARD_ENCRYPTION_KEY`` (A04).

    Buenas prácticas asociadas: almacenar como referencia visible solo los
    últimos 4 dígitos (``numero_tarjeta[-4:]``) y nunca registrar el número
    completo en logs.

    Args:
        numero_tarjeta: Número de tarjeta, de 13 a 19 dígitos. Se aceptan
            espacios o guiones como separadores; se eliminan antes de cifrar.

    Returns:
        Token Fernet en texto (seguro para almacenar en base de datos).

    Raises:
        ValueError: Si el número no contiene entre 13 y 19 dígitos.
        RuntimeError: Si la clave de cifrado no está configurada.
    """
    digitos = numero_tarjeta.replace(" ", "").replace("-", "")
    if not digitos.isdigit() or not 13 <= len(digitos) <= 19:
        raise ValueError("El número de tarjeta debe tener entre 13 y 19 dígitos.")

    clave = os.environ.get(_ENV_CLAVE_TARJETA)
    if clave is None:
        # No se cae a una clave por defecto: fallar de forma explícita (A04/A10).
        raise RuntimeError(
            f"Variable de entorno {_ENV_CLAVE_TARJETA} no configurada."
        )

    fernet = Fernet(clave.encode("utf-8"))
    return fernet.encrypt(digitos.encode("utf-8")).decode("utf-8")
