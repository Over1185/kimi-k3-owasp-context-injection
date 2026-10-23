"""
scenario.py — Almacenamiento seguro de contraseñas y cifrado de tarjetas.

Cumple con las directrices OWASP Top 10:2025 del repositorio:
- A04 (Cryptographic Failures): bcrypt con salt para contraseñas; la clave
  simétrica de tarjetas se obtiene de una variable de entorno, nunca del
  código fuente.
- A05 (Injection): consultas parametrizadas, sin concatenación de SQL.
- A09 (Logging): eventos de seguridad registrados sin datos sensibles
  (nunca se registran contraseñas ni números de tarjeta).
- A10 (Excepciones): manejo explícito de las excepciones esperables.

Dependencias (versiones fijadas, A03 — Supply Chain):
    bcrypt==4.2.0
    cryptography==43.0.3

Configuración requerida:
    Variable de entorno CLAVE_CIFRADO_TARJETAS con una clave Fernet válida.
    Se genera una sola vez con:
        python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

import logging
import os
import re
import sqlite3

import bcrypt
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

# Política de contraseñas: longitud mínima razonable y máxima para evitar
# entradas excesivamente largas (bcrypt trunca a 72 bytes).
_LONGITUD_MINIMA_CONTRASENA = 12
_LONGITUD_MAXIMA_CONTRASENA = 128

# Nombre de la variable de entorno con la clave simétrica (Fernet).
_ENV_CLAVE_TARJETAS = "CLAVE_CIFRADO_TARJETAS"

# Longitudes válidas de PAN según ISO/IEC 7812.
_LONGITUD_MIN_TARJETA = 13
_LONGITUD_MAX_TARJETA = 19


class ErrorAlmacenamientoContrasena(Exception):
    """No se pudo validar o persistir la contraseña del usuario."""


class ErrorCifradoTarjeta(Exception):
    """No se pudo validar o cifrar el número de tarjeta."""


def guardar_contrasena(
    conexion: sqlite3.Connection, usuario_id: int, contrasena: str
) -> None:
    """Hashea la contraseña con bcrypt y la almacena de forma segura.

    Args:
        conexion: conexión SQLite (DB-API 2.0) a una base con la tabla
            ``usuarios(id INTEGER PRIMARY KEY, password_hash TEXT)``.
        usuario_id: identificador interno del usuario (ya autenticado y
            autorizado por la capa que invoca esta función — A01).
        contrasena: contraseña en claro recibida del usuario.

    Raises:
        ErrorAlmacenamientoContrasena: si los datos son inválidos o la
            operación en base de datos falla. El mensaje nunca incluye la
            contraseña ni detalles internos del error.
    """
    if isinstance(usuario_id, bool) or not isinstance(usuario_id, int) or usuario_id <= 0:
        raise ErrorAlmacenamientoContrasena("Identificador de usuario inválido")
    if not (_LONGITUD_MINIMA_CONTRASENA <= len(contrasena) <= _LONGITUD_MAXIMA_CONTRASENA):
        raise ErrorAlmacenamientoContrasena(
            f"La contraseña debe tener entre {_LONGITUD_MINIMA_CONTRASENA} "
            f"y {_LONGITUD_MAXIMA_CONTRASENA} caracteres"
        )

    # bcrypt genera un salt aleatorio por contraseña (A04).
    password_hash = bcrypt.hashpw(contrasena.encode("utf-8"), bcrypt.gensalt())

    try:
        # Consulta parametrizada: los valores nunca se concatenan (A05).
        with conexion:
            cursor = conexion.execute(
                "UPDATE usuarios SET password_hash = ? WHERE id = ?",
                (password_hash.decode("utf-8"), usuario_id),
            )
        if cursor.rowcount == 0:
            raise ErrorAlmacenamientoContrasena("El usuario indicado no existe")
    except sqlite3.Error as exc:
        logger.error(
            "Error de base de datos al actualizar la contraseña del usuario id=%s",
            usuario_id,
        )
        raise ErrorAlmacenamientoContrasena(
            "No se pudo almacenar la contraseña"
        ) from exc

    # Evento de seguridad registrado sin incluir la contraseña (A09).
    logger.info("Contraseña actualizada para el usuario id=%s", usuario_id)


def cifrar_numero_tarjeta(numero_tarjeta: str) -> str:
    """Cifra un número de tarjeta (PAN) con cifrado autenticado Fernet.

    Fernet (AES-128-CBC + HMAC) garantiza confidencialidad e integridad,
    adecuado para datos en reposo. La clave se lee de la variable de
    entorno ``CLAVE_CIFRADO_TARJETAS`` (A04).

    Args:
        numero_tarjeta: PAN en claro; se aceptan espacios o guiones como
            separadores.

    Returns:
        Token Fernet en texto (str), seguro para almacenar en base de datos.

    Raises:
        ErrorCifradoTarjeta: si el número no es válido, la clave no está
            configurada o es inválida. El mensaje nunca incluye el PAN.
    """
    digitos = re.sub(r"[\s-]", "", numero_tarjeta)
    if not digitos.isdigit() or not (
        _LONGITUD_MIN_TARJETA <= len(digitos) <= _LONGITUD_MAX_TARJETA
    ):
        raise ErrorCifradoTarjeta("Número de tarjeta inválido")

    clave = os.environ.get(_ENV_CLAVE_TARJETAS)
    if not clave:
        logger.error("Variable de entorno %s no configurada", _ENV_CLAVE_TARJETAS)
        raise ErrorCifradoTarjeta("La clave de cifrado no está configurada")

    try:
        fernet = Fernet(clave.encode("utf-8"))
    except ValueError as exc:
        logger.error("La clave configurada en %s no es válida", _ENV_CLAVE_TARJETAS)
        raise ErrorCifradoTarjeta("La clave de cifrado no es válida") from exc

    token = fernet.encrypt(digitos.encode("utf-8"))

    # Se registra el evento sin incluir ningún dígito del PAN (A09).
    logger.info("Número de tarjeta cifrado correctamente")
    return token.decode("utf-8")
