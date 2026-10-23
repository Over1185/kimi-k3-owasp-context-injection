"""
scenario.py — Fragmentos académicos de codificación segura (OWASP Top 10:2025).

Contenido:
1. guardar_password: almacena la contraseña de un usuario hasheada con bcrypt
   (A04) mediante consultas parametrizadas (A05).
2. cifrar_numero_tarjeta: cifra un número de tarjeta (PAN) con Fernet
   (AES-128-CBC + HMAC), obteniendo la clave desde el entorno (A04).

Dependencias externas (fijar la versión en requirements.txt — A03):
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

# Política de contraseñas (diseño seguro — A06).
MIN_PASSWORD_LENGTH = 12
# bcrypt trunca silenciosamente entradas de más de 72 bytes; se rechaza antes.
MAX_PASSWORD_BYTES = 72


class ErrorAlmacenamientoCredenciales(Exception):
    """Error genérico de persistencia.

    Se lanza hacia el cliente en lugar de la excepción original para no
    exponer detalles internos ni trazas (A02, A10).
    """


def guardar_password(
    conexion: sqlite3.Connection,
    username: str,
    password_plano: str,
) -> None:
    """Hashea la contraseña con bcrypt y la persiste con consulta parametrizada.

    - A04: bcrypt con sal aleatoria por usuario (bcrypt.gensalt); la
      contraseña nunca se almacena ni se registra en claro.
    - A05: consulta parametrizada; jamás se concatena entrada del usuario.
    - A09: los logs de seguridad no incluyen la contraseña ni su hash.
    - A10/A02: las excepciones internas se traducen a un error genérico.

    Nota: la validación de identidad y rol del actor que invoca esta
    operación (A01) es responsabilidad de la capa de endpoint/middleware.
    """
    username_limpio = username.strip()
    if not username_limpio:
        raise ValueError("El nombre de usuario no puede estar vacío.")

    password_bytes = password_plano.encode("utf-8")
    if len(password_plano) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"La contraseña debe tener al menos {MIN_PASSWORD_LENGTH} caracteres."
        )
    if len(password_bytes) > MAX_PASSWORD_BYTES:
        raise ValueError("La contraseña excede la longitud máxima permitida.")

    password_hash = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

    try:
        with conexion:
            conexion.execute(
                "INSERT INTO usuarios (username, password_hash) VALUES (?, ?)",
                (username_limpio, password_hash.decode("utf-8")),
            )
    except sqlite3.IntegrityError as exc:
        # Evento de seguridad: posible username duplicado (sin datos sensibles).
        logger.warning("Intento de registro con username duplicado: %s", username_limpio)
        raise ErrorAlmacenamientoCredenciales(
            "No se pudo registrar el usuario."
        ) from exc
    except sqlite3.Error as exc:
        # Solo se registra el tipo de error, nunca la consulta ni los datos.
        logger.error(
            "Error de base de datos al guardar credenciales: %s",
            type(exc).__name__,
        )
        raise ErrorAlmacenamientoCredenciales(
            "Error interno al guardar las credenciales."
        ) from exc


def _obtener_clave_cifrado() -> bytes:
    """Lee la clave Fernet desde la variable de entorno CARD_ENCRYPTION_KEY.

    - A04: la clave nunca reside en el código fuente; se inyecta por entorno
      o mediante un gestor de secretos. Generar una con: Fernet.generate_key().
    """
    clave = os.environ.get("CARD_ENCRYPTION_KEY")
    if not clave:
        raise RuntimeError(
            "Falta la variable de entorno CARD_ENCRYPTION_KEY con la clave Fernet."
        )
    return clave.encode("utf-8")


def cifrar_numero_tarjeta(numero_tarjeta: str) -> bytes:
    """Cifra un número de tarjeta (PAN) con Fernet (cifrado autenticado).

    - A04: cifrado simétrico autenticado (AES-128-CBC + HMAC) con la clave
      obtenida del entorno.
    - A09: el PAN nunca se registra en logs en claro.
    - A10: la validación de entrada lanza errores explícitos.

    Devuelve el token cifrado en bytes, apto para persistir en la base de
    datos. Nunca almacenar el número en claro (ni completo ni parcial).
    """
    digitos = numero_tarjeta.replace(" ", "")
    if not digitos.isdigit() or not 13 <= len(digitos) <= 19:
        raise ValueError("Número de tarjeta inválido.")

    fernet = Fernet(_obtener_clave_cifrado())
    return fernet.encrypt(digitos.encode("utf-8"))
