"""
Utilidades de seguridad para credenciales y datos de pago.

Decisiones de seguridad (OWASP Top 10:2025):
- A04: las contrasenas se almacenan con bcrypt (sal automatica por hash),
  nunca en texto plano ni con MD5/SHA1/SHA256 sin salteo.
- A04: la clave de cifrado de tarjetas se lee de la variable de entorno
  CARD_ENCRYPTION_KEY (formato Fernet); nunca se define en el codigo fuente.
- A05: las consultas SQL usan parametros ligados (SQLAlchemy text()).
- A09: los eventos de seguridad se registran sin exponer contrasenas ni
  numeros de tarjeta (PAN) en los logs.
- A10: solo se capturan excepciones esperables y se relanzan como errores
  de dominio; no hay bloques except genericos ni vacios.

Dependencias (fijar la version al instalarlas, por ejemplo):
    bcrypt==4.2.1
    cryptography==43.0.3
    SQLAlchemy==2.0.36
"""

import logging
import os
import re

import bcrypt
from cryptography.fernet import Fernet
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

MIN_PASSWORD_LENGTH = 12
_CARD_KEY_ENV_VAR = "CARD_ENCRYPTION_KEY"
_CARD_NUMBER_PATTERN = re.compile(r"\d{12,19}")


class PasswordStorageError(Exception):
    """Error al guardar la contrasena de un usuario."""


class CardEncryptionError(Exception):
    """Error al cifrar un numero de tarjeta."""


def save_user_password(db: Session, username: str, plain_password: str) -> None:
    """Hashea la contrasena con bcrypt y la guarda en la base de datos.

    Solo se persiste el hash (con sal); la contrasena en texto plano nunca
    se almacena ni se registra en logs.
    """
    if not username or not username.strip():
        raise ValueError("El nombre de usuario no puede estar vacio.")
    if len(plain_password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"La contrasena debe tener al menos {MIN_PASSWORD_LENGTH} caracteres."
        )

    password_hash = bcrypt.hashpw(
        plain_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    try:
        db.execute(
            text(
                "INSERT INTO users (username, password_hash) "
                "VALUES (:username, :password_hash)"
            ),
            {"username": username, "password_hash": password_hash},
        )
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        logger.warning(
            "Fallo al guardar la contrasena del usuario '%s' (%s).",
            username,
            type(exc).__name__,
        )
        raise PasswordStorageError(
            "No se pudo guardar la contrasena del usuario."
        ) from exc

    logger.info("Contrasena almacenada correctamente para el usuario '%s'.", username)


def encrypt_card_number(card_number: str) -> str:
    """Cifra un numero de tarjeta (PAN) con Fernet (AES-128-CBC + HMAC).

    La clave simetrica se obtiene de la variable de entorno
    CARD_ENCRYPTION_KEY. El PAN en texto plano nunca se registra en logs.
    """
    if not _CARD_NUMBER_PATTERN.fullmatch(card_number):
        raise ValueError(
            "El numero de tarjeta debe contener entre 12 y 19 digitos."
        )

    key = os.environ.get(_CARD_KEY_ENV_VAR)
    if not key:
        logger.error(
            "Variable de entorno %s no configurada.", _CARD_KEY_ENV_VAR
        )
        raise CardEncryptionError(
            f"La clave de cifrado no esta configurada ({_CARD_KEY_ENV_VAR})."
        )

    try:
        fernet = Fernet(key.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        logger.error("La clave configurada no es una clave Fernet valida.")
        raise CardEncryptionError(
            "La clave de cifrado configurada no es valida."
        ) from exc

    return fernet.encrypt(card_number.encode("utf-8")).decode("utf-8")
