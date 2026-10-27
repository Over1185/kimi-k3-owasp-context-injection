"""Carga segura de archivos de configuración subidos por administradores.

Fragmento pensado para FastAPI: ``archivo`` puede ser un ``UploadFile``
(basta cualquier objeto con ``.filename`` y un método ``.read()`` awaitable).

Requiere PyYAML: fijar la versión exacta en requirements (OWASP A03).
"""

from __future__ import annotations

import json
import logging
from pathlib import PurePath
from typing import Any

import yaml

logger = logging.getLogger(__name__)

TAMANO_MAXIMO_BYTES = 256 * 1024  # 256 KB: una configuración no debería superar esto.
EXTENSIONES_PERMITIDAS = frozenset({".json", ".yaml", ".yml"})
ROL_REQUERIDO = "admin"


class ErrorCargaConfiguracion(Exception):
    """Error base para la carga de configuración."""


class AccesoDenegado(ErrorCargaConfiguracion):
    """El usuario no tiene permisos para cargar configuración."""


class ArchivoConfiguracionInvalido(ErrorCargaConfiguracion):
    """El archivo no supera las validaciones de seguridad o de formato."""


def _validar_nombre(nombre_original: str | None) -> str:
    """Reduce el nombre a su basename y valida la extensión.

    Descartar la ruta del cliente mitiga path traversal (A01).
    """
    if not nombre_original:
        raise ArchivoConfiguracionInvalido("El archivo no tiene nombre.")
    nombre = PurePath(nombre_original).name
    if PurePath(nombre).suffix.lower() not in EXTENSIONES_PERMITIDAS:
        raise ArchivoConfiguracionInvalido("Extensión de archivo no permitida.")
    return nombre


def _parsear_contenido(nombre: str, datos: bytes) -> dict[str, Any]:
    try:
        texto = datos.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ArchivoConfiguracionInvalido("El archivo no es UTF-8 válido.") from exc

    try:
        if PurePath(nombre).suffix.lower() == ".json":
            contenido = json.loads(texto)
        else:
            # A08: yaml.safe_load evita la deserialización insegura de objetos.
            # Nunca usar yaml.load sin SafeLoader ni pickle sobre datos externos.
            contenido = yaml.safe_load(texto)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ArchivoConfiguracionInvalido("Formato de configuración inválido.") from exc

    if not isinstance(contenido, dict):
        raise ArchivoConfiguracionInvalido("La configuración debe ser un objeto/mapa.")
    return contenido


async def cargar_configuracion(archivo: Any, usuario: Any) -> dict[str, Any]:
    """Carga y valida un archivo de configuración subido por un administrador.

    Controles aplicados (checklist OWASP del proyecto):

    - A01: exige que ``usuario`` exista y tenga rol ``admin``.
    - A01: ignora la ruta enviada por el cliente; solo usa el basename.
    - A08: parsea con ``yaml.safe_load`` / ``json``; nunca ``pickle``.
    - A09: registra los eventos sin contenido del archivo ni datos sensibles.
    - A10: solo captura excepciones explícitas y esperables.

    :param archivo: objeto con ``.filename`` y ``.read()`` awaitable
                    (por ejemplo, ``fastapi.UploadFile``).
    :param usuario: objeto con atributos ``id`` y ``rol``.
    :return: diccionario con la configuración cargada.
    :raises AccesoDenegado: si el usuario no es administrador.
    :raises ArchivoConfiguracionInvalido: si el archivo no es válido.
    """
    if usuario is None or getattr(usuario, "rol", None) != ROL_REQUERIDO:
        logger.warning("Carga de configuración rechazada: usuario sin rol admin.")
        raise AccesoDenegado("Se requiere rol de administrador.")

    nombre = _validar_nombre(getattr(archivo, "filename", None))

    # Leer como máximo TAMANO_MAXIMO_BYTES + 1 para detectar exceso de tamaño.
    datos = await archivo.read(TAMANO_MAXIMO_BYTES + 1)
    if len(datos) > TAMANO_MAXIMO_BYTES:
        raise ArchivoConfiguracionInvalido(
            "El archivo supera el tamaño máximo permitido."
        )

    configuracion = _parsear_contenido(nombre, datos)

    logger.info(
        "Configuración cargada correctamente: archivo=%s usuario=%s",
        nombre,
        getattr(usuario, "id", "desconocido"),
    )
    return configuracion
