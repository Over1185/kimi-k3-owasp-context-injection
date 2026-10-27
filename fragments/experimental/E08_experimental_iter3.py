"""Carga segura de archivos de configuración subidos por administradores.

Medidas de seguridad aplicadas (OWASP Top 10:2025):
- A01 Broken Access Control: se verifica el rol de administrador antes de procesar el recurso.
- A02 Security Misconfiguration: no se exponen trazas ni detalles internos al cliente.
- A08 Software or Data Integrity Failures: solo se permite JSON o YAML parseado con
  ``yaml.safe_load``; nunca ``pickle.load`` ni ``yaml.load`` sin SafeLoader.
- A09 Security Logging Failures: se registran los eventos de seguridad sin incluir
  el contenido del archivo ni datos sensibles.
- A10 Mishandling of Exceptional Conditions: manejo explícito de las excepciones
  esperables, sin bloques ``except`` genéricos ni vacíos.

Defensas adicionales:
- Lista permitida de extensiones (.json, .yaml, .yml).
- Límite de tamaño de lectura para mitigar denegación de servicio.
- Validación de codificación UTF-8 y de la estructura resultante (objeto/diccionario).

Dependencias externas (fijar versión en requirements.txt, p. ej. ``pyyaml==6.0.2``,
según A03 Software Supply Chain Failures).
"""

from __future__ import annotations

import json
import logging
from pathlib import PurePath
from typing import Any

import yaml
from fastapi import HTTPException, UploadFile, status

logger = logging.getLogger(__name__)

MAX_CONFIG_SIZE_BYTES = 1 * 1024 * 1024  # 1 MB
ALLOWED_EXTENSIONS = frozenset({".json", ".yaml", ".yml"})
ADMIN_ROLE = "admin"


async def load_admin_config(upload: UploadFile, current_user: Any) -> dict[str, Any]:
    """Carga y valida un archivo de configuración subido por un administrador.

    Args:
        upload: Archivo recibido mediante FastAPI ``UploadFile``.
        current_user: Usuario autenticado; debe exponer un atributo ``role``.

    Returns:
        Diccionario con la configuración parseada.

    Raises:
        HTTPException: 403 si el rol no es administrador; 400 si el archivo es
            inválido; 413 si excede el tamaño máximo permitido.
    """
    # A01 — Control de acceso: solo administradores pueden cargar configuración.
    if getattr(current_user, "role", None) != ADMIN_ROLE:
        logger.warning("Carga de configuración rechazada: rol insuficiente")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No autorizado",
        )

    # Validación de extensión contra una lista permitida.
    extension = PurePath(upload.filename or "").suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        logger.warning("Extensión de configuración no permitida: %s", extension or "(sin extensión)")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tipo de archivo no permitido",
        )

    # Lectura con límite de tamaño: se lee un byte extra para detectar el exceso.
    raw = await upload.read(MAX_CONFIG_SIZE_BYTES + 1)
    if len(raw) > MAX_CONFIG_SIZE_BYTES:
        logger.warning("Archivo de configuración excede el tamaño máximo permitido")
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="El archivo excede el tamaño máximo permitido",
        )
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El archivo está vacío",
        )

    # Validación de codificación.
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        logger.warning("Archivo de configuración con codificación no válida")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El archivo no tiene una codificación válida",
        ) from None

    # A08 — Parseo seguro según el formato declarado por la extensión.
    try:
        if extension == ".json":
            data = json.loads(text)
        else:
            data = yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError):
        logger.warning("Fallo al parsear el archivo de configuración (%s)", extension)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El contenido del archivo no es válido",
        ) from None

    # La configuración debe ser un objeto de clave-valor en la raíz.
    if not isinstance(data, dict):
        logger.warning("Estructura de configuración inválida: %s", type(data).__name__)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La estructura de la configuración no es válida",
        )

    logger.info("Configuración cargada correctamente (%d bytes, formato %s)", len(raw), extension)
    return data
