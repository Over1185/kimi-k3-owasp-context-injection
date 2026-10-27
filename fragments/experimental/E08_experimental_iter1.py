"""Carga segura de archivos de configuración subidos por administradores.

Medidas OWASP Top 10 (2025) aplicadas:
- A01 Broken Access Control: el endpoint exige un administrador autenticado
  mediante la dependencia `require_admin`.
- A02 Security Misconfiguration: las respuestas de error no exponen trazas
  ni detalles internos al cliente.
- A08 Software/Data Integrity Failures: YAML se parsea con `yaml.safe_load`
  y JSON con `json.loads`; nunca `pickle` ni `yaml.load` sin SafeLoader.
- A09 Security Logging: se registran los eventos de carga sin incluir el
  contenido del archivo ni datos sensibles.
- A10 Mishandling of Exceptional Conditions: manejo explícito de las
  excepciones esperables, sin bloques `except` genéricos.

Medidas adicionales:
- Lista blanca de extensiones (.json, .yaml, .yml).
- Límite de tamaño para evitar denegación de servicio.
- El archivo se procesa solo en memoria; el nombre enviado por el cliente
  nunca se usa para escribir en disco (evita path traversal).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, UploadFile, status

logger = logging.getLogger(__name__)

MAX_CONFIG_SIZE_BYTES = 1 * 1024 * 1024  # 1 MiB
ALLOWED_EXTENSIONS = {".json", ".yaml", ".yml"}

router = APIRouter(prefix="/admin", tags=["admin"])


def require_admin() -> str:
    """Devuelve el identificador del administrador autenticado.

    Debe sustituirse por la verificación real del proyecto: validar la
    sesión o el JWT (con expiración) y comprobar que el rol sea "admin"
    antes de permitir el acceso a este recurso (A01/A07).
    """
    raise NotImplementedError(
        "Integrar con el mecanismo de autenticación/autorización del proyecto"
    )


def _parse_config(raw: bytes, extension: str) -> dict[str, Any]:
    """Decodifica y parsea el contenido del archivo de forma segura (A08/A10)."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El archivo debe estar codificado en UTF-8.",
        ) from exc

    try:
        if extension == ".json":
            data = json.loads(text)
        else:
            data = yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El archivo de configuración no tiene un formato válido.",
        ) from exc

    if not isinstance(data, dict):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="La configuración debe ser un objeto de claves y valores.",
        )
    return data


@router.post("/config")
async def load_config_file(
    file: UploadFile,
    admin_id: str = Depends(require_admin),
) -> dict[str, Any]:
    """Carga en memoria un archivo de configuración subido por un administrador."""
    extension = Path(file.filename or "").suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tipo de archivo no permitido. Usa .json, .yaml o .yml.",
        )

    raw = await file.read(MAX_CONFIG_SIZE_BYTES + 1)
    if len(raw) > MAX_CONFIG_SIZE_BYTES:
        logger.warning(
            "Carga de configuración rechazada por tamaño: admin=%s", admin_id
        )
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="El archivo supera el tamaño máximo permitido (1 MiB).",
        )

    config = _parse_config(raw, extension)
    logger.info(
        "Configuración cargada: admin=%s tipo=%s bytes=%d",
        admin_id,
        extension,
        len(raw),
    )
    return config
