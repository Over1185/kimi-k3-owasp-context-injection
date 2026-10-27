"""Carga segura de archivos de configuración subidos por administradores.

Directrices aplicadas (OWASP Top 10:2025, ver .github/skills/owasp-mitigacion):
- A01 Broken Access Control: solo usuarios con rol 'admin' pueden cargar.
- A02 Security Misconfiguration: mensajes de error genéricos hacia el cliente.
- A08 Software/Data Integrity: yaml.safe_load; jamás pickle ni yaml.load.
- A09 Security Logging: eventos registrados sin datos sensibles ni contenido del archivo.
- A10 Exceptional Conditions: excepciones explícitas, sin except genéricos ni vacíos.
"""

from __future__ import annotations

import logging
import os
from typing import Annotated, Any

import yaml
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError

logger = logging.getLogger(__name__)

# Límite de tamaño para evitar consumo excesivo de memoria (diseño seguro, A06).
MAX_CONFIG_BYTES = 256 * 1024  # 256 KiB
ALLOWED_EXTENSIONS = frozenset({".yaml", ".yml"})

router = APIRouter(prefix="/admin", tags=["configuracion"])


class AppConfig(BaseModel):
    """Esquema de lista blanca para la configuración aceptada."""

    model_config = ConfigDict(extra="forbid")

    allowed_hosts: list[str] = Field(default_factory=list, max_length=50)
    max_upload_mb: int = Field(default=10, ge=1, le=1024)
    feature_flags: dict[str, bool] = Field(default_factory=dict)


def require_admin(request: Request) -> None:
    """Deniega por defecto salvo que el usuario autenticado sea administrador (A01)."""
    user = getattr(request.state, "user", None)
    role = getattr(user, "role", None)
    if role != "admin":
        logger.warning("Carga de configuración rechazada: rol insuficiente o ausente")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requiere rol de administrador.",
        )


def parse_config(raw: bytes) -> AppConfig:
    """Decodifica, deserializa de forma segura y valida la configuración.

    Raises:
        HTTPException: 400 si la codificación o el YAML son inválidos,
            422 si el contenido no cumple el esquema permitido.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El archivo debe estar codificado en UTF-8.",
        ) from None

    try:
        # A08: safe_load impide la construcción de objetos Python arbitrarios.
        data: Any = yaml.safe_load(text)
    except yaml.YAMLError:
        logger.warning("Archivo de configuración con YAML inválido")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El contenido no es YAML válido.",
        ) from None

    if not isinstance(data, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La configuración debe ser un objeto YAML de nivel superior.",
        )

    try:
        return AppConfig.model_validate(data)
    except ValidationError as exc:
        # No exponer detalles del esquema ni valores enviados por el usuario (A02/A09).
        logger.warning(
            "Configuración rechazada: %d errores de validación", len(exc.errors())
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="La configuración no cumple el esquema permitido.",
        ) from None


@router.post("/config", response_model=AppConfig)
async def load_config_file(
    config_file: Annotated[UploadFile, File(...)],
    _: Annotated[None, Depends(require_admin)],
) -> AppConfig:
    """Carga un archivo de configuración YAML subido por un administrador."""
    filename = config_file.filename or ""
    extension = os.path.splitext(filename)[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        logger.warning("Extensión de archivo de configuración no permitida")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Solo se permiten archivos .yaml o .yml.",
        )

    # Se lee como máximo MAX_CONFIG_BYTES + 1 para detectar exceso sin
    # cargar un archivo de tamaño ilimitado en memoria.
    raw = await config_file.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        logger.warning("Archivo de configuración excede el tamaño máximo permitido")
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="El archivo supera el tamaño máximo permitido.",
        )

    config = parse_config(raw)
    logger.info("Configuración cargada correctamente (%d bytes)", len(raw))
    return config
