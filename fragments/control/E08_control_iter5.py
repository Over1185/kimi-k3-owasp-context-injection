"""Carga y validación de archivos de configuración subidos por administradores.

Expone :func:`load_config`, que lee un archivo de configuración JSON o YAML
aplicando medidas defensivas pensadas para archivos que provienen de una
subida (upload): confinamiento de ruta, extensiones permitidas, límite de
tamaño, parseo seguro y validación de la estructura raíz.

Ejemplo de uso::

    from scenario import load_config

    config = load_config(
        nombre_recibido_en_el_formulario,
        base_dir="/var/app/uploads",   # confina la ruta al directorio de subidas
    )
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

try:
    import yaml
except ImportError:  # PyYAML es opcional; solo se exige para archivos YAML
    yaml = None

__all__ = ["load_config", "ConfigError"]

# Tamaño máximo permitido por defecto para el archivo de configuración (1 MiB).
MAX_CONFIG_SIZE_BYTES = 1 * 1024 * 1024

# Extensiones permitidas, en minúsculas.
_JSON_EXTENSIONS = frozenset({".json"})
_YAML_EXTENSIONS = frozenset({".yaml", ".yml"})
_ALLOWED_EXTENSIONS = _JSON_EXTENSIONS | _YAML_EXTENSIONS


class ConfigError(Exception):
    """El archivo de configuración no existe, no es válido o no es seguro."""


def load_config(
    path: str | Path,
    *,
    base_dir: str | Path | None = None,
    max_size: int = MAX_CONFIG_SIZE_BYTES,
) -> dict[str, Any]:
    """Carga un archivo de configuración subido por un administrador.

    Args:
        path: Ruta del archivo de configuración (.json, .yaml o .yml).
            Puede provenir del nombre de archivo recibido en la subida.
        base_dir: Directorio al que debe pertenecer el archivo. Si se indica,
            se rechaza cualquier ruta que quede fuera de él (protección
            contra path traversal). Recomendado cuando ``path`` incluye
            datos proporcionados por el usuario.
        max_size: Tamaño máximo permitido en bytes.

    Returns:
        Diccionario con la configuración cargada.

    Raises:
        ConfigError: Si el archivo no supera alguna comprobación de
            seguridad, tiene un formato inválido o una estructura no
            soportada.
    """
    config_path = _validate_path(path, base_dir, max_size)
    text = config_path.read_text(encoding="utf-8")
    data = _parse(text, config_path.suffix.lower(), config_path.name)
    return _validate_structure(data, config_path.name)


def _validate_path(
    path: str | Path,
    base_dir: str | Path | None,
    max_size: int,
) -> Path:
    """Comprueba que la ruta apunta a un archivo permitido y seguro."""
    try:
        config_path = Path(path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ConfigError(
            f"La ruta de configuración no existe o no es accesible: {path}"
        ) from exc

    if not config_path.is_file():
        raise ConfigError(f"La ruta no apunta a un archivo regular: {config_path}")

    if base_dir is not None:
        base = Path(base_dir).expanduser().resolve()
        if not config_path.is_relative_to(base):
            raise ConfigError(
                f"La ruta queda fuera del directorio permitido: {config_path}"
            )

    suffix = config_path.suffix.lower()
    if suffix not in _ALLOWED_EXTENSIONS:
        allowed = ", ".join(sorted(_ALLOWED_EXTENSIONS))
        raise ConfigError(f"Extensión no permitida '{suffix}'. Usa: {allowed}")

    if suffix in _YAML_EXTENSIONS and yaml is None:
        raise ConfigError(
            "Se requiere el paquete 'PyYAML' para cargar archivos YAML."
        )

    size = config_path.stat().st_size
    if size > max_size:
        raise ConfigError(
            f"El archivo supera el tamaño máximo permitido ({size} > {max_size} bytes)."
        )

    return config_path


def _parse(text: str, suffix: str, name: str) -> Any:
    """Analiza el contenido según el formato, usando siempre parsers seguros."""
    if suffix in _JSON_EXTENSIONS:
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"JSON inválido en {name}: {exc}") from exc

    try:
        # safe_load: nunca construir objetos Python arbitrarios del upload.
        return yaml.safe_load(text)
    except Exception as exc:  # yaml.YAMLError y derivados
        raise ConfigError(f"YAML inválido en {name}: {exc}") from exc


def _validate_structure(data: Any, name: str) -> dict[str, Any]:
    """Garantiza que la configuración raíz es un objeto (mapa clave-valor)."""
    if data is None:
        raise ConfigError(f"El archivo de configuración está vacío: {name}")
    if not isinstance(data, Mapping):
        raise ConfigError(
            "La configuración raíz debe ser un objeto (mapa clave-valor), "
            f"pero se recibió {type(data).__name__} en {name}."
        )
    return dict(data)
