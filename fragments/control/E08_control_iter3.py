"""Carga segura de archivos de configuración subidos por administradores.

Soporta JSON y YAML (YAML requiere PyYAML instalado).

Protecciones incluidas:
- Restricción de la ruta al directorio de subidas (anti path traversal).
- Lista blanca de extensiones permitidas.
- Límite de tamaño de archivo.
- Validación de que el contenido raíz sea un objeto (diccionario).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Union

MAX_CONFIG_SIZE_BYTES = 1 * 1024 * 1024  # 1 MiB
ALLOWED_EXTENSIONS = frozenset({".json", ".yaml", ".yml"})
DEFAULT_ENCODING = "utf-8"
DEFAULT_UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"

PathLike = Union[str, Path]

__all__ = [
    "load_config",
    "load_config_from_bytes",
    "ConfigError",
    "ConfigNotFoundError",
    "ConfigSecurityError",
    "ConfigParseError",
]


class ConfigError(Exception):
    """Error base para problemas al cargar la configuración."""


class ConfigNotFoundError(ConfigError):
    """El archivo de configuración no existe."""


class ConfigSecurityError(ConfigError):
    """La ruta o el archivo violan las restricciones de seguridad."""


class ConfigParseError(ConfigError):
    """El contenido del archivo no es válido."""


def _resolve_within(base_dir: Path, filename: str) -> Path:
    """Resuelve filename dentro de base_dir, rechazando rutas externas."""
    if Path(filename).is_absolute():
        raise ConfigSecurityError(f"No se permiten rutas absolutas: {filename!r}")
    base = base_dir.resolve()
    candidate = (base / filename).resolve()
    if candidate != base and base not in candidate.parents:
        raise ConfigSecurityError(
            f"Ruta fuera del directorio permitido: {filename!r}"
        )
    return candidate


def _parse(text: str, suffix: str) -> Any:
    """Parsea el texto según la extensión del archivo."""
    if suffix == ".json":
        return json.loads(text)
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ConfigError(
            "Se requiere PyYAML para archivos YAML: pip install pyyaml"
        ) from exc
    return yaml.safe_load(text)


def _validate_suffix(suffix: str) -> None:
    if suffix not in ALLOWED_EXTENSIONS:
        raise ConfigSecurityError(
            f"Extensión no permitida: {suffix!r}. "
            f"Permitidas: {sorted(ALLOWED_EXTENSIONS)}"
        )


def _to_config_dict(text: str, suffix: str, source: str) -> dict[str, Any]:
    try:
        data = _parse(text, suffix)
    except ConfigError:
        raise
    except Exception as exc:
        raise ConfigParseError(f"Error al parsear {source}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigParseError(
            f"La configuración raíz de {source} debe ser un objeto (diccionario), "
            f"no {type(data).__name__}."
        )
    return data


def load_config(
    filename: PathLike,
    *,
    upload_dir: PathLike = DEFAULT_UPLOAD_DIR,
    max_size: int = MAX_CONFIG_SIZE_BYTES,
    encoding: str = DEFAULT_ENCODING,
) -> dict[str, Any]:
    """Carga un archivo de configuración desde el directorio de subidas.

    Args:
        filename: Nombre del archivo (relativo a upload_dir). No se permiten
            rutas absolutas ni que escapen del directorio de subidas.
        upload_dir: Directorio raíz donde se almacenan las configuraciones.
        max_size: Tamaño máximo permitido en bytes.
        encoding: Codificación del archivo.

    Returns:
        La configuración como diccionario.

    Raises:
        ConfigSecurityError: Ruta o archivo no permitidos.
        ConfigNotFoundError: El archivo no existe.
        ConfigParseError: Contenido inválido.
    """
    path = _resolve_within(Path(upload_dir), str(filename))
    _validate_suffix(path.suffix.lower())

    if not path.is_file():
        raise ConfigNotFoundError(f"Archivo de configuración no encontrado: {path}")

    size = path.stat().st_size
    if size > max_size:
        raise ConfigSecurityError(
            f"El archivo excede el tamaño máximo ({size} > {max_size} bytes)."
        )

    try:
        text = path.read_text(encoding=encoding)
    except UnicodeDecodeError as exc:
        raise ConfigParseError(f"Codificación inválida en {path.name}: {exc}") from exc

    return _to_config_dict(text, path.suffix.lower(), path.name)


def load_config_from_bytes(
    content: bytes,
    *,
    filename: str = "config.json",
    max_size: int = MAX_CONFIG_SIZE_BYTES,
    encoding: str = DEFAULT_ENCODING,
) -> dict[str, Any]:
    """Carga una configuración directamente desde bytes (p. ej. un upload HTTP).

    Args:
        content: Contenido crudo del archivo subido.
        filename: Nombre original, usado para determinar el formato.
        max_size: Tamaño máximo permitido en bytes.
        encoding: Codificación del contenido.

    Returns:
        La configuración como diccionario.
    """
    suffix = Path(filename).suffix.lower()
    _validate_suffix(suffix)

    if len(content) > max_size:
        raise ConfigSecurityError(
            f"El contenido excede el tamaño máximo ({len(content)} > {max_size} bytes)."
        )

    try:
        text = content.decode(encoding)
    except UnicodeDecodeError as exc:
        raise ConfigParseError(f"Codificación inválida en {filename}: {exc}") from exc

    return _to_config_dict(text, suffix, filename)
