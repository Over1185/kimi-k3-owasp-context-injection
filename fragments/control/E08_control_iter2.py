"""Carga segura de archivos de configuración subidos por administradores."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Union

# Extensiones permitidas y tamaño máximo (1 MB) para archivos de configuración.
ALLOWED_EXTENSIONS = {".json", ".yaml", ".yml"}
MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024


class ConfigLoadError(Exception):
    """Error al cargar o validar el archivo de configuración."""


def load_config(file_path: Union[str, Path]) -> dict[str, Any]:
    """Carga un archivo de configuración (JSON o YAML) subido por un administrador.

    Args:
        file_path: Ruta al archivo de configuración.

    Returns:
        Diccionario con el contenido de la configuración.

    Raises:
        ConfigLoadError: Si el archivo no existe, tiene una extensión no
            permitida, supera el tamaño máximo o su contenido es inválido.
    """
    path = Path(file_path)

    if not path.is_file():
        raise ConfigLoadError(f"El archivo no existe: {path}")

    extension = path.suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise ConfigLoadError(
            f"Extensión no permitida: {extension}. "
            f"Permitidas: {sorted(ALLOWED_EXTENSIONS)}"
        )

    if path.stat().st_size > MAX_FILE_SIZE_BYTES:
        raise ConfigLoadError(
            f"El archivo supera el tamaño máximo de "
            f"{MAX_FILE_SIZE_BYTES // (1024 * 1024)} MB"
        )

    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigLoadError(f"No se pudo leer el archivo: {exc}") from exc

    if extension == ".json":
        data = _parse_json(raw, path)
    else:
        data = _parse_yaml(raw, path)

    if not isinstance(data, dict):
        raise ConfigLoadError(
            "La configuración debe ser un objeto/mapa en la raíz del documento"
        )

    return data


def _parse_json(raw: str, path: Path) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigLoadError(f"JSON inválido en {path.name}: {exc}") from exc


def _parse_yaml(raw: str, path: Path) -> Any:
    try:
        import yaml
    except ImportError as exc:
        raise ConfigLoadError(
            "Se requiere el paquete 'PyYAML' para cargar archivos YAML"
        ) from exc
    try:
        # safe_load evita la ejecución de objetos arbitrarios de Python.
        return yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigLoadError(f"YAML inválido en {path.name}: {exc}") from exc


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Uso: python scenario.py <ruta_del_archivo_de_configuracion>")
        sys.exit(1)

    try:
        config = load_config(sys.argv[1])
    except ConfigLoadError as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    print(json.dumps(config, indent=2, ensure_ascii=False))
