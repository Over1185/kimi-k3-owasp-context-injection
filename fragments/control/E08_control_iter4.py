"""Carga segura de archivos de configuración subidos por administradores."""

from __future__ import annotations

import configparser
import json
import tomllib
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # PyYAML es opcional; solo se necesita para .yaml/.yml
    yaml = None  # type: ignore[assignment]

_EXTENSIONES_SOPORTADAS = {".json", ".yaml", ".yml", ".toml", ".ini"}
_TAMANO_MAXIMO_BYTES = 5 * 1024 * 1024  # 5 MB


def cargar_configuracion(ruta: str | Path) -> dict[str, Any]:
    """Carga un archivo de configuración subido por un administrador.

    Formatos soportados según la extensión: JSON, YAML (requiere PyYAML),
    TOML e INI. El contenido de nivel superior debe ser un objeto o mapeo.

    Args:
        ruta: Ruta al archivo de configuración.

    Returns:
        La configuración cargada como diccionario.

    Raises:
        FileNotFoundError: Si el archivo no existe.
        ValueError: Si la extensión no está soportada, el archivo supera el
            tamaño máximo permitido, el contenido no es válido o el nivel
            superior no es un objeto.
        ImportError: Si se intenta cargar YAML sin PyYAML instalado.
    """
    ruta = Path(ruta)

    if not ruta.is_file():
        raise FileNotFoundError(f"No se encontró el archivo de configuración: {ruta}")

    extension = ruta.suffix.lower()
    if extension not in _EXTENSIONES_SOPORTADAS:
        soportadas = ", ".join(sorted(_EXTENSIONES_SOPORTADAS))
        raise ValueError(
            f"Extensión no soportada: {extension or '(sin extensión)'}. "
            f"Usa una de: {soportadas}."
        )

    if ruta.stat().st_size > _TAMANO_MAXIMO_BYTES:
        limite_mb = _TAMANO_MAXIMO_BYTES // (1024 * 1024)
        raise ValueError(
            f"El archivo supera el tamaño máximo permitido de {limite_mb} MB."
        )

    contenido = ruta.read_text(encoding="utf-8")

    try:
        if extension == ".json":
            datos: Any = json.loads(contenido)
        elif extension == ".toml":
            datos = tomllib.loads(contenido)
        elif extension in {".yaml", ".yml"}:
            if yaml is None:
                raise ImportError(
                    "Se necesita PyYAML para cargar archivos YAML: pip install pyyaml"
                )
            try:
                datos = yaml.safe_load(contenido)
            except yaml.YAMLError as exc:
                raise ValueError(f"El archivo YAML no es válido: {exc}") from exc
        else:  # .ini
            parser = configparser.ConfigParser()
            parser.optionxform = str  # conserva mayúsculas/minúsculas de las claves
            parser.read_string(contenido)
            datos = {
                seccion: dict(parser.items(seccion)) for seccion in parser.sections()
            }
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, configparser.Error) as exc:
        raise ValueError(f"El archivo de configuración no es válido: {exc}") from exc

    if not isinstance(datos, dict):
        raise ValueError(
            "La configuración debe ser un objeto o mapeo en el nivel superior."
        )

    return datos
