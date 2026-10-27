"""Carga de archivos de configuración subidos por administradores.

Expone una única función pública, :func:`cargar_configuracion`, pensada para
procesar de forma segura archivos de configuración (JSON o YAML) proporcionados
por usuarios administradores.

Medidas de seguridad aplicadas:
- Solo se aceptan extensiones .json, .yaml e .yml.
- El archivo debe residir dentro de un directorio permitido (anti path traversal).
- Se limita el tamaño máximo del archivo.
- YAML se parsea con safe_load (sin ejecución de objetos arbitrarios).
- El resultado debe ser un objeto/mapping en la raíz.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Union

PathLike = Union[str, Path]

_EXTENSIONES_PERMITIDAS = {".json", ".yaml", ".yml"}
_TAMANO_MAX_BYTES = 1 * 1024 * 1024  # 1 MiB


class ErrorConfiguracion(Exception):
    """Error al cargar o validar el archivo de configuración."""


def cargar_configuracion(
    ruta_archivo: PathLike,
    *,
    directorio_permitido: PathLike | None = None,
    tamano_max_bytes: int = _TAMANO_MAX_BYTES,
) -> dict[str, Any]:
    """Carga un archivo de configuración subido por un administrador.

    Args:
        ruta_archivo: Ruta del archivo a cargar (.json, .yaml o .yml).
        directorio_permitido: Directorio base dentro del cual debe residir el
            archivo. Si se indica, se rechaza cualquier ruta fuera de él
            (protección contra path traversal). Recomendado en producción.
        tamano_max_bytes: Tamaño máximo permitido del archivo en bytes.

    Returns:
        Diccionario con el contenido de la configuración.

    Raises:
        ErrorConfiguracion: Si el archivo no existe, no está permitido,
            excede el tamaño máximo o su contenido no es válido.
    """
    ruta = Path(ruta_archivo).expanduser()

    # 1. Validar extensión.
    if ruta.suffix.lower() not in _EXTENSIONES_PERMITIDAS:
        raise ErrorConfiguracion(
            f"Extensión no permitida: {ruta.suffix!r}. "
            f"Use: {', '.join(sorted(_EXTENSIONES_PERMITIDAS))}."
        )

    # 2. Resolver y confinar al directorio permitido.
    try:
        ruta = ruta.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ErrorConfiguracion(f"El archivo no existe: {ruta_archivo}") from exc

    if not ruta.is_file():
        raise ErrorConfiguracion(f"La ruta no es un archivo regular: {ruta}")

    if directorio_permitido is not None:
        base = Path(directorio_permitido).expanduser().resolve()
        if not ruta.is_relative_to(base):
            raise ErrorConfiguracion(
                f"El archivo está fuera del directorio permitido: {base}"
            )

    # 3. Validar tamaño.
    tamano = ruta.stat().st_size
    if tamano > tamano_max_bytes:
        raise ErrorConfiguracion(
            f"El archivo excede el tamaño máximo "
            f"({tamano} > {tamano_max_bytes} bytes)."
        )

    # 4. Leer y parsear según formato.
    try:
        contenido = ruta.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ErrorConfiguracion(f"No se pudo leer el archivo: {exc}") from exc

    if ruta.suffix.lower() == ".json":
        try:
            datos = json.loads(contenido)
        except json.JSONDecodeError as exc:
            raise ErrorConfiguracion(f"JSON inválido: {exc}") from exc
    else:
        try:
            import yaml  # PyYAML, solo necesario para .yaml/.yml
        except ImportError as exc:
            raise ErrorConfiguracion(
                "Se requiere PyYAML para cargar archivos YAML "
                "(pip install pyyaml)."
            ) from exc
        try:
            datos = yaml.safe_load(contenido)
        except yaml.YAMLError as exc:
            raise ErrorConfiguracion(f"YAML inválido: {exc}") from exc

    # 5. La configuración raíz debe ser un objeto/mapping.
    if not isinstance(datos, dict):
        raise ErrorConfiguracion(
            "La configuración debe ser un objeto/mapping en la raíz."
        )

    return datos
