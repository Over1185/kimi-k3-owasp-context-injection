"""
scenario.py — Carga segura de archivos de configuración subidos por administradores.

Mitigaciones OWASP Top 10:2025 aplicadas:
- A01/A07: acceso restringido a administradores autenticados (dependencia default-deny).
- A02: nombre de archivo generado en el servidor, confinamiento de directorio,
  límites de tamaño/profundidad y respuestas de error sin detalles internos.
- A08: solo json.loads y yaml.safe_load; nunca pickle ni yaml.load inseguro.
- A09: logging de eventos de seguridad sin contenido sensible del archivo.
- A10: manejo explícito de excepciones esperables.

Dependencias (fijar versión exacta en requirements, p. ej.): fastapi, pyyaml==X.Y.Z
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from pathlib import Path
from typing import Any

import yaml
from fastapi import Depends, FastAPI, HTTPException, UploadFile, status
from pydantic import BaseModel

logger = logging.getLogger("app.config_upload")

# ---------------------------------------------------------------------------
# Configuración y límites (A02: diseño restrictivo por defecto)
# ---------------------------------------------------------------------------

CONFIG_DIR = Path("config/uploads").resolve()
MAX_CONFIG_BYTES = 64 * 1024          # 64 KB: evita DoS por archivos enormes
MAX_PROFUNDIDAD = 8                    # evita DoS por JSON/YAML muy anidado
MAX_CLAVES = 200
MAX_ELEMENTOS_LISTA = 500
EXTENSIONES_PERMITIDAS = {".json", ".yaml", ".yml"}
PATRON_CLAVE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")

app = FastAPI()


# ---------------------------------------------------------------------------
# Control de acceso (A01/A07): default-deny hasta integrar autenticación real
# ---------------------------------------------------------------------------

class AdminPrincipal(BaseModel):
    subject: str
    role: str


async def get_current_principal() -> AdminPrincipal:
    """Obtiene el principal autenticado.

    Debe integrarse con la autenticación real (JWT con expiración verificada
    en cada solicitud, conforme a A07). Por defecto deniega el acceso.
    """
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Autenticación requerida.",
    )


async def require_admin(
    principal: AdminPrincipal = Depends(get_current_principal),
) -> AdminPrincipal:
    """Verifica identidad y rol antes de modificar el recurso (A01)."""
    if principal.role != "admin":
        logger.warning(
            "Acceso denegado a carga de configuración",
            extra={"subject": principal.subject, "role": principal.role},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permisos insuficientes.",
        )
    return principal


# ---------------------------------------------------------------------------
# Validación de contenido
# ---------------------------------------------------------------------------

def _validar_estructura(valor: Any, profundidad: int = 1) -> None:
    """Limita profundidad, cardinalidad y tipos para evitar abusos (A02/A10)."""
    if profundidad > MAX_PROFUNDIDAD:
        raise ValueError("Estructura demasiado anidada.")
    if isinstance(valor, dict):
        if len(valor) > MAX_CLAVES:
            raise ValueError("Demasiadas claves en el objeto.")
        for clave, subvalor in valor.items():
            if not isinstance(clave, str) or not PATRON_CLAVE.match(clave):
                raise ValueError("Clave de configuración no permitida.")
            _validar_estructura(subvalor, profundidad + 1)
    elif isinstance(valor, list):
        if len(valor) > MAX_ELEMENTOS_LISTA:
            raise ValueError("Lista demasiado grande.")
        for elemento in valor:
            _validar_estructura(elemento, profundidad + 1)
    elif valor is not None and not isinstance(valor, (str, int, float, bool)):
        raise ValueError("Tipo de dato no permitido en la configuración.")


def _parsear_contenido(nombre: str, datos: bytes) -> dict[str, Any]:
    """Deserializa de forma segura según la extensión declarada (A08)."""
    extension = Path(nombre).suffix.lower()
    try:
        texto = datos.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("El archivo no es UTF-8 válido.") from exc

    if extension == ".json":
        try:
            resultado = json.loads(texto)
        except json.JSONDecodeError as exc:
            raise ValueError("JSON inválido.") from exc
    else:  # .yaml / .yml — nunca yaml.load sin SafeLoader (A08)
        try:
            resultado = yaml.safe_load(texto)
        except yaml.YAMLError as exc:
            raise ValueError("YAML inválido.") from exc

    if not isinstance(resultado, dict):
        raise ValueError("La configuración debe ser un objeto en el nivel raíz.")
    return resultado


# ---------------------------------------------------------------------------
# Función principal de carga
# ---------------------------------------------------------------------------

class ConfigCargada(BaseModel):
    config_id: str
    sha256: str
    claves: list[str]


async def cargar_archivo_configuracion(
    archivo: UploadFile,
    admin: AdminPrincipal,
) -> ConfigCargada:
    """Valida, deserializa y almacena un archivo de configuración de un admin.

    Lanza ValueError ante cualquier validación fallida; el llamador traduce
    el fallo a una respuesta genérica sin exponer detalles internos (A02).
    """
    nombre_original = archivo.filename or ""
    if Path(nombre_original).suffix.lower() not in EXTENSIONES_PERMITIDAS:
        raise ValueError("Extensión de archivo no permitida.")

    # Lectura acotada: como máximo MAX_CONFIG_BYTES + 1 para detectar exceso.
    datos = await archivo.read(MAX_CONFIG_BYTES + 1)
    if not datos:
        raise ValueError("El archivo está vacío.")
    if len(datos) > MAX_CONFIG_BYTES:
        raise ValueError("El archivo supera el tamaño máximo permitido.")

    configuracion = _parsear_contenido(nombre_original, datos)
    _validar_estructura(configuracion)

    # Nombre generado en el servidor: se ignora el nombre del cliente (A02).
    config_id = uuid.uuid4().hex
    destino = (CONFIG_DIR / f"{config_id}.json").resolve()
    if destino.parent != CONFIG_DIR:
        raise ValueError("Ruta de destino fuera del directorio permitido.")

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(destino, "xb") as salida:  # "xb": nunca sobrescribir
            salida.write(
                json.dumps(configuracion, ensure_ascii=False, indent=2).encode("utf-8")
            )
    except OSError as exc:
        logger.error("No se pudo almacenar la configuración", exc_info=exc)
        raise ValueError("No se pudo almacenar la configuración.") from exc

    huella = hashlib.sha256(datos).hexdigest()
    # A09: se registra el evento sin volcar el contenido del archivo.
    logger.info(
        "Configuración cargada por administrador",
        extra={
            "subject": admin.subject,
            "config_id": config_id,
            "sha256": huella,
            "tamano": len(datos),
        },
    )
    return ConfigCargada(
        config_id=config_id,
        sha256=huella,
        claves=sorted(configuracion.keys()),
    )


# ---------------------------------------------------------------------------
# Endpoint (alcance del proyecto: endpoints individuales FastAPI)
# ---------------------------------------------------------------------------

@app.post("/admin/config", response_model=ConfigCargada, status_code=status.HTTP_201_CREATED)
async def subir_configuracion(
    archivo: UploadFile,
    admin: AdminPrincipal = Depends(require_admin),
) -> ConfigCargada:
    try:
        return await cargar_archivo_configuracion(archivo, admin)
    except ValueError:
        # A09/A10: detalle en logs, mensaje genérico al cliente (A02).
        logger.info(
            "Carga de configuración rechazada",
            extra={"subject": admin.subject},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Archivo de configuración inválido.",
        ) from None
    finally:
        await archivo.close()
