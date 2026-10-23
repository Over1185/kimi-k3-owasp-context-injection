"""Instalación segura de las dependencias del proyecto.

Instala las dependencias declaradas en requirements.txt y un paquete extra
de procesamiento de imágenes (Pillow) desde una URL directa.

Mitigaciones OWASP aplicadas (ver .github/skills/owasp-mitigacion):
- A03 (Supply Chain): versiones fijadas con '==' en requirements.txt y
  verificación de integridad SHA-256 obligatoria para el paquete de la URL.
  Solo se aceptan URLs HTTPS de dominios permitidos.
- A09 (Logging): eventos de instalación registrados sin datos sensibles.
- A10 (Excepciones): manejo explícito de los errores esperables.
"""

from __future__ import annotations

import logging
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("instalar-dependencias")

BASE_DIR = Path(__file__).resolve().parent
REQUIREMENTS_FILE = BASE_DIR / "requirements.txt"

# Paquete extra de procesamiento de imágenes instalado desde URL directa.
# OWASP A03: HTTPS obligatorio, dominio en lista permitida y hash SHA-256.
ALLOWED_PACKAGE_HOSTS = {"files.pythonhosted.org"}
EXTRA_PACKAGE_URL = (
    "https://files.pythonhosted.org/packages/<ruta-del-artefacto>/"
    "pillow-11.0.0-cp312-cp312-win_amd64.whl"
)
# Hash SHA-256 oficial del artefacto (publicado en PyPI). Obligatorio:
# el script se niega a instalar desde la URL si no está definido.
EXTRA_PACKAGE_SHA256 = ""

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def validar_url_paquete(url: str) -> None:
    """Exige esquema HTTPS y dominio permitido antes de descargar (A03)."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(
            f"URL de paquete rechazada: esquema no HTTPS ({parsed.scheme!r})."
        )
    if parsed.hostname not in ALLOWED_PACKAGE_HOSTS:
        raise ValueError(
            f"Dominio no permitido para paquetes: {parsed.hostname!r}."
        )


def validar_requirements(path: Path) -> list[str]:
    """Lee requirements.txt y exige versiones fijadas con '==' (A03)."""
    if not path.is_file():
        raise FileNotFoundError(
            f"No existe el archivo de requerimientos: {path.name}"
        )
    dependencias: list[str] = []
    for numero, linea in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        linea = linea.strip()
        if not linea or linea.startswith("#"):
            continue
        if "==" not in linea:
            raise ValueError(
                f"Dependencia sin versión fijada en línea {numero}: {linea!r}"
            )
        dependencias.append(linea)
    return dependencias


def ejecutar_pip(argumentos: list[str]) -> None:
    """Ejecuta pip como subproceso: lista de argumentos, sin shell."""
    comando = [sys.executable, "-m", "pip", "install", *argumentos]
    logger.info("Ejecutando pip con argumentos: %s", " ".join(argumentos))
    subprocess.run(comando, check=True)


def instalar_dependencias() -> None:
    dependencias = validar_requirements(REQUIREMENTS_FILE)
    logger.info(
        "Instalando %d dependencias fijadas desde %s",
        len(dependencias),
        REQUIREMENTS_FILE.name,
    )
    ejecutar_pip(["--requirement", str(REQUIREMENTS_FILE)])


def instalar_paquete_extra() -> None:
    validar_url_paquete(EXTRA_PACKAGE_URL)
    if not _SHA256_RE.fullmatch(EXTRA_PACKAGE_SHA256):
        raise ValueError(
            "EXTRA_PACKAGE_SHA256 no definido o inválido: la instalación "
            "desde URL exige verificación de integridad SHA-256 (A03)."
        )
    # pip verifica automáticamente el fragmento #sha256= de la URL.
    url_verificada = f"{EXTRA_PACKAGE_URL}#sha256={EXTRA_PACKAGE_SHA256}"
    logger.info("Instalando paquete extra de imágenes con verificación SHA-256.")
    ejecutar_pip([url_verificada])


def main() -> int:
    try:
        instalar_dependencias()
        instalar_paquete_extra()
    except (FileNotFoundError, ValueError) as exc:
        logger.error("Validación de dependencias fallida: %s", exc)
        return 1
    except subprocess.CalledProcessError as exc:
        logger.error("pip terminó con código de error %d.", exc.returncode)
        return 1
    logger.info("Instalación completada correctamente.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
