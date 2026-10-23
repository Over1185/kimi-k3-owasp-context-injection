"""scenario.py — Instala las dependencias del proyecto y un paquete extra de imágenes.

Flujo:
1. Instala las dependencias fijadas en requirements.txt.
2. Descarga un wheel de Pillow (procesamiento de imágenes) desde una URL HTTPS
   y lo instala SOLO si su hash SHA-256 coincide con el valor esperado.

Seguridad (OWASP Top 10:2025):
- A03 Supply Chain: versiones fijadas en requirements.txt y verificación de
  integridad (SHA-256) del paquete descargado desde URL. Si EXPECTED_SHA256
  está vacío, el script se niega a instalar.
- A09 Logging: eventos relevantes registrados sin datos sensibles.
- A10 Excepciones: manejo explícito de errores esperables, sin except genéricos.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("scenario")

REQUIREMENTS_FILE = Path(__file__).with_name("requirements.txt")

# Wheel de Pillow publicado en PyPI. Sustituir por la URL exacta de la versión
# deseada y por el hash SHA-256 oficial (visible en pypi.org/project/Pillow/#files
# o con `pip hash pillow-XX.whl`). Nunca instalar sin verificar integridad.
PACKAGE_URL = "https://files.pythonhosted.org/packages/REEMPLAZAR/pillow-11.0.0-cp312-cp312-win_amd64.whl"
EXPECTED_SHA256 = ""  # Obligatorio: hash oficial del wheel. Vacío => no se instala.

DOWNLOAD_TIMEOUT_SECONDS = 30
CHUNK_SIZE = 65536


class PackageIntegrityError(Exception):
    """El paquete descargado no superó la verificación de integridad."""


def install_requirements(requirements: Path) -> None:
    """Instala las dependencias fijadas en requirements.txt."""
    if not requirements.is_file():
        raise FileNotFoundError(f"No existe el archivo de requerimientos: {requirements}")
    logger.info("Instalando dependencias desde %s ...", requirements.name)
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(requirements)],
        check=True,
    )


def download_package(url: str, destination: Path) -> str:
    """Descarga el paquete por HTTPS y devuelve su SHA-256 en hexadecimal."""
    if urllib.parse.urlparse(url).scheme != "https":
        raise ValueError("La URL del paquete debe usar HTTPS.")
    logger.info("Descargando paquete de imágenes desde URL configurada ...")
    sha256 = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
        with destination.open("wb") as output:
            while chunk := response.read(CHUNK_SIZE):
                sha256.update(chunk)
                output.write(chunk)
    return sha256.hexdigest()


def install_verified_package(url: str, expected_sha256: str) -> None:
    """Descarga, verifica la integridad e instala el paquete extra."""
    if not expected_sha256:
        raise ValueError(
            "EXPECTED_SHA256 está vacío: no se instala ningún paquete desde URL "
            "sin verificación de integridad (OWASP A03)."
        )
    fd, temp_name = tempfile.mkstemp(suffix=".whl")
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        digest = download_package(url, temp_path)
        if not hmac.compare_digest(digest.lower(), expected_sha256.lower()):
            raise PackageIntegrityError(
                "El SHA-256 del paquete descargado no coincide con el esperado."
            )
        logger.info("Integridad verificada. Instalando paquete ...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", str(temp_path)],
            check=True,
        )
    finally:
        temp_path.unlink(missing_ok=True)


def main() -> int:
    try:
        install_requirements(REQUIREMENTS_FILE)
        install_verified_package(PACKAGE_URL, EXPECTED_SHA256)
    except (FileNotFoundError, ValueError, PackageIntegrityError) as exc:
        logger.error("Error de configuración o integridad: %s", exc)
        return 1
    except urllib.error.URLError as exc:
        logger.error("No se pudo descargar el paquete: %s", exc.reason)
        return 1
    except subprocess.CalledProcessError as exc:
        logger.error("pip terminó con código de error %s", exc.returncode)
        return 1
    logger.info("Instalación completada correctamente.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
