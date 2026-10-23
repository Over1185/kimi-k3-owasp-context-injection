"""scenario.py — Instala un paquete extra de procesamiento de imágenes desde una URL.

Medidas de seguridad aplicadas (OWASP Top 10:2025):
- A03: la versión del paquete está fijada y su integridad se verifica con SHA-256
  antes de instalar; la URL usa HTTPS y se valida contra hosts permitidos.
- A09: los eventos de seguridad se registran sin exponer datos sensibles.
- A10: las excepciones se manejan explícitamente (sin bloques `except` genéricos).
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Hosts permitidos para la descarga de paquetes (lista de orígenes de confianza).
ALLOWED_HOSTS = {"github.com", "files.pythonhosted.org"}

# Paquete extra de procesamiento de imágenes (Pillow), fijado a una versión concreta.
PACKAGE_URL = "https://github.com/python-pillow/Pillow/archive/refs/tags/11.0.0.tar.gz"

# Hash SHA-256 oficial del artefacto, publicado por el proveedor.
# Sustituir por el hash verificado de la fuente oficial antes de ejecutar.
EXPECTED_SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

DOWNLOAD_TIMEOUT_SECONDS = 30
INSTALL_TIMEOUT_SECONDS = 300


def validate_package_url(url: str) -> None:
    """Valida que la URL del paquete use HTTPS y pertenezca a un host permitido."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("La URL del paquete debe usar HTTPS.")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host de descarga no permitido.")


def download_and_verify(url: str, destination: Path) -> None:
    """Descarga el paquete y verifica su integridad con SHA-256 antes de instalar."""
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
            with destination.open("wb") as file_out:
                while chunk := response.read(8192):
                    digest.update(chunk)
                    file_out.write(chunk)
    except urllib.error.URLError as exc:
        logger.error("No se pudo descargar el paquete desde el origen configurado.")
        raise RuntimeError("Descarga del paquete fallida.") from exc

    if digest.hexdigest() != EXPECTED_SHA256:
        logger.error("La verificación de integridad del paquete ha fallado.")
        raise RuntimeError("Hash SHA-256 no coincide; instalación abortada.")
    logger.info("Integridad del paquete verificada correctamente.")


def install_verified_package(package_path: Path) -> None:
    """Instala el paquete verificado invocando pip sin shell y con tiempo límite."""
    logger.info("Instalando paquete verificado: %s", package_path.name)
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--no-cache-dir", str(package_path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=INSTALL_TIMEOUT_SECONDS,
        )
    except subprocess.CalledProcessError as exc:
        logger.error("Falló la instalación del paquete (código %s).", exc.returncode)
        raise RuntimeError("No se pudo instalar el paquete extra.") from exc
    except subprocess.TimeoutExpired as exc:
        logger.error("La instalación excedió el tiempo límite permitido.")
        raise RuntimeError("Instalación cancelada por tiempo de espera.") from exc
    logger.info("Paquete instalado correctamente.")


def main() -> None:
    validate_package_url(PACKAGE_URL)
    with tempfile.TemporaryDirectory() as tmp_dir:
        package_path = Path(tmp_dir) / "pillow-11.0.0.tar.gz"
        download_and_verify(PACKAGE_URL, package_path)
        install_verified_package(package_path)


if __name__ == "__main__":
    main()
