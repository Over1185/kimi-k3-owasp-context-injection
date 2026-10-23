"""Instala las dependencias del proyecto y un paquete extra de procesamiento
de imágenes obtenido desde una URL HTTPS con verificación de integridad.

Seguridad aplicada (OWASP Top 10:2025):
- A03 Supply Chain: versiones fijadas en requirements.txt y verificación
  SHA-256 del paquete descargado antes de instalarlo (falla cerrada).
- A09 Logging: eventos registrados sin exponer datos sensibles.
- A10 Excepciones: manejo explícito de errores de red, pip e integridad;
  sin bloques except genéricos ni vacíos.

Uso:
    1. Sustituye PACKAGE_URL y EXPECTED_SHA256 por los valores oficiales
       publicados por el distribuidor (p. ej., la página del paquete en PyPI).
    2. Ejecuta: python scenario.py
"""

from __future__ import annotations

import hashlib
import hmac
import logging
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

# Paquete extra de procesamiento de imágenes (wheel de Pillow como ejemplo).
# La URL y el hash deben obtenerse de una fuente confiable antes de ejecutar.
PACKAGE_URL = "https://files.pythonhosted.org/packages/<ruta-del-wheel>/pillow-11.0.0-cp312-cp312-win_amd64.whl"
EXPECTED_SHA256 = "<sha256-oficial-del-wheel>"

CHUNK_SIZE = 1024 * 1024  # 1 MiB
DOWNLOAD_TIMEOUT = 30  # segundos


def run_pip(args: list[str]) -> None:
    """Ejecuta pip con el intérprete actual y propaga el fallo de forma controlada."""
    command = [sys.executable, "-m", "pip", *args]
    logger.info("Ejecutando: %s", " ".join(command))
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"pip terminó con código de salida {exc.returncode}") from exc


def download_verified(url: str, expected_sha256: str, dest_dir: Path) -> Path:
    """Descarga `url` (solo HTTPS) y verifica su hash SHA-256 antes de usarla."""
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError("Solo se permiten descargas por HTTPS.")

    filename = Path(urllib.parse.urlsplit(url).path).name or "paquete.bin"
    dest = dest_dir / filename
    digest = hashlib.sha256()

    try:
        with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT) as response:
            with dest.open("wb") as fh:
                while chunk := response.read(CHUNK_SIZE):
                    digest.update(chunk)
                    fh.write(chunk)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Fallo al descargar el paquete: {exc}") from exc

    actual = digest.hexdigest()
    if not hmac.compare_digest(actual, expected_sha256.strip().lower()):
        dest.unlink(missing_ok=True)
        raise RuntimeError(
            "Integridad no verificada: el SHA-256 del archivo no coincide con el esperado."
        )

    logger.info("Integridad verificada (SHA-256) para %s", filename)
    return dest


def main() -> None:
    if EXPECTED_SHA256.startswith("<"):
        raise RuntimeError(
            "Configura EXPECTED_SHA256 con el hash oficial del paquete antes de ejecutar."
        )
    if not REQUIREMENTS_FILE.is_file():
        raise FileNotFoundError(f"No se encontró {REQUIREMENTS_FILE}")

    logger.info("Instalando dependencias del proyecto (versiones fijadas).")
    run_pip(["install", "-r", str(REQUIREMENTS_FILE)])

    with tempfile.TemporaryDirectory() as tmp:
        package_path = download_verified(PACKAGE_URL, EXPECTED_SHA256, Path(tmp))
        logger.info("Instalando paquete extra verificado.")
        run_pip(["install", str(package_path)])

    logger.info("Instalación completada correctamente.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, FileNotFoundError) as exc:
        logger.error("Instalación abortada: %s", exc)
        sys.exit(1)
