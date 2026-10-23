"""Instalación controlada de las dependencias del proyecto.

Pasos:
1. Instala las dependencias declaradas (con versión fijada) en requirements.txt.
2. Descarga e instala un paquete extra de procesamiento de imágenes (Pillow)
   desde una URL, verificando antes su integridad con SHA-256.

Seguridad (OWASP A03 — Software Supply Chain Failures):
- Solo se aceptan dependencias con versión fijada (==).
- El paquete extra se descarga únicamente por HTTPS y desde hosts permitidos.
- La instalación se aborta si el hash SHA-256 del archivo no coincide.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("scenario")

BASE_DIR = Path(__file__).resolve().parent
REQUIREMENTS_FILE = BASE_DIR / "requirements.txt"

# --- Paquete extra: Pillow (procesamiento de imágenes) ----------------------
# Para configurar la URL y el hash oficiales:
#   1. Consulta https://pypi.org/pypi/Pillow/json y elige el wheel que
#      coincida con tu versión de Python y plataforma.
#   2. Copia su campo "url" y su "digests.sha256" (o descarga el archivo y
#      ejecuta `pip hash <archivo>` para calcularlo localmente).
# El script falla de forma segura mientras estos valores no estén configurados.
PILLOW_WHEEL_URL = "https://files.pythonhosted.org/packages/REEMPLAZAR/pillow-11.0.0-cp312-cp312-win_amd64.whl"
PILLOW_WHEEL_SHA256 = "REEMPLAZAR_CON_SHA256_OFICIAL"

ALLOWED_DOWNLOAD_HOSTS = {"files.pythonhosted.org", "pypi.org"}
DOWNLOAD_TIMEOUT_SECONDS = 30
CHUNK_SIZE = 64 * 1024


def _read_pinned_requirements(path: Path) -> list[str]:
    """Lee el archivo de requerimientos y exige versión fijada en cada línea."""
    if not path.is_file():
        raise FileNotFoundError(f"Archivo de requerimientos no encontrado: {path}")
    pinned: list[str] = []
    for lineno, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            raise ValueError(f"Dependencia sin versión fijada en la línea {lineno}: {line}")
        pinned.append(line)
    return pinned


def install_requirements(path: Path = REQUIREMENTS_FILE) -> None:
    """Instala las dependencias declaradas en el archivo de requerimientos."""
    pinned = _read_pinned_requirements(path)
    logger.info("Instalando %d dependencias desde %s", len(pinned), path.name)
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(path)],
        check=True,
    )


def _validate_download_config(url: str, expected_sha256: str) -> None:
    """Valida esquema HTTPS, host permitido y configuración real del hash."""
    if "REEMPLAZAR" in url or "REEMPLAZAR" in expected_sha256:
        raise RuntimeError(
            "Configura PILLOW_WHEEL_URL y PILLOW_WHEEL_SHA256 con los valores "
            "oficiales de PyPI antes de ejecutar la instalación."
        )
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Solo se permiten descargas por HTTPS.")
    if parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
        raise ValueError(f"Host de descarga no permitido: {parsed.hostname}")


def download_and_verify(url: str, expected_sha256: str, dest: Path) -> None:
    """Descarga el wheel y aborta si su SHA-256 no coincide con el esperado."""
    _validate_download_config(url, expected_sha256)
    digest = hashlib.sha256()
    filename = Path(urlparse(url).path).name
    logger.info("Descargando %s", filename)
    try:
        with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
            with dest.open("wb") as fh:
                while chunk := response.read(CHUNK_SIZE):
                    digest.update(chunk)
                    fh.write(chunk)
    except urllib.error.URLError as exc:
        dest.unlink(missing_ok=True)
        raise RuntimeError(f"Falló la descarga del paquete extra: {exc.reason}") from exc

    if not hmac.compare_digest(digest.hexdigest(), expected_sha256.lower()):
        dest.unlink(missing_ok=True)
        raise RuntimeError("Verificación de integridad fallida: el SHA-256 no coincide.")
    logger.info("Integridad verificada correctamente (SHA-256 coincide).")


def install_extra_package() -> None:
    """Descarga, verifica e instala el paquete extra de imágenes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        wheel_path = Path(tmpdir) / Path(urlparse(PILLOW_WHEEL_URL).path).name
        download_and_verify(PILLOW_WHEEL_URL, PILLOW_WHEEL_SHA256, wheel_path)
        logger.info("Instalando paquete extra verificado")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", str(wheel_path)],
            check=True,
        )


def main() -> int:
    try:
        install_requirements()
        install_extra_package()
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        logger.error("Instalación abortada: %s", exc)
        return 1
    except subprocess.CalledProcessError as exc:
        logger.error("pip finalizó con error (código %d).", exc.returncode)
        return 1
    logger.info("Proceso completado correctamente.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
