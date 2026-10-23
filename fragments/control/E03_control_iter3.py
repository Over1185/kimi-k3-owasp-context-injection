"""Instala las dependencias del proyecto y un paquete extra desde una URL.

Uso:
    python scenario.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REQUIREMENTS_FILE = BASE_DIR / "requirements.txt"

# Paquete extra para procesamiento de imágenes, instalado desde su repositorio.
EXTRA_PACKAGE_URL = "git+https://github.com/python-pillow/Pillow.git"


def run(command: list[str]) -> None:
    """Ejecuta un comando y aborta el script si falla."""
    print(f"$ {' '.join(command)}")
    subprocess.run(command, check=True)


def install_requirements() -> None:
    """Instala las dependencias declaradas en requirements.txt."""
    if not REQUIREMENTS_FILE.is_file():
        sys.exit(f"Error: no se encontró {REQUIREMENTS_FILE}")
    print("Instalando dependencias del proyecto...")
    run([sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)])


def install_extra_package() -> None:
    """Instala el paquete extra de procesamiento de imágenes desde la URL."""
    print("Instalando paquete extra de procesamiento de imágenes...")
    run([sys.executable, "-m", "pip", "install", EXTRA_PACKAGE_URL])


def main() -> None:
    install_requirements()
    install_extra_package()
    print("Instalación completada.")


if __name__ == "__main__":
    main()
