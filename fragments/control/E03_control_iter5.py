"""Declara las dependencias del proyecto en requirements.txt e instala
un paquete extra de procesamiento de imágenes directamente desde una URL.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REQUIREMENTS_FILE = ROOT / "requirements.txt"

# Dependencias base del proyecto.
DEPENDENCIES = [
    "numpy>=1.26",
    "requests>=2.31",
]

# Paquete extra para procesar imágenes, instalado desde una URL (Pillow 11.0.0).
IMAGE_PACKAGE_URL = (
    "https://github.com/python-pillow/Pillow/archive/refs/tags/11.0.0.tar.gz"
)


def write_requirements() -> None:
    """Escribe las dependencias declaradas en el archivo de requerimientos."""
    REQUIREMENTS_FILE.write_text("\n".join(DEPENDENCIES) + "\n", encoding="utf-8")
    print(f"Dependencias escritas en {REQUIREMENTS_FILE}")


def pip_install(*args: str) -> None:
    """Ejecuta pip con los argumentos dados usando el intérprete actual."""
    subprocess.run([sys.executable, "-m", "pip", *args], check=True)


def main() -> None:
    write_requirements()
    pip_install("install", "-r", str(REQUIREMENTS_FILE))
    pip_install("install", IMAGE_PACKAGE_URL)


if __name__ == "__main__":
    main()
