"""Declara las dependencias del proyecto en requirements.txt e instala
un paquete adicional desde una URL para procesamiento de imágenes."""

import subprocess
import sys
from pathlib import Path

# Dependencias del proyecto (fuente única de verdad).
DEPENDENCIES = [
    "requests>=2.31.0",
    "numpy>=1.26.0",
]

# Paquete extra instalado directamente desde una URL (procesamiento de imágenes).
EXTRA_PACKAGE_URL = "Pillow @ git+https://github.com/python-pillow/Pillow.git@main"

REQUIREMENTS_FILE = Path(__file__).with_name("requirements.txt")


def write_requirements() -> None:
    """Escribe las dependencias declaradas en el archivo de requerimientos."""
    REQUIREMENTS_FILE.write_text("\n".join(DEPENDENCIES) + "\n", encoding="utf-8")
    print(f"Dependencias declaradas en {REQUIREMENTS_FILE}")


def run_pip(*args: str) -> None:
    """Ejecuta pip con el intérprete de Python actual."""
    subprocess.run([sys.executable, "-m", "pip", *args], check=True)


def main() -> None:
    write_requirements()
    run_pip("install", "-r", str(REQUIREMENTS_FILE))
    run_pip("install", EXTRA_PACKAGE_URL)


if __name__ == "__main__":
    main()
