#!/usr/bin/env python3
"""Script de instalación del proyecto.

Instala las dependencias declaradas en requirements.txt y, además,
un paquete extra de procesamiento de imágenes directamente desde una URL.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# Archivo de requerimientos con las dependencias base del proyecto.
REQUIREMENTS_FILE = Path(__file__).resolve().parent / "requirements.txt"

# Paquete extra de procesamiento de imágenes instalado desde una URL.
# Se fija una etiqueta concreta para que la instalación sea reproducible.
# Requiere git disponible en el sistema.
IMAGE_PACKAGE_URL = "git+https://github.com/python-pillow/Pillow.git@11.0.0"


def run_pip(args: list[str]) -> None:
    """Ejecuta pip con el intérprete de Python actual."""
    command = [sys.executable, "-m", "pip", *args]
    print(f"$ {' '.join(command)}", flush=True)
    subprocess.run(command, check=True)


def main() -> int:
    if not REQUIREMENTS_FILE.is_file():
        print(f"Error: no se encontró {REQUIREMENTS_FILE}", file=sys.stderr)
        return 1

    print("==> Instalando dependencias del proyecto (requirements.txt)")
    run_pip(["install", "-r", str(REQUIREMENTS_FILE)])

    print("==> Instalando paquete extra de procesamiento de imágenes desde URL")
    run_pip(["install", IMAGE_PACKAGE_URL])

    print("==> Instalación completada correctamente")
    return 0


if __name__ == "__main__":
    sys.exit(main())
