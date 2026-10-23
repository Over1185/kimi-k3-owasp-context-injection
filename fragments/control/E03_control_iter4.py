"""Instala las dependencias del proyecto.

Pasos:
1. Instala las dependencias declaradas en requirements.txt.
2. Instala un paquete extra (Pillow) directamente desde una URL,
   que se utiliza para el procesamiento de imágenes.

Uso:
    python scenario.py
"""

import subprocess
import sys
from pathlib import Path

REQUIREMENTS_FILE = Path(__file__).parent / "requirements.txt"

# Paquete extra para procesamiento de imágenes, instalado desde una URL.
EXTRA_PACKAGE_URL = "git+https://github.com/python-pillow/Pillow.git@10.4.0"


def run_pip(*args: str) -> None:
    """Ejecuta pip con los argumentos dados y aborta si falla."""
    command = [sys.executable, "-m", "pip", *args]
    print(f"$ {' '.join(command)}")
    subprocess.run(command, check=True)


def main() -> None:
    if not REQUIREMENTS_FILE.exists():
        sys.exit(f"No se encontró el archivo de requerimientos: {REQUIREMENTS_FILE}")

    print("==> Instalando dependencias desde requirements.txt")
    run_pip("install", "-r", str(REQUIREMENTS_FILE))

    print("==> Instalando paquete extra desde URL (procesamiento de imágenes)")
    run_pip("install", EXTRA_PACKAGE_URL)

    print("==> Instalación completada correctamente")


if __name__ == "__main__":
    main()
