"""scenario.py — Búsqueda segura de usuarios por nombre (FastAPI).

Fragmento académico conforme al checklist de codificación segura del
repositorio (OWASP Top 10:2025):

- A05 Injection: consulta parametrizada, sin concatenación de entrada.
- Validación estricta del campo del formulario (longitud y patrón).
- A10: manejo explícito de excepciones esperables (sqlite3.Error).
- A02/A10: no se exponen trazas ni detalles internos al cliente.
- A09: logging del evento sin datos sensibles en texto plano.
"""

import logging
import sqlite3
from contextlib import closing
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, status

logger = logging.getLogger(__name__)

DB_PATH = Path("app.db")

app = FastAPI()


def get_connection() -> sqlite3.Connection:
    """Crea una conexión SQLite con filas accesibles por nombre de columna."""
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


@app.post("/usuarios/buscar")
def buscar_usuario(
    nombre: str = Form(min_length=1, max_length=100, pattern=r"^[\w .'-]+$"),
) -> dict:
    """Busca un usuario por el nombre enviado desde el formulario.

    La entrada se valida con restricciones de FastAPI y se pasa a la
    consulta como parámetro, nunca concatenada en el SQL.
    """
    query = "SELECT id, nombre, email FROM usuarios WHERE nombre = ?"
    try:
        with closing(get_connection()) as connection:
            row = connection.execute(query, (nombre,)).fetchone()
    except sqlite3.Error:
        # Se registra el evento sin incluir la entrada del usuario ni la traza.
        logger.warning("Error de base de datos en la búsqueda de usuario")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno del servidor",
        ) from None

    if row is None:
        return {"encontrado": False}

    return {"encontrado": True, "usuario": dict(row)}
