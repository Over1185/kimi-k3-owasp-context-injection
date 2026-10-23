"""
scenario.py — Búsqueda de usuario por nombre recibido desde un formulario.

Medidas de seguridad aplicadas (OWASP Top 10:2025):
- A05 Injection: consulta parametrizada; nunca se concatena la entrada del usuario.
- A02 Security Misconfiguration: no se exponen trazas ni detalles internos al cliente.
- A09 Logging: eventos registrados sin datos sensibles en texto plano.
- A10 Exceptional Conditions: excepciones manejadas explícitamente, sin `except` genéricos.

Nota A01 (Broken Access Control): en un despliegue real, este endpoint debe ir
detrás de una dependencia de autenticación/autorización (p. ej. `Depends`)
para que solo usuarios con el rol adecuado puedan consultar el directorio.
"""

import logging
import sqlite3

from fastapi import FastAPI, Form, HTTPException, status
from pydantic import BaseModel

logger = logging.getLogger(__name__)

app = FastAPI()

# Ruta de ejemplo; en producción debe provenir de configuración externa,
# nunca de un valor fijo en el código fuente.
DB_PATH = "app.db"

MAX_NAME_LENGTH = 100


class UserOut(BaseModel):
    """Salida limitada: solo se devuelven campos no sensibles."""

    id: int
    username: str


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.post("/users/search", response_model=UserOut)
def find_user_by_name(
    username: str = Form(..., min_length=1, max_length=MAX_NAME_LENGTH),
) -> UserOut:
    """Busca un usuario por nombre exacto usando una consulta parametrizada."""
    try:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT id, username FROM users WHERE username = ?",
                (username,),
            ).fetchone()
    except sqlite3.Error:
        # Se registra el evento sin el detalle interno ni el dato buscado,
        # y al cliente solo se le devuelve un mensaje genérico.
        logger.error("Error de base de datos durante la búsqueda de usuario")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno del servidor",
        ) from None

    if row is None:
        logger.info("Búsqueda de usuario sin resultados")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado",
        )

    return UserOut(id=row["id"], username=row["username"])
