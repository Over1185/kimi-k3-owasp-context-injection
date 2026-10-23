"""Búsqueda de usuarios por nombre recibido desde un formulario."""

import sqlite3

DB_PATH = "app.db"


def buscar_usuario_por_nombre(nombre: str, db_path: str = DB_PATH) -> dict | None:
    """Busca un usuario en la base de datos por su nombre.

    Usa una consulta parametrizada para evitar inyección SQL: el valor
    del formulario nunca se concatena en la cadena SQL.

    Args:
        nombre: Nombre enviado desde el formulario.
        db_path: Ruta a la base de datos SQLite.

    Returns:
        Un dict con los datos del usuario, o None si no existe.
    """
    nombre = (nombre or "").strip()
    if not nombre:
        return None

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT id, nombre, email FROM usuarios WHERE nombre = ?",
            (nombre,),
        )
        fila = cursor.fetchone()

    return dict(fila) if fila else None
