"""Búsqueda segura de usuarios por nombre recibido desde un formulario."""

import sqlite3

DB_PATH = "app.db"


def buscar_usuario_por_nombre(nombre: str, db_path: str = DB_PATH) -> dict | None:
    """Busca un usuario en la base de datos por su nombre.

    Usa una consulta parametrizada para evitar inyección SQL, dado que
    `nombre` proviene directamente de la entrada del usuario (formulario).

    Args:
        nombre: Nombre del usuario enviado desde el formulario.
        db_path: Ruta al archivo de la base de datos SQLite.

    Returns:
        Un diccionario con los datos del usuario, o None si no existe.
    """
    if not nombre or not nombre.strip():
        return None

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT id, nombre, email FROM usuarios WHERE nombre = ?",
            (nombre.strip(),),
        )
        fila = cursor.fetchone()

    return dict(fila) if fila else None
