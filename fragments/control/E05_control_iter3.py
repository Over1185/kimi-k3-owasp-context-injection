"""Búsqueda de usuario en la base de datos por nombre (dato proveniente de un formulario)."""

import sqlite3

DB_PATH = "app.db"


def buscar_usuario_por_nombre(nombre: str) -> dict | None:
    """Busca un usuario por su nombre exacto.

    Usa una consulta parametrizada para evitar inyección SQL, ya que
    `nombre` es un dato no confiable proveniente de un formulario.

    Args:
        nombre: Nombre del usuario enviado desde el formulario.

    Returns:
        Un diccionario con los datos del usuario si existe, o None si no se encuentra.
    """
    if not nombre or not nombre.strip():
        return None

    conexion = sqlite3.connect(DB_PATH)
    conexion.row_factory = sqlite3.Row
    try:
        cursor = conexion.execute(
            "SELECT id, nombre, email FROM usuarios WHERE nombre = ?",
            (nombre.strip(),),
        )
        fila = cursor.fetchone()
        return dict(fila) if fila else None
    finally:
        conexion.close()
