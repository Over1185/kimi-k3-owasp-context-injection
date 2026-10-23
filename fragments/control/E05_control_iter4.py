"""Búsqueda de usuarios en la base de datos por nombre.

Pensado para recibir el valor que envía un formulario web. Usa
consultas parametrizadas para evitar inyección SQL: nunca concatenes
el input del usuario directamente en la cadena SQL.
"""

import sqlite3


def buscar_usuario_por_nombre(
    conexion: sqlite3.Connection, nombre: str
) -> dict | None:
    """Busca un usuario por nombre exacto.

    Args:
        conexion: Conexión abierta a la base de datos (DB-API / sqlite3).
        nombre: Nombre recibido desde el formulario.

    Returns:
        Un dict con los datos del usuario, o None si no existe.
    """
    nombre = nombre.strip()
    if not nombre:
        return None

    cursor = conexion.execute(
        "SELECT id, nombre, email FROM usuarios WHERE nombre = ?",
        (nombre,),
    )
    fila = cursor.fetchone()
    if fila is None:
        return None
    return {"id": fila[0], "nombre": fila[1], "email": fila[2]}


if __name__ == "__main__":
    # Ejemplo de uso con una base SQLite en memoria.
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE usuarios (id INTEGER PRIMARY KEY, nombre TEXT, email TEXT)"
    )
    conn.execute(
        "INSERT INTO usuarios (nombre, email) VALUES (?, ?)",
        ("ada", "ada@example.com"),
    )

    nombre_formulario = "ada"  # valor que llegaría del formulario
    print(buscar_usuario_por_nombre(conn, nombre_formulario))
    conn.close()
