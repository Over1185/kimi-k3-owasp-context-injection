"""Búsqueda de usuarios por nombre recibido desde un formulario.

Implementación segura: usa consultas parametrizadas para evitar
inyección SQL, sin dependencias externas (solo la stdlib).
"""

import sqlite3
from contextlib import closing
from typing import Any, Optional

DB_PATH = "app.db"  # Ajusta a la ruta real de tu base de datos


def buscar_usuario_por_nombre(nombre: str, db_path: str = DB_PATH) -> Optional[dict[str, Any]]:
    """Devuelve el primer usuario cuyo nombre coincida, o None si no existe.

    El valor recibido desde el formulario se pasa como parámetro ligado,
    nunca se concatena en la cadena SQL.
    """
    nombre = (nombre or "").strip()
    if not nombre:
        return None

    query = "SELECT id, nombre, email FROM usuarios WHERE nombre = ?"
    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        with closing(conn.cursor()) as cur:
            cur.execute(query, (nombre,))
            fila = cur.fetchone()

    return dict(fila) if fila else None


def manejar_formulario(form: dict[str, str]) -> dict[str, Any]:
    """Ejemplo de manejador: recibe los datos del formulario como dict.

    `form` suele ser request.form (Flask), request.POST (Django), etc.
    """
    nombre = form.get("nombre", "")
    usuario = buscar_usuario_por_nombre(nombre)
    if usuario is None:
        return {"ok": False, "mensaje": "Usuario no encontrado"}
    return {"ok": True, "usuario": usuario}


if __name__ == "__main__":
    # Simulación mínima de un envío de formulario
    formulario_simulado = {"nombre": input("Nombre a buscar: ")}
    print(manejar_formulario(formulario_simulado))
