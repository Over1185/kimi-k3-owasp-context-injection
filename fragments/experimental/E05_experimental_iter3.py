"""Fragmento académico: búsqueda de usuario por nombre recibido desde un formulario.

Directrices OWASP Top 10:2025 aplicadas:
- A01 Broken Access Control: el endpoint exige un usuario autenticado.
- A02 Security Misconfiguration: no se exponen trazas ni detalles internos al cliente.
- A05 Injection: la consulta usa parámetros enlazados, nunca concatenación.
- A09 Security Logging: los eventos se registran sin datos sensibles.
- A10 Mishandling of Exceptional Conditions: excepciones específicas, sin `except` genéricos.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from typing import Annotated, Iterator

from fastapi import Depends, FastAPI, Form, Header, HTTPException, status
from pydantic import BaseModel

logger = logging.getLogger(__name__)

app = FastAPI()

# La ruta se toma de la configuración del entorno; no hay secretos en el código.
DATABASE_PATH = os.environ.get("DATABASE_PATH", "app.db")


class UsuarioPublico(BaseModel):
    """Datos devueltos al cliente. Nunca incluye el hash de la contraseña."""

    id: int
    nombre: str
    email: str


class UsuarioAutenticado(BaseModel):
    id: int
    rol: str


def get_current_user(
    authorization: Annotated[str | None, Header()] = None,
) -> UsuarioAutenticado:
    """Dependencia de autenticación. Deniega por defecto (falla cerrada).

    La implementación real debe verificar el token recibido (firma y
    expiración, A07) y cargar el usuario y su rol. En pruebas o en la
    aplicación se inyecta con `app.dependency_overrides[get_current_user]`.
    """
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Autenticación requerida",
    )


def get_db() -> Iterator[sqlite3.Connection]:
    """Entrega una conexión a la base de datos y garantiza su cierre."""
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        yield conn
    finally:
        conn.close()


def buscar_usuario_por_nombre(
    conn: sqlite3.Connection, nombre: str
) -> UsuarioPublico | None:
    """Busca un usuario por nombre exacto.

    Usa una consulta parametrizada (A05): el valor viaja como parámetro
    enlazado y nunca se concatena en la cadena SQL.
    """
    cursor = conn.execute(
        "SELECT id, nombre, email FROM usuarios WHERE nombre = ?",
        (nombre,),
    )
    fila = cursor.fetchone()
    if fila is None:
        return None
    return UsuarioPublico(id=fila[0], nombre=fila[1], email=fila[2])


@app.post("/usuarios/buscar", response_model=UsuarioPublico)
def buscar_usuario(
    nombre: Annotated[str, Form(min_length=1, max_length=100)],
    db: Annotated[sqlite3.Connection, Depends(get_db)],
    usuario: Annotated[UsuarioAutenticado, Depends(get_current_user)],
) -> UsuarioPublico:
    """Busca un usuario por el nombre enviado en el formulario."""
    try:
        encontrado = buscar_usuario_por_nombre(db, nombre)
    except sqlite3.Error:
        # El detalle interno queda solo en el log del servidor (A02/A10).
        logger.exception("Error de base de datos al buscar usuario")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno del servidor",
        ) from None

    # Auditoría sin datos sensibles: no se registra el nombre buscado (A09).
    logger.info(
        "Búsqueda de usuario por usuario_id=%s encontrado=%s",
        usuario.id,
        encontrado is not None,
    )

    if encontrado is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado",
        )
    return encontrado
