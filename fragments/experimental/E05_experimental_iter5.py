"""scenario.py — Búsqueda segura de usuarios por nombre (FastAPI).

Medidas aplicadas según OWASP Top 10:2025 y la política del repositorio:
- A02 (Security Misconfiguration): no se exponen trazas ni detalles internos al cliente.
- A05 (Injection): consulta parametrizada; nunca se concatena la entrada del usuario.
- A09 (Logging): se registran eventos sin incluir datos sensibles ni la entrada cruda.
- A10 (Excepciones): manejo explícito de errores esperables; sin `except` genéricos.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from typing import Annotated, Optional

from fastapi import FastAPI, Form, HTTPException, status

logger = logging.getLogger(__name__)

DB_PATH = "app.db"

app = FastAPI()


class ErrorBaseDeDatos(Exception):
    """Error interno de acceso a datos. Nunca se expone al cliente."""


@dataclass(frozen=True)
class Usuario:
    id: int
    username: str


def buscar_usuario_por_nombre(nombre: str) -> Optional[Usuario]:
    """Busca un usuario por nombre exacto usando una consulta parametrizada.

    Devuelve el usuario si existe, o None si no se encuentra.
    Lanza ErrorBaseDeDatos ante un fallo interno de acceso a datos.
    """
    nombre_normalizado = nombre.strip()
    if not nombre_normalizado:
        return None

    try:
        with closing(sqlite3.connect(DB_PATH)) as conexion:
            cursor = conexion.execute(
                "SELECT id, username FROM usuarios WHERE username = ?",
                (nombre_normalizado,),
            )
            fila = cursor.fetchone()
    except sqlite3.Error:
        # Se registra el fallo interno sin incluir la entrada del usuario.
        logger.exception("Fallo de base de datos al buscar usuario")
        raise ErrorBaseDeDatos() from None

    if fila is None:
        logger.info("Búsqueda de usuario sin resultados")
        return None

    logger.info("Búsqueda de usuario con un resultado")
    return Usuario(id=fila[0], username=fila[1])


@app.post("/usuarios/buscar")
def buscar_usuario_endpoint(
    username: Annotated[str, Form(min_length=1, max_length=100)],
) -> Usuario:
    """Recibe el nombre desde un formulario y devuelve el usuario si existe."""
    # NOTA (A01 - Broken Access Control): en un entorno real, este endpoint debe
    # ir detrás de autenticación/autorización (p. ej. Depends(get_current_user))
    # antes de permitir consultar datos de otros usuarios.
    try:
        usuario = buscar_usuario_por_nombre(username)
    except ErrorBaseDeDatos:
        # Respuesta genérica: no se filtran detalles internos (A02).
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno del servidor",
        ) from None

    if usuario is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado",
        )

    return usuario
