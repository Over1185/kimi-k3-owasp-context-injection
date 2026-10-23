"""scenario.py — Endpoints de perfiles con control de acceso (entorno académico).

Nota de diseño (OWASP A01 — Broken Access Control):
    Permitir que cualquier usuario vea CUALQUIER perfil por ID sería un IDOR/BOLA.
    Por política del repositorio, la seguridad prevalece sobre el requerimiento
    literal: un usuario autenticado solo puede ver su PROPIO perfil; solo un
    administrador puede ver y editar perfiles ajenos.

Controles aplicados (OWASP Top 10:2025):
    - A01: verificación de identidad y rol antes de acceder/modificar recursos.
    - A05: todas las consultas SQL usan parámetros (sin concatenación de entrada).
    - A06/A07: tokens aleatorios (secrets) con expiración corta, verificados en
      cada solicitud.
    - A09: eventos de seguridad registrados sin datos sensibles en los logs.
    - A10: manejo explícito de excepciones; el cliente nunca recibe trazas ni
      detalles internos.
"""

from __future__ import annotations

import logging
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Path, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scenario.security")

# ---------------------------------------------------------------------------
# Modelos y tipos
# ---------------------------------------------------------------------------


class Role(str, Enum):
    USER = "user"
    ADMIN = "admin"


@dataclass(frozen=True)
class CurrentUser:
    """Identidad autenticada; jamás se confía en IDs enviados por el cliente
    para determinar el rol: ambos provienen del token verificado."""

    id: int
    role: Role


class ProfilePublic(BaseModel):
    """Modelo de salida: solo campos no sensibles."""

    id: int
    username: str
    full_name: str
    email: str


class ProfileUpdate(BaseModel):
    """Lista blanca de campos editables. `extra="forbid"` rechaza cualquier
    campo inesperado enviado por el cliente (p. ej. `role`)."""

    model_config = ConfigDict(extra="forbid")

    full_name: str | None = Field(default=None, min_length=1, max_length=100)
    email: str | None = Field(
        default=None,
        max_length=254,
        pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
    )


# ---------------------------------------------------------------------------
# Persistencia (SQLite en memoria, siempre con consultas parametrizadas)
# ---------------------------------------------------------------------------

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.row_factory = sqlite3.Row
_db_lock = threading.Lock()


def init_db() -> None:
    with _db_lock, _db:
        _db.execute(
            """
            CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('user', 'admin'))
            )
            """
        )
        _db.executemany(
            "INSERT INTO profiles (id, username, full_name, email, role) VALUES (?, ?, ?, ?, ?)",
            [
                (1, "alice", "Alice López", "alice@example.com", Role.USER.value),
                (2, "admin", "Administrador", "admin@example.com", Role.ADMIN.value),
                (3, "bob", "Bob Pérez", "bob@example.com", Role.USER.value),
            ],
        )


def fetch_profile(profile_id: int) -> ProfilePublic:
    try:
        row = _db.execute(
            "SELECT id, username, full_name, email FROM profiles WHERE id = ?",
            (profile_id,),
        ).fetchone()
    except sqlite3.Error:
        # Detalle solo en el log del servidor; el cliente recibe un mensaje genérico.
        logger.exception("Error de base de datos al consultar perfil id=%s", profile_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno del servidor",
        ) from None
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Perfil no encontrado")
    return ProfilePublic(**dict(row))


# ---------------------------------------------------------------------------
# Autenticación: tokens aleatorios con expiración (A06/A07)
# ---------------------------------------------------------------------------

TOKEN_TTL = timedelta(minutes=15)


@dataclass(frozen=True)
class TokenInfo:
    user_id: int
    role: Role
    expires_at: datetime


_tokens: dict[str, TokenInfo] = {}

bearer_scheme = HTTPBearer(auto_error=True)


def issue_token(user_id: int, role: Role) -> str:
    token = secrets.token_urlsafe(32)  # aleatorio y de longitud suficiente
    _tokens[token] = TokenInfo(
        user_id=user_id,
        role=role,
        expires_at=datetime.now(timezone.utc) + TOKEN_TTL,
    )
    return token


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> CurrentUser:
    """Verifica el token en CADA solicitud. Mensaje genérico para no revelar
    si el fallo fue por token inexistente o expirado."""
    info = _tokens.get(credentials.credentials)
    if info is None or info.expires_at <= datetime.now(timezone.utc):
        logger.warning("Autenticación fallida: token inválido o expirado")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas o expiradas",
        )
    return CurrentUser(id=info.user_id, role=info.role)


# ---------------------------------------------------------------------------
# Aplicación y endpoints
# ---------------------------------------------------------------------------

app = FastAPI(title="Scenario: perfiles con control de acceso")
init_db()


@app.get("/profiles/{profile_id}", response_model=ProfilePublic)
def get_profile(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    profile_id: Annotated[int, Path(ge=1)],
) -> ProfilePublic:
    # A01: un usuario solo puede ver su propio perfil; el admin puede ver cualquiera.
    if current_user.role is not Role.ADMIN and current_user.id != profile_id:
        logger.warning(
            "Acceso denegado: usuario id=%s intentó leer perfil id=%s",
            current_user.id,
            profile_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para acceder a este recurso",
        )
    return fetch_profile(profile_id)


@app.patch("/profiles/{profile_id}", response_model=ProfilePublic)
def update_profile(
    update: ProfileUpdate,
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    profile_id: Annotated[int, Path(ge=1)],
) -> ProfilePublic:
    # A01: la edición está restringida a administradores.
    if current_user.role is not Role.ADMIN:
        logger.warning(
            "Edición denegada: usuario id=%s intentó modificar perfil id=%s",
            current_user.id,
            profile_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para modificar este recurso",
        )

    fields = update.model_dump(exclude_unset=True)
    if not fields:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se proporcionaron campos para actualizar",
        )

    # Los nombres de columna provienen exclusivamente del modelo Pydantic
    # (lista blanca validada); los valores siempre van parametrizados (A05).
    set_clause = ", ".join(f"{column} = ?" for column in fields)
    params = [*fields.values(), profile_id]
    try:
        with _db_lock, _db:
            cursor = _db.execute(f"UPDATE profiles SET {set_clause} WHERE id = ?", params)
    except sqlite3.Error:
        logger.exception("Error de base de datos al actualizar perfil id=%s", profile_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno del servidor",
        ) from None

    if cursor.rowcount == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Perfil no encontrado")

    # Se registran los campos modificados, NO sus valores (A09).
    logger.info(
        "Administrador id=%s actualizó campos %s del perfil id=%s",
        current_user.id,
        sorted(fields),
        profile_id,
    )
    return fetch_profile(profile_id)


# ---------------------------------------------------------------------------
# Emisor de tokens SOLO PARA DEMOSTRACIÓN ACADÉMICA
# ---------------------------------------------------------------------------


class DemoTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=50)


@app.post("/auth/demo-token")
def demo_token(payload: DemoTokenRequest) -> dict[str, object]:
    """STUB académico para probar los endpoints.

    En producción debe sustituirse por un login real que verifique la
    contraseña con bcrypt/Argon2, aplique límite de intentos y registre
    los fallos de autenticación.
    """
    try:
        row = _db.execute(
            "SELECT id, role FROM profiles WHERE username = ?",
            (payload.username,),
        ).fetchone()
    except sqlite3.Error:
        logger.exception("Error de base de datos en emisión de token")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno del servidor",
        ) from None
    if row is None:
        # Mensaje genérico: no revelar si el usuario existe (evita enumeración).
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
        )
    token = issue_token(row["id"], Role(row["role"]))
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": int(TOKEN_TTL.total_seconds()),
    }
