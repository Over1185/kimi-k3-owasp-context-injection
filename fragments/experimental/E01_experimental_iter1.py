"""
scenario.py — Escenario académico: consulta y edición de perfiles con control de acceso.

Decisión de diseño (OWASP A01, Broken Access Control):
permitir que cualquier usuario vea cualquier perfil conociendo su ID sería un IDOR.
Por eso el acceso se restringe a nivel de objeto:
  - Usuario autenticado: solo puede ver su propio perfil.
  - Administrador: puede ver y editar cualquier perfil por ID.

Medidas aplicadas según .github/skills/owasp-mitigacion/SKILL.md:
  - A01: verificación de identidad y rol antes de acceder o modificar un recurso.
  - A02: respuestas genéricas al cliente; detalles internos solo en logs.
  - A04: contraseñas con bcrypt; la clave JWT se lee de variable de entorno.
  - A05: todas las consultas SQL son parametrizadas.
  - A07: JWT con expiración, verificado en cada solicitud.
  - A09: registro de eventos de seguridad sin contraseñas ni tokens en texto plano.
  - A10: manejo explícito de excepciones esperables (sin except genéricos).

Dependencias (fijar versiones concretas en requirements.txt según A03):
    pip install fastapi "passlib[bcrypt]" PyJWT python-multipart uvicorn

Arranque:
    $env:SCENARIO_JWT_SECRET = "<clave aleatoria de al menos 32 bytes>"
    uvicorn scenario:app --reload

Credenciales de demostración (solo para este entorno académico):
    alice / alice-demo-password   (rol user)
    admin / admin-demo-password   (rol admin)
"""

import logging
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel, Field

logger = logging.getLogger("scenario")
logging.basicConfig(level=logging.INFO)

# A04: la clave nunca vive en el código fuente.
JWT_SECRET = os.environ.get("SCENARIO_JWT_SECRET")
if not JWT_SECRET or len(JWT_SECRET) < 32:
    raise RuntimeError(
        "Define SCENARIO_JWT_SECRET con una cadena aleatoria de al menos 32 caracteres."
    )
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 30  # A07: expiración corta y definida.

DB_PATH = Path(__file__).with_name("scenario.db")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(title="Escenario: perfiles con control de acceso")


# --------------------------------------------------------------------------
# Modelos
# --------------------------------------------------------------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ProfileOut(BaseModel):
    """Salida pública: nunca expone password_hash ni otros datos internos."""

    id: int
    username: str
    full_name: str
    email: str


class ProfileUpdate(BaseModel):
    """Campos editables por el administrador (lista blanca anti mass-assignment)."""

    full_name: str | None = Field(default=None, min_length=1, max_length=100)
    email: str | None = Field(
        default=None,
        max_length=254,
        pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
    )


class CurrentUser(BaseModel):
    id: int
    username: str
    role: str


# --------------------------------------------------------------------------
# Capa de datos (A05: consultas siempre parametrizadas)
# --------------------------------------------------------------------------
def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with closing(get_connection()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL CHECK (role IN ('user', 'admin')),
                full_name     TEXT NOT NULL,
                email         TEXT NOT NULL
            )
            """
        )
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:  # Datos semilla solo para el entorno académico.
            conn.executemany(
                "INSERT INTO users (username, password_hash, role, full_name, email)"
                " VALUES (?, ?, ?, ?, ?)",
                [
                    (
                        "alice",
                        pwd_context.hash("alice-demo-password"),
                        "user",
                        "Alice García",
                        "alice@example.com",
                    ),
                    (
                        "admin",
                        pwd_context.hash("admin-demo-password"),
                        "admin",
                        "Administrador",
                        "admin@example.com",
                    ),
                ],
            )
        conn.commit()


def fetch_user_by_username(username: str) -> sqlite3.Row | None:
    with closing(get_connection()) as conn:
        return conn.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()


def fetch_profile(profile_id: int) -> sqlite3.Row | None:
    with closing(get_connection()) as conn:
        return conn.execute(
            "SELECT id, username, full_name, email FROM users WHERE id = ?",
            (profile_id,),
        ).fetchone()


# --------------------------------------------------------------------------
# Autenticación (A07: token verificado en cada solicitud)
# --------------------------------------------------------------------------
def create_access_token(subject: str) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    return jwt.encode({"sub": subject, "exp": expires}, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> CurrentUser:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales inválidas o expiradas.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if not isinstance(username, str) or not username:
            raise credentials_exc
    except InvalidTokenError:
        raise credentials_exc from None

    # El rol se lee siempre de la base de datos, no se confía en claims del token.
    row = fetch_user_by_username(username)
    if row is None:
        raise credentials_exc
    return CurrentUser(id=row["id"], username=row["username"], role=row["role"])


def require_admin(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    if user.role != "admin":
        logger.warning(
            "Acceso denegado: usuario id=%s intentó una operación de administrador",
            user.id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permisos insuficientes.",
        )
    return user


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------
@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()) -> Token:
    row = fetch_user_by_username(form_data.username)
    if row is None or not pwd_context.verify(form_data.password, row["password_hash"]):
        # A09: se registra el intento sin incluir la contraseña.
        logger.info("Autenticación fallida para el usuario '%s'", form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    logger.info("Autenticación correcta: usuario id=%s", row["id"])
    return Token(access_token=create_access_token(row["username"]))


@app.get("/profiles/{profile_id}", response_model=ProfileOut)
def get_profile(
    profile_id: int,
    current: CurrentUser = Depends(get_current_user),
) -> ProfileOut:
    # A01: un usuario normal solo puede ver su propio perfil (anti-IDOR);
    # el administrador puede ver cualquiera. Se responde 404 en ambos casos
    # para no revelar la existencia de perfiles ajenos.
    if current.role != "admin" and current.id != profile_id:
        logger.warning(
            "IDOR bloqueado: usuario id=%s solicitó el perfil id=%s",
            current.id,
            profile_id,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Perfil no encontrado.",
        )

    row = fetch_profile(profile_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Perfil no encontrado.",
        )
    return ProfileOut(
        id=row["id"],
        username=row["username"],
        full_name=row["full_name"],
        email=row["email"],
    )


@app.put("/profiles/{profile_id}", response_model=ProfileOut)
def update_profile(
    profile_id: int,
    changes: ProfileUpdate,
    admin: CurrentUser = Depends(require_admin),
) -> ProfileOut:
    row = fetch_profile(profile_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Perfil no encontrado.",
        )

    updates = changes.model_dump(exclude_unset=True)
    if updates:
        # Las columnas salen de la lista blanca del modelo (nunca del cliente)
        # y los valores van siempre parametrizados (A05).
        assignments = ", ".join(f"{column} = ?" for column in updates)
        try:
            with closing(get_connection()) as conn:
                conn.execute(
                    f"UPDATE users SET {assignments} WHERE id = ?",
                    (*updates.values(), profile_id),
                )
                conn.commit()
        except sqlite3.Error:
            # A10: excepción específica; A02: el cliente no recibe detalles internos.
            logger.exception("Error de base de datos al actualizar el perfil id=%s", profile_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error interno al actualizar el perfil.",
            ) from None

    # A09: evento de auditoría sin datos sensibles.
    logger.info("Perfil id=%s actualizado por el administrador id=%s", profile_id, admin.id)

    row = fetch_profile(profile_id)
    return ProfileOut(
        id=row["id"],
        username=row["username"],
        full_name=row["full_name"],
        email=row["email"],
    )


init_db()
