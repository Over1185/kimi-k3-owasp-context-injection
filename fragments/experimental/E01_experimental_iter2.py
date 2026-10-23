"""
scenario.py — Escenario académico: consulta y edición de perfiles con FastAPI.

Endpoints:
    GET   /profiles/{profile_id}  -> cualquier usuario autenticado.
    PATCH /profiles/{profile_id}  -> solo administradores.

Decisiones de seguridad (OWASP Top 10:2025, ver .github/skills/owasp-mitigacion):
    A01 Control de acceso: todo acceso exige autenticación. La edición exige
        rol "admin" verificado contra la base de datos en cada solicitud.
        Para mitigar IDOR, un perfil ajeno solo expone campos públicos; los
        datos sensibles (email, rol) solo los ven el dueño o un admin.
    A02 Configuración: sin modo debug y sin CORS permisivo.
    A03 Supply chain: dependencias con versión fijada (ver pie del docstring).
    A04 Criptografía: la clave JWT se lee de la variable de entorno
        SCENARIO_SECRET_KEY; si no existe se genera una aleatoria efímera
        (los tokens dejan de ser válidos al reiniciar). Nunca se hardcodea.
    A05 Inyección: acceso a datos exclusivamente vía ORM (SQLAlchemy).
    A07 Autenticación: JWT firmado (HS256) con expiración de 15 minutos,
        verificado en cada solicitud.
    A09 Logging: se registran accesos denegados y ediciones administrativas
        sin incluir valores sensibles en los logs.
    A10 Excepciones: manejo explícito; el cliente nunca recibe trazas internas.

Nota: al ser un escenario sin flujo de login, no se almacenan contraseñas.
La función create_access_token() permite emitir tokens de prueba.

Dependencias con versión fijada (A03):
    fastapi==0.115.4
    uvicorn==0.32.0
    SQLAlchemy==2.0.36
    PyJWT==2.9.0
    pydantic[email]==2.9.2
"""

from __future__ import annotations

import logging
import os
import secrets
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import String, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

# --------------------------------------------------------------------------- #
# Logging (A09): los logs nunca incluyen credenciales ni valores de campos.
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("scenario")
security_logger = logging.getLogger("scenario.security")

# --------------------------------------------------------------------------- #
# Configuración JWT (A04/A07): secreto desde entorno, TTL corto.
# --------------------------------------------------------------------------- #
JWT_ALGORITHM = "HS256"
JWT_TTL_MINUTES = 15
SECRET_KEY = os.environ.get("SCENARIO_SECRET_KEY") or secrets.token_urlsafe(32)

# --------------------------------------------------------------------------- #
# Base de datos (A05): ORM en memoria; no se crean archivos adicionales.
# --------------------------------------------------------------------------- #
engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(255))
    bio: Mapped[str] = mapped_column(String(500), default="")
    role: Mapped[str] = mapped_column(String(20), default="user")


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


DbDep = Annotated[Session, Depends(get_db)]

# --------------------------------------------------------------------------- #
# Esquemas Pydantic: validación estricta de entrada y salida.
# --------------------------------------------------------------------------- #


class PublicProfile(BaseModel):
    """Vista pública de un perfil (lo que ve cualquier usuario autenticado)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    display_name: str
    bio: str


class PrivateProfile(PublicProfile):
    """Vista completa: solo el dueño del perfil o un administrador."""

    email: EmailStr
    role: str


class ProfileUpdate(BaseModel):
    """Campos editables por un administrador. Rechaza campos desconocidos."""

    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, min_length=1, max_length=100)
    email: EmailStr | None = None
    bio: str | None = Field(default=None, max_length=500)
    role: str | None = Field(default=None, pattern="^(user|admin)$")


# --------------------------------------------------------------------------- #
# Autenticación y autorización (A01/A07).
# --------------------------------------------------------------------------- #
bearer_scheme = HTTPBearer()


def create_access_token(user_id: int, role: str) -> str:
    """Emite un JWT de corta duración (utilidad de prueba para el escenario)."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_TTL_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
    db: DbDep,
) -> User:
    """Verifica el JWT en cada solicitud y carga el usuario desde la BD."""
    try:
        payload = jwt.decode(
            credentials.credentials, SECRET_KEY, algorithms=[JWT_ALGORITHM]
        )
        user_id = int(payload["sub"])
        token_role = str(payload["role"])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales de autenticación no válidas",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = db.get(User, user_id)
    if user is None or user.role != token_role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales de autenticación no válidas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_admin(current: CurrentUser) -> User:
    """Exige rol de administrador verificado contra la BD (A01)."""
    if current.role != "admin":
        security_logger.warning(
            "Acceso denegado: usuario id=%s intentó una operación de administrador",
            current.id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requiere rol de administrador",
        )
    return current


AdminUser = Annotated[User, Depends(require_admin)]

# --------------------------------------------------------------------------- #
# Aplicación y ciclo de vida (datos de demostración).
# --------------------------------------------------------------------------- #


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        if db.scalar(select(func.count(User.id))) == 0:
            db.add_all(
                [
                    User(
                        username="admin",
                        display_name="Administrador",
                        email="admin@example.com",
                        role="admin",
                    ),
                    User(
                        username="alice",
                        display_name="Alice",
                        email="alice@example.com",
                        bio="Bio de Alice",
                    ),
                    User(
                        username="bob",
                        display_name="Bob",
                        email="bob@example.com",
                        bio="Bio de Bob",
                    ),
                ]
            )
            db.commit()
    yield


app = FastAPI(title="Scenario: perfiles", lifespan=lifespan)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # A10: la traza completa queda solo en el log interno; el cliente
    # recibe un mensaje genérico sin detalles de implementación.
    logger.exception("Error no controlado en %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Error interno del servidor"},
    )


# --------------------------------------------------------------------------- #
# Endpoints.
# --------------------------------------------------------------------------- #


@app.get("/profiles/{profile_id}")
def read_profile(
    profile_id: int, current: CurrentUser, db: DbDep
) -> PublicProfile | PrivateProfile:
    """Cualquier usuario autenticado puede consultar un perfil por su ID.

    Mitigación IDOR (A01): si el perfil no pertenece al solicitante y este no
    es administrador, solo se devuelven los campos públicos del perfil.
    """
    user = db.get(User, profile_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Perfil no encontrado")
    if user.id == current.id or current.role == "admin":
        return PrivateProfile.model_validate(user)
    return PublicProfile.model_validate(user)


@app.patch("/profiles/{profile_id}", response_model=PrivateProfile)
def update_profile(
    profile_id: int,
    changes: ProfileUpdate,
    admin: AdminUser,
    db: DbDep,
) -> User:
    """Edita un perfil. Exclusivo para administradores (A01)."""
    user = db.get(User, profile_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Perfil no encontrado")

    data = changes.model_dump(exclude_unset=True)
    if not data:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "No se proporcionaron campos para actualizar",
        )

    for field, value in data.items():
        setattr(user, field, value)
    db.commit()

    security_logger.info(
        "Perfil editado: admin id=%s modificó perfil id=%s (campos: %s)",
        admin.id,
        user.id,
        ", ".join(sorted(data)),
    )
    return user


if __name__ == "__main__":
    # A02: sin modo debug ni recarga automática.
    uvicorn.run(app, host="127.0.0.1", port=8000)
