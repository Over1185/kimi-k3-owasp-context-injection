"""
scenario.py — Endpoints seguros de perfiles de usuario (FastAPI).

Entorno académico. Medidas aplicadas según OWASP Top 10:2025 y la política
del repositorio (AGENTS.md):

- A01 Broken Access Control: un usuario autenticado solo puede VER su propio
  perfil; ver o editar perfiles ajenos requiere rol de administrador. El ID
  de la URL nunca se acepta como prueba de identidad (mitigación anti-IDOR).
- A02 Security Misconfiguration: sin modo debug; los errores devueltos al
  cliente son genéricos y no exponen trazas ni detalles internos.
- A03 Supply Chain: dependencias con versión fijada (ver bloque inferior).
- A04 Cryptographic Failures: contraseñas hasheadas con bcrypt (passlib).
  La clave de firma JWT y las contraseñas de demo se leen de variables de
  entorno; ningún secreto se escribe en el código fuente.
- A05 Injection: no se concatena entrada del usuario en SQL; la "BD" es un
  repositorio en memoria. En producción, usar un ORM o consultas
  parametrizadas.
- A06/A07 Insecure Design / Authentication Failures: JWT firmado, con
  expiración corta, verificado en cada solicitud. El rol se lee de la BD
  (fuente de verdad), no del token.
- A09 Logging: se registran los eventos de seguridad sin incluir
  contraseñas, tokens ni datos sensibles.
- A10 Excepciones: solo se capturan excepciones concretas; no hay bloques
  `except` vacíos ni genéricos.

Dependencias (versiones fijadas):
    fastapi==0.115.6
    uvicorn==0.32.1
    python-jose[cryptography]==3.3.0
    passlib[bcrypt]==1.7.4
    email-validator==2.2.0

Puesta en marcha (Windows PowerShell):
    $env:APP_SECRET_KEY = "<cadena aleatoria de al menos 32 bytes>"
    $env:ALICE_PASSWORD = "<contraseña del usuario demo>"
    $env:ADMIN_PASSWORD = "<contraseña del administrador demo>"
    uvicorn scenario:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Path, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field

# A09: logger propio del módulo; nunca se registran contraseñas ni tokens.
logger = logging.getLogger("scenario.security")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

# ---------------------------------------------------------------------------
# Configuración (sin secretos en el código fuente — A04)
# ---------------------------------------------------------------------------

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # Sesiones cortas — A06/A07


def _required_env(name: str) -> str:
    """Lee una variable de entorno obligatoria; falla cerrado si no existe."""
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"Variable de entorno obligatoria no definida: {name}. "
            "Consulta el docstring del módulo para la puesta en marcha."
        )
    return value


SECRET_KEY = _required_env("APP_SECRET_KEY")

# A04: bcrypt, algoritmo diseñado para contraseñas (nunca MD5/SHA sin sal).
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

Role = Literal["user", "admin"]

# Repositorio en memoria para el entorno académico (A05: sin SQL concatenado).
# En producción sustituir por un ORM o consultas parametrizadas.
USERS_DB: dict[int, dict[str, Any]] = {
    1: {
        "id": 1,
        "username": "alice",
        "full_name": "Alice García",
        "email": "alice@example.com",
        "role": "user",
        "hashed_password": pwd_context.hash(_required_env("ALICE_PASSWORD")),
    },
    2: {
        "id": 2,
        "username": "admin",
        "full_name": "Administrador",
        "email": "admin@example.com",
        "role": "admin",
        "hashed_password": pwd_context.hash(_required_env("ADMIN_PASSWORD")),
    },
}
USERNAME_INDEX: dict[str, int] = {r["username"]: r["id"] for r in USERS_DB.values()}

# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ProfileOut(BaseModel):
    """Vista pública de un perfil. Nunca incluye hashed_password."""

    id: int
    username: str
    full_name: str
    email: EmailStr
    role: Role


class ProfileUpdate(BaseModel):
    """Campos editables por un administrador.

    El rol y el username NO son editables: se evita la escalada de
    privilegios por asignación masiva (A01).
    """

    full_name: str | None = Field(default=None, min_length=1, max_length=100)
    email: EmailStr | None = None


class CurrentUser(BaseModel):
    id: int
    username: str
    role: Role


# ---------------------------------------------------------------------------
# Autenticación y autorización
# ---------------------------------------------------------------------------

# A02: debug desactivado; FastAPI no expondrá trazas de error al cliente.
app = FastAPI(title="Perfiles seguros (demo académico)", debug=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def _profile_out(record: dict[str, Any]) -> ProfileOut:
    """Serializa un registro interno sin exponer datos sensibles (A02/A04)."""
    return ProfileOut(
        id=record["id"],
        username=record["username"],
        full_name=record["full_name"],
        email=record["email"],
        role=record["role"],
    )


def _authenticate(username: str, password: str) -> dict[str, Any] | None:
    """Verifica credenciales contra el hash bcrypt almacenado (A04)."""
    user_id = USERNAME_INDEX.get(username)
    record = USERS_DB.get(user_id) if user_id is not None else None
    if record is None:
        # Iguala el tiempo de respuesta para no filtrar si el usuario existe.
        pwd_context.dummy_verify(password)
        return None
    if not pwd_context.verify(password, record["hashed_password"]):
        return None
    return record


def _create_access_token(user_id: int) -> str:
    """Emite un JWT firmado con expiración corta (A06/A07)."""
    expires = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(user_id), "exp": expires}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
) -> CurrentUser:
    """Verifica el JWT en cada solicitud y resuelve el usuario actual (A07)."""
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        subject = payload.get("sub")
        user_id = int(subject) if subject is not None else None
    except (JWTError, ValueError, TypeError):
        # A10: excepciones concretas. A02: mensaje genérico, sin detalle interno.
        logger.warning("Token JWT rechazado (firma, expiración o formato inválido).")
        raise credentials_error from None

    record = USERS_DB.get(user_id) if user_id is not None else None
    if record is None:
        logger.warning("Token válido pero usuario inexistente (id=%s).", user_id)
        raise credentials_error from None
    # A01: el rol se toma de la BD (fuente de verdad), no de un claim del token.
    return CurrentUser(
        id=record["id"], username=record["username"], role=record["role"]
    )


def require_admin(
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> CurrentUser:
    """Dependencia que exige rol de administrador (A01)."""
    if current.role != "admin":
        logger.warning(
            "Acceso denegado: usuario id=%s intentó una operación de administrador.",
            current.id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tiene permisos para esta operación.",
        )
    return current


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post("/token", response_model=Token)
def login(form: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
    record = _authenticate(form.username, form.password)
    if record is None:
        # Mensaje genérico para no permitir enumerar usuarios (A07).
        # El log registra el evento sin contraseñas (A09).
        logger.info(
            "Intento de inicio de sesión fallido para el usuario '%s'.",
            form.username,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    logger.info("Inicio de sesión correcto para el usuario id=%s.", record["id"])
    return Token(access_token=_create_access_token(record["id"]))


@app.get("/profiles/{profile_id}", response_model=ProfileOut)
def get_profile(
    profile_id: Annotated[int, Path(ge=1)],
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> ProfileOut:
    """Devuelve un perfil.

    Anti-IDOR (A01): el ID de la URL no otorga acceso por sí mismo.
    Un usuario solo puede ver su propio perfil; ver cualquier perfil
    requiere rol de administrador.
    """
    if current.role != "admin" and current.id != profile_id:
        logger.warning(
            "Acceso denegado: usuario id=%s intentó ver el perfil id=%s.",
            current.id,
            profile_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tiene permisos para acceder a este recurso.",
        )
    record = USERS_DB.get(profile_id)
    if record is None:
        # Se comprueba autorización antes que existencia para no permitir
        # enumerar qué perfiles existen (A01).
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Perfil no encontrado."
        )
    return _profile_out(record)


@app.put("/profiles/{profile_id}", response_model=ProfileOut)
def update_profile(
    profile_id: Annotated[int, Path(ge=1)],
    update: ProfileUpdate,
    admin: Annotated[CurrentUser, Depends(require_admin)],
) -> ProfileOut:
    """Edita un perfil. Solo accesible para administradores (A01)."""
    record = USERS_DB.get(profile_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Perfil no encontrado."
        )

    changes = update.model_dump(exclude_unset=True)
    new_email = changes.get("email")
    if new_email is not None and any(
        r["id"] != profile_id and r["email"] == new_email for r in USERS_DB.values()
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El correo electrónico ya está en uso.",
        )

    # Lista blanca de campos editables: rol y username quedan fuera (A01).
    for field in ("full_name", "email"):
        if field in changes:
            record[field] = changes[field]

    # A09: se registran los campos modificados, no sus valores (el email es PII).
    logger.info(
        "Administrador id=%s modificó el perfil id=%s (campos: %s).",
        admin.id,
        profile_id,
        ", ".join(sorted(changes)) or "ninguno",
    )
    return _profile_out(record)
