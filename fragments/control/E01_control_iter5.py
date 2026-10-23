"""Escenario FastAPI: consulta y edición de perfiles.

- Cualquier usuario autenticado puede VER el perfil de cualquier usuario dado su ID.
- Solo un administrador puede EDITAR los datos de un perfil.

Autenticación simulada mediante cabecera `X-Token` contra usuarios en memoria.
Ejecutar con: uvicorn scenario:app --reload
"""

from enum import Enum
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, EmailStr

app = FastAPI(title="Scenario API - Perfiles")


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------
class Role(str, Enum):
    USER = "user"
    ADMIN = "admin"


class User(BaseModel):
    id: int
    username: str
    role: Role
    token: str


class Profile(BaseModel):
    id: int
    username: str
    full_name: str
    email: EmailStr
    bio: Optional[str] = None


class ProfileUpdate(BaseModel):
    """Campos editables de un perfil (todos opcionales para PATCH)."""

    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    bio: Optional[str] = None


# ---------------------------------------------------------------------------
# "Base de datos" en memoria
# ---------------------------------------------------------------------------
USERS: dict[str, User] = {
    "token-user-1": User(id=1, username="ana", role=Role.USER, token="token-user-1"),
    "token-user-2": User(id=2, username="luis", role=Role.USER, token="token-user-2"),
    "token-admin": User(id=99, username="root", role=Role.ADMIN, token="token-admin"),
}

PROFILES: dict[int, Profile] = {
    1: Profile(id=1, username="ana", full_name="Ana García", email="ana@example.com", bio="Dev"),
    2: Profile(id=2, username="luis", full_name="Luis Pérez", email="luis@example.com"),
    99: Profile(id=99, username="root", full_name="Administrador", email="root@example.com"),
}


# ---------------------------------------------------------------------------
# Dependencias de seguridad
# ---------------------------------------------------------------------------
async def get_current_user(x_token: str = Header(...)) -> User:
    """Resuelve el usuario autenticado a partir de la cabecera X-Token."""
    user = USERS.get(x_token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o ausente",
        )
    return user


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Exige que el usuario autenticado tenga rol de administrador."""
    if current_user.role != Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requieren privilegios de administrador",
        )
    return current_user


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/profiles/{profile_id}", response_model=Profile)
async def get_profile(
    profile_id: int,
    current_user: User = Depends(get_current_user),
) -> Profile:
    """Ver los datos de cualquier perfil dado su ID (requiere estar autenticado)."""
    profile = PROFILES.get(profile_id)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Perfil {profile_id} no encontrado",
        )
    return profile


@app.patch("/profiles/{profile_id}", response_model=Profile)
async def update_profile(
    profile_id: int,
    changes: ProfileUpdate,
    admin: User = Depends(require_admin),
) -> Profile:
    """Editar los datos de un perfil (solo administradores)."""
    profile = PROFILES.get(profile_id)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Perfil {profile_id} no encontrado",
        )

    update_data = changes.model_dump(exclude_unset=True)
    updated_profile = profile.model_copy(update=update_data)
    PROFILES[profile_id] = updated_profile
    return updated_profile
