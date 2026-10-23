"""
Scenario: perfiles de usuario con FastAPI.

- Cualquier usuario autenticado puede VER el perfil de cualquier otro usuario dado su ID.
- Solo un administrador puede EDITAR cualquier perfil.

Autenticación simulada mediante cabeceras (solo para fines de demostración):
    X-User-Id: ID del usuario que hace la petición
"""

from enum import Enum
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

class Role(str, Enum):
    USER = "user"
    ADMIN = "admin"


class Profile(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    role: Role = Role.USER


class ProfileUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[Role] = None


# ---------------------------------------------------------------------------
# "Base de datos" en memoria
# ---------------------------------------------------------------------------

PROFILES: dict[int, Profile] = {
    1: Profile(id=1, username="alice", email="alice@example.com",
               full_name="Alice Smith", role=Role.ADMIN),
    2: Profile(id=2, username="bob", email="bob@example.com",
               full_name="Bob Jones", role=Role.USER),
    3: Profile(id=3, username="carol", email="carol@example.com",
               full_name="Carol Davis", role=Role.USER),
}


# ---------------------------------------------------------------------------
# Dependencias de autenticación / autorización
# ---------------------------------------------------------------------------

def get_current_user(x_user_id: int = Header(...)) -> Profile:
    """Simula la autenticación: identifica al usuario por la cabecera X-User-Id."""
    user = PROFILES.get(x_user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no autenticado o inexistente",
        )
    return user


def require_admin(current_user: Profile = Depends(get_current_user)) -> Profile:
    """Solo deja pasar a usuarios con rol de administrador."""
    if current_user.role != Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requieren permisos de administrador",
        )
    return current_user


# ---------------------------------------------------------------------------
# Aplicación y endpoints
# ---------------------------------------------------------------------------

app = FastAPI(title="Scenario - Perfiles")


@app.get("/profiles/{profile_id}", response_model=Profile)
def get_profile(
    profile_id: int,
    current_user: Profile = Depends(get_current_user),
):
    """Cualquier usuario autenticado puede ver el perfil de cualquier usuario."""
    profile = PROFILES.get(profile_id)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Perfil no encontrado",
        )
    return profile


@app.patch("/profiles/{profile_id}", response_model=Profile)
def update_profile(
    profile_id: int,
    update: ProfileUpdate,
    admin: Profile = Depends(require_admin),
):
    """Solo un administrador puede editar perfiles."""
    profile = PROFILES.get(profile_id)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Perfil no encontrado",
        )
    updated = profile.model_copy(update=update.model_dump(exclude_unset=True))
    PROFILES[profile_id] = updated
    return updated
