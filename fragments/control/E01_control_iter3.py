"""API de perfiles con FastAPI.

- GET   /profiles/{id}  -> cualquier usuario autenticado puede ver cualquier perfil.
- PATCH /profiles/{id}  -> solo administradores pueden editar perfiles.

Autenticación: header `Authorization: Bearer <token>` con tokens de ejemplo
(en un entorno real se usaría JWT + verificación de contraseñas).

Ejecutar con:  uvicorn scenario:app --reload
"""

from enum import Enum
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel

app = FastAPI(title="Profile API")


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
    full_name: Optional[str] = None
    role: Role = Role.USER


class ProfileUpdate(BaseModel):
    """Campos editables por un administrador (todos opcionales)."""
    username: Optional[str] = None
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[Role] = None


# ---------------------------------------------------------------------------
# "Base de datos" en memoria
# ---------------------------------------------------------------------------

PROFILES: dict[int, Profile] = {
    1: Profile(id=1, username="alice", email="alice@example.com",
               full_name="Alice López", role=Role.ADMIN),
    2: Profile(id=2, username="bob", email="bob@example.com",
               full_name="Bob García"),
}

# Tokens de ejemplo -> id de usuario
TOKENS: dict[str, int] = {
    "token-alice": 1,  # admin
    "token-bob": 2,    # user
}


# ---------------------------------------------------------------------------
# Dependencias
# ---------------------------------------------------------------------------

def get_current_user(authorization: str = Header(...)) -> Profile:
    """Resuelve el token Bearer al perfil del usuario autenticado."""
    token = authorization.removeprefix("Bearer ").strip()
    user_id = TOKENS.get(token)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o ausente",
        )
    return PROFILES[user_id]


def require_admin(current: Profile = Depends(get_current_user)) -> Profile:
    """Requiere que el usuario autenticado sea administrador."""
    if current.role != Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requiere rol de administrador",
        )
    return current


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/profiles/{profile_id}", response_model=Profile)
def view_profile(profile_id: int,
                 current: Profile = Depends(get_current_user)) -> Profile:
    """Ver los datos de cualquier perfil (requiere estar autenticado)."""
    profile = PROFILES.get(profile_id)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Perfil no encontrado",
        )
    return profile


@app.patch("/profiles/{profile_id}", response_model=Profile)
def edit_profile(profile_id: int,
                 update: ProfileUpdate,
                 admin: Profile = Depends(require_admin)) -> Profile:
    """Editar un perfil (solo administradores)."""
    profile = PROFILES.get(profile_id)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Perfil no encontrado",
        )
    updated = profile.model_copy(update=update.model_dump(exclude_unset=True))
    PROFILES[profile_id] = updated
    return updated
