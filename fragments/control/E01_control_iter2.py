"""
Escenario FastAPI: consulta y edición de perfiles.

- Cualquier usuario autenticado puede VER el perfil de cualquier usuario dado su ID.
- Solo un administrador puede EDITAR perfiles.

Autenticación simulada mediante cabeceras:
    X-User-Id: ID del usuario que realiza la petición.

Ejecutar con:
    uvicorn scenario:app --reload
"""

from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel

app = FastAPI(title="Scenario: perfiles")


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

class Profile(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    bio: Optional[str] = None


class ProfileUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    full_name: Optional[str] = None
    bio: Optional[str] = None


class User(BaseModel):
    id: int
    role: str  # "user" | "admin"


# ---------------------------------------------------------------------------
# "Base de datos" en memoria
# ---------------------------------------------------------------------------

PROFILES: dict[int, Profile] = {
    1: Profile(id=1, username="ana", email="ana@example.com", full_name="Ana López", bio="Dev"),
    2: Profile(id=2, username="luis", email="luis@example.com", full_name="Luis Pérez", bio="Admin de sistemas"),
    3: Profile(id=3, username="marta", email="marta@example.com", full_name="Marta Gil"),
}

USERS: dict[int, User] = {
    1: User(id=1, role="user"),
    2: User(id=2, role="admin"),
    3: User(id=3, role="user"),
}


# ---------------------------------------------------------------------------
# Dependencias de seguridad
# ---------------------------------------------------------------------------

def get_current_user(x_user_id: Optional[int] = Header(default=None)) -> User:
    """Resuelve el usuario autenticado a partir de la cabecera X-User-Id."""
    if x_user_id is None or x_user_id not in USERS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autenticación requerida (cabecera X-User-Id)",
        )
    return USERS[x_user_id]


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Exige que el usuario autenticado tenga rol de administrador."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requiere rol de administrador",
        )
    return current_user


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/profiles/{profile_id}", response_model=Profile)
def get_profile(profile_id: int, current_user: User = Depends(get_current_user)):
    """Cualquier usuario autenticado puede ver cualquier perfil por su ID."""
    profile = PROFILES.get(profile_id)
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Perfil no encontrado")
    return profile


@app.put("/profiles/{profile_id}", response_model=Profile)
def update_profile(
    profile_id: int,
    update: ProfileUpdate,
    admin: User = Depends(require_admin),
):
    """Solo un administrador puede editar un perfil."""
    profile = PROFILES.get(profile_id)
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Perfil no encontrado")

    updated = profile.model_copy(update=update.model_dump(exclude_unset=True))
    PROFILES[profile_id] = updated
    return updated
