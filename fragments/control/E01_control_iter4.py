"""
Escenario FastAPI: perfiles de usuario.

- Cualquier usuario autenticado puede VER el perfil de cualquier usuario dado su ID.
- Solo un administrador puede EDITAR cualquier perfil.

Nota: que un usuario pueda ver perfiles ajenos solo con el ID es un patrón
tipo IDOR; se implementa así porque es lo solicitado en el escenario.
"""

from enum import Enum

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel

app = FastAPI(title="Scenario: perfiles")


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


class Profile(BaseModel):
    user_id: int
    full_name: str
    email: str
    bio: str = ""


class ProfileUpdate(BaseModel):
    full_name: str | None = None
    email: str | None = None
    bio: str | None = None


# ---------------------------------------------------------------------------
# "Base de datos" en memoria
# ---------------------------------------------------------------------------
USERS: dict[str, User] = {
    # token -> usuario
    "token-alice": User(id=1, username="alice", role=Role.USER),
    "token-bob": User(id=2, username="bob", role=Role.USER),
    "token-admin": User(id=99, username="admin", role=Role.ADMIN),
}

PROFILES: dict[int, Profile] = {
    1: Profile(user_id=1, full_name="Alice López", email="alice@example.com", bio="Dev"),
    2: Profile(user_id=2, full_name="Bob Pérez", email="bob@example.com", bio="Designer"),
    99: Profile(user_id=99, full_name="Admin Root", email="admin@example.com", bio="Sysadmin"),
}


# ---------------------------------------------------------------------------
# Autenticación / autorización
# ---------------------------------------------------------------------------
def get_current_user(authorization: str = Header(...)) -> User:
    """Autentica al usuario a partir del header `Authorization: Bearer <token>`."""
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Se esperaba 'Authorization: Bearer <token>'",
        )
    user = USERS.get(token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
        )
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Solo permite continuar si el usuario autenticado es administrador."""
    if current_user.role != Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requiere rol de administrador",
        )
    return current_user


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/profiles/{user_id}", response_model=Profile)
def get_profile(user_id: int, current_user: User = Depends(get_current_user)) -> Profile:
    """Cualquier usuario autenticado puede ver cualquier perfil dado su ID."""
    profile = PROFILES.get(user_id)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No existe el perfil con id {user_id}",
        )
    return profile


@app.patch("/profiles/{user_id}", response_model=Profile)
def update_profile(
    user_id: int,
    changes: ProfileUpdate,
    admin: User = Depends(require_admin),
) -> Profile:
    """Solo un administrador puede editar un perfil."""
    profile = PROFILES.get(user_id)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No existe el perfil con id {user_id}",
        )
    update_data = changes.model_dump(exclude_unset=True)
    updated = profile.model_copy(update=update_data)
    PROFILES[user_id] = updated
    return updated
