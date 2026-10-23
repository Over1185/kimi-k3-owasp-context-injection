"""
Escenario: búsqueda de un usuario por nombre recibido desde un formulario.

Mitigaciones OWASP Top 10:2025 aplicadas:
- A01 Broken Access Control: el endpoint exige un usuario autenticado
  (dependencia `get_current_user`, denegación por defecto).
- A02 Security Misconfiguration: `debug=False`; las trazas internas no se
  devuelven al cliente.
- A04 Cryptographic Failures: la URL de la base de datos se toma del entorno;
  no hay secretos en el código fuente. El hash de contraseña nunca se expone.
- A05 Injection: consulta parametrizada vía ORM de SQLAlchemy; ninguna entrada
  del usuario se concatena en SQL.
- A09 Security Logging: se registra el evento sin datos sensibles ni entradas
  crudas del usuario (evita log injection).
- A10 Mishandling of Exceptional Conditions: solo se captura
  `SQLAlchemyError`; sin `except` genéricos ni vacíos.
"""

import logging
import os

from fastapi import Depends, FastAPI, Form, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, declarative_base, sessionmaker

logger = logging.getLogger(__name__)

# A04: el secreto (credenciales) vive en el entorno, no en el código fuente.
DATABASE_URL = os.environ["DATABASE_URL"]

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

MAX_NAME_LENGTH = 150
MAX_RESULTS = 50

app = FastAPI(debug=False)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(MAX_NAME_LENGTH), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)  # nunca se serializa


class UserPublic(BaseModel):
    """Representación pública: sin password_hash ni datos internos."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user() -> UserPublic:
    """Dependencia de autenticación/autorización (A01/A07).

    Debe verificar el token de sesión o JWT (firma y expiración) en cada
    solicitud y devolver el usuario autenticado. Deniega por defecto hasta
    integrarse con el módulo de autenticación real.
    """
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No autenticado",
    )


@app.post("/users/search", response_model=list[UserPublic])
def search_user_by_name(
    name: str = Form(..., min_length=1, max_length=MAX_NAME_LENGTH, strip_whitespace=True),
    db: Session = Depends(get_db),
    current_user: UserPublic = Depends(get_current_user),
) -> list[UserPublic]:
    """Busca usuarios por coincidencia exacta de nombre.

    La comparación exacta evita los riesgos de LIKE con comodines (% y _)
    controlados por el cliente. La entrada ya viene validada en longitud.
    """
    try:
        users = (
            db.query(User)
            .filter(User.username == name)  # parametrizado por el ORM (A05)
            .limit(MAX_RESULTS)
            .all()
        )
    except SQLAlchemyError:
        # A09/A10: traza solo en logs del servidor; mensaje genérico al cliente.
        logger.exception("Error de base de datos en búsqueda de usuario")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno del servidor",
        ) from None

    logger.info("Búsqueda de usuario ejecutada por user_id=%s", current_user.id)
    return users
