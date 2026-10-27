"""Login de API (FastAPI).

Recibe usuario y contraseña y devuelve un JWT firmado y con expiración
para mantener la sesión. Cumple el checklist OWASP Top 10:2025 del repo.

Dependencias (fijar versiones en producción, A03):
    fastapi, PyJWT, pwdlib[argon2]

Variables de entorno requeridas:
    API_SECRET_KEY: clave de firma del JWT (nunca en el código, A04).
"""

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from threading import Lock

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from pwdlib import PasswordHash

# --- Configuración (A02: sin debug, sin secretos hardcodeados) ---
SECRET_KEY = os.environ.get("API_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Falta la variable de entorno API_SECRET_KEY")

ALGORITHM = "HS256"
TOKEN_TTL_MINUTOS = 30
MAX_INTENTOS = 5          # A06: límite de intentos en flujo sensible
VENTANA_SEGUNDOS = 300

logger = logging.getLogger("auth")
logging.basicConfig(level=logging.INFO)

app = FastAPI(debug=False)
password_hasher = PasswordHash.recommended()  # Argon2id (A04)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# --- Modelos de entrada/salida ---
class Credenciales(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


# --- Almacén de usuarios simulado ---
# En producción: base de datos con consultas parametrizadas (A05).
USUARIOS: dict[str, str] = {
    "alice": password_hasher.hash("cambiar-en-produccion"),
}
# Hash señuelo para igualar el tiempo de respuesta si el usuario no existe
# (evita enumeración de usuarios).
DUMMY_HASH = password_hasher.hash("contrasena-senuelo")


# --- Limitador de intentos en memoria (A06) ---
class LimitadorIntentos:
    def __init__(self, max_intentos: int, ventana: int) -> None:
        self._max = max_intentos
        self._ventana = ventana
        self._intentos: dict[str, list[float]] = {}
        self._lock = Lock()

    def permitido(self, clave: str) -> bool:
        ahora = time.monotonic()
        with self._lock:
            recientes = [
                t for t in self._intentos.get(clave, [])
                if ahora - t < self._ventana
            ]
            self._intentos[clave] = recientes
            return len(recientes) < self._max

    def registrar_fallo(self, clave: str) -> None:
        with self._lock:
            self._intentos.setdefault(clave, []).append(time.monotonic())


limitador = LimitadorIntentos(MAX_INTENTOS, VENTANA_SEGUNDOS)


# --- Endpoints ---
@app.post("/login", response_model=Token)
def login(cred: Credenciales, request: Request) -> Token:
    host = request.client.host if request.client else "desconocido"
    clave = f"{cred.username}:{host}"

    if not limitador.permitido(clave):
        logger.warning("Intentos excedidos: usuario=%s", cred.username)
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos. Intente más tarde.",
        )

    hash_almacenado = USUARIOS.get(cred.username, DUMMY_HASH)
    if not password_hasher.verify(cred.password, hash_almacenado):
        limitador.registrar_fallo(clave)
        # A09: log sin contraseña ni datos sensibles; mensaje genérico al cliente
        logger.info("Login fallido: usuario=%s", cred.username)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
        )

    ahora = datetime.now(timezone.utc)
    expira = ahora + timedelta(minutes=TOKEN_TTL_MINUTOS)
    payload = {"sub": cred.username, "iat": ahora, "exp": expira}  # A07
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    logger.info("Login correcto: usuario=%s", cred.username)
    return Token(access_token=token, expires_in=TOKEN_TTL_MINUTOS * 60)


def usuario_actual(token: str = Depends(oauth2_scheme)) -> str:
    """Verifica el JWT en cada solicitud (A07) y devuelve la identidad (A01)."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Token expirado"
        ) from None
    except jwt.InvalidTokenError:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Token inválido"
        ) from None

    username = payload.get("sub")
    if not isinstance(username, str):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
    return username


@app.get("/me")
def me(username: str = Depends(usuario_actual)) -> dict[str, str]:
    return {"username": username}
