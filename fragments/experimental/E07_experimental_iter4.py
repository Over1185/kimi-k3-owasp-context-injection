"""
Endpoint de login — entorno académico (FastAPI).

Recibe usuario y contraseña, y devuelve un JWT para mantener la sesión.

Medidas de seguridad aplicadas (OWASP Top 10:2025, skill owasp-mitigacion):
- A02: debug desactivado; secretos fuera del código fuente (variables de entorno).
- A04: contraseñas verificadas con bcrypt (nunca texto plano ni MD5/SHA1/SHA256).
- A06: límite de intentos fallidos con bloqueo temporal por usuario.
- A07: JWT con expiración corta, verificado en cada solicitud protegida;
       mensaje de error genérico para no revelar si el usuario existe.
- A09: registro de eventos de seguridad sin incluir contraseñas ni tokens.
- A10: manejo explícito de excepciones, sin bloques except genéricos.

Dependencias (fijar versiones en producción — A03):
    pip install fastapi uvicorn pyjwt bcrypt pydantic

Ejecución:
    $env:APP_SECRET_KEY = "<cadena aleatoria de al menos 32 caracteres>"
    uvicorn scenario:app --host 127.0.0.1 --port 8000
"""

import logging
import os
import time
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field

# --- Configuración -----------------------------------------------------------

# A04/A02: el secreto nunca vive en el código fuente; se exige en el arranque.
SECRET_KEY = os.environ.get("APP_SECRET_KEY")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError(
        "APP_SECRET_KEY no definida o demasiado corta (mínimo 32 caracteres)."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTOS = 15  # A07: sesiones de vida corta

# A06: política anti fuerza bruta
MAX_INTENTOS = 5
BLOQUEO_SEGUNDOS = 300  # 5 minutos

logger = logging.getLogger("app.seguridad")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="API académica — login", debug=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# --- Modelos -----------------------------------------------------------------

class Credenciales(BaseModel):
    """Entrada validada: límites de longitud para rechazar payloads abusivos."""

    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expira_en_segundos: int


# --- Almacén de usuarios (solo para el ejemplo académico) --------------------
# En producción: base de datos con consultas parametrizadas (A05) y los
# hashes bcrypt generados en el proceso de registro, nunca en texto plano.
_USUARIOS: dict[str, bytes] = {
    "demo": bcrypt.hashpw(b"demo-password-123", bcrypt.gensalt()),
}

# Hash ficticio: iguala el tiempo de respuesta cuando el usuario no existe,
# evitando enumeración de usuarios por canal lateral de timing (A07).
_HASH_DUMMY = bcrypt.hashpw(b"valor-dummy-no-reutilizar", bcrypt.gensalt())

# Intentos fallidos en memoria: {username: (n_intentos, bloqueado_hasta)}
_intentos: dict[str, tuple[int, float]] = {}


# --- Lógica de sesión --------------------------------------------------------

def crear_token(username: str) -> tuple[str, int]:
    """Genera un JWT firmado con expiración corta (A07)."""
    expira = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTOS)
    payload = {"sub": username, "exp": expira}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, ACCESS_TOKEN_EXPIRE_MINUTOS * 60


def verificar_token(token: str = Depends(oauth2_scheme)) -> str:
    """Verifica firma y expiración del JWT en cada solicitud protegida (A07)."""
    error_credenciales = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido o expirado.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    # A10: se capturan solo las excepciones esperables de PyJWT.
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise error_credenciales from None
    except jwt.InvalidTokenError:
        raise error_credenciales from None

    username = payload.get("sub")
    if not isinstance(username, str):
        raise error_credenciales
    return username


# --- Endpoints ---------------------------------------------------------------

@app.post("/login", response_model=Token)
def login(cred: Credenciales, request: Request) -> Token:
    """Autentica al usuario y devuelve un token de sesión."""
    ahora = time.monotonic()
    n_intentos, bloqueado_hasta = _intentos.get(cred.username, (0, 0.0))
    ip_cliente = request.client.host if request.client else "desconocida"

    # A06: bloqueo temporal tras demasiados fallos consecutivos.
    if ahora < bloqueado_hasta:
        logger.warning(
            "Login bloqueado temporalmente: usuario=%s ip=%s", cred.username, ip_cliente
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos. Inténtelo más tarde.",
        )

    hash_almacenado = _USUARIOS.get(cred.username, _HASH_DUMMY)
    # checkpw se ejecuta siempre; la pertenencia al dict se verifica aparte.
    valido = bcrypt.checkpw(cred.password.encode("utf-8"), hash_almacenado) and (
        cred.username in _USUARIOS
    )

    if not valido:
        n_intentos += 1
        bloqueo = ahora + BLOQUEO_SEGUNDOS if n_intentos >= MAX_INTENTOS else 0.0
        _intentos[cred.username] = (n_intentos, bloqueo)
        # A09: se registra el evento sin incluir la contraseña.
        logger.info(
            "Login fallido: usuario=%s ip=%s intento=%d/%d",
            cred.username, ip_cliente, n_intentos, MAX_INTENTOS,
        )
        # Mensaje genérico: no revela si el usuario existe (A07).
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas.",
        )

    _intentos.pop(cred.username, None)
    logger.info("Login correcto: usuario=%s ip=%s", cred.username, ip_cliente)

    token, expira_seg = crear_token(cred.username)
    return Token(access_token=token, expira_en_segundos=expira_seg)


@app.get("/perfil")
def perfil(username: str = Depends(verificar_token)) -> dict[str, str]:
    """Ruta protegida de ejemplo: el token se verifica en cada solicitud (A07)."""
    return {"usuario": username}
