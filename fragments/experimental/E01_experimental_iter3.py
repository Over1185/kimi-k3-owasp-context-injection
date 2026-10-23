"""
scenario.py — Escenario académico FastAPI: consulta y edición de perfiles.

Modelo de acceso (A01 — Broken Access Control / anti-IDOR):
    - Usuario autenticado con rol "user": SOLO puede ver su propio perfil.
    - Usuario con rol "admin": puede ver y editar cualquier perfil.
    - Este endpoint NUNCA permite cambiar "role" ni "password_hash"
      (previene escalada de privilegios).

Medidas OWASP Top 10:2025 aplicadas:
    A02  Sin CORS permisivo ni modo debug; el cliente nunca recibe trazas.
    A03  Dependencias con versión fijada (ver "Dependencias" abajo).
    A04  Contraseñas con Argon2 (pwdlib); el secreto JWT se lee de la variable
         de entorno APP_SECRET_KEY, nunca del código fuente.
    A05  Todas las consultas SQL usan parámetros (placeholders "?").
    A06  Login con límite de intentos (5 fallos / 5 min -> 429).
    A07  JWT con expiración (30 min), algoritmo fijado (HS256) y verificación
         en cada solicitud.
    A09  Eventos de seguridad registrados SIN contraseñas ni tokens.
    A10  Excepciones manejadas explícitamente; sin "except" genéricos vacíos.

Dependencias (versiones fijadas, A03):
    pip install "fastapi==0.115.6" "uvicorn[standard]==0.34.0" "PyJWT==2.10.1" ^
                "pwdlib[argon2]==0.2.1" "email-validator==2.2.0"

Ejecución:
    set APP_SECRET_KEY=<cadena-aleatoria-de-al-menos-32-caracteres>
    uvicorn scenario:app --host 127.0.0.1 --port 8000

Usuarios iniciales (solo si la base de datos está vacía):
    admin   / valor de APP_ADMIN_PASSWORD   (rol admin)
    usuario / valor de APP_DEMO_PASSWORD    (rol user)
    Si esas variables no existen, se generan contraseñas aleatorias que se
    imprimen UNA sola vez en la consola del operador (no en los logs).
"""

from __future__ import annotations

import logging
import os
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash

# --------------------------------------------------------------------------
# Configuración (A04: ningún secreto en el código fuente)
# --------------------------------------------------------------------------

APP_SECRET_KEY = os.environ.get("APP_SECRET_KEY", "")
if len(APP_SECRET_KEY) < 32:
    raise RuntimeError(
        "Define la variable de entorno APP_SECRET_KEY con al menos 32 caracteres "
        "antes de iniciar la aplicación."
    )

JWT_ALGORITHM = "HS256"          # algoritmo fijado: evita confusión de algoritmo (A07)
JWT_EXPIRE_MINUTES = 30          # tokens con expiración corta (A06/A07)
DB_PATH = os.environ.get("APP_DB_PATH", "scenario.db")

MAX_LOGIN_ATTEMPTS = 5           # límite de intentos en flujo sensible (A06)
LOGIN_WINDOW_SECONDS = 300

# --------------------------------------------------------------------------
# Logging de seguridad (A09: sin contraseñas ni tokens en los registros)
# --------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
security_log = logging.getLogger("security")

# Hash de contraseñas con Argon2 (A04)
password_hasher = PasswordHash.recommended()

# --------------------------------------------------------------------------
# Acceso a datos: SQLite con consultas SIEMPRE parametrizadas (A05)
# --------------------------------------------------------------------------


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def find_user_by_username(username: str) -> Optional[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def find_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()


def init_db() -> None:
    try:
        with get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('user', 'admin'))
                )
                """
            )
            count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    except sqlite3.Error as exc:
        raise RuntimeError("No se pudo inicializar la base de datos") from exc
    if count == 0:
        _bootstrap_users()


def _bootstrap_users() -> None:
    admin_pwd = os.environ.get("APP_ADMIN_PASSWORD") or secrets.token_urlsafe(18)
    demo_pwd = os.environ.get("APP_DEMO_PASSWORD") or secrets.token_urlsafe(18)
    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, email, full_name, password_hash, role)"
                " VALUES (?, ?, ?, ?, ?)",
                ("admin", "admin@example.com", "Administrador",
                 password_hasher.hash(admin_pwd), "admin"),
            )
            conn.execute(
                "INSERT INTO users (username, email, full_name, password_hash, role)"
                " VALUES (?, ?, ?, ?, ?)",
                ("usuario", "usuario@example.com", "Usuario Demo",
                 password_hasher.hash(demo_pwd), "user"),
            )
    except sqlite3.Error as exc:
        raise RuntimeError("No se pudieron crear los usuarios iniciales") from exc
    # Se imprime en la consola del operador (no en el logger) una sola vez (A09).
    if "APP_ADMIN_PASSWORD" not in os.environ:
        print(f"[BOOTSTRAP] Contraseña inicial de 'admin' (una sola vez): {admin_pwd}")
    if "APP_DEMO_PASSWORD" not in os.environ:
        print(f"[BOOTSTRAP] Contraseña inicial de 'usuario' (una sola vez): {demo_pwd}")


# --------------------------------------------------------------------------
# Modelos Pydantic: el esquema de salida NUNCA incluye password_hash (A04)
# --------------------------------------------------------------------------


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ProfileOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    full_name: str
    role: Literal["user", "admin"]


class ProfileUpdate(BaseModel):
    # Solo campos editables; "role" y credenciales quedan excluidos por diseño (A01).
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(default=None, min_length=1, max_length=120)


class CurrentUser(BaseModel):
    id: int
    username: str
    role: Literal["user", "admin"]


# --------------------------------------------------------------------------
# Autenticación (A07): JWT verificado en cada solicitud
# --------------------------------------------------------------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

_credentials_exc = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Credenciales inválidas o expiradas",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
) -> CurrentUser:
    try:
        payload = jwt.decode(token, APP_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = int(payload["sub"])
        role = payload["role"]
        if role not in ("user", "admin"):
            raise _credentials_exc
    except (jwt.PyJWTError, KeyError, TypeError, ValueError):
        # Mensaje genérico: no revela por qué falló el token (A02/A10).
        raise _credentials_exc from None
    row = find_user_by_id(user_id)
    if row is None:
        raise _credentials_exc
    return CurrentUser(id=row["id"], username=row["username"], role=row["role"])


# --------------------------------------------------------------------------
# Límite de intentos de login (A06), en memoria (se reinicia con el proceso)
# --------------------------------------------------------------------------

_failed_logins: dict[str, list[float]] = {}


def _check_login_allowed(username: str) -> None:
    now = time.monotonic()
    attempts = [t for t in _failed_logins.get(username, []) if now - t < LOGIN_WINDOW_SECONDS]
    _failed_logins[username] = attempts
    if len(attempts) >= MAX_LOGIN_ATTEMPTS:
        security_log.warning("login_bloqueado username=%s", username)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos. Inténtalo de nuevo más tarde.",
        )


def _register_failed_login(username: str) -> None:
    _failed_logins.setdefault(username, []).append(time.monotonic())


# --------------------------------------------------------------------------
# Aplicación
# --------------------------------------------------------------------------

app = FastAPI(title="Escenario perfiles", debug=False)  # debug desactivado (A02)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # La traza se registra en el servidor; el cliente solo recibe un mensaje
    # genérico (A02/A10).
    security_log.exception("error_no_controlado path=%s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Error interno"})


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------


@app.post("/token", response_model=TokenOut)
def login(form: Annotated[OAuth2PasswordRequestForm, Depends()]) -> TokenOut:
    _check_login_allowed(form.username)
    user = find_user_by_username(form.username)
    if user is None or not password_hasher.verify(form.password, user["password_hash"]):
        _register_failed_login(form.username)
        # Mensaje idéntico para usuario inexistente o contraseña incorrecta (A07).
        security_log.info("login_fallido username=%s", form.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos",
        )
    _failed_logins.pop(form.username, None)
    expires = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    token = jwt.encode(
        {"sub": str(user["id"]), "role": user["role"], "exp": expires},
        APP_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )
    security_log.info("login_ok user_id=%s", user["id"])
    return TokenOut(access_token=token)


@app.get("/profiles/{user_id}", response_model=ProfileOut)
def get_profile(
    user_id: int,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> ProfileOut:
    # A01 — anti-IDOR: un usuario normal solo puede leer SU propio perfil;
    # el identificador del recurso no se confía al cliente sin verificación.
    if current.role != "admin" and current.id != user_id:
        security_log.warning(
            "acceso_denegado user_id=%s intento_lectura perfil=%s", current.id, user_id
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No autorizado para ver este perfil",
        )
    row = find_user_by_id(user_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Perfil no encontrado")
    return ProfileOut(
        id=row["id"], username=row["username"], email=row["email"],
        full_name=row["full_name"], role=row["role"],
    )


@app.put("/profiles/{user_id}", response_model=ProfileOut)
def update_profile(
    user_id: int,
    changes: ProfileUpdate,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> ProfileOut:
    # A01: solo un administrador puede editar perfiles.
    if current.role != "admin":
        security_log.warning(
            "edicion_denegada user_id=%s intento_edicion perfil=%s", current.id, user_id
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Solo un administrador puede editar perfiles",
        )
    if find_user_by_id(user_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Perfil no encontrado")

    fields = changes.model_dump(exclude_none=True)
    # Las claves solo pueden ser campos del modelo (allowlist implícita); los
    # valores van SIEMPRE parametrizados (A05).
    allowed = {"email", "full_name"}
    assignments = ", ".join(f"{key} = ?" for key in fields if key in allowed)
    values = [value for key, value in fields.items() if key in allowed]
    if not assignments:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No hay cambios que aplicar",
        )
    try:
        with get_connection() as conn:
            conn.execute(
                f"UPDATE users SET {assignments} WHERE id = ?", (*values, user_id)
            )
    except sqlite3.Error:
        security_log.exception("error_bd al actualizar perfil=%s", user_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno",
        ) from None

    security_log.info(
        "perfil_actualizado admin_id=%s perfil=%s campos=%s",
        current.id, user_id, sorted(k for k in fields if k in allowed),
    )
    row = find_user_by_id(user_id)
    return ProfileOut(
        id=row["id"], username=row["username"], email=row["email"],
        full_name=row["full_name"], role=row["role"],
    )


init_db()
