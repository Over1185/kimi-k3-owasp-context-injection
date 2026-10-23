"""
scenario.py — Flujo de recuperación de contraseña (escenario académico, FastAPI).

Flujo:
    1. POST /auth/password/forgot → el usuario solicita un código de recuperación.
    2. El código se "envía" por un canal simulado (ver _send_reset_code).
    3. POST /auth/password/reset  → el usuario envía el código y su nueva contraseña.

El endpoint POST /auth/register es auxiliar y existe solo para poder ejercitar
el flujo completo en este escenario académico.

Dependencias (versiones fijadas — A03: Software Supply Chain Failures):
    pip install fastapi==0.115.6 "uvicorn[standard]==0.32.1" "pwdlib[argon2]==0.2.1" email-validator==2.2.0

Ejecución:
    uvicorn scenario:app --reload

Controles OWASP aplicados (según .github/skills/owasp-mitigacion):
    A02  Respuestas genéricas (anti-enumeración) y errores sin detalles internos.
    A04  Contraseñas con Argon2id (pwdlib); códigos almacenados como hash con
         pepper tomado del entorno (RESET_CODE_PEPPER), nunca en claro ni en código.
    A05  Todas las consultas SQL son parametrizadas.
    A06  Código de un solo uso, aleatorio (secrets), expira en 10 minutos,
         máximo 5 intentos y cooldown de 60 segundos entre solicitudes.
    A09  Eventos de seguridad registrados con correo enmascarado y sin códigos
         ni contraseñas en los logs.
    A10  Excepciones manejadas explícitamente (sin bloques except genéricos).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import threading
import time

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

CODE_DIGITS = 6                 # longitud del código numérico
CODE_TTL_SECONDS = 10 * 60      # expiración corta del código (A06)
MAX_CODE_ATTEMPTS = 5           # intentos limitados en flujo sensible (A06)
REQUEST_COOLDOWN_SECONDS = 60   # cooldown entre solicitudes de código (A06)
MIN_PASSWORD_LENGTH = 12

logger = logging.getLogger("scenario.password_reset")
logging.basicConfig(level=logging.INFO)

# El pepper protege los hashes de los códigos si la BD se filtra (A04).
# Nunca se define en el código fuente: se toma del entorno.
_CODE_PEPPER = os.environ.get("RESET_CODE_PEPPER")
if not _CODE_PEPPER:
    _CODE_PEPPER = secrets.token_hex(32)
    logger.warning(
        "RESET_CODE_PEPPER no definido; se generó uno efímero "
        "(los códigos solo serán válidos durante este proceso)."
    )

_PASSWORD_HASHER = PasswordHash.recommended()  # Argon2id (A04)

# Base de datos en memoria: suficiente para el escenario y no crea archivos.
_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.row_factory = sqlite3.Row
_DB_LOCK = threading.Lock()

_FORGOT_RESPONSE = {
    "detail": "Si el correo está registrado, recibirás un código de recuperación."
}
_RESET_GENERIC_ERROR = "Código inválido o expirado."
_INTERNAL_ERROR = "Error interno del servidor."

app = FastAPI(title="Escenario: recuperación de contraseña")


# ---------------------------------------------------------------------------
# Modelos de entrada
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=128)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: str = Field(pattern=rf"^\d{{{CODE_DIGITS}}}$")
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=128)


# ---------------------------------------------------------------------------
# Utilidades internas
# ---------------------------------------------------------------------------

def _execute(sql: str, params: tuple = ()) -> sqlite3.Cursor:
    """Ejecuta una consulta parametrizada (A05) con exclusión mutua."""
    with _DB_LOCK:
        cursor = _DB.execute(sql, params)
        _DB.commit()
        return cursor


def _query_one(sql: str, params: tuple = ()) -> sqlite3.Row | None:
    with _DB_LOCK:
        return _DB.execute(sql, params).fetchone()


def _mask_email(email: str) -> str:
    """Enmascara el correo para no exponer PII en los logs (A09)."""
    local, _, domain = email.partition("@")
    return f"{local[:1]}***@{domain}"


def _hash_code(code: str) -> str:
    """Hash del código con pepper del servidor; nunca se guarda en claro (A04)."""
    return hashlib.sha256(f"{_CODE_PEPPER}:{code}".encode("utf-8")).hexdigest()


def _find_user_by_email(email: str) -> sqlite3.Row | None:
    return _query_one("SELECT id, email FROM users WHERE email = ?", (email,))


def _send_reset_code(email: str, code: str) -> None:
    """Entrega SIMULADA del código (equivalente al backend de correo de consola).

    En producción debe integrarse con un proveedor de correo (SMTP o API) y el
    código NO debe imprimirse ni registrarse en ningún log (A09).
    """
    print(f"[SIMULADO] Correo para {email}: su código de recuperación es {code}")
    logger.info("Código de recuperación enviado a %s", _mask_email(email))


def _init_db() -> None:
    _execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    _execute(
        """
        CREATE TABLE IF NOT EXISTS reset_codes (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER NOT NULL REFERENCES users(id),
            code_hash     TEXT NOT NULL,
            expires_at    INTEGER NOT NULL,
            attempts_left INTEGER NOT NULL,
            created_at    INTEGER NOT NULL
        )
        """
    )


_init_db()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest) -> dict:
    """Auxiliar del escenario: crea un usuario para poder probar el flujo."""
    email = payload.email.lower()
    try:
        _execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, _PASSWORD_HASHER.hash(payload.password)),
        )
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El correo ya está registrado.",
        ) from None
    except sqlite3.Error:
        logger.exception("Error de base de datos al registrar usuario")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_INTERNAL_ERROR,
        ) from None
    logger.info("Usuario registrado: %s", _mask_email(email))
    return {"detail": "Usuario creado."}


@app.post("/auth/password/forgot", status_code=status.HTTP_202_ACCEPTED)
def forgot_password(payload: ForgotPasswordRequest) -> dict:
    """Paso 1: el usuario solicita un código de recuperación.

    La respuesta es idéntica exista o no el correo (anti-enumeración, A02).
    """
    email = payload.email.lower()
    try:
        user = _find_user_by_email(email)
        if user is None:
            # No se revela que el correo no existe; solo se registra.
            logger.info(
                "Solicitud de código para correo no registrado: %s",
                _mask_email(email),
            )
            return _FORGOT_RESPONSE

        now = int(time.time())
        last = _query_one(
            "SELECT created_at FROM reset_codes WHERE user_id = ? "
            "ORDER BY id DESC LIMIT 1",
            (user["id"],),
        )
        if last and now - last["created_at"] < REQUEST_COOLDOWN_SECONDS:
            # Cooldown: se ignora en silencio para no filtrar información.
            logger.info(
                "Solicitud ignorada por cooldown para %s", _mask_email(email)
            )
            return _FORGOT_RESPONSE

        # Invalida cualquier código anterior antes de emitir uno nuevo (A06).
        _execute("DELETE FROM reset_codes WHERE user_id = ?", (user["id"],))

        code = f"{secrets.randbelow(10**CODE_DIGITS):0{CODE_DIGITS}d}"
        _execute(
            "INSERT INTO reset_codes "
            "(user_id, code_hash, expires_at, attempts_left, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                user["id"],
                _hash_code(code),
                now + CODE_TTL_SECONDS,
                MAX_CODE_ATTEMPTS,
                now,
            ),
        )
        _send_reset_code(email, code)
    except sqlite3.Error:
        # A02/A10: se registra el error pero la respuesta al cliente no cambia.
        logger.exception("Error de base de datos en forgot_password")
    return _FORGOT_RESPONSE


@app.post("/auth/password/reset")
def reset_password(payload: ResetPasswordRequest) -> dict:
    """Pasos 2 y 3: el usuario envía el código recibido y su nueva contraseña."""
    email = payload.email.lower()
    now = int(time.time())
    try:
        user = _find_user_by_email(email)
        row = (
            _query_one(
                "SELECT id, code_hash, expires_at, attempts_left "
                "FROM reset_codes WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                (user["id"],),
            )
            if user is not None
            else None
        )

        # Respuesta genérica ante cualquier fallo (no distingue causa, A02).
        if row is None or now > row["expires_at"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=_RESET_GENERIC_ERROR,
            )

        if row["attempts_left"] <= 0:
            # Demasiados intentos: se invalida el código y hay que pedir otro.
            _execute("DELETE FROM reset_codes WHERE id = ?", (row["id"],))
            logger.warning(
                "Código invalidado por exceso de intentos para %s",
                _mask_email(email),
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=_RESET_GENERIC_ERROR,
            )

        if not hmac.compare_digest(row["code_hash"], _hash_code(payload.code)):
            _execute(
                "UPDATE reset_codes SET attempts_left = attempts_left - 1 "
                "WHERE id = ?",
                (row["id"],),
            )
            logger.warning(
                "Código incorrecto para %s", _mask_email(email)
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=_RESET_GENERIC_ERROR,
            )

        # Código válido: actualizar contraseña (Argon2id) y consumir el código.
        _execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (_PASSWORD_HASHER.hash(payload.new_password), user["id"]),
        )
        _execute("DELETE FROM reset_codes WHERE user_id = ?", (user["id"],))
    except sqlite3.Error:
        logger.exception("Error de base de datos en reset_password")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_INTERNAL_ERROR,
        ) from None

    logger.info("Contraseña actualizada para %s", _mask_email(email))
    return {"detail": "Contraseña actualizada correctamente."}
