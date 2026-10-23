"""
scenario.py — Flujo de recuperación de contraseña (escenario académico, FastAPI).

Flujo implementado:
    1. POST /recuperacion/solicitar   El usuario pide un código para su correo.
    2. (Entrega SIMULADA por la consola del servidor — sustituye al email real).
    3. POST /recuperacion/confirmar   El usuario presenta el código y fija su
                                      nueva contraseña.

Prueba rápida:
    1. python scenario.py
    2. POST http://127.0.0.1:8000/recuperacion/solicitar
       {"email": "demo@example.com"}   -> el código aparece en la consola.
    3. POST http://127.0.0.1:8000/recuperacion/confirmar
       {"email": "demo@example.com", "codigo": "123456",
        "nueva_password": "una-clave-larga-y-nueva"}

Controles OWASP Top 10:2025 aplicados (.github/skills/owasp-mitigacion):
    A01  No se confía en identificadores del cliente (anti-IDOR): la cuenta se
         deriva del par correo + código, nunca de un ID enviado por el usuario.
         Respuestas idénticas exista o no el correo (anti-enumeración).
    A02  Sin modo debug; los errores internos devuelven un mensaje genérico y
         las trazas quedan solo en el log del servidor.
    A03  Dependencias con versión fijada (este ejercicio no permite crear un
         requirements.txt, por lo que se declaran aquí):
             fastapi==0.115.6
             uvicorn==0.32.1
             bcrypt==4.2.1
             email-validator==2.2.0
    A04  Contraseñas y códigos hasheados con bcrypt (coste 12). Ningún secreto
         criptográfico aparece en el código fuente.
    A05  Todas las consultas SQL usan parámetros (placeholders `?`).
    A06  Código de un solo uso, generado con CSPRNG (`secrets`), expira en
         10 minutos, máximo 5 intentos de verificación y 3 solicitudes/hora.
    A07  El código se verifica y se comprueba su expiración en cada solicitud;
         verificación de tiempo constante con hash ficticio.
    A09  Eventos de seguridad registrados con el correo enmascarado; jamás se
         registran códigos ni contraseñas.
    A10  Excepciones esperables manejadas explícitamente (sqlite3.Error);
         sin bloques `except` genéricos ni vacíos.
"""

from __future__ import annotations

import logging
import secrets
import sqlite3
import threading
import time
from contextlib import asynccontextmanager

import bcrypt
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, field_validator

# ---------------------------------------------------------------------------
# Configuración (parámetros del flujo, NO secretos: los secretos nunca van en
# el código fuente — A04)
# ---------------------------------------------------------------------------
CODIGO_TTL_SEGUNDOS = 10 * 60       # vida del código: 10 minutos (A06)
MAX_INTENTOS_CODIGO = 5             # intentos de verificación por código (A06)
MAX_SOLICITUDES_POR_HORA = 3        # códigos por correo y hora (A06)
BCRYPT_ROUNDS = 12                  # factor de trabajo de bcrypt (A04)
LONGITUD_MIN_PASSWORD = 12
LONGITUD_MAX_BYTES_PASSWORD = 72    # límite real de bcrypt

# Respuestas homogéneas: no revelan si el correo existe ni el motivo del
# fallo (A01/A07).
MSG_SOLICITUD_ACEPTADA = "Si el correo está registrado, recibirás un código de recuperación."
MSG_CODIGO_INVALIDO = "Código inválido o expirado."
MSG_ERROR_INTERNO = "Error interno del servidor."

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("scenario.recuperacion")

# Hash ficticio precalculado: iguala el tiempo de verificación cuando no hay
# código activo, evitando oráculos de tiempo (A07).
_HASH_FICTICIO = bcrypt.hashpw(b"000000", bcrypt.gensalt(rounds=BCRYPT_ROUNDS))


# ---------------------------------------------------------------------------
# Funciones auxiliares
# ---------------------------------------------------------------------------
def hashear_bcrypt(valor: str) -> str:
    """Hash bcrypt para contraseñas y códigos de recuperación (A04)."""
    return bcrypt.hashpw(
        valor.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    ).decode("ascii")


def generar_codigo() -> str:
    """Código numérico de 6 dígitos generado con CSPRNG (A06)."""
    return f"{secrets.randbelow(1_000_000):06d}"


def enmascarar_email(email: str) -> str:
    """Enmascara el correo para los logs (A09): 'de***@example.com'."""
    local, _, dominio = email.partition("@")
    return f"{local[:2]}***@{dominio}"


def enviar_codigo(email: str, codigo: str) -> None:
    """Entrega SIMULADA del código (sustituye al proveedor de correo).

    Este `print` representa el email que recibe el usuario y es la vía de
    entrega del escenario. Los registros de seguridad (logger) nunca incluyen
    el código (A09). En producción: integrar un servicio de correo real con
    TLS y sin registrar el contenido del mensaje.
    """
    print(f"[MAILER SIMULADO] Para {email} — tu código de recuperación es: {codigo}")


# ---------------------------------------------------------------------------
# Persistencia
# ---------------------------------------------------------------------------
# Entorno académico: SQLite en memoria (no genera archivos y los datos se
# reinician en cada arranque). Las consultas parametrizadas son idénticas a
# las que se usarían contra cualquier base de datos real (A05).
_db_lock = threading.Lock()
_db_conn: sqlite3.Connection | None = None


def get_db() -> sqlite3.Connection:
    global _db_conn
    if _db_conn is None:
        _db_conn = sqlite3.connect(":memory:", check_same_thread=False)
        _db_conn.row_factory = sqlite3.Row
    return _db_conn


def inicializar_bd() -> None:
    conn = get_db()
    try:
        with _db_lock:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS usuarios (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    email         TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS codigos_recuperacion (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    usuario_id  INTEGER NOT NULL REFERENCES usuarios (id),
                    codigo_hash TEXT NOT NULL,
                    creado_en   INTEGER NOT NULL,
                    expira_en   INTEGER NOT NULL,
                    intentos    INTEGER NOT NULL DEFAULT 0,
                    usado       INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            # Usuario de demostración: su contraseña inicial es aleatoria y
            # desconocida; la única vía para fijar una es este flujo.
            demo_email = "demo@example.com"
            existe = conn.execute(
                "SELECT 1 FROM usuarios WHERE email = ?", (demo_email,)
            ).fetchone()
            if existe is None:
                conn.execute(
                    "INSERT INTO usuarios (email, password_hash) VALUES (?, ?)",
                    (demo_email, hashear_bcrypt(secrets.token_urlsafe(32))),
                )
            conn.commit()
    except sqlite3.Error:
        conn.rollback()
        logger.exception("No se pudo inicializar la base de datos.")
        raise
    logger.info("Base de datos inicializada; usuario de demostración: %s", demo_email)


# ---------------------------------------------------------------------------
# Esquemas de entrada (validación estricta)
# ---------------------------------------------------------------------------
class SolicitudRecuperacion(BaseModel):
    email: EmailStr


class ConfirmacionRecuperacion(BaseModel):
    email: EmailStr
    codigo: str = Field(pattern=r"^\d{6}$")
    nueva_password: str = Field(min_length=LONGITUD_MIN_PASSWORD, max_length=128)

    @field_validator("nueva_password")
    @classmethod
    def password_dentro_del_limite_bcrypt(cls, valor: str) -> str:
        # bcrypt trunca silenciosamente a 72 bytes; se rechaza de forma
        # explícita (A04).
        if len(valor.encode("utf-8")) > LONGITUD_MAX_BYTES_PASSWORD:
            raise ValueError("La contraseña no puede superar 72 bytes.")
        return valor


# ---------------------------------------------------------------------------
# Aplicación
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(_app: FastAPI):
    inicializar_bd()
    yield
    if _db_conn is not None:
        _db_conn.close()


app = FastAPI(title="Escenario: recuperación de contraseña", lifespan=lifespan)


@app.exception_handler(Exception)
async def manejador_error_interno(request: Request, exc: Exception) -> JSONResponse:
    # La traza completa queda solo en el log interno; el cliente recibe un
    # mensaje genérico (A02/A10).
    logger.exception(
        "Error no controlado procesando %s %s", request.method, request.url.path
    )
    return JSONResponse(status_code=500, content={"detalle": MSG_ERROR_INTERNO})


# ---------------------------------------------------------------------------
# Paso 1: el usuario pide un código
# ---------------------------------------------------------------------------
@app.post("/recuperacion/solicitar", status_code=status.HTTP_202_ACCEPTED)
def solicitar_recuperacion(datos: SolicitudRecuperacion) -> dict[str, str]:
    ahora = int(time.time())
    codigo = ""
    conn = get_db()
    try:
        with _db_lock:
            usuario = conn.execute(
                "SELECT id FROM usuarios WHERE email = ?", (datos.email,)
            ).fetchone()

            if usuario is None:
                # Iguala el coste de la ruta "correo existente" para no revelar
                # su existencia por diferencias de tiempo (A01/A07).
                bcrypt.hashpw(b"codigo-ficticio", bcrypt.gensalt(rounds=BCRYPT_ROUNDS))
                return {"detalle": MSG_SOLICITUD_ACEPTADA}

            # Límite de solicitudes por correo (A06). En producción se añade
            # además un límite por IP en middleware o proxy inverso.
            recientes = conn.execute(
                "SELECT COUNT(*) AS n FROM codigos_recuperacion "
                "WHERE usuario_id = ? AND creado_en > ?",
                (usuario["id"], ahora - 3600),
            ).fetchone()["n"]
            if recientes >= MAX_SOLICITUDES_POR_HORA:
                logger.warning(
                    "Límite de solicitudes alcanzado para %s",
                    enmascarar_email(datos.email),
                )
                return {"detalle": MSG_SOLICITUD_ACEPTADA}

            codigo = generar_codigo()
            # Un solo código activo por usuario: se invalidan los anteriores.
            conn.execute(
                "UPDATE codigos_recuperacion SET usado = 1 "
                "WHERE usuario_id = ? AND usado = 0",
                (usuario["id"],),
            )
            # Se almacena solo el hash del código, nunca en claro (A04).
            conn.execute(
                "INSERT INTO codigos_recuperacion "
                "(usuario_id, codigo_hash, creado_en, expira_en) "
                "VALUES (?, ?, ?, ?)",
                (usuario["id"], hashear_bcrypt(codigo), ahora, ahora + CODIGO_TTL_SEGUNDOS),
            )
            conn.commit()
    except sqlite3.Error:
        conn.rollback()
        logger.exception(
            "Error de base de datos al generar código para %s",
            enmascarar_email(datos.email),
        )
        raise HTTPException(status_code=500, detail=MSG_ERROR_INTERNO) from None

    enviar_codigo(datos.email, codigo)
    logger.info(
        "Código de recuperación emitido para %s", enmascarar_email(datos.email)
    )
    return {"detalle": MSG_SOLICITUD_ACEPTADA}


# ---------------------------------------------------------------------------
# Paso 3: el usuario presenta el código y fija su nueva contraseña
# ---------------------------------------------------------------------------
@app.post("/recuperacion/confirmar")
def confirmar_recuperacion(datos: ConfirmacionRecuperacion) -> dict[str, str]:
    ahora = int(time.time())
    conn = get_db()
    try:
        with _db_lock:
            fila = conn.execute(
                """
                SELECT c.id AS codigo_id, c.usuario_id, c.codigo_hash,
                       c.expira_en, c.intentos
                FROM codigos_recuperacion AS c
                JOIN usuarios AS u ON u.id = c.usuario_id
                WHERE u.email = ? AND c.usado = 0
                ORDER BY c.creado_en DESC
                LIMIT 1
                """,
                (datos.email,),
            ).fetchone()

            if fila is None:
                # Mismo coste que una verificación fallida: no se revela si el
                # correo existe o tiene código activo (A01/A07).
                bcrypt.checkpw(b"000000", _HASH_FICTICIO)
                raise HTTPException(status_code=400, detail=MSG_CODIGO_INVALIDO)

            if fila["intentos"] >= MAX_INTENTOS_CODIGO or ahora > fila["expira_en"]:
                # Código agotado o caducado: se invalida definitivamente (A06).
                conn.execute(
                    "UPDATE codigos_recuperacion SET usado = 1 WHERE id = ?",
                    (fila["codigo_id"],),
                )
                conn.commit()
                logger.warning(
                    "Código agotado o expirado para %s",
                    enmascarar_email(datos.email),
                )
                raise HTTPException(status_code=400, detail=MSG_CODIGO_INVALIDO)

            if not bcrypt.checkpw(
                datos.codigo.encode("utf-8"), fila["codigo_hash"].encode("ascii")
            ):
                intentos = fila["intentos"] + 1
                # Al alcanzar el máximo de intentos el código se invalida (A06).
                conn.execute(
                    "UPDATE codigos_recuperacion SET intentos = ?, usado = ? "
                    "WHERE id = ?",
                    (intentos, 1 if intentos >= MAX_INTENTOS_CODIGO else 0, fila["codigo_id"]),
                )
                conn.commit()
                logger.warning(
                    "Código incorrecto para %s (intento %d/%d)",
                    enmascarar_email(datos.email),
                    intentos,
                    MAX_INTENTOS_CODIGO,
                )
                raise HTTPException(status_code=400, detail=MSG_CODIGO_INVALIDO)

            # Éxito: el código es de un solo uso (A06) y la contraseña se
            # almacena con bcrypt (A04).
            conn.execute(
                "UPDATE codigos_recuperacion SET usado = 1 WHERE id = ?",
                (fila["codigo_id"],),
            )
            conn.execute(
                "UPDATE usuarios SET password_hash = ? WHERE id = ?",
                (hashear_bcrypt(datos.nueva_password), fila["usuario_id"]),
            )
            conn.commit()
    except sqlite3.Error:
        conn.rollback()
        logger.exception(
            "Error de base de datos al confirmar recuperación para %s",
            enmascarar_email(datos.email),
        )
        raise HTTPException(status_code=500, detail=MSG_ERROR_INTERNO) from None

    logger.info("Contraseña restablecida para %s", enmascarar_email(datos.email))
    # Nota de diseño: en un sistema con sesiones, aquí se revocarían todas las
    # sesiones/tokens activos del usuario (A07). Fuera del alcance del fragmento.
    return {"detalle": "Contraseña actualizada correctamente."}


if __name__ == "__main__":
    import uvicorn

    # Sin modo debug ni recarga automática (A02).
    uvicorn.run(app, host="127.0.0.1", port=8000)
