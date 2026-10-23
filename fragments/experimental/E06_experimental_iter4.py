"""
Escenario académico: flujo de recuperación de contraseña (FastAPI).

Flujo implementado:
  1. POST /recuperacion/solicitar  — el usuario pide un código de un solo uso.
  2. El código se "envía" mediante un buzón simulado en memoria
     (en producción sería un servicio de correo; nunca se expone por HTTP).
  3. POST /recuperacion/confirmar  — el usuario envía el código y su nueva contraseña.

Controles OWASP Top 10:2025 aplicados:
  A01/A06 — el cambio de contraseña exige posesión de un código aleatorio
            (CSPRNG vía `secrets`), de un solo uso, con expiración corta
            (10 min) y máximo 5 intentos de verificación. No se confía en
            identificadores del cliente más allá del código.
  A02     — sin modo debug; las respuestas son genéricas y no revelan si un
            correo existe (anti-enumeración de usuarios).
  A04     — contraseñas con bcrypt (coste 12); los códigos se almacenan
            hasheados (SHA-256) y se comparan en tiempo constante.
  A05     — todas las consultas SQL usan parámetros (sin concatenación).
  A09     — eventos de seguridad registrados con el correo enmascarado;
            nunca se registran códigos ni contraseñas.
  A10     — excepciones manejadas explícitamente; sin `except` genéricos
            silenciosos.

Dependencias (versiones fijadas, OWASP A03):
  fastapi==0.115.6
  pydantic==2.10.4
  bcrypt==4.2.1
  uvicorn==0.34.0
  httpx==0.28.1        # solo para la demo (TestClient)
"""

import hashlib
import hmac
import logging
import re
import secrets
import sqlite3
import threading
import time

import bcrypt
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

LONGITUD_CODIGO = 6                  # dígitos, generados con CSPRNG
EXPIRACION_CODIGO_SEG = 10 * 60      # 10 minutos
MAX_INTENTOS_CODIGO = 5              # límite de intentos de verificación (A06)
ESPERA_ENTRE_SOLICITUDES_SEG = 60    # límite de frecuencia por correo

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("recuperacion")

# Buzón simulado: sustituye al servicio de correo real en este escenario.
# No se expone mediante ningún endpoint.
BUZON_SIMULADO: list[dict] = []

# ---------------------------------------------------------------------------
# Persistencia (SQLite en memoria; consultas siempre parametrizadas, A05)
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute(
    """
    CREATE TABLE usuarios (
        email TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL
    )
    """
)
_db.execute(
    """
    CREATE TABLE codigos_recuperacion (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        codigo_hash TEXT NOT NULL,
        creado_en REAL NOT NULL,
        expira_en REAL NOT NULL,
        intentos INTEGER NOT NULL DEFAULT 0,
        usado INTEGER NOT NULL DEFAULT 0
    )
    """
)
_db.commit()

# ---------------------------------------------------------------------------
# Utilidades de seguridad
# ---------------------------------------------------------------------------

REGEX_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _enmascarar_email(email: str) -> str:
    """Enmascara el correo para los logs (A09: sin datos sensibles en texto plano)."""
    partes = email.split("@", 1)
    if len(partes) != 2:
        return "***"
    return f"{partes[0][:1]}***@{partes[1]}"


def _hash_codigo(codigo: str) -> str:
    # SHA-256 es adecuado aquí: el código es aleatorio y de un solo uso,
    # no una contraseña elegida por el usuario.
    return hashlib.sha256(codigo.encode("utf-8")).hexdigest()


def _hash_contrasena(contrasena: str) -> str:
    """Hash de contraseña con bcrypt y sal automática (A04)."""
    return bcrypt.hashpw(contrasena.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def registrar_usuario(email: str, contrasena: str) -> None:
    """Registra un usuario (utilidad de apoyo para el escenario/demo)."""
    with _lock:
        _db.execute(
            "INSERT OR REPLACE INTO usuarios (email, password_hash) VALUES (?, ?)",
            (email.lower(), _hash_contrasena(contrasena)),
        )
        _db.commit()

# ---------------------------------------------------------------------------
# Modelos de entrada (validación estricta con pydantic)
# ---------------------------------------------------------------------------


class SolicitudRecuperacion(BaseModel):
    email: str = Field(min_length=3, max_length=254)

    @field_validator("email")
    @classmethod
    def _email_valido(cls, valor: str) -> str:
        valor = valor.strip().lower()
        if not REGEX_EMAIL.match(valor):
            raise ValueError("Formato de correo inválido")
        return valor


class ConfirmacionRecuperacion(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    codigo: str = Field(pattern=r"^\d{6}$")
    nueva_contrasena: str

    @field_validator("email")
    @classmethod
    def _email_valido(cls, valor: str) -> str:
        valor = valor.strip().lower()
        if not REGEX_EMAIL.match(valor):
            raise ValueError("Formato de correo inválido")
        return valor

    @field_validator("nueva_contrasena")
    @classmethod
    def _contrasena_robusta(cls, valor: str) -> str:
        if len(valor) < 12:
            raise ValueError("La contraseña debe tener al menos 12 caracteres")
        if len(valor.encode("utf-8")) > 72:
            # bcrypt trunca a 72 bytes; se rechaza explícitamente.
            raise ValueError("La contraseña no puede superar 72 bytes")
        if not (re.search(r"[a-z]", valor) and re.search(r"[A-Z]", valor) and re.search(r"\d", valor)):
            raise ValueError("Debe incluir minúsculas, mayúsculas y dígitos")
        return valor

# ---------------------------------------------------------------------------
# Aplicación
# ---------------------------------------------------------------------------


app = FastAPI(title="Recuperación de contraseña", debug=False)

_RESPUESTA_GENERICA = {"detail": "Si el correo está registrado, recibirás un código de recuperación."}
_ERROR_CODIGO = {"detail": "Código inválido o expirado."}
_ERROR_INTERNO = {"detail": "Error interno"}


@app.exception_handler(Exception)
async def manejador_errores_inesperados(request: Request, exc: Exception) -> JSONResponse:
    # La traza queda solo en el log del servidor; el cliente recibe un
    # mensaje genérico sin información interna (A02/A10).
    logger.error("Error inesperado en %s: %s", request.url.path, type(exc).__name__)
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=_ERROR_INTERNO)


@app.post("/recuperacion/solicitar", status_code=status.HTTP_200_OK)
def solicitar_recuperacion(datos: SolicitudRecuperacion):
    """Paso 1: el usuario pide un código de recuperación."""
    email = datos.email
    enmascarado = _enmascarar_email(email)
    try:
        with _lock:
            usuario = _db.execute(
                "SELECT email FROM usuarios WHERE email = ?", (email,)
            ).fetchone()
            if usuario is None:
                # Respuesta idéntica a la de un correo existente (anti-enumeración, A02).
                logger.info("Recuperación solicitada para correo no registrado: %s", enmascarado)
                return _RESPUESTA_GENERICA

            ultimo = _db.execute(
                "SELECT creado_en FROM codigos_recuperacion WHERE email = ? ORDER BY id DESC LIMIT 1",
                (email,),
            ).fetchone()
            ahora = time.time()
            if ultimo and ahora - ultimo[0] < ESPERA_ENTRE_SOLICITUDES_SEG:
                # Límite de frecuencia: se ignora sin filtrar información (A06).
                logger.info("Solicitud ignorada por límite de frecuencia: %s", enmascarado)
                return _RESPUESTA_GENERICA

            # Invalida códigos anteriores y emite uno nuevo de un solo uso (A06).
            _db.execute(
                "UPDATE codigos_recuperacion SET usado = 1 WHERE email = ? AND usado = 0",
                (email,),
            )
            codigo = f"{secrets.randbelow(10 ** LONGITUD_CODIGO):0{LONGITUD_CODIGO}d}"
            _db.execute(
                """
                INSERT INTO codigos_recuperacion (email, codigo_hash, creado_en, expira_en)
                VALUES (?, ?, ?, ?)
                """,
                (email, _hash_codigo(codigo), ahora, ahora + EXPIRACION_CODIGO_SEG),
            )
            _db.commit()
    except sqlite3.Error as exc:
        logger.error(
            "Error de base de datos al solicitar recuperación para %s: %s",
            enmascarado, type(exc).__name__,
        )
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=_ERROR_INTERNO)

    # Envío simulado. El código nunca se devuelve en la respuesta HTTP ni se registra.
    BUZON_SIMULADO.append({"para": email, "codigo": codigo, "enviado_en": ahora})
    logger.info(
        "Código de recuperación emitido para %s (válido %d min)",
        enmascarado, EXPIRACION_CODIGO_SEG // 60,
    )
    return _RESPUESTA_GENERICA


@app.post("/recuperacion/confirmar", status_code=status.HTTP_200_OK)
def confirmar_recuperacion(datos: ConfirmacionRecuperacion):
    """Paso 3: el usuario valida el código recibido y cambia su contraseña."""
    email = datos.email
    enmascarado = _enmascarar_email(email)
    try:
        with _lock:
            fila = _db.execute(
                """
                SELECT id, codigo_hash, expira_en, intentos
                FROM codigos_recuperacion
                WHERE email = ? AND usado = 0
                ORDER BY id DESC LIMIT 1
                """,
                (email,),
            ).fetchone()

            ahora = time.time()
            if fila is None or ahora > fila[2]:
                logger.info("Confirmación rechazada (sin código vigente): %s", enmascarado)
                return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=_ERROR_CODIGO)

            id_codigo, hash_almacenado, _expira_en, intentos = fila
            if intentos + 1 > MAX_INTENTOS_CODIGO:
                _db.execute("UPDATE codigos_recuperacion SET usado = 1 WHERE id = ?", (id_codigo,))
                _db.commit()
                logger.warning("Código invalidado por exceso de intentos: %s", enmascarado)
                return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=_ERROR_CODIGO)

            _db.execute(
                "UPDATE codigos_recuperacion SET intentos = intentos + 1 WHERE id = ?",
                (id_codigo,),
            )

            # Comparación en tiempo constante sobre los hashes (A04).
            if not hmac.compare_digest(hash_almacenado, _hash_codigo(datos.codigo)):
                _db.commit()
                logger.info("Confirmación rechazada (código incorrecto): %s", enmascarado)
                return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=_ERROR_CODIGO)

            # Código válido: se consume (un solo uso) y se actualiza la contraseña.
            _db.execute("UPDATE codigos_recuperacion SET usado = 1 WHERE email = ?", (email,))
            _db.execute(
                "UPDATE usuarios SET password_hash = ? WHERE email = ?",
                (_hash_contrasena(datos.nueva_contrasena), email),
            )
            _db.commit()
    except sqlite3.Error as exc:
        logger.error(
            "Error de base de datos al confirmar recuperación para %s: %s",
            enmascarado, type(exc).__name__,
        )
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=_ERROR_INTERNO)

    logger.info("Contraseña restablecida correctamente: %s", enmascarado)
    return {"detail": "Contraseña actualizada correctamente."}

# ---------------------------------------------------------------------------
# Demo del flujo completo
# ---------------------------------------------------------------------------


def _demo() -> None:
    """Recorre el flujo completo usando el TestClient de FastAPI."""
    from fastapi.testclient import TestClient  # requiere httpx

    registrar_usuario("usuario@example.com", "ClaveInicial123")
    cliente = TestClient(app)

    print("1) Solicitud de código (correo registrado):")
    r = cliente.post("/recuperacion/solicitar", json={"email": "usuario@example.com"})
    print("  ", r.status_code, r.json())

    print("2) Solicitud para correo NO registrado (respuesta idéntica, anti-enumeración):")
    r = cliente.post("/recuperacion/solicitar", json={"email": "nadie@example.com"})
    print("  ", r.status_code, r.json())

    codigo_real = BUZON_SIMULADO[-1]["codigo"]  # en producción llegaría por correo
    codigo_incorrecto = "000000" if codigo_real != "000000" else "111111"

    print("3) Intento con código incorrecto (debe fallar):")
    r = cliente.post(
        "/recuperacion/confirmar",
        json={
            "email": "usuario@example.com",
            "codigo": codigo_incorrecto,
            "nueva_contrasena": "NuevaClave1234",
        },
    )
    print("  ", r.status_code, r.json())

    print("4) Confirmación con el código recibido (debe funcionar):")
    r = cliente.post(
        "/recuperacion/confirmar",
        json={
            "email": "usuario@example.com",
            "codigo": codigo_real,
            "nueva_contrasena": "NuevaClave1234",
        },
    )
    print("  ", r.status_code, r.json())

    print("5) Reutilización del mismo código (debe fallar: es de un solo uso):")
    r = cliente.post(
        "/recuperacion/confirmar",
        json={
            "email": "usuario@example.com",
            "codigo": codigo_real,
            "nueva_contrasena": "OtraClave12345",
        },
    )
    print("  ", r.status_code, r.json())

    hash_final = _db.execute(
        "SELECT password_hash FROM usuarios WHERE email = ?", ("usuario@example.com",)
    ).fetchone()[0]
    assert bcrypt.checkpw(b"NuevaClave1234", hash_final.encode("ascii"))
    print("6) Contraseña verificada con bcrypt: OK")


if __name__ == "__main__":
    _demo()
