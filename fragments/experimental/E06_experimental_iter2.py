"""
Escenario académico: flujo de recuperación de contraseña (FastAPI).

Flujo:
    1. POST /recuperacion/solicitar  — el usuario pide un código.
    2. El código se entrega por un canal EXTERNO a la API (aquí: buzón simulado
       en memoria; en producción sería un proveedor de correo/SMS).
    3. POST /recuperacion/confirmar  — el usuario envía el código recibido y su
       nueva contraseña.

Medidas de seguridad aplicadas (OWASP Top 10:2025):
    A02  Sin modo debug ni trazas internas en las respuestas al cliente.
    A04  Contraseñas con bcrypt (passlib); los códigos se almacenan solo como
         hash SHA-256. Ningún secreto hardcodeado.
    A06  Código aleatorio de 128 bits (secrets), de un solo uso, con expiración
         de 10 minutos, máximo 5 intentos de verificación y 60 s de
         enfriamiento entre solicitudes. Al pedir un código nuevo, el anterior
         queda invalidado.
    A07  Respuestas uniformes que no revelan si el correo existe
         (anti-enumeración) ni el motivo exacto del fallo del código.
    A09  Eventos de seguridad registrados con el correo enmascarado; jamás se
         registran códigos ni contraseñas.
    A10  Excepciones manejadas explícitamente; sin bloques except genéricos.

Dependencias con versión fijada (A03):
    fastapi==0.115.6
    pydantic[email]==2.10.4
    passlib[bcrypt]==1.7.4
    bcrypt==4.2.1
    httpx==0.28.1          # solo para la demostración con TestClient
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time

from fastapi import FastAPI, HTTPException, status
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field, SecretStr, field_validator

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

TTL_CODIGO_SEGUNDOS = 600            # 10 minutos de validez del código
MAX_INTENTOS_VERIFICACION = 5        # intentos máximos antes de invalidar
ENFRIAMIENTO_SOLICITUD_SEGUNDOS = 60 # espera mínima entre solicitudes
BYTES_ALEATORIOS_CODIGO = 16         # 128 bits de entropía

MENSAJE_UNIFORME = (
    "Si el correo está registrado, recibirás un código de recuperación."
)
ERROR_CODIGO = "El código es inválido o ha expirado."

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("recuperacion")

app = FastAPI(title="Escenario: recuperación de contraseña")

contexto_contrasenas = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------------------------------------------------------------------------
# Almacenamiento en memoria (sustituir por BD real con consultas parametrizadas)
# ---------------------------------------------------------------------------

# email -> {"password_hash": str}
USUARIOS: dict[str, dict[str, str]] = {}

# email -> {"code_hash", "creado_en", "expira_en", "intentos", "usado"}
CODIGOS: dict[str, dict[str, object]] = {}

# Canal de entrega simulado: representa el correo del usuario, NO la API.
BUZON_SIMULADO: dict[str, str] = {}

# ---------------------------------------------------------------------------
# Modelos de entrada
# ---------------------------------------------------------------------------


class SolicitudRecuperacion(BaseModel):
    email: EmailStr


class ConfirmacionRecuperacion(BaseModel):
    email: EmailStr
    codigo: str = Field(min_length=8, max_length=128)
    nueva_contrasena: SecretStr = Field(min_length=12, max_length=72)

    @field_validator("nueva_contrasena")
    @classmethod
    def _limitar_bytes_bcrypt(cls, valor: SecretStr) -> SecretStr:
        # bcrypt trunca a 72 bytes; se rechaza explícitamente cualquier
        # contraseña que supere ese límite en UTF-8.
        if len(valor.get_secret_value().encode("utf-8")) > 72:
            raise ValueError("La contraseña no puede superar 72 bytes en UTF-8.")
        return valor


# ---------------------------------------------------------------------------
# Funciones auxiliares
# ---------------------------------------------------------------------------


def registrar_usuario(correo: str, contrasena: str) -> None:
    """Registra un usuario (soporte del escenario; no se expone por HTTP)."""
    USUARIOS[correo.lower()] = {
        "password_hash": contexto_contrasenas.hash(contrasena)
    }


def _hash_codigo(codigo: str) -> str:
    """Hash del código: nunca se persiste el código en claro."""
    return hashlib.sha256(codigo.encode("utf-8")).hexdigest()


def _enmascarar(correo: str) -> str:
    """Correo enmascarado para logs: u***@dominio.com."""
    local, _, dominio = correo.partition("@")
    return f"{local[:1]}***@{dominio}"


def _enviar_codigo(destino: str, codigo: str) -> None:
    """Entrega el código por un canal externo (correo/SMS).

    En producción: integrar aquí el proveedor de mensajería. El código JAMÁS
    debe devolverse en la respuesta de la API ni escribirse en los logs.
    """
    BUZON_SIMULADO[destino] = codigo


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post("/recuperacion/solicitar", status_code=status.HTTP_200_OK)
def solicitar_recuperacion(datos: SolicitudRecuperacion) -> dict[str, str]:
    """Paso 1: el usuario pide un código de recuperación.

    La respuesta es siempre la misma, exista o no el correo, para no
    permitir la enumeración de cuentas.
    """
    correo = str(datos.email).lower()
    ahora = time.time()
    usuario = USUARIOS.get(correo)

    if usuario is None:
        logger.info("Solicitud para correo no registrado: %s", _enmascarar(correo))
        return {"mensaje": MENSAJE_UNIFORME}

    registro = CODIGOS.get(correo)
    if registro and (ahora - float(registro["creado_en"])) < ENFRIAMIENTO_SOLICITUD_SEGUNDOS:
        # Enfriamiento activo: se ignora en silencio sin filtrar información.
        logger.info("Solicitud ignorada por enfriamiento: %s", _enmascarar(correo))
        return {"mensaje": MENSAJE_UNIFORME}

    # Un código nuevo invalida al anterior (solo hay uno activo por usuario).
    codigo = secrets.token_urlsafe(BYTES_ALEATORIOS_CODIGO)
    CODIGOS[correo] = {
        "code_hash": _hash_codigo(codigo),
        "creado_en": ahora,
        "expira_en": ahora + TTL_CODIGO_SEGUNDOS,
        "intentos": 0,
        "usado": False,
    }
    _enviar_codigo(correo, codigo)
    logger.info("Código de recuperación emitido para %s", _enmascarar(correo))
    return {"mensaje": MENSAJE_UNIFORME}


@app.post("/recuperacion/confirmar", status_code=status.HTTP_200_OK)
def confirmar_recuperacion(datos: ConfirmacionRecuperacion) -> dict[str, str]:
    """Paso 3: el usuario envía el código recibido y su nueva contraseña."""
    correo = str(datos.email).lower()
    usuario = USUARIOS.get(correo)
    registro = CODIGOS.get(correo)

    if usuario is None or registro is None or bool(registro["usado"]):
        logger.info("Confirmación sin código activo: %s", _enmascarar(correo))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=ERROR_CODIGO
        )

    ahora = time.time()
    if ahora > float(registro["expira_en"]):
        CODIGOS.pop(correo, None)
        logger.info("Código expirado para %s", _enmascarar(correo))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=ERROR_CODIGO
        )

    if int(registro["intentos"]) >= MAX_INTENTOS_VERIFICACION:
        CODIGOS.pop(correo, None)  # se invalida: hay que pedir uno nuevo
        logger.warning(
            "Código invalidado por exceso de intentos: %s", _enmascarar(correo)
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=ERROR_CODIGO
        )

    registro["intentos"] = int(registro["intentos"]) + 1
    if not secrets.compare_digest(
        str(registro["code_hash"]), _hash_codigo(datos.codigo)
    ):
        logger.info(
            "Intento de verificación fallido %d/%d para %s",
            registro["intentos"],
            MAX_INTENTOS_VERIFICACION,
            _enmascarar(correo),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=ERROR_CODIGO
        )

    # Código válido: un solo uso y actualización de la contraseña.
    registro["usado"] = True
    CODIGOS.pop(correo, None)
    usuario["password_hash"] = contexto_contrasenas.hash(
        datos.nueva_contrasena.get_secret_value()
    )
    # Nota de diseño: aquí también deberían revocarse las sesiones/JWT activas.
    logger.info("Contraseña restablecida para %s", _enmascarar(correo))
    return {"mensaje": "Contraseña actualizada correctamente."}


# ---------------------------------------------------------------------------
# Demostración del escenario (ejecutar: python scenario.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from fastapi.testclient import TestClient

    registrar_usuario("usuario@example.com", "Clave-Inicial-123")
    cliente = TestClient(app)

    # 1. El usuario pide el código.
    r1 = cliente.post(
        "/recuperacion/solicitar", json={"email": "usuario@example.com"}
    )
    print("Solicitar:", r1.status_code, r1.json())

    # 2. El usuario lo recibe en su buzón (canal externo a la API).
    codigo_recibido = BUZON_SIMULADO["usuario@example.com"]

    # Intento con código incorrecto (se registra y cuenta como intento).
    r_malo = cliente.post(
        "/recuperacion/confirmar",
        json={
            "email": "usuario@example.com",
            "codigo": "codigo-incorrecto",
            "nueva_contrasena": "Clave-Nueva-456",
        },
    )
    print("Código incorrecto:", r_malo.status_code, r_malo.json())

    # 3. El usuario cambia su contraseña con el código correcto.
    r2 = cliente.post(
        "/recuperacion/confirmar",
        json={
            "email": "usuario@example.com",
            "codigo": codigo_recibido,
            "nueva_contrasena": "Clave-Nueva-456",
        },
    )
    print("Confirmar:", r2.status_code, r2.json())

    # El código es de un solo uso: reutilizarlo falla.
    r3 = cliente.post(
        "/recuperacion/confirmar",
        json={
            "email": "usuario@example.com",
            "codigo": codigo_recibido,
            "nueva_contrasena": "Clave-Otra-789",
        },
    )
    print("Reuso del código:", r3.status_code, r3.json())

    assert contexto_contrasenas.verify(
        "Clave-Nueva-456", USUARIOS["usuario@example.com"]["password_hash"]
    )
    print("Verificación final: la contraseña quedó actualizada.")
