"""Flujo de recuperación de contraseña.

Escenario:
    1. El usuario solicita un código de recuperación para su email.
    2. El sistema genera un código de un solo uso, con caducidad, y lo "envía".
    3. El usuario introduce el código recibido junto con su nueva contraseña.
    4. Si el código es válido, la contraseña se actualiza y el código queda invalidado.

Diseño en memoria, sin dependencias externas. En producción habría que sustituir
el almacenamiento y el envío por servicios reales (BD, SMTP, etc.).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import string
import time
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Excepciones de dominio
# ---------------------------------------------------------------------------

class ErrorRecuperacion(Exception):
    """Error base del flujo de recuperación."""


class UsuarioNoEncontrado(ErrorRecuperacion):
    """No existe ningún usuario con ese email."""


class CodigoInvalido(ErrorRecuperacion):
    """El código no existe, ya fue usado o ha caducado."""


class DemasiadosIntentos(ErrorRecuperacion):
    """Se superó el número máximo de verificaciones fallidas."""


class ContrasenaDebil(ErrorRecuperacion):
    """La nueva contraseña no cumple la política mínima."""


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

@dataclass
class Usuario:
    email: str
    _hash_contrasena: str = field(repr=False)

    def verificar_contrasena(self, contrasena: str) -> bool:
        return hmac.compare_digest(self._hash_contrasena, _hashear(contrasena))

    def cambiar_contrasena(self, contrasena: str) -> None:
        self._hash_contrasena = _hashear(contrasena)


@dataclass
class CodigoRecuperacion:
    email: str
    codigo: str
    expira_en: float
    usado: bool = False
    intentos_fallidos: int = 0

    def caducado(self) -> bool:
        return time.time() > self.expira_en


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def _hashear(contrasena: str) -> str:
    # Simplificación didáctica; en producción usar bcrypt/argon2 con sal.
    return hashlib.sha256(contrasena.encode("utf-8")).hexdigest()


def _generar_codigo(longitud: int = 6) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(longitud))


# ---------------------------------------------------------------------------
# Servicio de recuperación
# ---------------------------------------------------------------------------

class ServicioRecuperacion:
    """Orquesta el flujo: solicitud de código -> verificación -> cambio de contraseña."""

    PATRON_CONTRASENA = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$")

    def __init__(
        self,
        usuarios: dict[str, Usuario],
        ttl_codigo_segundos: int = 600,
        max_intentos: int = 5,
    ) -> None:
        self._usuarios = usuarios
        self._ttl = ttl_codigo_segundos
        self._max_intentos = max_intentos
        self._codigos: dict[str, CodigoRecuperacion] = {}
        self.bandeja_salida: list[tuple[str, str]] = []  # simula el envío de emails

    # -- Paso 1: el usuario pide el código ----------------------------------

    def solicitar_codigo(self, email: str) -> None:
        """Genera un código de un solo uso y lo envía al email del usuario.

        No revela si el email existe: la respuesta externa debe ser siempre
        la misma para no filtrar qué cuentas están registradas.
        """
        usuario = self._usuarios.get(email)
        if usuario is None:
            return  # respuesta idéntica a la de un email registrado

        codigo = _generar_codigo()
        self._codigos[email] = CodigoRecuperacion(
            email=email,
            codigo=codigo,
            expira_en=time.time() + self._ttl,
        )
        self._enviar_codigo(email, codigo)

    def _enviar_codigo(self, email: str, codigo: str) -> None:
        # Simulación del envío; en producción iría un cliente SMTP/API.
        self.bandeja_salida.append((email, codigo))

    # -- Paso 2 y 3: el usuario usa el código para cambiar su contraseña -----

    def restablecer_contrasena(self, email: str, codigo: str, nueva_contrasena: str) -> None:
        """Valida el código y, si es correcto, actualiza la contraseña."""
        registro = self._codigos.get(email)

        if registro is None or registro.usado or registro.caducado():
            raise CodigoInvalido("El código no es válido o ha caducado.")

        if registro.intentos_fallidos >= self._max_intentos:
            raise DemasiadosIntentos("Se superó el máximo de intentos. Pide un nuevo código.")

        if not hmac.compare_digest(registro.codigo, codigo):
            registro.intentos_fallidos += 1
            raise CodigoInvalido("El código no coincide.")

        self._validar_contrasena(nueva_contrasena)

        usuario = self._usuarios.get(email)
        if usuario is None:
            raise UsuarioNoEncontrado(email)

        usuario.cambiar_contrasena(nueva_contrasena)
        registro.usado = True  # el código es de un solo uso

    def _validar_contrasena(self, contrasena: str) -> None:
        if not self.PATRON_CONTRASENA.match(contrasena):
            raise ContrasenaDebil(
                "Mínimo 8 caracteres, con mayúsculas, minúsculas y dígitos."
            )


# ---------------------------------------------------------------------------
# Demostración del escenario completo
# ---------------------------------------------------------------------------

def main() -> None:
    usuarios = {"ana@ejemplo.com": Usuario("ana@ejemplo.com", _hashear("ClaveVieja1"))}
    servicio = ServicioRecuperacion(usuarios)

    # 1. La usuaria pide el código.
    servicio.solicitar_codigo("ana@ejemplo.com")
    email, codigo_recibido = servicio.bandeja_salida[-1]
    print(f"Código enviado a {email}: {codigo_recibido}")

    # 2. Intenta con un código incorrecto (falla de forma controlada).
    try:
        servicio.restablecer_contrasena(email, "000000", "ClaveNueva1")
    except CodigoInvalido as exc:
        print(f"Intento fallido: {exc}")

    # 3. Usa el código correcto y cambia su contraseña.
    servicio.restablecer_contrasena(email, codigo_recibido, "ClaveNueva1")
    print("Contraseña actualizada:", usuarios[email].verificar_contrasena("ClaveNueva1"))

    # 4. El código ya no puede reutilizarse.
    try:
        servicio.restablecer_contrasena(email, codigo_recibido, "OtraClave2")
    except CodigoInvalido as exc:
        print(f"Reuso rechazado: {exc}")


if __name__ == "__main__":
    main()
