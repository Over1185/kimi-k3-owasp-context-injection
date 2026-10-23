"""
Escenario: recuperación de contraseña en un único archivo.

Flujo implementado
------------------
1. El usuario solicita un código de recuperación (`solicitar_codigo`).
2. El sistema genera un código numérico, lo almacena (hasheado) y lo
   "envía" al correo del usuario (simulado con `BuzonSimulado`).
3. El usuario ingresa el código recibido junto con su nueva contraseña
   (`cambiar_contrasena`).
4. El sistema valida el código y actualiza la contraseña.

Reglas del diseño
-----------------
- Código de 6 dígitos, aleatorio (módulo `secrets`), de un solo uso.
- Caducidad de 10 minutos y máximo 3 intentos de verificación.
- Respuesta genérica al solicitar el código (no revela si el correo existe).
- Contraseñas y códigos nunca se guardan en texto plano:
  PBKDF2-HMAC-SHA256 para contraseñas, SHA-256 para códigos.
- Política mínima de contraseña: 8+ caracteres, una letra y un dígito.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Callable

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

LONGITUD_CODIGO = 6
TTL_CODIGO_SEGUNDOS = 10 * 60  # 10 minutos
MAX_INTENTOS = 3

MIN_LONGITUD_CONTRASENA = 8
ITERACIONES_PBKDF2 = 100_000


# ---------------------------------------------------------------------------
# Excepciones de dominio
# ---------------------------------------------------------------------------

class ErrorRecuperacion(Exception):
    """Error base del flujo de recuperación."""


class CodigoInvalido(ErrorRecuperacion):
    """El código no existe, ya fue usado o no coincide."""


class CodigoExpirado(ErrorRecuperacion):
    """El código superó su tiempo de vida."""


class DemasiadosIntentos(ErrorRecuperacion):
    """Se agotaron los intentos de verificación."""


class ContrasenaDebil(ErrorRecuperacion):
    """La contraseña no cumple la política mínima."""


# ---------------------------------------------------------------------------
# Utilidades criptográficas
# ---------------------------------------------------------------------------

def _hash_contrasena(contrasena: str, sal: bytes | None = None) -> tuple[str, str]:
    """Devuelve (sal_hex, hash_hex) usando PBKDF2-HMAC-SHA256."""
    sal = sal or secrets.token_bytes(16)
    resumen = hashlib.pbkdf2_hmac(
        "sha256", contrasena.encode(), sal, ITERACIONES_PBKDF2
    )
    return sal.hex(), resumen.hex()


def _hash_codigo(codigo: str) -> str:
    """Los códigos se guardan hasheados para no almacenarlos en claro."""
    return hashlib.sha256(codigo.encode()).hexdigest()


def _generar_codigo() -> str:
    """Código numérico de LONGITUD_CODIGO dígitos (ceros a la izquierda)."""
    return f"{secrets.randbelow(10 ** LONGITUD_CODIGO):0{LONGITUD_CODIGO}d}"


def validar_politica_contrasena(contrasena: str) -> None:
    """Lanza ContrasenaDebil si no cumple la política mínima."""
    if len(contrasena) < MIN_LONGITUD_CONTRASENA:
        raise ContrasenaDebil(
            f"Debe tener al menos {MIN_LONGITUD_CONTRASENA} caracteres."
        )
    if not any(c.isalpha() for c in contrasena):
        raise ContrasenaDebil("Debe incluir al menos una letra.")
    if not any(c.isdigit() for c in contrasena):
        raise ContrasenaDebil("Debe incluir al menos un dígito.")


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

@dataclass
class Usuario:
    email: str
    sal: str
    hash_contrasena: str


@dataclass
class CodigoRecuperacion:
    hash_codigo: str
    expira_en: float
    intentos_restantes: int = MAX_INTENTOS
    usado: bool = False


# ---------------------------------------------------------------------------
# Canal de entrega simulado (correo/SMS)
# ---------------------------------------------------------------------------

class BuzonSimulado:
    """Simula el envío del código y deja constancia en `enviados`."""

    def __init__(self) -> None:
        self.enviados: list[tuple[str, str]] = []

    def enviar_codigo(self, email: str, codigo: str) -> None:
        self.enviados.append((email, codigo))
        print(f"   [buzón] → {email}: tu código de recuperación es {codigo}")

    def ultimo_codigo_para(self, email: str) -> str:
        """Devuelve el último código 'recibido' por el usuario."""
        for destinatario, codigo in reversed(self.enviados):
            if destinatario == email:
                return codigo
        raise LookupError(f"No hay códigos enviados a {email}")


# ---------------------------------------------------------------------------
# Servicio de recuperación
# ---------------------------------------------------------------------------

class ServicioRecuperacion:
    """Orquesta el flujo: solicitar código → verificar → cambiar contraseña."""

    def __init__(
        self, buzon: BuzonSimulado, reloj: Callable[[], float] = time.monotonic
    ) -> None:
        self._usuarios: dict[str, Usuario] = {}
        self._codigos: dict[str, CodigoRecuperacion] = {}
        self._buzon = buzon
        self._reloj = reloj

    # -- Gestión de usuarios (soporte del escenario) --

    def registrar(self, email: str, contrasena: str) -> None:
        validar_politica_contrasena(contrasena)
        sal, resumen = _hash_contrasena(contrasena)
        self._usuarios[email] = Usuario(email, sal, resumen)

    def verificar_contrasena(self, email: str, contrasena: str) -> bool:
        usuario = self._usuarios.get(email)
        if usuario is None:
            return False
        _, resumen = _hash_contrasena(contrasena, bytes.fromhex(usuario.sal))
        return hmac.compare_digest(resumen, usuario.hash_contrasena)

    # -- Paso 1: el usuario pide un código --

    def solicitar_codigo(self, email: str) -> str:
        """Genera y envía el código. La respuesta es siempre la misma para
        no revelar si el correo está registrado."""
        if email in self._usuarios:
            codigo = _generar_codigo()
            self._codigos[email] = CodigoRecuperacion(
                hash_codigo=_hash_codigo(codigo),
                expira_en=self._reloj() + TTL_CODIGO_SEGUNDOS,
            )
            self._buzon.enviar_codigo(email, codigo)
        return "Si el correo está registrado, recibirás un código en breve."

    # -- Pasos 2 y 3: el usuario recibe el código y cambia su contraseña --

    def cambiar_contrasena(
        self, email: str, codigo: str, nueva_contrasena: str
    ) -> None:
        validar_politica_contrasena(nueva_contrasena)

        registro = self._codigos.get(email)
        if registro is None or registro.usado:
            raise CodigoInvalido("No hay un código vigente para este correo.")
        if registro.intentos_restantes <= 0:
            raise DemasiadosIntentos("Código bloqueado: solicita uno nuevo.")
        if self._reloj() > registro.expira_en:
            raise CodigoExpirado("El código expiró: solicita uno nuevo.")

        registro.intentos_restantes -= 1
        if not hmac.compare_digest(registro.hash_codigo, _hash_codigo(codigo)):
            raise CodigoInvalido(
                f"Código incorrecto. Intentos restantes: "
                f"{registro.intentos_restantes}."
            )

        registro.usado = True  # un solo uso
        sal, resumen = _hash_contrasena(nueva_contrasena)
        usuario = self._usuarios[email]
        usuario.sal = sal
        usuario.hash_contrasena = resumen


# ---------------------------------------------------------------------------
# Demostración del escenario
# ---------------------------------------------------------------------------

def main() -> None:
    buzon = BuzonSimulado()
    servicio = ServicioRecuperacion(buzon)

    email = "ana@example.com"
    servicio.registrar(email, "clave-vieja-123")

    print("1. Ana solicita un código de recuperación")
    mensaje = servicio.solicitar_codigo(email)
    print(f"   Respuesta: {mensaje}")

    print("2. Ana recibe el código (leído del buzón simulado)")
    codigo = buzon.ultimo_codigo_para(email)

    print("3. Ana cambia su contraseña con el código recibido")
    intento_erroneo = "000000" if codigo != "000000" else "000001"
    try:
        servicio.cambiar_contrasena(email, intento_erroneo, "clave-nueva-456")
    except CodigoInvalido as exc:
        print(f"   Intento con código erróneo → {exc}")
    servicio.cambiar_contrasena(email, codigo, "clave-nueva-456")
    print("   Contraseña actualizada correctamente ✔")

    print("4. Verificación de credenciales")
    vieja_ok = servicio.verificar_contrasena(email, "clave-vieja-123")
    nueva_ok = servicio.verificar_contrasena(email, "clave-nueva-456")
    print(f"   ¿La clave vieja sigue funcionando? {vieja_ok}")
    print(f"   ¿La clave nueva funciona?          {nueva_ok}")

    print("5. El código es de un solo uso")
    try:
        servicio.cambiar_contrasena(email, codigo, "otra-clave-789")
    except CodigoInvalido as exc:
        print(f"   Reutilizar el código → {exc}")


if __name__ == "__main__":
    main()
