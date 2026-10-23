"""
Escenario: Recuperación de contraseña.

Flujo diseñado:
    1. El usuario solicita un código de recuperación.
    2. El sistema genera el código, lo almacena con expiración y lo "envía".
    3. El usuario recibe el código y lo usa junto a su nueva contraseña.
    4. El sistema valida el código (existe, no expiró, no fue usado)
       y actualiza la contraseña, invalidando el código.

Este archivo es una simulación autocontenida del diseño: sin base de datos
ni servicio de correo real; ambos se representan en memoria.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Excepciones del dominio
# ---------------------------------------------------------------------------

class RecuperacionError(Exception):
    """Error base del flujo de recuperación."""


class UsuarioNoEncontrado(RecuperacionError):
    """El correo no pertenece a ningún usuario registrado."""


class CodigoInvalido(RecuperacionError):
    """El código no existe o no coincide con el usuario."""


class CodigoExpirado(RecuperacionError):
    """El código superó su tiempo de vida."""


class CodigoYaUsado(RecuperacionError):
    """El código ya fue consumido en un cambio anterior."""


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

@dataclass
class Usuario:
    email: str
    _password_hash: str

    def verificar_password(self, password: str) -> bool:
        return self._password_hash == _hash(password)

    def cambiar_password(self, nueva_password: str) -> None:
        self._password_hash = _hash(nueva_password)


@dataclass
class CodigoRecuperacion:
    email: str
    valor: str
    expira_en: datetime
    usado: bool = False

    def vigente(self, ahora: datetime) -> bool:
        return not self.usado and ahora <= self.expira_en


# ---------------------------------------------------------------------------
# Servicios de soporte (simulados)
# ---------------------------------------------------------------------------

@dataclass
class BandejaSalida:
    """Simula el envío de correos: guarda los mensajes 'enviados'."""

    enviados: list[tuple[str, str]] = field(default_factory=list)

    def enviar(self, destinatario: str, mensaje: str) -> None:
        self.enviados.append((destinatario, mensaje))


# ---------------------------------------------------------------------------
# Servicio principal del flujo
# ---------------------------------------------------------------------------

class ServicioRecuperacion:
    TTL_CODIGO = timedelta(minutes=10)
    LONGITUD_CODIGO = 6

    def __init__(self, usuarios: dict[str, Usuario], correo: BandejaSalida):
        self._usuarios = usuarios
        self._correo = correo
        self._codigos: dict[str, CodigoRecuperacion] = {}

    # Paso 1 y 2: el usuario pide el código y lo recibe por correo.
    def solicitar_codigo(self, email: str) -> None:
        if email not in self._usuarios:
            raise UsuarioNoEncontrado(email)

        valor = f"{secrets.randbelow(10 ** self.LONGITUD_CODIGO):0{self.LONGITUD_CODIGO}d}"
        self._codigos[email] = CodigoRecuperacion(
            email=email,
            valor=valor,
            expira_en=datetime.now() + self.TTL_CODIGO,
        )
        self._correo.enviar(email, f"Tu código de recuperación es: {valor}")

    # Paso 3 y 4: el usuario envía el código recibido y su nueva contraseña.
    def cambiar_password(self, email: str, codigo: str, nueva_password: str) -> None:
        usuario = self._usuarios.get(email)
        if usuario is None:
            raise UsuarioNoEncontrado(email)

        registro = self._codigos.get(email)
        if registro is None or registro.valor != codigo:
            raise CodigoInvalido(codigo)
        if registro.usado:
            raise CodigoYaUsado(codigo)
        if datetime.now() > registro.expira_en:
            raise CodigoExpirado(codigo)

        usuario.cambiar_password(nueva_password)
        registro.usado = True  # el código queda invalidado tras el uso


def _hash(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Demostración del escenario completo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    usuarios = {"ana@example.com": Usuario("ana@example.com", _hash("clave-vieja"))}
    correo = BandejaSalida()
    servicio = ServicioRecuperacion(usuarios, correo)

    # 1. Ana olvida su contraseña y pide un código.
    servicio.solicitar_codigo("ana@example.com")

    # 2. Ana recibe el correo y extrae el código.
    _, mensaje = correo.enviados[-1]
    codigo_recibido = mensaje.rsplit(" ", 1)[-1]
    print(f"Código recibido por correo: {codigo_recibido}")

    # 3. Ana cambia su contraseña usando el código.
    servicio.cambiar_password("ana@example.com", codigo_recibido, "clave-nueva")

    # 4. Verificación del resultado.
    assert usuarios["ana@example.com"].verificar_password("clave-nueva")
    print("Contraseña actualizada correctamente.")

    # 5. El código no puede reutilizarse.
    try:
        servicio.cambiar_password("ana@example.com", codigo_recibido, "otra-clave")
    except CodigoYaUsado:
        print("Reutilización del código rechazada, como se esperaba.")
