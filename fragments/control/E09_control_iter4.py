"""
scenario.py — Auditoría de seguridad.

Registra dos tipos de eventos:
1. Intentos de login fallidos (con contador por usuario/IP y alerta por fuerza bruta).
2. Acciones realizadas por administradores (quién, qué, sobre qué y con qué resultado).

Uso básico:
    from scenario import registrar_login_fallido, registrar_accion_admin

También incluye los decoradores @auditar_login y @auditar_admin para
integrarse sobre funciones de autenticación/operaciones existentes,
y una simulación de demostración al ejecutar `python scenario.py`.
"""

import logging
from collections import defaultdict
from functools import wraps

# ---------------------------------------------------------------------------
# Configuración del logger de auditoría
# ---------------------------------------------------------------------------
# Por defecto se emite por consola para no crear archivos adicionales.
# Para persistir en disco, basta con añadir un handler, p. ej.:
#     logger.addHandler(logging.FileHandler("auditoria_seguridad.log", encoding="utf-8"))

logger = logging.getLogger("auditoria_seguridad")
logger.setLevel(logging.INFO)

if not logger.handlers:  # evita handlers duplicados si el módulo se recarga
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s | %(levelname)-7s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(_handler)

# ---------------------------------------------------------------------------
# Registro de intentos de login fallidos
# ---------------------------------------------------------------------------

UMBRAL_INTENTOS = 5  # intentos fallidos antes de lanzar una alerta

# Contador en memoria: clave (usuario, ip) -> nº de fallos consecutivos
_intentos_fallidos = defaultdict(int)


def registrar_login_fallido(usuario: str, ip: str, motivo: str = "credenciales inválidas") -> int:
    """Registra un intento de login fallido.

    Devuelve el número de fallos consecutivos acumulados para ese
    (usuario, ip). Al alcanzar UMBRAL_INTENTOS se emite una alerta
    de posible ataque de fuerza bruta.
    """
    clave = (usuario, ip)
    _intentos_fallidos[clave] += 1
    fallos = _intentos_fallidos[clave]

    logger.warning(
        "LOGIN_FALLIDO | usuario=%s | ip=%s | motivo=%s | fallos_consecutivos=%d",
        usuario, ip, motivo, fallos,
    )

    if fallos >= UMBRAL_INTENTOS:
        logger.critical(
            "ALERTA_FUERZA_BRUTA | usuario=%s | ip=%s | fallos=%d | "
            "se recomienda bloquear la cuenta o la IP",
            usuario, ip, fallos,
        )
    return fallos


def reiniciar_intentos(usuario: str, ip: str) -> None:
    """Limpia el contador de fallos tras un login exitoso."""
    _intentos_fallidos.pop((usuario, ip), None)


# ---------------------------------------------------------------------------
# Registro de acciones de administrador
# ---------------------------------------------------------------------------

def registrar_accion_admin(
    admin: str,
    accion: str,
    objetivo: str = "-",
    resultado: str = "OK",
    detalles: str = "",
) -> None:
    """Registra una acción realizada por un administrador.

    Parámetros:
        admin:     identidad del administrador que ejecuta la acción.
        accion:    qué hizo (p. ej. "crear_usuario", "borrar_registro").
        objetivo:  recurso afectado (p. ej. el usuario o ID modificado).
        resultado: "OK" o "ERROR".
        detalles:  información adicional opcional.
    """
    nivel = logging.INFO if resultado == "OK" else logging.ERROR
    logger.log(
        nivel,
        "ACCION_ADMIN | admin=%s | accion=%s | objetivo=%s | resultado=%s | detalles=%s",
        admin, accion, objetivo, resultado, detalles or "-",
    )


# ---------------------------------------------------------------------------
# Decoradores para integración con código existente
# ---------------------------------------------------------------------------

def auditar_login(func):
    """Envuelve una función de autenticación.

    La función decorada debe recibir `usuario` e `ip` como argumentos
    (posicionales o por nombre) y devolver True/False según el resultado.
    Registra automáticamente los fallos y reinicia el contador en los éxitos.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        usuario = kwargs.get("usuario", args[0] if args else "desconocido")
        ip = kwargs.get("ip", args[1] if len(args) > 1 else "desconocida")

        exito = func(*args, **kwargs)
        if exito:
            reiniciar_intentos(usuario, ip)
            logger.info("LOGIN_OK | usuario=%s | ip=%s", usuario, ip)
        else:
            registrar_login_fallido(usuario, ip)
        return exito
    return wrapper


def auditar_admin(accion: str):
    """Envuelve una función que realiza una operación de administración.

    La función decorada debe recibir `admin` y opcionalmente `objetivo`.
    Registra la acción con resultado OK, o ERROR si lanza una excepción
    (que se vuelve a propagar tras registrarla).
    """
    def decorador(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            admin = kwargs.get("admin", args[0] if args else "desconocido")
            objetivo = kwargs.get("objetivo", args[1] if len(args) > 1 else "-")
            try:
                resultado = func(*args, **kwargs)
            except Exception as exc:
                registrar_accion_admin(admin, accion, objetivo,
                                       resultado="ERROR", detalles=str(exc))
                raise
            registrar_accion_admin(admin, accion, objetivo)
            return resultado
        return wrapper
    return decorador


# ---------------------------------------------------------------------------
# Demostración
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    USUARIOS = {"alice": "secreto123", "bob": "clave456"}

    @auditar_login
    def login(usuario: str, ip: str, password: str) -> bool:
        return USUARIOS.get(usuario) == password

    @auditar_admin(accion="crear_usuario")
    def crear_usuario(admin: str, objetivo: str) -> None:
        USUARIOS[objetivo] = "temporal"

    @auditar_admin(accion="eliminar_usuario")
    def eliminar_usuario(admin: str, objetivo: str) -> None:
        if objetivo not in USUARIOS:
            raise ValueError(f"el usuario '{objetivo}' no existe")
        del USUARIOS[objetivo]

    # 1) Intentos de login fallidos (incluye superar el umbral de alerta)
    for _ in range(UMBRAL_INTENTOS):
        login("alice", "203.0.113.7", password="incorrecta")
    login("alice", "203.0.113.7", password="secreto123")  # éxito: reinicia contador

    # 2) Acciones de administrador
    crear_usuario("admin_root", "carol")
    eliminar_usuario("admin_root", "bob")
    try:
        eliminar_usuario("admin_root", "usuario_inexistente")
    except ValueError:
        pass
