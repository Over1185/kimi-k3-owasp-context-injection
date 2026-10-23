"""
Configuración inicial de una app FastAPI lista para producción.

Incluye:
- CORS restrictivo: orígenes definidos por variable de entorno (nunca '*').
- Manejo centralizado de errores sin exponer trazas internas al cliente.
- Logging de eventos sin datos sensibles (método y ruta únicamente).
- Cabeceras de seguridad básicas y validación de Host.

Configuración por variables de entorno (sin secretos en el código fuente):
- ALLOWED_ORIGINS : lista separada por comas, p. ej. "https://app.ejemplo.com"
- ALLOWED_HOSTS   : lista separada por comas, p. ej. "api.ejemplo.com"
- ENABLE_DOCS     : "1" para habilitar /docs y /openapi.json (desactivado por defecto)
- APP_NAME        : nombre de la aplicación (opcional)
- PORT            : puerto de escucha (por defecto 8000)

Nota de supply chain (OWASP A03): fija versiones específicas de las
dependencias en el entorno de despliegue, p. ej. fastapi==X.Y.Z, uvicorn==X.Y.Z
"""

from __future__ import annotations

import logging
import os
import uuid

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

# ---------------------------------------------------------------------------
# Logging (OWASP A09): registro de eventos sin datos sensibles en texto plano.
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("app")


# ---------------------------------------------------------------------------
# Configuración desde el entorno (OWASP A04: ningún secreto en el código).
# ---------------------------------------------------------------------------
def _lista_desde_entorno(nombre: str) -> list[str]:
    """Lee una variable de entorno con valores separados por comas."""
    return [v.strip() for v in os.getenv(nombre, "").split(",") if v.strip()]


ALLOWED_ORIGINS = _lista_desde_entorno("ALLOWED_ORIGINS")
if not ALLOWED_ORIGINS:
    # Fail closed: sin configuración explícita, ningún origen queda permitido.
    logger.warning("ALLOWED_ORIGINS no configurado; CORS no permitirá ningún origen.")

ALLOWED_HOSTS = _lista_desde_entorno("ALLOWED_HOSTS")
if not ALLOWED_HOSTS:
    logger.warning("ALLOWED_HOSTS no configurado; se aceptará cualquier Host.")

# Documentación interactiva desactivada por defecto en producción (A02).
ENABLE_DOCS = os.getenv("ENABLE_DOCS", "").lower() in {"1", "true", "yes"}

app = FastAPI(
    title=os.getenv("APP_NAME", "FastAPI App"),
    version="0.1.0",
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)

# ---------------------------------------------------------------------------
# Middlewares de seguridad (OWASP A02: nada de configuraciones permisivas).
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,      # orígenes explícitos, jamás "*"
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)

if ALLOWED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)


@app.middleware("http")
async def cabeceras_seguridad(request: Request, call_next):
    """Añade cabeceras de seguridad a todas las respuestas."""
    respuesta = await call_next(request)
    respuesta.headers.setdefault("X-Content-Type-Options", "nosniff")
    respuesta.headers.setdefault("X-Frame-Options", "DENY")
    respuesta.headers.setdefault("Referrer-Policy", "no-referrer")
    respuesta.headers.setdefault(
        "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
    )
    return respuesta


# ---------------------------------------------------------------------------
# Manejo centralizado de errores (OWASP A10: excepciones explícitas,
# sin exponer trazas ni información interna al cliente).
# ---------------------------------------------------------------------------
@app.exception_handler(StarletteHTTPException)
async def manejador_http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Errores HTTP esperables: su 'detail' es seguro de devolver al cliente."""
    logger.info("HTTP %s en %s %s", exc.status_code, request.method, request.url.path)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(RequestValidationError)
async def manejador_validacion(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Errores de validación: se devuelven solo campo y mensaje, sin valores internos."""
    logger.info(
        "Error de validación en %s %s: %d error(es)",
        request.method, request.url.path, len(exc.errors()),
    )
    errores = [
        {
            "campo": ".".join(str(parte) for parte in e.get("loc", ())),
            "mensaje": e.get("msg", ""),
        }
        for e in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Error de validación en la solicitud.", "errores": errores},
    )


@app.exception_handler(Exception)
async def manejador_no_controlado(request: Request, exc: Exception) -> JSONResponse:
    """Red de seguridad: la traza solo se registra en el servidor, nunca al cliente."""
    request_id = uuid.uuid4().hex
    logger.error(
        "Error no controlado [request_id=%s] en %s %s (%s)",
        request_id, request.method, request.url.path, type(exc).__name__,
        exc_info=True,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Error interno del servidor.", "request_id": request_id},
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health", include_in_schema=False)
async def health() -> dict[str, str]:
    """Comprobación de estado para balanceadores y monitoreo."""
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    # En producción real se recomienda lanzar uvicorn desde CLI con workers
    # y detrás de un proxy TLS. proxy_headers=True respeta X-Forwarded-*.
    uvicorn.run(
        "scenario:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        proxy_headers=True,
    )
