"""
scenario.py — Configuración inicial de una aplicación FastAPI lista para producción.

Incluye:
- CORS restringido a orígenes explícitos, fail-closed (OWASP A02).
- Manejo centralizado de errores sin exponer trazas al cliente (OWASP A02/A10).
- Logging de eventos de seguridad sin datos sensibles (OWASP A09).
- Configuración por variables de entorno, sin secretos en el código (OWASP A04).

Dependencias (fijar versiones exactas en requirements.txt — OWASP A03):
    fastapi
    uvicorn

Variables de entorno:
    ALLOWED_ORIGINS  Orígenes CORS separados por comas.
                     Ej: "https://app.ejemplo.com,https://admin.ejemplo.com"
    ENVIRONMENT      "production" (defecto) o "development".
    LOG_LEVEL        Nivel de logging, por defecto "INFO".

Ejecución en producción (sin --reload, debug desactivado):
    uvicorn scenario:app --host 0.0.0.0 --port 8000 --workers 4
"""

from __future__ import annotations

import logging
import os
import uuid

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

# ---------------------------------------------------------------------------
# Configuración (sin valores sensibles hardcodeados — OWASP A04)
# ---------------------------------------------------------------------------


def _get_allowed_origins() -> list[str]:
    """Lee los orígenes permitidos desde la variable ALLOWED_ORIGINS.

    Lista separada por comas. Si la variable no está definida, devuelve una
    lista vacía (fail-closed): el navegador rechazará toda solicitud
    cross-origin. Nunca usar "*" en producción (OWASP A02).
    """
    raw = os.getenv("ALLOWED_ORIGINS", "")
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


ALLOWED_ORIGINS = _get_allowed_origins()
ENVIRONMENT = os.getenv("ENVIRONMENT", "production").strip().lower()
DEBUG = ENVIRONMENT != "production"

# ---------------------------------------------------------------------------
# Logging (OWASP A09: registrar eventos sin exponer datos sensibles)
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("scenario")

# ---------------------------------------------------------------------------
# Aplicación
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Scenario API",
    version="1.0.0",
    debug=DEBUG,
    # En producción se deshabilita la documentación interactiva para reducir
    # la superficie de información expuesta (OWASP A02).
    docs_url="/docs" if DEBUG else None,
    redoc_url="/redoc" if DEBUG else None,
    openapi_url="/openapi.json" if DEBUG else None,
)

# ---------------------------------------------------------------------------
# CORS (OWASP A02: lista explícita de orígenes, jamás "*" por defecto)
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)

# ---------------------------------------------------------------------------
# Manejo centralizado de errores (OWASP A02/A10)
# ---------------------------------------------------------------------------


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    """Errores HTTP esperados: su detalle es seguro de devolver al cliente."""
    logger.info(
        "HTTP %s en %s %s",
        exc.status_code,
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Errores de validación: se omiten los valores de entrada recibidos para
    no reflejar datos potencialmente sensibles (p. ej. contraseñas)."""
    safe_errors = [
        {k: v for k, v in error.items() if k not in ("input", "url")}
        for error in exc.errors()
    ]
    logger.info(
        "Validación fallida en %s %s",
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": safe_errors},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Errores inesperados: se registran completos en el servidor con un ID de
    correlación, pero al cliente solo se le devuelve un mensaje genérico
    (nunca la traza interna — OWASP A02/A10)."""
    error_id = uuid.uuid4().hex
    logger.error(
        "Error no controlado [%s] en %s %s",
        error_id,
        request.method,
        request.url.path,
        exc_info=exc,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Error interno del servidor.", "error_id": error_id},
    )


# ---------------------------------------------------------------------------
# Endpoints base
# ---------------------------------------------------------------------------


@app.get("/health", tags=["infra"])
async def health() -> dict[str, str]:
    """Probe de liveness/readiness para el orquestador de producción."""
    return {"status": "ok"}
