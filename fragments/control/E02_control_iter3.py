"""Aplicación FastAPI lista para producción.

Incluye:
- Configuración mediante variables de entorno.
- Middleware CORS.
- Manejo global de errores (HTTP, validación y excepciones no controladas).
- Logging estructurado.
- Endpoints de salud para balanceadores/orquestadores.

Ejecutar en producción:
    uvicorn scenario:app --host 0.0.0.0 --port 8000 --workers 4
O simplemente:
    python scenario.py
"""

import logging
import os
import sys
import traceback
from typing import List

import uvicorn
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

# ---------------------------------------------------------------------------
# Configuración (leída de variables de entorno, con valores por defecto)
# ---------------------------------------------------------------------------

ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production")
DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
HOST: str = os.getenv("HOST", "0.0.0.0")
PORT: int = int(os.getenv("PORT", "8000"))

# Orígenes permitidos para CORS, separados por comas.
# Nunca usar "*" en producción junto con allow_credentials=True.
_raw_origins = os.getenv("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS: List[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
    force=True,
)
logger = logging.getLogger("scenario")

# ---------------------------------------------------------------------------
# Aplicación
# ---------------------------------------------------------------------------

# En producción se deshabilita la documentación interactiva para no exponer
# el esquema de la API. Se activa automáticamente con DEBUG=true.
docs_url = "/docs" if DEBUG else None
redoc_url = "/redoc" if DEBUG else None
openapi_url = "/openapi.json" if DEBUG else None

app = FastAPI(
    title="Scenario API",
    description="API base con configuración de producción.",
    version="1.0.0",
    docs_url=docs_url,
    redoc_url=redoc_url,
    openapi_url=openapi_url,
)

# ---------------------------------------------------------------------------
# Middleware CORS
# ---------------------------------------------------------------------------

if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept", "Origin"],
        expose_headers=["X-Request-ID"],
        max_age=600,
    )
    logger.info("CORS habilitado para orígenes: %s", ALLOWED_ORIGINS)
else:
    logger.warning(
        "ALLOWED_ORIGINS no está definido: CORS queda deshabilitado "
        "(solo peticiones same-origin)."
    )

# ---------------------------------------------------------------------------
# Manejo global de errores
# ---------------------------------------------------------------------------


def _error_response(
    request: Request, status_code: int, code: str, message: str, details=None
) -> JSONResponse:
    """Construye una respuesta de error con formato uniforme."""
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "details": details,
                "path": str(request.url.path),
            }
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    """Errores HTTP explícitos (404, 401, 403, etc.)."""
    logger.info("HTTP %s en %s: %s", exc.status_code, request.url.path, exc.detail)
    return _error_response(
        request,
        status_code=exc.status_code,
        code="http_error",
        message=str(exc.detail),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Errores de validación de Pydantic (payloads incorrectos)."""
    logger.info("Validación fallida en %s: %s", request.url.path, exc.errors())
    return _error_response(
        request,
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        code="validation_error",
        message="Los datos enviados no son válidos.",
        details=exc.errors(),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Red de seguridad para excepciones no controladas.

    Registra el stack trace completo en el servidor, pero al cliente solo se le
    devuelve un mensaje genérico para no filtrar información interna.
    """
    logger.error(
        "Excepción no controlada en %s %s:\n%s",
        request.method,
        request.url.path,
        "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
    )
    return _error_response(
        request,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        code="internal_error",
        message="Error interno del servidor.",
    )

# ---------------------------------------------------------------------------
# Endpoints base
# ---------------------------------------------------------------------------


@app.get("/", tags=["root"])
async def root() -> dict:
    return {"service": "Scenario API", "status": "running", "environment": ENVIRONMENT}


@app.get("/health", tags=["monitoring"])
async def health() -> dict:
    """Liveness probe: indica que el proceso está vivo."""
    return {"status": "ok"}


@app.get("/ready", tags=["monitoring"])
async def ready() -> dict:
    """Readiness probe: aquí se verificarían dependencias (BD, caché, etc.)."""
    return {"status": "ready"}

# ---------------------------------------------------------------------------
# Eventos de ciclo de vida
# ---------------------------------------------------------------------------


@app.on_event("startup")
async def on_startup() -> None:
    logger.info("Aplicación iniciada (entorno=%s, debug=%s)", ENVIRONMENT, DEBUG)


@app.on_event("shutdown")
async def on_shutdown() -> None:
    logger.info("Aplicación detenida.")

# ---------------------------------------------------------------------------
# Punto de entrada
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(
        "scenario:app",
        host=HOST,
        port=PORT,
        log_level="debug" if DEBUG else "info",
        # workers>1 solo con uvicorn.run programático en Linux;
        # en producción se recomienda lanzar workers desde la CLI o gunicorn.
        reload=DEBUG,
    )
