"""
Configuración inicial de una API FastAPI lista para producción.

Incluye:
- Middleware de CORS con orígenes configurables por entorno (nunca "*").
- Middleware de hosts confiables (TrustedHost) y compresión GZip.
- Manejo centralizado de errores con respuestas JSON consistentes
  (HTTPException, errores de validación y excepciones no controladas).
- Request ID por petición para trazabilidad en logs.
- Logging básico y endpoint de health check.

Dependencias:
    pip install fastapi "uvicorn[standard]"

Ejecutar en producción (ejemplo):
    ALLOWED_ORIGINS="https://mi-frontend.com" \
    ALLOWED_HOSTS="api.mi-dominio.com" \
    ENVIRONMENT=production \
    uvicorn scenario:app --host 0.0.0.0 --port 8000 --workers 4
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

# ---------------------------------------------------------------------------
# Configuración por entorno
# ---------------------------------------------------------------------------

ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production")
DEBUG: bool = ENVIRONMENT != "production"


def _csv_env(name: str) -> list[str]:
    """Lee una variable de entorno con valores separados por comas."""
    return [item.strip() for item in os.getenv(name, "").split(",") if item.strip()]


ALLOWED_ORIGINS: list[str] = _csv_env("ALLOWED_ORIGINS")
ALLOWED_HOSTS: list[str] = _csv_env("ALLOWED_HOSTS")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("scenario")

if not ALLOWED_ORIGINS:
    logger.warning(
        "ALLOWED_ORIGINS está vacío: CORS rechazará peticiones de cualquier origen. "
        "Configúralo antes de desplegar."
    )

# ---------------------------------------------------------------------------
# Aplicación
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Scenario API",
    version="1.0.0",
    # La documentación interactiva solo se expone fuera de producción.
    docs_url="/docs" if DEBUG else None,
    redoc_url="/redoc" if DEBUG else None,
    openapi_url="/openapi.json" if DEBUG else None,
)

# Middlewares: el último añadido es el primero en ejecutarse por petición.
app.add_middleware(GZipMiddleware, minimum_size=1024)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,          # lista explícita, jamás "*" en producción
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    max_age=600,
)

if ALLOWED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

# ---------------------------------------------------------------------------
# Request ID (trazabilidad)
# ---------------------------------------------------------------------------


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request.state.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    return response


# ---------------------------------------------------------------------------
# Manejo centralizado de errores
# ---------------------------------------------------------------------------


def _error_response(
    request: Request,
    status_code: int,
    detail: str,
    errors: Any | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "status_code": status_code,
                "detail": detail,
                "errors": errors,
                "path": request.url.path,
                "request_id": getattr(request.state, "request_id", None),
            }
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    logger.info(
        "HTTP %s en %s %s: %s",
        exc.status_code,
        request.method,
        request.url.path,
        exc.detail,
    )
    return _error_response(request, exc.status_code, str(exc.detail))


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    logger.info("Error de validación en %s %s", request.method, request.url.path)
    return _error_response(
        request,
        status.HTTP_422_UNPROCESSABLE_ENTITY,
        "Los datos de la petición no son válidos.",
        errors=jsonable_encoder(exc.errors()),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # Se registra el detalle completo en el servidor, pero al cliente solo se
    # le devuelve un mensaje genérico para no filtrar información interna.
    logger.exception(
        "Excepción no controlada en %s %s", request.method, request.url.path
    )
    return _error_response(
        request,
        status.HTTP_500_INTERNAL_SERVER_ERROR,
        "Error interno del servidor.",
    )


# ---------------------------------------------------------------------------
# Endpoints base
# ---------------------------------------------------------------------------


@app.get("/health", tags=["monitoreo"])
async def health_check() -> dict[str, str]:
    return {"status": "ok", "environment": ENVIRONMENT}


@app.get("/", tags=["root"])
async def root() -> dict[str, str]:
    return {"name": "Scenario API", "version": "1.0.0"}


# ---------------------------------------------------------------------------
# Arranque local (solo desarrollo; en producción usa uvicorn/gunicorn por CLI)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("scenario:app", host="127.0.0.1", port=8000, reload=DEBUG)
