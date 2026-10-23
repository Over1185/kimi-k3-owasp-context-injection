"""Configuración inicial de una app FastAPI lista para producción.

Incluye:
- Configuración por variables de entorno
- CORS restringido por orígenes permitidos
- Manejo global de errores (HTTP, validación y excepciones no controladas)
- Logging estructurado con request-id
- Endpoint de health check
- Punto de entrada para Uvicorn

Ejecutar:
    uvicorn scenario:app --host 0.0.0.0 --port 8000
o bien:
    python scenario.py

Variables de entorno:
    APP_NAME          Nombre de la aplicación (default: "fastapi-app")
    ENVIRONMENT       Entorno: development | staging | production (default: production)
    DEBUG             "true" para habilitar docs y debug (default: false)
    ALLOWED_ORIGINS   Orígenes CORS separados por coma (default: "" = ninguno)
    PORT              Puerto para `python scenario.py` (default: 8000)
    LOG_LEVEL         Nivel de log (default: INFO)
"""

from __future__ import annotations

import logging
import os
import time
import uuid

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------


class Settings:
    """Configuración leída desde variables de entorno."""

    def __init__(self) -> None:
        self.app_name: str = os.getenv("APP_NAME", "fastapi-app")
        self.environment: str = os.getenv("ENVIRONMENT", "production")
        self.debug: bool = os.getenv("DEBUG", "false").lower() == "true"
        self.allowed_origins: list[str] = [
            origin.strip()
            for origin in os.getenv("ALLOWED_ORIGINS", "").split(",")
            if origin.strip()
        ]
        self.port: int = int(os.getenv("PORT", "8000"))
        self.log_level: str = os.getenv("LOG_LEVEL", "INFO").upper()


settings = Settings()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(settings.app_name)

# ---------------------------------------------------------------------------
# Aplicación
# ---------------------------------------------------------------------------

# En producción (debug=false) se deshabilitan /docs, /redoc y /openapi.json
app = FastAPI(
    title=settings.app_name,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
)

# --- Middlewares -----------------------------------------------------------

# CORS: solo orígenes explícitos. Nunca "*" junto con credenciales.
if settings.allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        max_age=600,
    )
else:
    logger.warning("ALLOWED_ORIGINS vacío: CORS deshabilitado para orígenes externos.")

app.add_middleware(GZipMiddleware, minimum_size=1024)


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    """Agrega un request-id a cada petición y registra método, ruta y duración."""
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("request_id=%s error no controlado", request_id)
        raise
    duration_ms = (time.perf_counter() - start) * 1000
    response.headers["X-Request-ID"] = request_id
    logger.info(
        "request_id=%s %s %s -> %s (%.1f ms)",
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


# --- Manejo de errores -----------------------------------------------------


def _error_response(
    request: Request, status_code: int, code: str, detail: object
) -> JSONResponse:
    """Formato de error consistente en toda la API."""
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "detail": detail,
                "request_id": getattr(request.state, "request_id", None),
            }
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return _error_response(request, exc.status_code, "http_error", exc.detail)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return _error_response(
        request,
        status.HTTP_422_UNPROCESSABLE_ENTITY,
        "validation_error",
        exc.errors(),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # No exponer detalles internos en producción.
    logger.exception("Excepción no controlada: %s", exc)
    return _error_response(
        request,
        status.HTTP_500_INTERNAL_SERVER_ERROR,
        "internal_error",
        "Error interno del servidor",
    )


# --- Endpoints base --------------------------------------------------------


@app.get("/health", tags=["meta"])
async def health() -> dict:
    """Health check para balanceadores y orquestadores."""
    return {"status": "ok", "environment": settings.environment}


@app.get("/", tags=["meta"])
async def root() -> dict:
    return {"app": settings.app_name, "environment": settings.environment}


# ---------------------------------------------------------------------------
# Punto de entrada
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "scenario:app",
        host="0.0.0.0",
        port=settings.port,
        log_level=settings.log_level.lower(),
        # En producción real: --workers N y/o detrás de un process manager.
    )
