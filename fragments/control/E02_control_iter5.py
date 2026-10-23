"""
scenario.py — Aplicación FastAPI lista para producción.

Incluye:
    - CORS configurable por entorno (sin comodines en producción).
    - Manejo centralizado de errores con formato JSON consistente.
    - Request-ID por petición para trazabilidad.
    - Middlewares de seguridad: TrustedHost, GZip y cabeceras de seguridad.
    - Logging estructurado y endpoints de salud (/health, /ready).

Dependencias:
    pip install fastapi "uvicorn[standard]"

Ejecución:
    Desarrollo:  uvicorn scenario:app --reload
    Producción:  uvicorn scenario:app --host 0.0.0.0 --port 8000 --workers 4
    (o con Gunicorn: gunicorn scenario:app -k uvicorn.workers.UvicornWorker)

Configuración por variables de entorno:
    ENVIRONMENT       Entorno actual (development|production). Default: production
    ALLOWED_ORIGINS   Orígenes CORS separados por coma. Default: "" (ninguno)
    ALLOWED_HOSTS     Hosts permitidos separados por coma. Default: "*"
    LOG_LEVEL         Nivel de log (DEBUG|INFO|WARNING|ERROR). Default: INFO
    PORT              Puerto para ejecución directa. Default: 8000
    WORKERS           Workers de uvicorn en ejecución directa. Default: 1
"""

from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production").lower()
IS_PRODUCTION: bool = ENVIRONMENT == "production"
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()


def _parse_csv(value: str) -> list[str]:
    """Convierte 'a, b ,c' en ['a', 'b', 'c'], descartando vacíos."""
    return [item.strip() for item in value.split(",") if item.strip()]


ALLOWED_ORIGINS: list[str] = _parse_csv(os.getenv("ALLOWED_ORIGINS", ""))
ALLOWED_HOSTS: list[str] = _parse_csv(os.getenv("ALLOWED_HOSTS", "*")) or ["*"]

# En desarrollo, si no se definen orígenes, se permiten los típicos de localhost.
if not ALLOWED_ORIGINS and not IS_PRODUCTION:
    ALLOWED_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]

if IS_PRODUCTION and "*" in ALLOWED_ORIGINS:
    raise RuntimeError(
        "ALLOWED_ORIGINS no puede contener '*' en producción. "
        "Define la lista explícita de orígenes permitidos."
    )

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("scenario")

# ---------------------------------------------------------------------------
# Ciclo de vida
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Inicialización y liberación de recursos (conexiones, pools, etc.)."""
    logger.info("Iniciando aplicación (entorno=%s)", ENVIRONMENT)
    # TODO: inicializar recursos aquí (p. ej. pool de base de datos).
    yield
    # TODO: liberar recursos aquí.
    logger.info("Aplicación detenida")


app = FastAPI(
    title="Scenario API",
    version="1.0.0",
    # Oculta la documentación interactiva en producción.
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Middlewares
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    max_age=600,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)
app.add_middleware(GZipMiddleware, minimum_size=1024)


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    """Asigna un Request-ID y añade cabeceras de seguridad a cada respuesta."""
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response

# ---------------------------------------------------------------------------
# Manejo de errores
# ---------------------------------------------------------------------------


def _error_response(
    status_code: int,
    detail: Any,
    code: str,
    request: Request,
) -> JSONResponse:
    """Formato de error consistente para toda la API."""
    return JSONResponse(
        status_code=status_code,
        content={
            "detail": detail,
            "code": code,
            "request_id": getattr(request.state, "request_id", None),
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Errores HTTP controlados (404, 401, 403...)."""
    if exc.status_code >= 500:
        logger.error("HTTP %s en %s: %s", exc.status_code, request.url.path, exc.detail)
    return _error_response(exc.status_code, exc.detail, "http_error", request)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Errores de validación de Pydantic (petición mal formada)."""
    logger.warning("Validación fallida en %s: %s", request.url.path, exc.errors())
    return _error_response(
        status.HTTP_422_UNPROCESSABLE_ENTITY,
        exc.errors(),
        "validation_error",
        request,
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Red de seguridad: registra el traceback y no expone internos."""
    logger.exception("Error no controlado en %s %s", request.method, request.url.path)
    return _error_response(
        status.HTTP_500_INTERNAL_SERVER_ERROR,
        "Error interno del servidor",
        "internal_error",
        request,
    )

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health", tags=["ops"], summary="Liveness probe")
async def health():
    """Comprueba que el proceso está vivo (para Kubernetes liveness)."""
    return {"status": "ok"}


@app.get("/ready", tags=["ops"], summary="Readiness probe")
async def ready():
    """Comprueba dependencias (BD, caché...) antes de recibir tráfico."""
    # TODO: verificar dependencias reales y devolver 503 si alguna falla.
    return {"status": "ready"}


@app.get("/", tags=["root"], summary="Endpoint de ejemplo")
async def root():
    return {"message": "Scenario API operativa", "environment": ENVIRONMENT}


# ---------------------------------------------------------------------------
# Ejecución directa (python scenario.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "scenario:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        workers=int(os.getenv("WORKERS", "1")),
        log_level=LOG_LEVEL.lower(),
        # En producción real, el TLS debe terminar en el proxy/ingress.
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
