"""Configuración inicial de una app FastAPI lista para producción.

Incluye:
- Configuración mediante variables de entorno.
- Middleware CORS con orígenes restringidos.
- Manejo centralizado de errores (HTTP, validación y excepciones no controladas).
- Logging estructurado.
- Endpoint de health check.

Requisitos: fastapi, uvicorn
Ejecución local:  python scenario.py
Producción:       uvicorn scenario:app --host 0.0.0.0 --port 8000 --workers 4
"""

import logging
import os
import uuid
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

# ---------------------------------------------------------------------------
# Configuración (variables de entorno)
# ---------------------------------------------------------------------------

ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
DEBUG: bool = ENVIRONMENT != "production"

# Lista de orígenes permitidos separados por comas.
# Ejemplo: ALLOWED_ORIGINS="https://app.midominio.com,https://admin.midominio.com"
ALLOWED_ORIGINS: list[str] = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]

if ENVIRONMENT == "production" and not ALLOWED_ORIGINS:
    raise RuntimeError(
        "ALLOWED_ORIGINS no puede estar vacío en producción. "
        "Define los orígenes permitidos, p. ej.: "
        'ALLOWED_ORIGINS="https://app.midominio.com"'
    )

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("scenario")

# ---------------------------------------------------------------------------
# Aplicación
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Scenario API",
    version="1.0.0",
    debug=DEBUG,
    # En producción se oculta la documentación interactiva.
    docs_url="/docs" if DEBUG else None,
    redoc_url="/redoc" if DEBUG else None,
    openapi_url="/openapi.json" if DEBUG else None,
)

# ---------------------------------------------------------------------------
# Middleware CORS
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS or ["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    max_age=600,
)


# ---------------------------------------------------------------------------
# Respuestas de error uniformes
# ---------------------------------------------------------------------------

def _error_response(
    request: Request,
    status_code: int,
    message: str,
    details: Any = None,
) -> JSONResponse:
    """Construye una respuesta de error consistente con un ID de correlación."""
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    body: dict[str, Any] = {
        "error": {
            "message": message,
            "status_code": status_code,
            "request_id": request_id,
        }
    }
    if details is not None:
        body["error"]["details"] = details
    return JSONResponse(status_code=status_code, content=body)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    """Maneja errores HTTP esperados (404, 401, etc.)."""
    logger.info("HTTP %s en %s %s", exc.status_code, request.method, request.url.path)
    return _error_response(
        request,
        status_code=exc.status_code,
        message=str(exc.detail),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Maneja errores de validación de payloads (422)."""
    logger.info(
        "Error de validación en %s %s: %s", request.method, request.url.path, exc.errors()
    )
    return _error_response(
        request,
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        message="Los datos enviados no son válidos.",
        details=jsonable_encoder(exc.errors()),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Maneja excepciones no controladas sin filtrar detalles internos."""
    logger.exception(
        "Excepción no controlada en %s %s", request.method, request.url.path
    )
    return _error_response(
        request,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        message="Error interno del servidor.",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", tags=["infra"])
async def health_check() -> dict[str, str]:
    """Health check para balanceadores y orquestadores."""
    return {"status": "ok", "environment": ENVIRONMENT}


# ---------------------------------------------------------------------------
# Arranque local
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "scenario:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=DEBUG,
    )
