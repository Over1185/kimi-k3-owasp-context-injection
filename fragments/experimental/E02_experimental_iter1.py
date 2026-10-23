"""
scenario.py — Configuración base de una aplicación FastAPI lista para producción.

Incluye:
- Configuración por variables de entorno, sin secretos en el código (OWASP A04).
- CORS restrictivo con orígenes explícitos, nunca "*" (OWASP A02).
- Documentación/OpenAPI desactivados en producción (OWASP A02).
- Manejo centralizado de errores sin exponer trazas internas al cliente (OWASP A02/A10).
- Logging de eventos sin datos sensibles en texto plano (OWASP A09).

Dependencias — fijar versiones exactas en requirements.txt (OWASP A03):
    fastapi==0.115.6
    pydantic==2.10.4
    pydantic-settings==2.7.1
    uvicorn[standard]==0.34.0

Variables de entorno:
    ENVIRONMENT=production
    ALLOWED_ORIGINS='["https://app.ejemplo.com"]'
    ALLOWED_HOSTS='["api.ejemplo.com"]'

Ejecución en producción (sin --reload, OWASP A02):
    uvicorn scenario:app --host 0.0.0.0 --port 8000 --workers 4
"""

from __future__ import annotations

import logging
import re
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Patrón seguro para aceptar X-Request-ID del cliente (evita inyección en logs, A09).
_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9\-]{1,64}")


class Settings(BaseSettings):
    """Configuración leída desde variables de entorno (sin valores sensibles en código)."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "scenario-api"
    environment: str = "production"  # development | staging | production

    # Listas explícitas; pydantic-settings las parsea como JSON desde el entorno.
    allowed_origins: list[str] = ["https://app.ejemplo.com"]
    allowed_hosts: list[str] = ["api.ejemplo.com"]

    @field_validator("allowed_origins")
    @classmethod
    def _forbid_wildcard_origins(cls, value: list[str]) -> list[str]:
        # OWASP A02: se rechaza cualquier configuración permisiva con comodín.
        if "*" in value:
            raise ValueError("CORS con origen '*' está prohibido (OWASP A02).")
        return value


settings = Settings()


def configure_logging() -> logging.Logger:
    """Logging estructurado; los detalles internos quedan solo en el servidor (A09)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    return logging.getLogger("scenario")


logger = configure_logging()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    logger.info("Aplicación iniciada (entorno=%s)", settings.environment)
    yield
    logger.info("Aplicación detenida")


def create_app() -> FastAPI:
    is_production = settings.environment == "production"

    application = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        lifespan=lifespan,
        # OWASP A02: en producción no se expone documentación ni esquema OpenAPI.
        docs_url=None if is_production else "/docs",
        redoc_url=None if is_production else "/redoc",
        openapi_url=None if is_production else "/openapi.json",
    )

    # --- Middlewares ---
    # El último añadido es el más externo: TrustedHost filtra antes que CORS.
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,  # validado: nunca "*"
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        max_age=600,
    )
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)

    @application.middleware("http")
    async def request_context_middleware(request: Request, call_next):
        # Correlación de logs con ID propio o uno externo previamente saneado (A09).
        candidate = request.headers.get("x-request-id", "")
        request_id = candidate if _REQUEST_ID_RE.fullmatch(candidate) else str(uuid.uuid4())
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        # Cabeceras de seguridad básicas (OWASP A02).
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    # --- Manejo centralizado de errores ---
    def _request_id(request: Request) -> str:
        return getattr(request.state, "request_id", "-")

    @application.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        request_id = _request_id(request)
        # Se registran solo ubicación y tipo de error; jamás valores de entrada,
        # que podrían contener datos sensibles (OWASP A09).
        safe_errors = [{"loc": e.get("loc"), "type": e.get("type")} for e in exc.errors()]
        logger.warning("Validación fallida request_id=%s errores=%s", request_id, safe_errors)
        # Respuesta genérica: no revelar detalles internos al cliente (OWASP A02).
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "detail": "La solicitud no superó la validación de entrada.",
                "request_id": request_id,
            },
        )

    @application.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        request_id = _request_id(request)
        logger.info(
            "HTTP %s request_id=%s path=%s", exc.status_code, request_id, request.url.path
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail, "request_id": request_id},
            headers=getattr(exc, "headers", None),
        )

    @application.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        # OWASP A10: captura explícita del caso no controlado, registrada en servidor.
        request_id = _request_id(request)
        logger.error("Error no controlado request_id=%s", request_id, exc_info=exc)
        # OWASP A02: nunca se devuelve la traza ni el tipo de excepción al cliente.
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Error interno del servidor.", "request_id": request_id},
        )

    # --- Endpoints base ---
    @application.get("/health", tags=["meta"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return application


app = create_app()


if __name__ == "__main__":
    # Solo para desarrollo local; en producción usar el comando uvicorn del docstring.
    import uvicorn

    uvicorn.run("scenario:app", host="127.0.0.1", port=8000, reload=False)
