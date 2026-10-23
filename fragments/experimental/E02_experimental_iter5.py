"""
scenario.py — Configuración inicial de una app FastAPI lista para producción.

Incluye:
- Configuración por variables de entorno (sin secretos ni valores sensibles en el código).
- CORS restrictivo: lista explícita de orígenes, jamás "*".
- Manejo centralizado de errores: el cliente nunca recibe trazas ni detalles internos.
- Logging de eventos sin datos sensibles, con correlación por request_id.

Variables de entorno:
    ALLOWED_ORIGINS   Orígenes permitidos, separados por comas (ej. "https://app.example.com").
    ENVIRONMENT       "production" (default) | "development".
    LOG_LEVEL         Nivel de logging (default: "INFO").
"""

import logging
import uuid

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.exceptions import HTTPException as StarletteHTTPException


class Settings(BaseSettings):
    """Configuración leída desde variables de entorno (nada sensible en el código fuente)."""

    model_config = SettingsConfigDict(case_sensitive=False)

    app_name: str = "scenario-api"
    environment: str = "production"
    log_level: str = "INFO"
    allowed_origins: list[str] = []

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def split_origins(cls, value: object) -> object:
        """Permite definir orígenes como cadena separada por comas."""
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @model_validator(mode="after")
    def validate_origins(self) -> "Settings":
        """A02: en producción no se permiten comodines y cada origen debe ser una URL válida."""
        for origin in self.allowed_origins:
            if origin == "*":
                if self.environment == "production":
                    raise ValueError("CORS con '*' no está permitido en producción.")
            elif not origin.startswith(("http://", "https://")):
                raise ValueError(f"Origen CORS inválido: {origin!r}")
        return self


settings = Settings()

logging.basicConfig(
    level=settings.log_level.upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(settings.app_name)

IS_PRODUCTION = settings.environment == "production"

app = FastAPI(
    title=settings.app_name,
    debug=not IS_PRODUCTION,  # A02: modo debug siempre desactivado en producción
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
)

# --- CORS restrictivo (A02) ---------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,  # lista explícita; vacía = sin acceso cross-origin
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    max_age=600,
)


def _error_response(request: Request, status_code: int, message: str) -> JSONResponse:
    """Construye la respuesta de error y registra el evento con un id de correlación."""
    request_id = uuid.uuid4().hex
    # A09: se registra el evento sin cuerpos, cabeceras ni otros datos sensibles.
    logger.warning(
        "request_error id=%s method=%s path=%s status=%s",
        request_id,
        request.method,
        request.url.path,
        status_code,
    )
    return JSONResponse(
        status_code=status_code,
        content={"detail": message, "request_id": request_id},
    )


# --- Manejo centralizado de errores (A10) --------------------------------------
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Errores HTTP controlados: solo se devuelve el detalle declarado explícitamente por la app."""
    return _error_response(request, exc.status_code, str(exc.detail))


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Errores de validación: respuesta genérica al cliente; el detalle queda solo en logs."""
    # Se registran ubicación y tipo de error, nunca los valores de entrada del usuario.
    safe_errors = [{"loc": err.get("loc"), "type": err.get("type")} for err in exc.errors()]
    logger.info("validation_error path=%s errors=%s", request.url.path, safe_errors)
    return _error_response(request, status.HTTP_422_UNPROCESSABLE_ENTITY, "Solicitud inválida.")


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Red de seguridad: el cliente recibe un 500 genérico y la traza completa queda en logs."""
    # A10: no es un except silencioso; la excepción se registra con su traza internamente.
    logger.exception("unhandled_error method=%s path=%s", request.method, request.url.path)
    return _error_response(
        request,
        status.HTTP_500_INTERNAL_SERVER_ERROR,
        "Error interno del servidor.",
    )


# --- Endpoints base -------------------------------------------------------------
@app.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "scenario:app",
        host="0.0.0.0",
        port=8000,
        reload=False,  # A02: sin auto-reload en producción
    )
