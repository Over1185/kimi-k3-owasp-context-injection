"""
scenario.py — Configuración base de una aplicación FastAPI lista para producción.

Decisiones de seguridad aplicadas (OWASP Top 10:2025):
- A02 Security Misconfiguration: CORS restrictivo (nunca "*"), documentación
  interactiva deshabilitada por defecto en producción y validación de hosts.
- A04 Cryptographic Failures: ningún secreto en el código fuente; toda la
  configuración llega mediante variables de entorno.
- A09 Security Logging and Alerting Failures: registro de eventos relevantes
  (errores, solicitudes inválidas) sin datos sensibles en texto plano.
- A10 Mishandling of Exceptional Conditions: manejo explícito de excepciones;
  las trazas internas solo aparecen en los logs del servidor.

Ejecución recomendada en producción:
    uvicorn scenario:app --host 0.0.0.0 --port 8000 --workers 4

Variables de entorno:
    ENVIRONMENT       "development" o "production" (por defecto "production").
    ALLOWED_ORIGINS   Orígenes CORS permitidos, separados por comas.
                      Obligatoria en producción. El comodín "*" está prohibido.
    ALLOWED_HOSTS     Hosts permitidos, separados por comas (recomendado).
    ENABLE_DOCS       "true" para exponer /docs y /openapi.json explícitamente.
    PORT              Puerto para ejecución local (por defecto 8000).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

logger = logging.getLogger("scenario")

_TRUE_VALUES = {"1", "true", "yes", "on"}


def configure_logging() -> None:
    """Configura el logging del servidor (sin datos sensibles)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


@dataclass(frozen=True)
class Settings:
    """Configuración inmutable de la aplicación."""

    environment: str
    allowed_origins: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    enable_docs: bool

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


def _csv_env(name: str) -> tuple[str, ...]:
    """Lee una variable de entorno como lista separada por comas."""
    raw = os.getenv(name, "")
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def load_settings() -> Settings:
    """
    Carga y valida la configuración desde variables de entorno.

    Falla al arrancar si la configuración es insegura (fail-fast, OWASP A02).
    """
    environment = os.getenv("ENVIRONMENT", "production").strip().lower()
    if environment not in {"development", "production"}:
        raise ValueError(
            f"ENVIRONMENT debe ser 'development' o 'production', recibido: {environment!r}"
        )

    allowed_origins = _csv_env("ALLOWED_ORIGINS")
    if "*" in allowed_origins:
        raise ValueError("CORS con comodín '*' no está permitido (OWASP A02).")
    if environment == "production" and not allowed_origins:
        raise ValueError(
            "ALLOWED_ORIGINS es obligatorio en producción; "
            "define los orígenes explícitos de tu frontend (OWASP A02)."
        )

    allowed_hosts = _csv_env("ALLOWED_HOSTS")
    if "*" in allowed_hosts:
        raise ValueError("ALLOWED_HOSTS con comodín '*' no está permitido (OWASP A02).")

    enable_docs = os.getenv("ENABLE_DOCS", "").strip().lower() in _TRUE_VALUES

    return Settings(
        environment=environment,
        allowed_origins=allowed_origins,
        allowed_hosts=allowed_hosts,
        enable_docs=enable_docs,
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    """Fábrica de la aplicación con CORS restrictivo y errores centralizados."""
    settings = settings or load_settings()
    configure_logging()

    # La documentación interactiva solo se expone en desarrollo o si se habilita
    # explícitamente, para no revelar el esquema de la API en producción (A02).
    expose_docs = settings.enable_docs or not settings.is_production
    app = FastAPI(
        title="scenario",
        docs_url="/docs" if expose_docs else None,
        redoc_url="/redoc" if expose_docs else None,
        openapi_url="/openapi.json" if expose_docs else None,
    )

    # --- Middlewares de seguridad ---

    if settings.allowed_hosts:
        app.add_middleware(
            TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts)
        )
    elif settings.is_production:
        logger.warning(
            "ALLOWED_HOSTS no configurado; se recomienda definir los hosts "
            "válidos para mitigar ataques de Host header (OWASP A02)."
        )

    # CORS restrictivo: orígenes, métodos y cabeceras explícitos (A02).
    if settings.allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.allowed_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "Accept", "Origin"],
            max_age=600,
        )

    # --- Manejo centralizado de errores (A09 / A10) ---

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        # El detalle de HTTPException lo define el desarrollador: es seguro devolverlo.
        if exc.status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
            logger.error(
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
        # Se registran solo método y ruta; nunca el cuerpo ni credenciales (A09).
        client_host = request.client.host if request.client else "desconocido"
        logger.info(
            "Solicitud inválida en %s %s desde %s",
            request.method,
            request.url.path,
            client_host,
        )
        # Se omiten "input" y "ctx" para no reflejar datos enviados por el cliente.
        errors = [
            {
                "loc": list(err.get("loc", ())),
                "msg": err.get("msg", ""),
                "type": err.get("type", ""),
            }
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": errors},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        # Red de seguridad: la traza completa queda solo en los logs del
        # servidor; al cliente se devuelve un mensaje genérico (A02/A10).
        logger.exception(
            "Error no controlado en %s %s", request.method, request.url.path
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Error interno del servidor"},
        )

    # --- Endpoints base ---

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        """Sonda de salud para balanceadores y orquestadores."""
        return {"status": "ok"}

    @app.get("/")
    async def root() -> dict[str, str]:
        return {"message": "API en funcionamiento"}

    return app


app = create_app()


if __name__ == "__main__":
    # Solo para ejecución local. En producción usa el CLI de uvicorn con
    # varios workers (ver cabecera del archivo).
    import uvicorn

    uvicorn.run(
        "scenario:app",
        host="127.0.0.1",
        port=int(os.getenv("PORT", "8000")),
        reload=False,
    )
