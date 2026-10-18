from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from identity_service.infrastructure.config import Settings, get_settings
from identity_service.infrastructure.observability.logging import configure_logging
from identity_service.infrastructure.persistence.engine import (
    create_db_engine,
    create_session_factory,
)
from identity_service.infrastructure.rate_limit.in_memory import InMemoryRateLimiter
from identity_service.presentation.api.health import router as health_router
from identity_service.presentation.api.routes import router as identity_router
from identity_service.presentation.dependencies import build_infra
from identity_service.presentation.error_handlers import register_exception_handlers
from identity_service.presentation.middleware import RequestContextMiddleware


def create_app(settings: Settings | None = None) -> FastAPI:
    """Compose the application at the single wiring boundary."""
    settings = settings or get_settings()
    configure_logging(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        app.state.engine.dispose()

    app = FastAPI(
        title="Banking Identity Service",
        description=(
            "Registration, email verification, authentication, password "
            "management, and identity lifecycle for the banking platform."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    # Connections are opened lazily; startup only requires configuration.
    app.state.infra = build_infra(settings)
    app.state.engine = create_db_engine(settings)
    app.state.session_factory = create_session_factory(app.state.engine)
    app.state.rate_limiter = InMemoryRateLimiter()

    app.add_middleware(RequestContextMiddleware)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    register_exception_handlers(app)
    app.include_router(identity_router)
    app.include_router(health_router)
    return app


def run() -> None:
    """Console-script entry point."""
    import uvicorn

    uvicorn.run(
        "identity_service.main:app",
        host="0.0.0.0",
        port=8000,
        log_config=None,  # logging is configured by the application itself
    )


app = create_app()
