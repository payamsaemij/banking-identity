import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


def database_ready(request: Request) -> bool:
    """Liveness vs readiness split: this executes a trivial query."""
    try:
        with request.app.state.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        logger.error(
            "Database readiness check failed.",
            extra={"event": "health.database_unavailable"},
        )
        return False
    return True


DatabaseReady = Annotated[bool, Depends(database_ready)]


@router.get("/health", summary="Liveness probe")
def health(request: Request) -> dict[str, str]:
    service = request.app.state.infra.settings.service_name
    return {"status": "ok", "service": service}


@router.get("/health/ready", summary="Readiness probe (checks the database)")
def ready(database_ready: DatabaseReady) -> JSONResponse:
    if database_ready:
        return JSONResponse({"status": "ready"})
    return JSONResponse({"status": "unavailable"}, status_code=503)
