# --- build stage -----------------------------------------------------------
# Python base pinned to match the runtime stage; the uv binary is copied
# from the exact version tag that generated uv.lock, for reproducible
# dependency installation.
FROM python:3.13-slim-bookworm AS builder
COPY --from=ghcr.io/astral-sh/uv:0.12.21 /uv /uvx /usr/local/bin/

WORKDIR /app

# Copy dependency manifests first so the resolve layer caches cleanly.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# Copy the rest and install the project itself. `--no-editable` keeps the
# runtime image self-contained (no reliance on the /app/src path).
COPY README.md ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

# --- runtime stage ---------------------------------------------------------
FROM python:3.13-slim-bookworm AS runtime

# Run as an unprivileged user.
RUN groupadd --system identity && useradd --system --gid identity identity

WORKDIR /app
COPY --from=builder --chown=identity:identity /app/.venv /app/.venv

# Alembic is part of the deployment surface: migrations run from this
# image (`docker compose run --rm identity alembic upgrade head`). The
# URL still comes from DATABASE_URL at runtime, never from the image.
COPY --chown=identity:identity alembic.ini ./
COPY --chown=identity:identity alembic ./alembic

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER identity
EXPOSE 8000

# Container health = the process and its HTTP loop are alive. This is the
# liveness endpoint on purpose; readiness (DB reachable) is a separate
# concern served by GET /health/ready for orchestration probes.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"]

# Exec form keeps uvicorn as PID 1: it receives SIGTERM directly and shuts
# down gracefully (the lifespan disposes the DB engine). The timeout
# bounds that shutdown so the orchestrator never has to SIGKILL late.
CMD ["uvicorn", "identity_service.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--timeout-graceful-shutdown", "20"]
