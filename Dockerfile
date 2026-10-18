# --- build stage -----------------------------------------------------------
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder

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

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

USER identity
EXPOSE 8000

# Migrations are applied separately (see README) before the service starts.
CMD ["uvicorn", "identity_service.main:app", "--host", "0.0.0.0", "--port", "8000"]
