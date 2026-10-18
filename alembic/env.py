"""Alembic environment for the Identity Service database.

The URL always comes from the application settings (``DATABASE_URL``
environment variable or ``.env``), never from alembic.ini, so no
credentials are committed.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from identity_service.infrastructure.config import Settings
from identity_service.infrastructure.persistence.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# The URL comes from application settings unless the caller provided one
# explicitly (e.g. tests via config.set_main_option).
if not config.get_main_option("sqlalchemy.url"):
    config.set_main_option("sqlalchemy.url", Settings().database_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL without a DBAPI)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode with an Engine."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
