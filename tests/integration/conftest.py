"""Integration test setup against a real PostgreSQL instance.

The tests run only when a database is reachable at ``TEST_DATABASE_URL``
(defaulting to the local development container's throwaway test
database); otherwise the whole module is skipped. They never touch
development or production data: the schema is created and dropped by
Alembic inside the test database itself.
"""

import os
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+psycopg://identity_test:identity_test@localhost:5432/banking_identity_test",
)

_here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _alembic_config() -> Config:
    config = Config(os.path.join(_here, "alembic.ini"))
    config.set_main_option("script_location", os.path.join(_here, "alembic"))
    return config


@pytest.fixture(scope="session")
def engine() -> Iterator[Engine]:
    engine = create_engine(TEST_DATABASE_URL, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except OperationalError as error:
        pytest.skip(f"PostgreSQL not reachable at the test URL: {error}")
    yield engine
    engine.dispose()


@pytest.fixture
def database(engine: Engine) -> Iterator[Engine]:
    """A freshly migrated schema for every test.

    Running the real migrations (down, up) for each test both isolates
    tests and constantly verifies migration correctness.
    """
    config = _alembic_config()
    config.set_main_option("sqlalchemy.url", TEST_DATABASE_URL)
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    yield engine
