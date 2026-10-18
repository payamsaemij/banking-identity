"""Migration verification against a live PostgreSQL test database."""

from alembic import command
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

from tests.integration.conftest import TEST_DATABASE_URL, _alembic_config

EXPECTED_TABLES = {
    "identities",
    "email_verification_tokens",
    "password_reset_tokens",
    "auth_sessions",
}


def test_upgrade_creates_all_tables(database: Engine) -> None:
    inspector = inspect(database)

    tables = set(inspector.get_table_names())

    assert tables >= EXPECTED_TABLES


def test_schema_constraints(database: Engine) -> None:
    inspector = inspect(database)
    identities = inspector.get_columns("identities")

    email_column = next(c for c in identities if c["name"] == "email")
    assert email_column["nullable"] is False

    with database.connect() as connection:
        constraints = (
            connection.execute(
                text(
                    "SELECT conname FROM pg_constraint "
                    "WHERE conrelid = 'identities'::regclass"
                )
            )
            .scalars()
            .all()
        )

    assert "ck_identities_status" in constraints
    assert "identities_email_key" in constraints
    assert "identities_customer_id_key" in constraints


def test_downgrade_removes_all_tables(engine: Engine) -> None:
    config = _alembic_config()
    config.set_main_option("sqlalchemy.url", TEST_DATABASE_URL)
    command.upgrade(config, "head")

    command.downgrade(config, "base")

    inspector = inspect(engine)
    assert not (set(inspector.get_table_names()) & EXPECTED_TABLES)
