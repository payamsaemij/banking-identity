import os

# The application factory validates configuration at import time; tests
# never connect to this URL (unit tests use fakes, integration tests use
# TEST_DATABASE_URL), but the setting must parse.
os.environ.setdefault(
    "DATABASE_URL", "postgresql+psycopg://test:test@localhost:5432/identity_test"
)
