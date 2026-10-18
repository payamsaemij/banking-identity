from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from identity_service.infrastructure.config import Settings


def create_db_engine(settings: Settings) -> Engine:
    """Create the application engine (connections are opened lazily)."""
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
    )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)
