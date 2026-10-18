"""Repository behaviour against real PostgreSQL: constraints, atomicity,
and concurrency guarantees that fakes cannot prove."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from identity_service.application.security import hash_token
from identity_service.domain.entities.auth_session import AuthSession
from identity_service.domain.entities.identity import Identity
from identity_service.domain.entities.one_time_token import OneTimeToken
from identity_service.domain.enums.identity_status import IdentityStatus
from identity_service.domain.exceptions import (
    CustomerAlreadyLinkedError,
    IdentityAlreadyExistsError,
)
from identity_service.infrastructure.persistence.models import (
    AuthSessionModel,
    EmailVerificationTokenModel,
    IdentityModel,
)
from identity_service.infrastructure.persistence.repositories import (
    SqlAlchemyIdentityRepository,
    SqlAlchemyPasswordResetTokenRepository,
    SqlAlchemySessionRepository,
    SqlAlchemyVerificationTokenRepository,
)

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def make_identity(email: str | None = None) -> Identity:
    return Identity(
        id=uuid4(),
        email=email or f"{uuid4().hex[:12]}@example.com",
        password_hash="argon2id$fake",
        customer_id=None,
    )


def make_token(identity_id: object, *, ttl_seconds: int = 3600) -> OneTimeToken:
    return OneTimeToken(
        id=uuid4(),
        identity_id=identity_id,  # type: ignore[arg-type]
        token_hash=hash_token(f"raw-{uuid4()}"),
        created_at=NOW,
        expires_at=NOW + timedelta(seconds=ttl_seconds),
    )


@pytest.fixture
def session_factory(database) -> sessionmaker[Session]:
    return sessionmaker(bind=database, expire_on_commit=False)


class TestIdentityRepository:
    def test_roundtrip_preserves_domain_state(self, session_factory) -> None:
        with session_factory() as session:
            repo = SqlAlchemyIdentityRepository(session)
            identity = make_identity()
            repo.add(identity)

            loaded = repo.get_by_email(identity.email)

            assert loaded is not None
            assert loaded.id == identity.id
            assert loaded.status == IdentityStatus.PENDING_VERIFICATION
            assert loaded.email_verified_at is None

    def test_duplicate_email_raises_domain_error(self, session_factory) -> None:
        with session_factory() as session:
            repo = SqlAlchemyIdentityRepository(session)
            repo.add(make_identity("dup@example.com"))
            session.commit()

        with session_factory() as session:
            repo = SqlAlchemyIdentityRepository(session)
            with pytest.raises(IdentityAlreadyExistsError):
                repo.add(make_identity("dup@example.com"))

    def test_duplicate_customer_reference_raises_domain_error(
        self, session_factory
    ) -> None:
        customer_id = uuid4()
        with session_factory() as session:
            repo = SqlAlchemyIdentityRepository(session)
            first = make_identity("one@example.com")
            first.customer_id = customer_id
            repo.add(first)
            session.commit()

        with session_factory() as session:
            repo = SqlAlchemyIdentityRepository(session)
            second = make_identity("two@example.com")
            second.customer_id = customer_id
            with pytest.raises(CustomerAlreadyLinkedError):
                repo.add(second)

    def test_status_check_constraint_rejects_unknown_values(
        self, session_factory
    ) -> None:
        with session_factory() as session:
            session.add(
                IdentityModel(
                    id=uuid4(),
                    email="bad-status@example.com",
                    password_hash="x",
                    status="teleported",
                )
            )
            with pytest.raises(IntegrityError):
                session.commit()

    def test_update_persists_lifecycle_changes(self, session_factory) -> None:
        with session_factory() as session:
            repo = SqlAlchemyIdentityRepository(session)
            identity = make_identity()
            repo.add(identity)
            session.commit()

        with session_factory() as session:
            repo = SqlAlchemyIdentityRepository(session)
            loaded = repo.get_by_id(identity.id)
            assert loaded is not None
            loaded.verify_email(NOW)
            repo.update(loaded)
            session.commit()

        with session_factory() as session:
            repo = SqlAlchemyIdentityRepository(session)
            reloaded = repo.get_by_id(identity.id)
            assert reloaded is not None
            assert reloaded.status == IdentityStatus.ACTIVE
            assert reloaded.email_verified_at == NOW


class TestOneTimeTokenRepositories:
    def _identity_id(self, session_factory) -> "object":
        with session_factory() as session:
            repo = SqlAlchemyIdentityRepository(session)
            identity = make_identity()
            repo.add(identity)
            session.commit()
            return identity.id

    def test_consume_succeeds_exactly_once(self, session_factory) -> None:
        identity_id = self._identity_id(session_factory)
        raw = f"raw-{uuid4()}"
        with session_factory() as session:
            repo = SqlAlchemyVerificationTokenRepository(session)
            repo.add(
                OneTimeToken(
                    id=uuid4(),
                    identity_id=identity_id,
                    token_hash=hash_token(raw),
                    created_at=NOW,
                    expires_at=NOW + timedelta(hours=24),
                )
            )
            session.commit()

        with session_factory() as session:
            repo = SqlAlchemyVerificationTokenRepository(session)
            consumed = repo.consume_by_token_hash(hash_token(raw), NOW)
            assert consumed is not None
            session.commit()

        with session_factory() as session:
            repo = SqlAlchemyVerificationTokenRepository(session)
            assert repo.consume_by_token_hash(hash_token(raw), NOW) is None

    def test_expired_token_cannot_be_consumed(self, session_factory) -> None:
        identity_id = self._identity_id(session_factory)
        raw = f"raw-{uuid4()}"
        with session_factory() as session:
            repo = SqlAlchemyVerificationTokenRepository(session)
            repo.add(make_token(identity_id))
            session.add(
                EmailVerificationTokenModel(
                    id=uuid4(),
                    identity_id=identity_id,
                    token_hash=hash_token(raw),
                    expires_at=NOW - timedelta(seconds=1),
                )
            )
            session.commit()

        with session_factory() as session:
            repo = SqlAlchemyVerificationTokenRepository(session)
            assert repo.consume_by_token_hash(hash_token(raw), NOW) is None

    def test_concurrent_consumption_has_exactly_one_winner(
        self, session_factory
    ) -> None:
        import threading

        identity_id = self._identity_id(session_factory)
        raw = f"raw-{uuid4()}"
        with session_factory() as session:
            session.add(
                EmailVerificationTokenModel(
                    id=uuid4(),
                    identity_id=identity_id,
                    token_hash=hash_token(raw),
                    expires_at=NOW + timedelta(hours=24),
                )
            )
            session.commit()

        results: list[bool] = []
        lock = threading.Lock()

        def attempt() -> None:
            with session_factory() as session:
                repo = SqlAlchemyVerificationTokenRepository(session)
                consumed = repo.consume_by_token_hash(hash_token(raw), NOW)
                session.commit()
                with lock:
                    results.append(consumed is not None)

        threads = [threading.Thread(target=attempt) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert sum(results) == 1

    def test_invalidate_all_for_identity(self, session_factory) -> None:
        identity_id = self._identity_id(session_factory)
        other_id = self._identity_id(session_factory)
        with session_factory() as session:
            repo = SqlAlchemyVerificationTokenRepository(session)
            repo.add(make_token(identity_id))
            repo.add(make_token(identity_id))
            repo.add(make_token(other_id))
            session.commit()

        with session_factory() as session:
            repo = SqlAlchemyVerificationTokenRepository(session)
            count = repo.invalidate_all_for_identity(identity_id, NOW)
            session.commit()

        assert count == 2
        with session_factory() as session:
            repo = SqlAlchemyVerificationTokenRepository(session)
            for token in session.query(EmailVerificationTokenModel).all():
                if token.identity_id == identity_id:
                    assert token.used_at == NOW

    def test_password_reset_repository_uses_its_own_table(
        self, session_factory
    ) -> None:
        identity_id = self._identity_id(session_factory)
        raw = f"raw-{uuid4()}"
        with session_factory() as session:
            repo = SqlAlchemyPasswordResetTokenRepository(session)
            repo.add(
                OneTimeToken(
                    id=uuid4(),
                    identity_id=identity_id,
                    token_hash=hash_token(raw),
                    created_at=NOW,
                    expires_at=NOW + timedelta(hours=1),
                )
            )
            session.commit()

        with session_factory() as session:
            assert session.query(EmailVerificationTokenModel).count() == 0
            repo = SqlAlchemyPasswordResetTokenRepository(session)
            assert repo.find_by_token_hash(hash_token(raw)) is not None


class TestSessionRepository:
    def _create_identity(self, session_factory) -> "object":
        with session_factory() as session:
            repo = SqlAlchemyIdentityRepository(session)
            identity = make_identity()
            repo.add(identity)
            session.commit()
            return identity.id

    def test_find_active_excludes_expired_and_revoked(self, session_factory) -> None:
        identity_id = self._create_identity(session_factory)
        active = f"active-{uuid4()}"
        expired = f"expired-{uuid4()}"
        revoked = f"revoked-{uuid4()}"

        with session_factory() as session:
            repo = SqlAlchemySessionRepository(session)
            repo.add(
                AuthSession(
                    id=uuid4(),
                    identity_id=identity_id,
                    token_hash=hash_token(active),
                    created_at=NOW,
                    expires_at=NOW + timedelta(hours=8),
                )
            )
            repo.add(
                AuthSession(
                    id=uuid4(),
                    identity_id=identity_id,
                    token_hash=hash_token(expired),
                    created_at=NOW - timedelta(hours=9),
                    expires_at=NOW - timedelta(hours=1),
                )
            )
            repo.add(
                AuthSession(
                    id=uuid4(),
                    identity_id=identity_id,
                    token_hash=hash_token(revoked),
                    created_at=NOW,
                    expires_at=NOW + timedelta(hours=8),
                    revoked_at=NOW - timedelta(minutes=1),
                )
            )
            session.commit()

        with session_factory() as session:
            repo = SqlAlchemySessionRepository(session)
            assert repo.find_active_by_token_hash(hash_token(active), NOW)
            assert repo.find_active_by_token_hash(hash_token(expired), NOW) is None
            assert repo.find_active_by_token_hash(hash_token(revoked), NOW) is None

    def test_revoke_all_for_identity(self, session_factory) -> None:
        identity_id = self._create_identity(session_factory)
        other_id = self._create_identity(session_factory)
        with session_factory() as session:
            repo = SqlAlchemySessionRepository(session)
            for _ in range(3):
                repo.add(
                    AuthSession(
                        id=uuid4(),
                        identity_id=identity_id,
                        token_hash=hash_token(f"s-{uuid4()}"),
                        created_at=NOW,
                        expires_at=NOW + timedelta(hours=8),
                    )
                )
            repo.add(
                AuthSession(
                    id=uuid4(),
                    identity_id=other_id,
                    token_hash=hash_token(f"s-{uuid4()}"),
                    created_at=NOW,
                    expires_at=NOW + timedelta(hours=8),
                )
            )
            session.commit()

        with session_factory() as session:
            repo = SqlAlchemySessionRepository(session)
            count = repo.revoke_all_for_identity(identity_id, NOW)
            session.commit()

        assert count == 3

    def test_deleting_identity_cascades_to_sessions_and_tokens(
        self, session_factory
    ) -> None:
        identity_id = self._create_identity(session_factory)
        with session_factory() as session:
            repo = SqlAlchemySessionRepository(session)
            repo.add(
                AuthSession(
                    id=uuid4(),
                    identity_id=identity_id,
                    token_hash=hash_token(f"s-{uuid4()}"),
                    created_at=NOW,
                    expires_at=NOW + timedelta(hours=8),
                )
            )
            session.add(
                EmailVerificationTokenModel(
                    id=uuid4(),
                    identity_id=identity_id,
                    token_hash=hash_token(f"t-{uuid4()}"),
                    expires_at=NOW + timedelta(hours=24),
                )
            )
            session.commit()

        with session_factory() as session:
            session.execute(
                delete(IdentityModel).where(IdentityModel.id == identity_id)
            )
            session.commit()

        with session_factory() as session:
            assert session.query(AuthSessionModel).count() == 0
            assert session.query(EmailVerificationTokenModel).count() == 0

    def test_timestamps_are_timezone_aware(self, session_factory) -> None:
        identity_id = self._create_identity(session_factory)
        with session_factory() as session:
            repo = SqlAlchemyIdentityRepository(session)
            identity = repo.get_by_id(identity_id)
            assert identity is not None
            identity.verify_email(NOW)
            repo.update(identity)
            session.commit()

        with session_factory() as session:
            loaded = (
                session.query(IdentityModel)
                .filter(IdentityModel.id == identity_id)
                .one()
            )
            assert loaded.email_verified_at is not None
            assert loaded.email_verified_at.tzinfo is not None
            assert loaded.created_at.tzinfo is not None
