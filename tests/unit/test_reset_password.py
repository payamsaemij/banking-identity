import pytest

from identity_service.domain.enums.identity_status import IdentityStatus
from identity_service.domain.exceptions import (
    AuthenticationError,
    InvalidPasswordError,
    InvalidTokenError,
)
from tests.unit.fakes import OTHER_PASSWORD, VALID_PASSWORD, Harness


def raw_reset_token(harness: Harness) -> str:
    return harness.email_sender.reset_emails[-1][1]


def completed_reset_flow(harness: Harness) -> None:
    harness.register_and_verify()
    harness.login()
    harness.use_cases.request_password_reset.execute("customer@example.com")


def test_successful_reset_updates_hash_and_revokes_sessions() -> None:
    harness = Harness()
    completed_reset_flow(harness)
    identity = next(iter(harness.identity_repository.identities.values()))

    harness.use_cases.reset_password.execute(raw_reset_token(harness), OTHER_PASSWORD)

    stored = harness.identity_repository.get_by_id(identity.id)
    assert stored is not None
    assert stored.password_hash == harness.password_hasher._fake_hash(OTHER_PASSWORD)
    session = next(iter(harness.sessions.sessions.values()))
    assert session.revoked_at is not None


def test_old_password_no_longer_works_after_reset() -> None:
    harness = Harness()
    completed_reset_flow(harness)

    harness.use_cases.reset_password.execute(raw_reset_token(harness), OTHER_PASSWORD)

    with pytest.raises(AuthenticationError):
        harness.use_cases.login.execute("customer@example.com", VALID_PASSWORD)
    result = harness.use_cases.login.execute("customer@example.com", OTHER_PASSWORD)
    assert result.access_token


def test_invalid_token_is_rejected() -> None:
    harness = Harness()
    completed_reset_flow(harness)

    with pytest.raises(InvalidTokenError):
        harness.use_cases.reset_password.execute("bogus-token", OTHER_PASSWORD)


def test_expired_token_is_rejected() -> None:
    harness = Harness(reset_ttl_seconds=300)
    completed_reset_flow(harness)

    harness.clock.advance(seconds=301)

    with pytest.raises(InvalidTokenError):
        harness.use_cases.reset_password.execute(
            raw_reset_token(harness), OTHER_PASSWORD
        )


def test_token_cannot_be_reused() -> None:
    harness = Harness()
    completed_reset_flow(harness)
    harness.use_cases.reset_password.execute(raw_reset_token(harness), OTHER_PASSWORD)

    with pytest.raises(InvalidTokenError):
        harness.use_cases.reset_password.execute(
            raw_reset_token(harness), VALID_PASSWORD
        )


def test_weak_new_password_is_rejected_without_consuming_token() -> None:
    harness = Harness()
    completed_reset_flow(harness)
    token = next(iter(harness.reset_tokens.tokens.values()))

    with pytest.raises(InvalidPasswordError):
        harness.use_cases.reset_password.execute(raw_reset_token(harness), "short")

    assert token.used_at is None
    # The same link still works with a valid password.
    harness.use_cases.reset_password.execute(raw_reset_token(harness), OTHER_PASSWORD)


def test_reset_of_deactivated_identity_changes_password_but_not_status() -> None:
    harness = Harness()
    harness.register_and_verify()
    harness.use_cases.request_password_reset.execute("customer@example.com")
    identity = next(iter(harness.identity_repository.identities.values()))
    identity.deactivate()
    harness.identity_repository.update(identity)

    harness.use_cases.reset_password.execute(raw_reset_token(harness), OTHER_PASSWORD)

    stored = harness.identity_repository.get_by_id(identity.id)
    assert stored is not None
    assert stored.status == IdentityStatus.DEACTIVATED
    assert stored.password_hash == harness.password_hasher._fake_hash(OTHER_PASSWORD)
