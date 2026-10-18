from uuid import uuid4

import pytest

from identity_service.domain.exceptions import (
    IdentityNotActiveError,
    IdentityNotFoundError,
    InvalidCurrentPasswordError,
    InvalidPasswordError,
)
from tests.unit.fakes import OTHER_PASSWORD, VALID_PASSWORD, Harness


def test_change_password_updates_hash_and_revokes_sessions() -> None:
    harness = Harness()
    identity = harness.register_and_verify()
    harness.login()

    harness.use_cases.change_password.execute(
        identity.id, VALID_PASSWORD, OTHER_PASSWORD
    )

    stored = harness.identity_repository.get_by_id(identity.id)
    assert stored is not None
    assert stored.password_hash == harness.password_hasher._fake_hash(OTHER_PASSWORD)
    session = next(iter(harness.sessions.sessions.values()))
    assert session.revoked_at is not None


def test_change_password_invalidates_outstanding_reset_tokens() -> None:
    harness = Harness()
    identity = harness.register_and_verify()
    harness.use_cases.request_password_reset.execute("customer@example.com")
    reset_token = next(iter(harness.reset_tokens.tokens.values()))

    harness.use_cases.change_password.execute(
        identity.id, VALID_PASSWORD, OTHER_PASSWORD
    )

    assert reset_token.used_at is not None


def test_wrong_current_password_is_rejected_without_changes() -> None:
    harness = Harness()
    identity = harness.register_and_verify()
    harness.login()
    hash_before = identity.password_hash

    with pytest.raises(InvalidCurrentPasswordError):
        harness.use_cases.change_password.execute(
            identity.id, "wrong-current-password", OTHER_PASSWORD
        )

    stored = harness.identity_repository.get_by_id(identity.id)
    assert stored is not None
    assert stored.password_hash == hash_before
    session = next(iter(harness.sessions.sessions.values()))
    assert session.revoked_at is None  # sessions survive a failed attempt


def test_weak_new_password_is_rejected() -> None:
    harness = Harness()
    identity = harness.register_and_verify()

    with pytest.raises(InvalidPasswordError):
        harness.use_cases.change_password.execute(identity.id, VALID_PASSWORD, "short")


def test_change_password_for_unknown_identity_fails() -> None:
    harness = Harness()

    with pytest.raises(IdentityNotFoundError):
        harness.use_cases.change_password.execute(
            uuid4(), VALID_PASSWORD, OTHER_PASSWORD
        )


def test_deactivated_identity_cannot_change_password() -> None:
    harness = Harness()
    identity = harness.register_and_verify()
    identity.deactivate()
    harness.identity_repository.update(identity)

    with pytest.raises(IdentityNotActiveError):
        harness.use_cases.change_password.execute(
            identity.id, VALID_PASSWORD, OTHER_PASSWORD
        )
