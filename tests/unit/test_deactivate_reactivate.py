from uuid import uuid4

import pytest

from identity_service.domain.enums.identity_status import IdentityStatus
from identity_service.domain.exceptions import (
    IdentityNotFoundError,
    InvalidCurrentPasswordError,
    InvalidIdentityStateError,
)
from tests.unit.fakes import VALID_PASSWORD, Harness


def test_deactivate_with_correct_password_succeeds_and_revokes_sessions() -> None:
    harness = Harness()
    identity = harness.register_and_verify()
    harness.login()

    harness.use_cases.deactivate_identity.execute(identity.id, VALID_PASSWORD)

    stored = harness.identity_repository.get_by_id(identity.id)
    assert stored is not None
    assert stored.status == IdentityStatus.DEACTIVATED
    session = next(iter(harness.sessions.sessions.values()))
    assert session.revoked_at is not None


def test_deactivate_with_wrong_password_changes_nothing() -> None:
    harness = Harness()
    identity = harness.register_and_verify()

    with pytest.raises(InvalidCurrentPasswordError):
        harness.use_cases.deactivate_identity.execute(
            identity.id, "wrong-current-password"
        )

    stored = harness.identity_repository.get_by_id(identity.id)
    assert stored is not None
    assert stored.status == IdentityStatus.ACTIVE


def test_deactivate_invalidates_outstanding_tokens() -> None:
    harness = Harness()
    identity = harness.register_and_verify()
    harness.use_cases.request_password_reset.execute("customer@example.com")
    reset_token = next(iter(harness.reset_tokens.tokens.values()))

    harness.use_cases.deactivate_identity.execute(identity.id, VALID_PASSWORD)

    assert reset_token.used_at is not None


def test_deactivate_unknown_identity_fails() -> None:
    harness = Harness()

    with pytest.raises(IdentityNotFoundError):
        harness.use_cases.deactivate_identity.execute(uuid4(), VALID_PASSWORD)


def test_deactivating_twice_is_rejected_by_the_domain() -> None:
    harness = Harness()
    identity = harness.register_and_verify()
    harness.use_cases.deactivate_identity.execute(identity.id, VALID_PASSWORD)

    with pytest.raises(InvalidIdentityStateError):
        harness.use_cases.deactivate_identity.execute(identity.id, VALID_PASSWORD)


def test_reactivate_restores_verified_identity_to_active() -> None:
    harness = Harness()
    identity = harness.register_and_verify()
    harness.use_cases.deactivate_identity.execute(identity.id, VALID_PASSWORD)

    reactivated = harness.use_cases.reactivate_identity.execute(identity.id)

    assert reactivated.status == IdentityStatus.ACTIVE
    assert reactivated.can_authenticate() is True


def test_reactivate_unverified_identity_returns_to_pending() -> None:
    harness = Harness()
    identity = harness.register()
    identity.deactivate()
    harness.identity_repository.update(identity)

    reactivated = harness.use_cases.reactivate_identity.execute(identity.id)

    assert reactivated.status == IdentityStatus.PENDING_VERIFICATION


def test_reactivate_unknown_identity_fails() -> None:
    harness = Harness()

    with pytest.raises(IdentityNotFoundError):
        harness.use_cases.reactivate_identity.execute(uuid4())


def test_reactivated_identity_can_authenticate_again() -> None:
    harness = Harness()
    identity = harness.register_and_verify()
    harness.use_cases.deactivate_identity.execute(identity.id, VALID_PASSWORD)

    harness.use_cases.reactivate_identity.execute(identity.id)
    result = harness.use_cases.login.execute("customer@example.com", VALID_PASSWORD)

    assert result.access_token
