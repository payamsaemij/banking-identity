from datetime import UTC, datetime
from uuid import uuid4

import pytest

from identity_service.domain.entities.identity import Identity
from identity_service.domain.enums.identity_status import IdentityStatus
from identity_service.domain.exceptions import (
    EmailAlreadyVerifiedError,
    IdentityNotActiveError,
    InvalidIdentityStateError,
)


def create_identity() -> Identity:
    return Identity(
        id=uuid4(),
        email="customer@example.com",
        password_hash="hashed-password",
    )


def verified_identity() -> Identity:
    identity = create_identity()
    identity.verify_email(datetime.now(UTC))
    return identity


def test_new_identity_starts_pending_and_cannot_authenticate() -> None:
    identity = create_identity()

    assert identity.status == IdentityStatus.PENDING_VERIFICATION
    assert identity.email_verified_at is None
    assert identity.can_authenticate() is False


def test_verifying_email_activates_identity() -> None:
    identity = create_identity()
    verified_at = datetime.now(UTC)

    identity.verify_email(verified_at)

    assert identity.status == IdentityStatus.ACTIVE
    assert identity.email_verified_at == verified_at
    assert identity.can_authenticate() is True


def test_email_cannot_be_verified_twice() -> None:
    identity = verified_identity()

    with pytest.raises(EmailAlreadyVerifiedError):
        identity.verify_email(datetime.now(UTC))


def test_verification_does_not_reactivate_deactivated_identity() -> None:
    identity = create_identity()
    identity.deactivate()

    with pytest.raises(IdentityNotActiveError):
        identity.verify_email(datetime.now(UTC))

    assert identity.status == IdentityStatus.DEACTIVATED
    assert identity.email_verified_at is None
    assert identity.can_authenticate() is False


def test_deactivated_identity_cannot_authenticate() -> None:
    identity = verified_identity()

    identity.deactivate()

    assert identity.status == IdentityStatus.DEACTIVATED
    assert identity.can_authenticate() is False
    # Email verification survives deactivation for a later reactivation.
    assert identity.email_verified_at is not None


def test_deactivating_twice_is_rejected() -> None:
    identity = verified_identity()
    identity.deactivate()

    with pytest.raises(InvalidIdentityStateError):
        identity.deactivate()


def test_reactivate_returns_verified_identity_to_active() -> None:
    identity = verified_identity()
    identity.deactivate()

    identity.reactivate()

    assert identity.status == IdentityStatus.ACTIVE
    assert identity.can_authenticate() is True


def test_reactivate_unverified_identity_returns_to_pending() -> None:
    identity = create_identity()
    identity.deactivate()

    identity.reactivate()

    assert identity.status == IdentityStatus.PENDING_VERIFICATION
    assert identity.can_authenticate() is False


def test_only_deactivated_identity_can_be_reactivated() -> None:
    identity = verified_identity()

    with pytest.raises(InvalidIdentityStateError):
        identity.reactivate()

    pending = create_identity()
    with pytest.raises(InvalidIdentityStateError):
        pending.reactivate()


def test_change_password_replaces_hash_for_active_identity() -> None:
    identity = verified_identity()

    identity.change_password("new-hash")

    assert identity.password_hash == "new-hash"


def test_change_password_rejected_for_non_active_identity() -> None:
    identity = create_identity()

    with pytest.raises(IdentityNotActiveError):
        identity.change_password("new-hash")


def test_password_reset_applies_to_deactivated_identity_without_reactivating() -> None:
    identity = verified_identity()
    identity.deactivate()

    identity.apply_password_reset("reset-hash")

    assert identity.password_hash == "reset-hash"
    assert identity.status == IdentityStatus.DEACTIVATED
    assert identity.can_authenticate() is False


def test_password_reset_applies_to_pending_identity_without_verifying() -> None:
    identity = create_identity()

    identity.apply_password_reset("reset-hash")

    assert identity.password_hash == "reset-hash"
    assert identity.status == IdentityStatus.PENDING_VERIFICATION
    assert identity.can_authenticate() is False
