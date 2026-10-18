
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from identity_service.domain.entities.identity import Identity
from identity_service.domain.enums.identity_status import IdentityStatus


def create_identity() -> Identity:
    return Identity(
        id=uuid4(),
        email="customer@example.com",
        password_hash="hashed-password",
    )


def test_new_identity_cannot_authenticate() -> None:
    identity = create_identity()

    assert identity.status == IdentityStatus.PENDING_VERIFICATION
    assert identity.can_authenticate() is False


def test_verifying_email_activates_identity() -> None:
    identity = create_identity()

    identity.verify_email(datetime.now(UTC))

    assert identity.status == IdentityStatus.ACTIVE
    assert identity.can_authenticate() is True


def test_deactivated_identity_cannot_authenticate() -> None:
    identity = create_identity()
    identity.verify_email(datetime.now(UTC))

    identity.deactivate()

    assert identity.status == IdentityStatus.DEACTIVATED
    assert identity.can_authenticate() is False


def test_email_cannot_be_verified_twice() -> None:
    identity = create_identity()
    identity.verify_email(datetime.now(UTC))

    with pytest.raises(ValueError):
        identity.verify_email(datetime.now(UTC))
