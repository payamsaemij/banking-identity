import pytest

from identity_service.domain.enums.identity_status import IdentityStatus
from identity_service.domain.exceptions import (
    IdentityNotActiveError,
    InvalidTokenError,
)
from tests.unit.fakes import Harness


def raw_token_of(harness: Harness) -> str:
    return harness.email_sender.verification_emails[-1][1]


def test_valid_token_verifies_email_and_activates_identity() -> None:
    harness = Harness()
    harness.register()

    identity = harness.use_cases.verify_email.execute(raw_token_of(harness))

    assert identity.status == IdentityStatus.ACTIVE
    assert identity.email_verified_at == harness.clock.utc_now()
    assert identity.can_authenticate() is True


def test_unknown_token_is_rejected() -> None:
    harness = Harness()
    harness.register()

    with pytest.raises(InvalidTokenError):
        harness.use_cases.verify_email.execute("never-issued-token")


def test_expired_token_is_rejected() -> None:
    harness = Harness(verification_ttl_seconds=60)
    harness.register()

    harness.clock.advance(seconds=61)

    with pytest.raises(InvalidTokenError):
        harness.use_cases.verify_email.execute(raw_token_of(harness))

    # The identity stays pending.
    identity = next(iter(harness.identity_repository.identities.values()))
    assert identity.status == IdentityStatus.PENDING_VERIFICATION


def test_token_cannot_be_reused() -> None:
    harness = Harness()
    harness.register_and_verify()

    with pytest.raises(InvalidTokenError):
        harness.use_cases.verify_email.execute(raw_token_of(harness))


def test_deactivated_identity_cannot_verify_email() -> None:
    harness = Harness()
    identity = harness.register()
    identity.deactivate()
    harness.identity_repository.update(identity)

    with pytest.raises(IdentityNotActiveError):
        harness.use_cases.verify_email.execute(raw_token_of(harness))

    assert identity.status == IdentityStatus.DEACTIVATED
    assert identity.email_verified_at is None


def test_verification_token_is_marked_used_on_success() -> None:
    harness = Harness()
    harness.register()

    harness.use_cases.verify_email.execute(raw_token_of(harness))

    token = next(iter(harness.verification_tokens.tokens.values()))
    assert token.used_at == harness.clock.utc_now()
