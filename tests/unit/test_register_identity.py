from datetime import timedelta
from uuid import uuid4

import pytest

from identity_service.application.security import hash_token
from identity_service.domain.enums.identity_status import IdentityStatus
from identity_service.domain.exceptions import (
    IdentityAlreadyExistsError,
    InvalidEmailError,
    InvalidPasswordError,
)
from tests.unit.fakes import VALID_PASSWORD, Harness


def test_valid_registration_creates_pending_identity() -> None:
    harness = Harness()

    identity = harness.register()

    assert identity.status == IdentityStatus.PENDING_VERIFICATION
    assert identity.email_verified_at is None
    assert harness.identity_repository.get_by_id(identity.id) is identity


def test_registration_normalizes_email() -> None:
    harness = Harness()

    identity = harness.use_cases.register_identity.execute(
        "  CUSTOMER@Example.COM ", VALID_PASSWORD
    )

    assert identity.email == "customer@example.com"
    # Lookups use the same normalization policy, so either spelling finds it.
    assert harness.identity_repository.get_by_email("customer@example.com") is identity
    # And the differently-spelled duplicate is caught by the same policy.
    with pytest.raises(IdentityAlreadyExistsError):
        harness.use_cases.register_identity.execute(
            "customer@EXAMPLE.com", VALID_PASSWORD
        )


def test_registration_stores_hash_not_raw_password() -> None:
    harness = Harness()

    identity = harness.register()

    assert VALID_PASSWORD in harness.password_hasher.hashed
    assert identity.password_hash != VALID_PASSWORD
    assert identity.password_hash.startswith("fake-hash$")


def test_registration_issues_single_use_verification_token() -> None:
    harness = Harness(verification_ttl_seconds=7200)

    identity = harness.register()

    tokens = list(harness.verification_tokens.tokens.values())
    assert len(tokens) == 1
    token = tokens[0]
    assert token.identity_id == identity.id
    assert token.used_at is None
    assert token.created_at == harness.clock.utc_now()
    assert token.expires_at == token.created_at + timedelta(seconds=7200)
    # Only the hash of the raw token is persisted.
    assert token.token_hash == hash_token(harness.token_generator.generated[0])
    assert token.token_hash != harness.token_generator.generated[0]


def test_registration_sends_verification_email_with_raw_token() -> None:
    harness = Harness()

    harness.register()

    (to_email, raw_token, expires_at) = harness.email_sender.verification_emails[0]
    assert to_email == "customer@example.com"
    assert raw_token == harness.token_generator.generated[0]
    assert expires_at > harness.clock.utc_now()


def test_registration_with_customer_reference_keeps_it_stable() -> None:
    harness = Harness()
    customer_id = uuid4()

    identity = harness.use_cases.register_identity.execute(
        "customer@example.com", VALID_PASSWORD, customer_id=customer_id
    )

    assert identity.customer_id == customer_id
    assert harness.identity_repository.get_by_id(identity.id).customer_id == customer_id


def test_invalid_email_rejects_registration_without_side_effects() -> None:
    harness = Harness()

    with pytest.raises(InvalidEmailError):
        harness.use_cases.register_identity.execute("not-an-email", VALID_PASSWORD)

    assert harness.identity_repository.add_calls == []
    assert harness.email_sender.verification_emails == []
    assert harness.password_hasher.hashed == []


def test_weak_password_rejects_registration_without_side_effects() -> None:
    harness = Harness()

    with pytest.raises(InvalidPasswordError):
        harness.use_cases.register_identity.execute("customer@example.com", "short")

    assert harness.identity_repository.add_calls == []
    assert harness.email_sender.verification_emails == []


def test_duplicate_email_is_rejected_at_application_level() -> None:
    harness = Harness()
    harness.register()

    with pytest.raises(IdentityAlreadyExistsError):
        harness.use_cases.register_identity.execute(
            "CUSTOMER@example.com", VALID_PASSWORD
        )

    assert len(harness.identity_repository.identities) == 1
    # No second email went out for the rejected attempt.
    assert len(harness.email_sender.verification_emails) == 1


def test_concurrent_registration_race_is_caught_by_constraint() -> None:
    harness = Harness()
    harness.identity_repository.race_on_add = True

    with pytest.raises(IdentityAlreadyExistsError):
        harness.register()

    assert harness.email_sender.verification_emails == []


def test_email_delivery_failure_does_not_lose_the_registration() -> None:
    harness = Harness(email_fail=True)

    identity = harness.register()

    assert harness.identity_repository.get_by_id(identity.id) is not None
    assert len(harness.verification_tokens.tokens) == 1
    # The user can recover through the resend endpoint.
    assert harness.email_sender.verification_emails == []
