import pytest

from identity_service.domain.enums.identity_status import IdentityStatus
from identity_service.domain.exceptions import InvalidTokenError
from tests.unit.fakes import Harness


def test_resend_for_pending_identity_issues_new_token_and_email() -> None:
    harness = Harness()
    harness.register()

    harness.use_cases.resend_email_verification.execute("customer@example.com")

    assert len(harness.email_sender.verification_emails) == 2
    assert len(harness.verification_tokens.tokens) == 2


def test_resend_invalidates_previous_tokens() -> None:
    harness = Harness()
    harness.register()
    first_token = next(iter(harness.verification_tokens.tokens.values()))

    harness.use_cases.resend_email_verification.execute("CUSTOMER@example.com")

    assert first_token.used_at is not None
    # The old link no longer verifies anything.
    with pytest.raises(InvalidTokenError):
        harness.use_cases.verify_email.execute(
            harness.email_sender.verification_emails[0][1]
        )


def test_resend_for_unknown_email_is_silent() -> None:
    harness = Harness()

    harness.use_cases.resend_email_verification.execute("unknown@example.com")

    assert harness.email_sender.verification_emails == []
    assert harness.verification_tokens.tokens == {}


def test_resend_for_active_identity_is_silent() -> None:
    harness = Harness()
    harness.register_and_verify()

    harness.use_cases.resend_email_verification.execute("customer@example.com")

    assert len(harness.email_sender.verification_emails) == 1  # only the original
    assert len(harness.verification_tokens.tokens) == 1


def test_resend_for_deactivated_identity_is_silent() -> None:
    harness = Harness()
    identity = harness.register()
    identity.deactivate()
    harness.identity_repository.update(identity)

    harness.use_cases.resend_email_verification.execute("customer@example.com")

    assert len(harness.email_sender.verification_emails) == 1
    assert len(harness.verification_tokens.tokens) == 1


def test_new_token_from_resend_verifies_the_identity() -> None:
    harness = Harness()
    harness.register()
    harness.use_cases.resend_email_verification.execute("customer@example.com")

    identity = harness.use_cases.verify_email.execute(
        harness.email_sender.verification_emails[1][1]
    )

    assert identity.status == IdentityStatus.ACTIVE
