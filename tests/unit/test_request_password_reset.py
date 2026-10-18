from datetime import timedelta

from identity_service.application.security import hash_token
from tests.unit.fakes import Harness


def test_request_for_known_active_identity_sends_reset_email() -> None:
    harness = Harness(reset_ttl_seconds=1800)
    harness.register_and_verify()

    harness.use_cases.request_password_reset.execute("  CUSTOMER@example.com ")

    assert len(harness.email_sender.reset_emails) == 1
    (to_email, raw_token, _expires_at) = harness.email_sender.reset_emails[0]
    assert to_email == "customer@example.com"
    token = next(iter(harness.reset_tokens.tokens.values()))
    assert token.token_hash == hash_token(raw_token)
    assert token.expires_at == token.created_at + timedelta(seconds=1800)


def test_request_for_unknown_email_is_silent() -> None:
    harness = Harness()

    harness.use_cases.request_password_reset.execute("unknown@example.com")

    assert harness.email_sender.reset_emails == []
    assert harness.reset_tokens.tokens == {}


def test_request_for_pending_identity_is_silent() -> None:
    harness = Harness()
    harness.register()

    harness.use_cases.request_password_reset.execute("customer@example.com")

    assert harness.email_sender.reset_emails == []


def test_request_for_deactivated_identity_is_silent() -> None:
    harness = Harness()
    identity = harness.register_and_verify()
    identity.deactivate()
    harness.identity_repository.update(identity)

    harness.use_cases.request_password_reset.execute("customer@example.com")

    assert harness.email_sender.reset_emails == []


def test_new_request_invalidates_previous_reset_tokens() -> None:
    harness = Harness()
    harness.register_and_verify()
    harness.use_cases.request_password_reset.execute("customer@example.com")
    first_token = next(iter(harness.reset_tokens.tokens.values()))

    harness.use_cases.request_password_reset.execute("customer@example.com")

    assert first_token.used_at is not None
    assert len(harness.reset_tokens.tokens) == 2
    assert len(harness.email_sender.reset_emails) == 2


def test_email_delivery_failure_is_swallowed() -> None:
    harness = Harness(email_fail=True)
    harness.register_and_verify()

    harness.use_cases.request_password_reset.execute("customer@example.com")

    # No exception: the response must not reveal delivery problems.
    assert harness.reset_tokens.tokens
