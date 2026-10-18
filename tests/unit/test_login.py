from datetime import timedelta

import pytest

from identity_service.application.security import hash_token
from identity_service.domain.exceptions import AuthenticationError
from tests.unit.fakes import OTHER_PASSWORD, VALID_PASSWORD, Harness


def test_successful_login_returns_session_token() -> None:
    harness = Harness(session_ttl_seconds=3600)
    harness.register_and_verify()

    result = harness.use_cases.login.execute("CUSTOMER@example.com", VALID_PASSWORD)

    assert result.email == "customer@example.com"
    assert result.access_token  # raw token handed to the client exactly once
    session = next(iter(harness.sessions.sessions.values()))
    assert session.identity_id == result.identity_id
    assert session.token_hash == hash_token(result.access_token)
    assert session.revoked_at is None
    assert session.expires_at == harness.clock.utc_now() + timedelta(seconds=3600)


def test_wrong_password_raises_generic_error() -> None:
    harness = Harness()
    harness.register_and_verify()

    with pytest.raises(AuthenticationError, match="Invalid email or password"):
        harness.use_cases.login.execute("customer@example.com", "wrong-password")


def test_unknown_email_raises_same_generic_error() -> None:
    harness = Harness()

    with pytest.raises(AuthenticationError, match="Invalid email or password"):
        harness.use_cases.login.execute("unknown@example.com", VALID_PASSWORD)


def test_unknown_email_still_performs_a_password_check() -> None:
    harness = Harness()

    with pytest.raises(AuthenticationError):
        harness.use_cases.login.execute("unknown@example.com", VALID_PASSWORD)

    assert harness.password_hasher.dummy_verifications == 1


def test_pending_identity_cannot_authenticate() -> None:
    harness = Harness()
    harness.register()

    with pytest.raises(AuthenticationError, match="Invalid email or password"):
        harness.use_cases.login.execute("customer@example.com", VALID_PASSWORD)


def test_deactivated_identity_cannot_authenticate() -> None:
    harness = Harness()
    identity = harness.register_and_verify()
    identity.deactivate()
    harness.identity_repository.update(identity)

    with pytest.raises(AuthenticationError, match="Invalid email or password"):
        harness.use_cases.login.execute("customer@example.com", VALID_PASSWORD)


def test_login_rehashes_password_when_parameters_are_outdated() -> None:
    harness = Harness()
    identity = harness.register_and_verify()
    harness.password_hasher.needs_rehash_result = True

    harness.use_cases.login.execute("customer@example.com", VALID_PASSWORD)

    stored = harness.identity_repository.get_by_id(identity.id)
    assert stored is not None
    assert harness.identity_repository.update_calls  # hash refreshed at login
    assert stored.password_hash == harness.password_hasher._fake_hash(VALID_PASSWORD)


def test_old_password_no_longer_works_after_change() -> None:
    harness = Harness()
    identity = harness.register_and_verify()
    harness.use_cases.change_password.execute(
        identity.id, VALID_PASSWORD, OTHER_PASSWORD
    )

    with pytest.raises(AuthenticationError):
        harness.use_cases.login.execute("customer@example.com", VALID_PASSWORD)

    result = harness.use_cases.login.execute("customer@example.com", OTHER_PASSWORD)
    assert result.access_token
