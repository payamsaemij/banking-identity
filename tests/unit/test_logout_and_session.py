from uuid import uuid4

from tests.unit.fakes import VALID_PASSWORD, Harness


def test_authenticate_session_resolves_valid_token() -> None:
    harness = Harness()
    identity = harness.register_and_verify()
    raw_token = harness.login()

    context = harness.use_cases.authenticate_session.execute(raw_token)

    assert context is not None
    assert context.identity_id == identity.id
    assert context.email == "customer@example.com"


def test_authenticate_session_rejects_unknown_token() -> None:
    harness = Harness()

    assert harness.use_cases.authenticate_session.execute("no-such-token") is None


def test_authenticate_session_rejects_expired_session() -> None:
    harness = Harness(session_ttl_seconds=600)
    harness.register_and_verify()
    raw_token = harness.login()

    harness.clock.advance(seconds=601)

    assert harness.use_cases.authenticate_session.execute(raw_token) is None


def test_logout_revokes_the_session_immediately() -> None:
    harness = Harness()
    harness.register_and_verify()
    raw_token = harness.login()
    context = harness.use_cases.authenticate_session.execute(raw_token)
    assert context is not None

    harness.use_cases.logout.execute(context.session_id)

    assert harness.use_cases.authenticate_session.execute(raw_token) is None


def test_logout_is_idempotent() -> None:
    harness = Harness()
    harness.register_and_verify()
    raw_token = harness.login()
    context = harness.use_cases.authenticate_session.execute(raw_token)
    assert context is not None

    harness.use_cases.logout.execute(context.session_id)
    harness.use_cases.logout.execute(context.session_id)

    assert harness.use_cases.authenticate_session.execute(raw_token) is None


def test_deactivation_invalidates_live_sessions() -> None:
    harness = Harness()
    identity = harness.register_and_verify()
    raw_token = harness.login()

    harness.use_cases.deactivate_identity.execute(identity.id, VALID_PASSWORD)

    assert harness.use_cases.authenticate_session.execute(raw_token) is None


def test_session_of_deactivated_identity_is_rejected() -> None:
    harness = Harness(session_ttl_seconds=9999)
    harness.register_and_verify()
    raw_token = harness.login()
    # Direct deactivation (as the administrative path would do).
    identity = next(iter(harness.identity_repository.identities.values()))
    identity.deactivate()
    harness.identity_repository.update(identity)

    assert harness.use_cases.authenticate_session.execute(raw_token) is None


def test_logout_for_unknown_session_is_harmless() -> None:
    harness = Harness()

    harness.use_cases.logout.execute(uuid4())  # no error expected
