"""Introspection endpoint contract tests.

The endpoint is the service-to-service half of the Identity/Accounts
authentication integration: Accounts validates bearer tokens here. The
database layer is faked as in ``test_api.py``; only the presentation
contract (status codes, bodies, key handling) is under test.
"""

from typing import Any

from fastapi.testclient import TestClient

from identity_service.infrastructure.config import Settings
from identity_service.main import create_app
from identity_service.presentation.dependencies import get_settings, get_use_cases
from tests.unit.fakes import VALID_PASSWORD, Harness

API = "/api/v1/identity/introspect"
SERVICE_KEY = "test-service-key"


def test_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "database_url": "postgresql+psycopg://test:test@localhost:5432/test",
        "environment": "test",
        "log_format": "console",
        "service_api_key": SERVICE_KEY,
    }
    values.update(overrides)
    return Settings(**values)


def make_client(
    settings: Settings | None = None, harness: Harness | None = None
) -> tuple[TestClient, Harness]:
    harness = harness or Harness()
    settings = settings or test_settings()
    app = create_app(settings)
    app.dependency_overrides[get_use_cases] = lambda: harness.use_cases
    app.dependency_overrides[get_settings] = lambda: settings
    return TestClient(app, raise_server_exceptions=False), harness


def prepared(**harness_kwargs: Any) -> tuple[TestClient, Harness, str, Any]:
    """A verified identity, a live login token, and its identity id."""
    client, harness = make_client(harness=Harness(**harness_kwargs))
    identity = harness.register_and_verify()
    token = harness.login()
    return client, harness, token, identity.id


def introspect(client: TestClient, token: str, key: str | None = SERVICE_KEY) -> Any:
    headers = {"X-Service-Key": key} if key is not None else {}
    return client.post(API, json={"token": token}, headers=headers)


class TestActiveTokens:
    def test_valid_token_returns_identity_and_expiry(self) -> None:
        client, _, token, identity_id = prepared()

        response = introspect(client, token)

        assert response.status_code == 200
        body = response.json()
        assert body["active"] is True
        assert body["identity_id"] == str(identity_id)
        assert body["expires_at"]

    def test_response_discloses_no_email_or_raw_token(self) -> None:
        client, _, token, _ = prepared()

        response = introspect(client, token)

        assert "email" not in response.json()
        assert token not in response.text


class TestInactiveTokens:
    def test_unknown_token_is_inactive_without_optional_fields(self) -> None:
        client, _, _, _ = prepared()

        response = introspect(client, "never-issued-token")

        assert response.status_code == 200
        assert response.json() == {"active": False}

    def test_expired_session_is_inactive(self) -> None:
        client, harness, token, _ = prepared(session_ttl_seconds=60)
        harness.clock.advance(seconds=61)

        response = introspect(client, token)

        assert response.status_code == 200
        assert response.json() == {"active": False}

    def test_revoked_session_is_inactive(self) -> None:
        client, harness, token, _ = prepared()
        session_id = next(iter(harness.sessions.sessions))
        harness.use_cases.logout.execute(session_id)

        response = introspect(client, token)

        assert response.status_code == 200
        assert response.json() == {"active": False}

    def test_deactivated_identity_is_inactive(self) -> None:
        client, harness, token, identity_id = prepared()
        harness.use_cases.deactivate_identity.execute(identity_id, VALID_PASSWORD)

        response = introspect(client, token)

        assert response.status_code == 200
        assert response.json() == {"active": False}

    def test_all_inactive_bodies_are_identical(self) -> None:
        client, harness, token, identity_id = prepared()
        harness.use_cases.deactivate_identity.execute(identity_id, VALID_PASSWORD)

        unknown = introspect(client, "nope").json()
        deactivated = introspect(client, token).json()

        assert unknown == deactivated == {"active": False}


class TestServiceKey:
    def test_missing_key_is_403(self) -> None:
        client, _, token, _ = prepared()

        response = introspect(client, token, key=None)

        assert response.status_code == 403

    def test_wrong_key_is_403(self) -> None:
        client, _, token, _ = prepared()

        response = introspect(client, token, key="not-the-key")

        assert response.status_code == 403
        assert response.json()["error"]["code"] == "http_403"

    def test_endpoint_disabled_when_no_key_configured(self) -> None:
        settings = test_settings(service_api_key=None)
        harness = Harness()
        harness.register_and_verify()
        token = harness.login()
        client, _ = make_client(settings=settings, harness=harness)

        with_key = introspect(client, token, key=SERVICE_KEY)
        without_key = introspect(client, token, key=None)

        assert with_key.status_code == without_key.status_code == 403

    def test_validation_error_without_token_field(self) -> None:
        client, _, _, _ = prepared()

        response = client.post(API, json={}, headers={"X-Service-Key": SERVICE_KEY})

        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_error"
