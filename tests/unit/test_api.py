"""API contract tests: schemas, status codes, and error mapping.

The database and email layers are replaced with the in-memory fakes by
overriding the composition dependencies; no PostgreSQL or SMTP needed.
"""

from typing import Any

from fastapi.testclient import TestClient

from identity_service.infrastructure.config import Settings
from identity_service.main import create_app
from identity_service.presentation.api.health import database_ready
from identity_service.presentation.dependencies import get_settings, get_use_cases
from tests.unit.fakes import OTHER_PASSWORD, VALID_PASSWORD, Harness

API = "/api/v1/identity"


def test_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "database_url": "postgresql+psycopg://test:test@localhost:5432/test",
        "environment": "test",
        "log_format": "console",
        "register_rate_limit_max": 1000,
        "login_rate_limit_max": 1000,
        "resend_rate_limit_max": 1000,
        "password_reset_request_rate_limit_max": 1000,
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


def register_payload(email: str = "customer@example.com") -> dict[str, Any]:
    return {"email": email, "password": VALID_PASSWORD}


class TestRegistration:
    def test_register_returns_201_with_identity(self) -> None:
        client, harness = make_client()

        response = client.post(f"{API}/register", json=register_payload())

        assert response.status_code == 201
        body = response.json()
        assert body["email"] == "customer@example.com"
        assert body["status"] == "pending_verification"
        assert body["email_verified_at"] is None
        assert "password_hash" not in body
        assert len(harness.email_sender.verification_emails) == 1

    def test_register_normalizes_email(self) -> None:
        client, _ = make_client()

        response = client.post(
            f"{API}/register", json=register_payload("  CUSTOMER@Example.COM ")
        )

        assert response.status_code == 201
        assert response.json()["email"] == "customer@example.com"

    def test_register_duplicate_returns_409(self) -> None:
        client, _ = make_client()
        client.post(f"{API}/register", json=register_payload())

        response = client.post(f"{API}/register", json=register_payload())

        assert response.status_code == 409
        assert response.json()["error"]["code"] == "email_already_registered"

    def test_register_invalid_email_returns_422(self) -> None:
        client, harness = make_client()

        response = client.post(f"{API}/register", json=register_payload("nope"))

        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_error"
        assert harness.identity_repository.add_calls == []

    def test_register_weak_password_returns_422_without_echoing_it(self) -> None:
        client, _ = make_client()

        response = client.post(
            f"{API}/register", json={"email": "a@example.com", "password": "short"}
        )

        assert response.status_code == 422
        text = response.text
        assert VALID_PASSWORD not in text and "short" not in text


class TestVerification:
    def test_verify_email_returns_200(self) -> None:
        client, harness = make_client()
        client.post(f"{API}/register", json=register_payload())
        raw_token = harness.email_sender.verification_emails[0][1]

        response = client.post(f"{API}/verify-email", json={"token": raw_token})

        assert response.status_code == 200
        assert response.json()["status"] == "active"

    def test_verify_email_invalid_token_returns_400(self) -> None:
        client, _ = make_client()

        response = client.post(f"{API}/verify-email", json={"token": "bogus"})

        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_token"

    def test_resend_is_always_202_and_generic(self) -> None:
        client, _ = make_client()
        client.post(f"{API}/register", json=register_payload())

        known = client.post(
            f"{API}/resend-verification", json={"email": "customer@example.com"}
        )
        unknown = client.post(
            f"{API}/resend-verification", json={"email": "unknown@example.com"}
        )

        assert known.status_code == unknown.status_code == 202
        assert known.json() == unknown.json()


class TestLoginAndSessions:
    def login_token(self, client: TestClient) -> str:
        response = client.post(
            f"{API}/login",
            json={"email": "customer@example.com", "password": VALID_PASSWORD},
        )
        assert response.status_code == 200
        return response.json()["access_token"]

    def prepared(self) -> tuple[TestClient, Harness]:
        client, harness = make_client()
        client.post(f"{API}/register", json=register_payload())
        raw = harness.email_sender.verification_emails[0][1]
        client.post(f"{API}/verify-email", json={"token": raw})
        return client, harness

    def test_login_returns_token_and_expiry(self) -> None:
        client, _ = self.prepared()

        response = client.post(
            f"{API}/login",
            json={"email": "CUSTOMER@example.com", "password": VALID_PASSWORD},
        )

        body = response.json()
        assert response.status_code == 200
        assert body["token_type"] == "bearer"
        assert body["access_token"]
        assert body["expires_at"]

    def test_login_failure_is_generic_401(self) -> None:
        client, _ = self.prepared()

        wrong = client.post(
            f"{API}/login",
            json={"email": "customer@example.com", "password": "wrong-wrong-wrong"},
        )
        unknown = client.post(
            f"{API}/login",
            json={"email": "ghost@example.com", "password": "wrong-wrong-wrong"},
        )

        assert wrong.status_code == unknown.status_code == 401
        # Identical apart from the per-request correlation id.
        wrong_error = wrong.json()["error"]
        unknown_error = unknown.json()["error"]
        wrong_error.pop("request_id")
        unknown_error.pop("request_id")
        assert wrong_error == unknown_error
        assert wrong.headers["www-authenticate"] == "Bearer"

    def test_protected_endpoints_require_bearer_token(self) -> None:
        client, _ = self.prepared()

        response = client.post(
            f"{API}/password/change",
            json={"current_password": VALID_PASSWORD, "new_password": OTHER_PASSWORD},
        )

        assert response.status_code == 401

    def test_logout_revokes_session(self) -> None:
        client, _ = self.prepared()
        token = self.login_token(client)

        logout = client.post(
            f"{API}/logout", headers={"Authorization": f"Bearer {token}"}
        )
        reuse = client.post(
            f"{API}/password/change",
            headers={"Authorization": f"Bearer {token}"},
            json={"current_password": VALID_PASSWORD, "new_password": OTHER_PASSWORD},
        )

        assert logout.status_code == 204
        assert reuse.status_code == 401

    def test_change_password_revokes_current_session(self) -> None:
        client, _ = self.prepared()
        token = self.login_token(client)

        response = client.post(
            f"{API}/password/change",
            headers={"Authorization": f"Bearer {token}"},
            json={"current_password": VALID_PASSWORD, "new_password": OTHER_PASSWORD},
        )

        assert response.status_code == 204
        reused = client.post(
            f"{API}/logout", headers={"Authorization": f"Bearer {token}"}
        )
        assert reused.status_code == 401
        login = client.post(
            f"{API}/login",
            json={"email": "customer@example.com", "password": OTHER_PASSWORD},
        )
        assert login.status_code == 200


class TestPasswordReset:
    def test_reset_request_is_always_202_and_generic(self) -> None:
        client, _ = make_client()

        known = client.post(
            f"{API}/password/reset-request", json={"email": "who@example.com"}
        )
        unknown = client.post(
            f"{API}/password/reset-request", json={"email": "ghost@example.com"}
        )

        assert known.status_code == unknown.status_code == 202
        assert known.json() == unknown.json()

    def test_full_reset_flow(self) -> None:
        client, harness = make_client()
        client.post(f"{API}/register", json=register_payload())
        raw = harness.email_sender.verification_emails[0][1]
        client.post(f"{API}/verify-email", json={"token": raw})
        client.post(
            f"{API}/password/reset-request", json={"email": "customer@example.com"}
        )
        reset_token = harness.email_sender.reset_emails[0][1]

        response = client.post(
            f"{API}/password/reset",
            json={"token": reset_token, "new_password": OTHER_PASSWORD},
        )
        login = client.post(
            f"{API}/login",
            json={"email": "customer@example.com", "password": OTHER_PASSWORD},
        )

        assert response.status_code == 204
        assert login.status_code == 200

    def test_reset_with_invalid_token_returns_400(self) -> None:
        client, _ = make_client()

        response = client.post(
            f"{API}/password/reset",
            json={"token": "bogus", "new_password": OTHER_PASSWORD},
        )

        assert response.status_code == 400


class TestLifecycle:
    def prepared(self) -> tuple[TestClient, Harness]:
        client, harness = make_client()
        client.post(f"{API}/register", json=register_payload())
        raw = harness.email_sender.verification_emails[0][1]
        client.post(f"{API}/verify-email", json={"token": raw})
        return client, harness

    def test_deactivate_with_wrong_password_returns_403(self) -> None:
        client, _ = self.prepared()
        token = self.login_token(client)

        response = client.post(
            f"{API}/deactivate",
            headers={"Authorization": f"Bearer {token}"},
            json={"current_password": "wrong-wrong-wrong"},
        )

        assert response.status_code == 403
        assert response.json()["error"]["code"] == "invalid_current_password"

    def test_deactivate_then_cannot_login(self) -> None:
        client, _ = self.prepared()
        token = self.login_token(client)

        response = client.post(
            f"{API}/deactivate",
            headers={"Authorization": f"Bearer {token}"},
            json={"current_password": VALID_PASSWORD},
        )
        login = client.post(
            f"{API}/login",
            json={"email": "customer@example.com", "password": VALID_PASSWORD},
        )

        assert response.status_code == 204
        assert login.status_code == 401

    def login_token(self, client: TestClient) -> str:
        response = client.post(
            f"{API}/login",
            json={"email": "customer@example.com", "password": VALID_PASSWORD},
        )
        return response.json()["access_token"]

    def test_reactivate_requires_admin_key(self) -> None:
        client, harness = self.prepared()
        identity_id = next(iter(harness.identity_repository.identities.values())).id

        no_key = client.post(
            f"{API}/reactivate", json={"identity_id": str(identity_id)}
        )
        wrong_key = client.post(
            f"{API}/reactivate",
            json={"identity_id": str(identity_id)},
            headers={"X-Admin-Key": "not-the-key"},
        )

        assert no_key.status_code == wrong_key.status_code == 403

    def test_reactivate_with_admin_key_restores_identity(self) -> None:
        settings = test_settings(admin_api_key="test-admin-key")
        client, harness = make_client(settings=settings)
        client.post(f"{API}/register", json=register_payload())
        raw = harness.email_sender.verification_emails[0][1]
        client.post(f"{API}/verify-email", json={"token": raw})
        identity_id = next(iter(harness.identity_repository.identities.values())).id
        token = client.post(
            f"{API}/login",
            json={"email": "customer@example.com", "password": VALID_PASSWORD},
        ).json()["access_token"]
        client.post(
            f"{API}/deactivate",
            headers={"Authorization": f"Bearer {token}"},
            json={"current_password": VALID_PASSWORD},
        )

        response = client.post(
            f"{API}/reactivate",
            json={"identity_id": str(identity_id)},
            headers={"X-Admin-Key": "test-admin-key"},
        )

        assert response.status_code == 200
        assert response.json()["status"] == "active"


class TestRateLimit:
    def test_login_rate_limit_returns_429_with_retry_after(self) -> None:
        client, _ = make_client(test_settings(login_rate_limit_max=2))

        first = client.post(
            f"{API}/login", json={"email": "a@example.com", "password": "x" * 20}
        )
        second = client.post(
            f"{API}/login", json={"email": "a@example.com", "password": "x" * 20}
        )
        third = client.post(
            f"{API}/login", json={"email": "a@example.com", "password": "x" * 20}
        )

        assert first.status_code == 401
        assert second.status_code == 401
        assert third.status_code == 429
        assert third.headers["retry-after"].isdigit()
        assert third.json()["error"]["code"] == "rate_limit_exceeded"


class TestHealthAndObservability:
    def test_health_returns_ok(self) -> None:
        client, _ = make_client()

        response = client.get("/health")

        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_ready_reflects_database(self) -> None:
        client, _ = make_client()
        app = client.app
        app.dependency_overrides[database_ready] = lambda: True
        assert client.get("/health/ready").status_code == 200

        app.dependency_overrides[database_ready] = lambda: False
        assert client.get("/health/ready").status_code == 503

    def test_request_id_is_echoed(self) -> None:
        client, _ = make_client()

        response = client.get("/health", headers={"X-Request-ID": "abc-123"})

        assert response.headers["x-request-id"] == "abc-123"

    def test_internal_errors_return_generic_500(self) -> None:
        client, harness = make_client()
        original = harness.use_cases.login.execute

        def explode(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("boom with secrets")

        harness.use_cases.login.execute = explode  # type: ignore[method-assign]
        try:
            response = client.post(
                f"{API}/login",
                json={"email": "a@example.com", "password": "x" * 20},
            )
        finally:
            harness.use_cases.login.execute = original  # type: ignore[method-assign]

        assert response.status_code == 500
        assert "boom" not in response.text
        assert response.json()["error"]["code"] == "internal_error"
