"""In-memory fakes for the application ports, shared by unit tests."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from identity_service.application.exceptions import EmailDeliveryError
from identity_service.application.use_cases.authenticate_session import (
    AuthenticateSession,
)
from identity_service.application.use_cases.change_password import ChangePassword
from identity_service.application.use_cases.deactivate_identity import (
    DeactivateIdentity,
)
from identity_service.application.use_cases.login import Login
from identity_service.application.use_cases.logout import Logout
from identity_service.application.use_cases.reactivate_identity import (
    ReactivateIdentity,
)
from identity_service.application.use_cases.register_identity import (
    RegisterIdentity,
)
from identity_service.application.use_cases.request_password_reset import (
    RequestPasswordReset,
)
from identity_service.application.use_cases.resend_email_verification import (
    ResendEmailVerification,
)
from identity_service.application.use_cases.reset_password import ResetPassword
from identity_service.application.use_cases.verify_email import VerifyEmail
from identity_service.domain.entities.auth_session import AuthSession
from identity_service.domain.entities.identity import Identity
from identity_service.domain.entities.one_time_token import OneTimeToken
from identity_service.domain.exceptions import (
    CustomerAlreadyLinkedError,
    IdentityAlreadyExistsError,
    IdentityNotFoundError,
)
from identity_service.presentation.dependencies import UseCases

VALID_PASSWORD = "correct-horse-battery"
OTHER_PASSWORD = "another-valid-password"


class FakeClock:
    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    def utc_now(self) -> datetime:
        return self._now

    def advance(self, **kwargs: float) -> None:
        self._now += timedelta(**kwargs)  # type: ignore[arg-type]


class FakePasswordHasher:
    """Deterministic fake: hash is a tagged version of the password."""

    def __init__(self) -> None:
        self.hashed: list[str] = []
        self.verified: list[tuple[str, str]] = []
        self.dummy_verifications = 0
        self.needs_rehash_result = False

    @staticmethod
    def _fake_hash(password: str) -> str:
        return f"fake-hash${password}"

    def hash(self, password: str) -> str:
        self.hashed.append(password)
        return self._fake_hash(password)

    def verify(self, password: str, password_hash: str) -> bool:
        self.verified.append((password, password_hash))
        return password_hash == self._fake_hash(password)

    def needs_rehash(self, password_hash: str) -> bool:
        return self.needs_rehash_result

    def verify_dummy(self, password: str) -> bool:
        self.dummy_verifications += 1
        return False


class FakeTokenGenerator:
    def __init__(self) -> None:
        self._counter = 0
        self.generated: list[str] = []

    def generate(self) -> str:
        self._counter += 1
        token = f"raw-token-{self._counter:04d}"
        self.generated.append(token)
        return token


class FakeEmailSender:
    """Records outgoing messages; optionally fails every send."""

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.verification_emails: list[tuple[str, str, datetime]] = []
        self.reset_emails: list[tuple[str, str, datetime]] = []

    def send_verification(
        self, to_email: str, raw_token: str, expires_at: datetime
    ) -> None:
        if self.fail:
            raise EmailDeliveryError("SMTP unavailable")
        self.verification_emails.append((to_email, raw_token, expires_at))

    def send_password_reset(
        self, to_email: str, raw_token: str, expires_at: datetime
    ) -> None:
        if self.fail:
            raise EmailDeliveryError("SMTP unavailable")
        self.reset_emails.append((to_email, raw_token, expires_at))


class FakeIdentityRepository:
    def __init__(self) -> None:
        self.identities: dict[UUID, Identity] = {}
        self.add_calls: list[Identity] = []
        self.update_calls: list[Identity] = []
        # When set, add() raises as if a concurrent request had already
        # inserted the same unique key (the database race backstop).
        self.race_on_add = False

    def add(self, identity: Identity) -> None:
        self.add_calls.append(identity)
        if self.race_on_add:
            raise IdentityAlreadyExistsError("Email is already registered.")
        for existing in self.identities.values():
            if existing.email == identity.email:
                raise IdentityAlreadyExistsError("Email is already registered.")
            if (
                identity.customer_id is not None
                and existing.customer_id == identity.customer_id
            ):
                raise CustomerAlreadyLinkedError(
                    "Customer reference is already linked to an identity."
                )
        self.identities[identity.id] = identity

    def get_by_id(self, identity_id: UUID) -> Identity | None:
        return self.identities.get(identity_id)

    def get_by_email(self, email: str) -> Identity | None:
        return next((i for i in self.identities.values() if i.email == email), None)

    def update(self, identity: Identity) -> None:
        if identity.id not in self.identities:
            raise IdentityNotFoundError("Identity not found.")
        self.update_calls.append(identity)
        self.identities[identity.id] = identity


class FakeOneTimeTokenRepository:
    """Backs both token kinds; instances stay separate in tests."""

    def __init__(self) -> None:
        self.tokens: dict[UUID, OneTimeToken] = {}

    def add(self, token: OneTimeToken) -> None:
        self.tokens[token.id] = token

    def find_by_token_hash(self, token_hash: str) -> OneTimeToken | None:
        return next(
            (t for t in self.tokens.values() if t.token_hash == token_hash), None
        )

    def consume_by_token_hash(
        self, token_hash: str, now: datetime
    ) -> OneTimeToken | None:
        token = self.find_by_token_hash(token_hash)
        if token is None or not token.is_available(now):
            return None
        token.consume(now)
        return token

    def invalidate_all_for_identity(self, identity_id: UUID, now: datetime) -> int:
        count = 0
        for token in self.tokens.values():
            if token.identity_id == identity_id and token.used_at is None:
                token.invalidate(now)
                count += 1
        return count


class FakeSessionRepository:
    def __init__(self) -> None:
        self.sessions: dict[UUID, AuthSession] = {}
        self.revoked: list[UUID] = []
        self.revoked_all: list[UUID] = []

    def add(self, session: AuthSession) -> None:
        self.sessions[session.id] = session

    def find_active_by_token_hash(
        self, token_hash: str, now: datetime
    ) -> AuthSession | None:
        session = next(
            (s for s in self.sessions.values() if s.token_hash == token_hash), None
        )
        if session is None or not session.is_active(now):
            return None
        return session

    def revoke(self, session_id: UUID, now: datetime) -> None:
        session = self.sessions.get(session_id)
        if session is not None:
            session.revoke(now)
        self.revoked.append(session_id)

    def revoke_all_for_identity(self, identity_id: UUID, now: datetime) -> int:
        self.revoked_all.append(identity_id)
        count = 0
        for session in self.sessions.values():
            if session.identity_id == identity_id and session.revoked_at is None:
                session.revoke(now)
                count += 1
        return count


class Harness:
    """All fakes plus every use case wired the way production wires them."""

    def __init__(
        self,
        *,
        verification_ttl_seconds: int = 24 * 3600,
        reset_ttl_seconds: int = 3600,
        session_ttl_seconds: int = 8 * 3600,
        email_fail: bool = False,
    ) -> None:
        self.clock = FakeClock()
        self.password_hasher = FakePasswordHasher()
        self.token_generator = FakeTokenGenerator()
        self.email_sender = FakeEmailSender(fail=email_fail)
        self.identity_repository = FakeIdentityRepository()
        self.verification_tokens = FakeOneTimeTokenRepository()
        self.reset_tokens = FakeOneTimeTokenRepository()
        self.sessions = FakeSessionRepository()

        self.use_cases = UseCases(
            register_identity=RegisterIdentity(
                identity_repository=self.identity_repository,
                verification_token_repository=self.verification_tokens,
                password_hasher=self.password_hasher,
                token_generator=self.token_generator,
                verification_email_sender=self.email_sender,
                clock=self.clock,
                verification_token_ttl_seconds=verification_ttl_seconds,
            ),
            verify_email=VerifyEmail(
                identity_repository=self.identity_repository,
                verification_token_repository=self.verification_tokens,
                clock=self.clock,
            ),
            resend_email_verification=ResendEmailVerification(
                identity_repository=self.identity_repository,
                verification_token_repository=self.verification_tokens,
                token_generator=self.token_generator,
                verification_email_sender=self.email_sender,
                clock=self.clock,
                verification_token_ttl_seconds=verification_ttl_seconds,
            ),
            login=Login(
                identity_repository=self.identity_repository,
                session_repository=self.sessions,
                password_hasher=self.password_hasher,
                token_generator=self.token_generator,
                clock=self.clock,
                session_ttl_seconds=session_ttl_seconds,
            ),
            authenticate_session=AuthenticateSession(
                session_repository=self.sessions,
                identity_repository=self.identity_repository,
                clock=self.clock,
            ),
            logout=Logout(session_repository=self.sessions, clock=self.clock),
            change_password=ChangePassword(
                identity_repository=self.identity_repository,
                session_repository=self.sessions,
                password_reset_token_repository=self.reset_tokens,
                password_hasher=self.password_hasher,
                clock=self.clock,
            ),
            request_password_reset=RequestPasswordReset(
                identity_repository=self.identity_repository,
                password_reset_token_repository=self.reset_tokens,
                token_generator=self.token_generator,
                password_reset_email_sender=self.email_sender,
                clock=self.clock,
                password_reset_token_ttl_seconds=reset_ttl_seconds,
            ),
            reset_password=ResetPassword(
                identity_repository=self.identity_repository,
                password_reset_token_repository=self.reset_tokens,
                session_repository=self.sessions,
                password_hasher=self.password_hasher,
                clock=self.clock,
            ),
            deactivate_identity=DeactivateIdentity(
                identity_repository=self.identity_repository,
                session_repository=self.sessions,
                verification_token_repository=self.verification_tokens,
                password_reset_token_repository=self.reset_tokens,
                password_hasher=self.password_hasher,
                clock=self.clock,
            ),
            reactivate_identity=ReactivateIdentity(
                identity_repository=self.identity_repository
            ),
        )

    def register(self, email: str = "customer@example.com") -> Identity:
        return self.use_cases.register_identity.execute(email, VALID_PASSWORD)

    def register_and_verify(self, email: str = "customer@example.com") -> Identity:
        self.register(email)
        if self.email_sender.verification_emails:
            raw_token = self.email_sender.verification_emails[-1][1]
        else:
            # Delivery failed; the raw token is still the last one generated.
            raw_token = self.token_generator.generated[-1]
        return self.use_cases.verify_email.execute(raw_token)

    def login(self, email: str = "customer@example.com") -> str:
        result = self.use_cases.login.execute(email, VALID_PASSWORD)
        return result.access_token
