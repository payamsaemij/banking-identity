import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from identity_service.application.ports.clock import Clock
from identity_service.application.ports.identity_repository import IdentityRepository
from identity_service.application.ports.password_hasher import PasswordHasher
from identity_service.application.ports.session_repository import SessionRepository
from identity_service.application.ports.token_generator import TokenGenerator
from identity_service.application.security import hash_token
from identity_service.application.validators.email import normalize_email
from identity_service.domain.entities.auth_session import AuthSession
from identity_service.domain.exceptions import AuthenticationError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LoginResult:
    identity_id: UUID
    email: str
    access_token: str
    expires_at: datetime


class Login:
    """Authenticate with email and password and open a session.

    Every failure — unknown email, wrong password, pending or deactivated
    identity — raises the same generic ``AuthenticationError``, and the
    password is always put through the hasher so response timing does not
    reveal whether the email exists.
    """

    def __init__(
        self,
        *,
        identity_repository: IdentityRepository,
        session_repository: SessionRepository,
        password_hasher: PasswordHasher,
        token_generator: TokenGenerator,
        clock: Clock,
        session_ttl_seconds: int,
    ) -> None:
        self._identity_repository = identity_repository
        self._session_repository = session_repository
        self._password_hasher = password_hasher
        self._token_generator = token_generator
        self._clock = clock
        self._session_ttl = timedelta(seconds=session_ttl_seconds)

    def execute(self, email: str, password: str) -> LoginResult:
        normalized_email = normalize_email(email)
        identity = self._identity_repository.get_by_email(normalized_email)

        if identity is None:
            self._password_hasher.verify_dummy(password)
            self._log_failure("unknown_email")
            raise AuthenticationError("Invalid email or password.")

        if not self._password_hasher.verify(password, identity.password_hash):
            self._log_failure("bad_password")
            raise AuthenticationError("Invalid email or password.")

        if not identity.can_authenticate():
            self._log_failure("identity_not_active")
            raise AuthenticationError("Invalid email or password.")

        if self._password_hasher.needs_rehash(identity.password_hash):
            identity.change_password(self._password_hasher.hash(password))
            self._identity_repository.update(identity)

        now = self._clock.utc_now()
        raw_token = self._token_generator.generate()
        session = AuthSession(
            id=uuid4(),
            identity_id=identity.id,
            token_hash=hash_token(raw_token),
            created_at=now,
            expires_at=now + self._session_ttl,
        )
        self._session_repository.add(session)

        logger.info(
            "Login succeeded.",
            extra={
                "event": "auth.login_succeeded",
                "identity_id": str(identity.id),
                "session_id": str(session.id),
            },
        )
        return LoginResult(
            identity_id=identity.id,
            email=identity.email,
            access_token=raw_token,
            expires_at=session.expires_at,
        )

    @staticmethod
    def _log_failure(reason: str) -> None:
        """Record a login failure without any identifying information."""
        logger.warning(
            "Login failed.",
            extra={"event": "auth.login_failed", "reason": reason},
        )
