from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from identity_service.application.ports.clock import Clock
from identity_service.application.ports.identity_repository import IdentityRepository
from identity_service.application.ports.session_repository import SessionRepository
from identity_service.application.security import hash_token
from identity_service.domain.entities.auth_session import AuthSession


@dataclass(frozen=True)
class AuthContext:
    """The authenticated principal bound to one request."""

    session_id: UUID
    identity_id: UUID
    email: str
    expires_at: datetime

    @classmethod
    def of(cls, session: AuthSession, email: str) -> "AuthContext":
        return cls(
            session_id=session.id,
            identity_id=session.identity_id,
            email=email,
            expires_at=session.expires_at,
        )


class AuthenticateSession:
    """Resolve an opaque bearer token into an authenticated principal.

    Returns ``None`` for unknown, expired, revoked sessions and for
    identities that may no longer authenticate (e.g. deactivated after
    the session was issued).
    """

    def __init__(
        self,
        *,
        session_repository: SessionRepository,
        identity_repository: IdentityRepository,
        clock: Clock,
    ) -> None:
        self._session_repository = session_repository
        self._identity_repository = identity_repository
        self._clock = clock

    def execute(self, raw_token: str) -> AuthContext | None:
        session = self._session_repository.find_active_by_token_hash(
            hash_token(raw_token), self._clock.utc_now()
        )
        if session is None:
            return None

        identity = self._identity_repository.get_by_id(session.identity_id)
        if identity is None or not identity.can_authenticate():
            return None

        return AuthContext.of(session, identity.email)
