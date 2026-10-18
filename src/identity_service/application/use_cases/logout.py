import logging
from uuid import UUID

from identity_service.application.ports.clock import Clock
from identity_service.application.ports.session_repository import SessionRepository

logger = logging.getLogger(__name__)


class Logout:
    """Revoke the session presented by the caller.

    Because sessions are database-backed, revocation takes effect
    immediately for subsequent requests. Revoking an already-revoked or
    unknown session is a no-op, making logout idempotent.
    """

    def __init__(self, *, session_repository: SessionRepository, clock: Clock) -> None:
        self._session_repository = session_repository
        self._clock = clock

    def execute(self, session_id: UUID) -> None:
        self._session_repository.revoke(session_id, self._clock.utc_now())
        logger.info(
            "Session revoked.",
            extra={"event": "auth.session_revoked", "session_id": str(session_id)},
        )
