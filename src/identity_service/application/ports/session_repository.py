from datetime import datetime
from typing import Protocol
from uuid import UUID

from identity_service.domain.entities.auth_session import AuthSession


class SessionRepository(Protocol):
    """Persistence contract for opaque authentication sessions."""

    def add(self, session: AuthSession) -> None: ...

    def find_active_by_token_hash(
        self, token_hash: str, now: datetime
    ) -> AuthSession | None:
        """Return the non-revoked, non-expired session for a token hash."""
        ...

    def revoke(self, session_id: UUID, now: datetime) -> None:
        """Revoke one session; idempotent."""
        ...

    def revoke_all_for_identity(self, identity_id: UUID, now: datetime) -> int:
        """Revoke every outstanding session of an identity.

        Used after password changes/resets and deactivation. Returns the
        number of sessions revoked.
        """
        ...
