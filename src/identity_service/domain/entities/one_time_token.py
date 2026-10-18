from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from identity_service.domain.exceptions import InvalidTokenError


@dataclass
class OneTimeToken:
    """A single-use, expiring token used for email verification and
    password resets.

    Modeling decision: tokens are lightweight domain records rather than
    full entities. Their only invariants are single use and expiry, which
    ``consume`` enforces, while concurrent single-use consumption is
    guaranteed atomically by the persistence layer (a conditional
    ``UPDATE``). Only the token *hash* is ever persisted; the raw value
    exists solely in the outgoing email and the client's request.
    """

    id: UUID
    identity_id: UUID
    token_hash: str
    expires_at: datetime
    created_at: datetime | None = None
    used_at: datetime | None = None

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def is_available(self, now: datetime) -> bool:
        return self.used_at is None and not self.is_expired(now)

    def consume(self, now: datetime) -> None:
        """Mark the token as used, enforcing single use and expiry."""
        if self.used_at is not None:
            raise InvalidTokenError("Token has already been used.")

        if self.is_expired(now):
            raise InvalidTokenError("Token has expired.")

        self.used_at = now

    def invalidate(self, now: datetime) -> None:
        """Neutralize the token without claiming a successful use."""
        if self.used_at is None:
            self.used_at = now
