from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass
class AuthSession:
    """An opaque, revocable login session.

    Only the SHA-256 hash of the raw session token is persisted; the raw
    value is returned once at login and never stored. Sessions are the
    service's authentication strategy: revoking a session (logout) or all
    sessions of an identity (password change/reset, deactivation) takes
    effect immediately because every authenticated request resolves the
    session from the database.
    """

    id: UUID
    identity_id: UUID
    token_hash: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None

    def is_active(self, now: datetime) -> bool:
        return self.revoked_at is None and now < self.expires_at

    def revoke(self, revoked_at: datetime) -> None:
        if self.revoked_at is None:
            self.revoked_at = revoked_at
