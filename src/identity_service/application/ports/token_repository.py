from datetime import datetime
from typing import Protocol
from uuid import UUID

from identity_service.domain.entities.one_time_token import OneTimeToken


class OneTimeTokenRepository(Protocol):
    """Shared contract for verification and password-reset token stores."""

    def add(self, token: OneTimeToken) -> None: ...

    def find_by_token_hash(self, token_hash: str) -> OneTimeToken | None: ...

    def consume_by_token_hash(
        self, token_hash: str, now: datetime
    ) -> OneTimeToken | None:
        """Atomically consume a token.

        Succeeds exactly once per token across concurrent requests: the
        row is claimed with a conditional update requiring ``used_at`` to
        be null and ``expires_at`` to be in the future. Returns the
        consumed token, or ``None`` when it is unknown, expired, or
        already used.
        """
        ...

    def invalidate_all_for_identity(self, identity_id: UUID, now: datetime) -> int:
        """Mark all outstanding tokens of an identity as used.

        Used by the resend and credential-change policies so older tokens
        can never be consumed afterwards. Returns the number of tokens
        invalidated.
        """
        ...


class VerificationTokenRepository(OneTimeTokenRepository, Protocol):
    """Token store backing the email-verification flow."""


class PasswordResetTokenRepository(OneTimeTokenRepository, Protocol):
    """Token store backing the password-reset flow."""
