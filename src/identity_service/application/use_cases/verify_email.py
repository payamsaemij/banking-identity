import logging

from identity_service.application.ports.clock import Clock
from identity_service.application.ports.identity_repository import IdentityRepository
from identity_service.application.ports.token_repository import (
    VerificationTokenRepository,
)
from identity_service.application.security import hash_token
from identity_service.domain.entities.identity import Identity
from identity_service.domain.exceptions import InvalidTokenError

logger = logging.getLogger(__name__)


class VerifyEmail:
    """Verify an email address and activate the identity.

    The token is consumed atomically before the identity is touched, so
    concurrent requests cannot use one token twice. Every failure —
    unknown, expired, or already-used token — surfaces as the same
    ``InvalidTokenError``.
    """

    def __init__(
        self,
        *,
        identity_repository: IdentityRepository,
        verification_token_repository: VerificationTokenRepository,
        clock: Clock,
    ) -> None:
        self._identity_repository = identity_repository
        self._verification_token_repository = verification_token_repository
        self._clock = clock

    def execute(self, raw_token: str) -> Identity:
        token_hash = hash_token(raw_token)
        now = self._clock.utc_now()

        consumed = self._verification_token_repository.consume_by_token_hash(
            token_hash, now
        )
        if consumed is None:
            raise InvalidTokenError("Verification token is invalid or expired.")

        identity = self._identity_repository.get_by_id(consumed.identity_id)
        if identity is None:
            raise InvalidTokenError("Verification token is invalid or expired.")

        identity.verify_email(now)
        self._identity_repository.update(identity)

        logger.info(
            "Email verified.",
            extra={"event": "identity.email_verified", "identity_id": str(identity.id)},
        )
        return identity
