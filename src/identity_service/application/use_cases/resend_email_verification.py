import logging
from datetime import timedelta
from uuid import uuid4

from identity_service.application.exceptions import EmailDeliveryError
from identity_service.application.ports.clock import Clock
from identity_service.application.ports.email_senders import VerificationEmailSender
from identity_service.application.ports.identity_repository import IdentityRepository
from identity_service.application.ports.token_generator import TokenGenerator
from identity_service.application.ports.token_repository import (
    VerificationTokenRepository,
)
from identity_service.application.security import hash_token
from identity_service.application.validators.email import normalize_email
from identity_service.domain.entities.one_time_token import OneTimeToken
from identity_service.domain.enums.identity_status import IdentityStatus

logger = logging.getLogger(__name__)


class ResendEmailVerification:
    """Re-issue a verification email for a pending identity.

    Enumeration-safe: unknown, already active, and deactivated identities
    return without any observable difference. Previously outstanding
    tokens are invalidated so only the newest link ever works.
    """

    def __init__(
        self,
        *,
        identity_repository: IdentityRepository,
        verification_token_repository: VerificationTokenRepository,
        token_generator: TokenGenerator,
        verification_email_sender: VerificationEmailSender,
        clock: Clock,
        verification_token_ttl_seconds: int,
    ) -> None:
        self._identity_repository = identity_repository
        self._verification_token_repository = verification_token_repository
        self._token_generator = token_generator
        self._verification_email_sender = verification_email_sender
        self._clock = clock
        self._verification_token_ttl = timedelta(seconds=verification_token_ttl_seconds)

    def execute(self, email: str) -> None:
        normalized_email = normalize_email(email)
        identity = self._identity_repository.get_by_email(normalized_email)
        if identity is None or identity.status != IdentityStatus.PENDING_VERIFICATION:
            return

        now = self._clock.utc_now()
        self._verification_token_repository.invalidate_all_for_identity(
            identity.id, now
        )

        raw_token = self._token_generator.generate()
        token = OneTimeToken(
            id=uuid4(),
            identity_id=identity.id,
            token_hash=hash_token(raw_token),
            created_at=now,
            expires_at=now + self._verification_token_ttl,
        )
        self._verification_token_repository.add(token)

        try:
            self._verification_email_sender.send_verification(
                normalized_email, raw_token, token.expires_at
            )
        except EmailDeliveryError:
            logger.error(
                "Verification email delivery failed on resend.",
                extra={
                    "event": "email.delivery_failed",
                    "identity_id": str(identity.id),
                },
            )

        logger.info(
            "Verification email resent.",
            extra={
                "event": "identity.verification_resent",
                "identity_id": str(identity.id),
            },
        )
