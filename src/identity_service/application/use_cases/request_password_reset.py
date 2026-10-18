import logging
from datetime import timedelta
from uuid import uuid4

from identity_service.application.exceptions import EmailDeliveryError
from identity_service.application.ports.clock import Clock
from identity_service.application.ports.email_senders import PasswordResetEmailSender
from identity_service.application.ports.identity_repository import IdentityRepository
from identity_service.application.ports.token_generator import TokenGenerator
from identity_service.application.ports.token_repository import (
    PasswordResetTokenRepository,
)
from identity_service.application.security import hash_token
from identity_service.application.validators.email import normalize_email
from identity_service.domain.entities.one_time_token import OneTimeToken

logger = logging.getLogger(__name__)


class RequestPasswordReset:
    """Issue a password-reset email without disclosing account existence.

    Unknown, pending, and deactivated identities return silently. Older
    reset tokens are invalidated so at most one reset link is live at a
    time. Rate limiting happens at the API boundary.
    """

    def __init__(
        self,
        *,
        identity_repository: IdentityRepository,
        password_reset_token_repository: PasswordResetTokenRepository,
        token_generator: TokenGenerator,
        password_reset_email_sender: PasswordResetEmailSender,
        clock: Clock,
        password_reset_token_ttl_seconds: int,
    ) -> None:
        self._identity_repository = identity_repository
        self._password_reset_token_repository = password_reset_token_repository
        self._token_generator = token_generator
        self._password_reset_email_sender = password_reset_email_sender
        self._clock = clock
        self._password_reset_token_ttl = timedelta(
            seconds=password_reset_token_ttl_seconds
        )

    def execute(self, email: str) -> None:
        normalized_email = normalize_email(email)
        identity = self._identity_repository.get_by_email(normalized_email)
        if identity is None or not identity.can_authenticate():
            return

        now = self._clock.utc_now()
        self._password_reset_token_repository.invalidate_all_for_identity(
            identity.id, now
        )

        raw_token = self._token_generator.generate()
        token = OneTimeToken(
            id=uuid4(),
            identity_id=identity.id,
            token_hash=hash_token(raw_token),
            created_at=now,
            expires_at=now + self._password_reset_token_ttl,
        )
        self._password_reset_token_repository.add(token)

        try:
            self._password_reset_email_sender.send_password_reset(
                normalized_email, raw_token, token.expires_at
            )
        except EmailDeliveryError:
            logger.error(
                "Password reset email delivery failed; the user can request again.",
                extra={
                    "event": "email.delivery_failed",
                    "identity_id": str(identity.id),
                },
            )

        logger.info(
            "Password reset requested.",
            extra={
                "event": "auth.password_reset_requested",
                "identity_id": str(identity.id),
            },
        )
