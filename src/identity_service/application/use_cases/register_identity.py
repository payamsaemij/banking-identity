import logging
from datetime import timedelta
from uuid import UUID, uuid4

from identity_service.application.exceptions import EmailDeliveryError
from identity_service.application.ports.clock import Clock
from identity_service.application.ports.email_senders import VerificationEmailSender
from identity_service.application.ports.identity_repository import IdentityRepository
from identity_service.application.ports.password_hasher import PasswordHasher
from identity_service.application.ports.token_generator import TokenGenerator
from identity_service.application.ports.token_repository import (
    VerificationTokenRepository,
)
from identity_service.application.security import hash_token
from identity_service.application.validators.email import normalize_and_validate_email
from identity_service.application.validators.password import validate_password
from identity_service.domain.entities.identity import Identity
from identity_service.domain.entities.one_time_token import OneTimeToken
from identity_service.domain.exceptions import IdentityAlreadyExistsError

logger = logging.getLogger(__name__)


class RegisterIdentity:
    """Create a pending identity and send a verification email."""

    def __init__(
        self,
        *,
        identity_repository: IdentityRepository,
        verification_token_repository: VerificationTokenRepository,
        password_hasher: PasswordHasher,
        token_generator: TokenGenerator,
        verification_email_sender: VerificationEmailSender,
        clock: Clock,
        verification_token_ttl_seconds: int,
    ) -> None:
        self._identity_repository = identity_repository
        self._verification_token_repository = verification_token_repository
        self._password_hasher = password_hasher
        self._token_generator = token_generator
        self._verification_email_sender = verification_email_sender
        self._clock = clock
        self._verification_token_ttl = timedelta(seconds=verification_token_ttl_seconds)

    def execute(
        self, email: str, password: str, *, customer_id: UUID | None = None
    ) -> Identity:
        normalized_email = normalize_and_validate_email(email)
        validate_password(password)

        if self._identity_repository.get_by_email(normalized_email) is not None:
            raise IdentityAlreadyExistsError("Email is already registered.")

        identity = Identity(
            id=uuid4(),
            email=normalized_email,
            password_hash=self._password_hasher.hash(password),
            customer_id=customer_id,
        )
        self._identity_repository.add(identity)

        now = self._clock.utc_now()
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
                "Verification email delivery failed after registration; "
                "the identity can request a resend.",
                extra={
                    "event": "email.delivery_failed",
                    "identity_id": str(identity.id),
                },
            )

        logger.info(
            "Identity registered.",
            extra={"event": "identity.registered", "identity_id": str(identity.id)},
        )
        return identity
