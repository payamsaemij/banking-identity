import logging
from uuid import UUID

from identity_service.application.ports.clock import Clock
from identity_service.application.ports.identity_repository import IdentityRepository
from identity_service.application.ports.password_hasher import PasswordHasher
from identity_service.application.ports.session_repository import SessionRepository
from identity_service.application.ports.token_repository import (
    PasswordResetTokenRepository,
    VerificationTokenRepository,
)
from identity_service.domain.exceptions import (
    IdentityNotFoundError,
    InvalidCurrentPasswordError,
)

logger = logging.getLogger(__name__)


class DeactivateIdentity:
    """Deactivate an identity after confirming its current password.

    This is the explicitly authorized self-service deactivation path.
    On success all sessions and all outstanding one-time tokens are
    invalidated. Reactivation is a separate, administrative operation.
    """

    def __init__(
        self,
        *,
        identity_repository: IdentityRepository,
        session_repository: SessionRepository,
        verification_token_repository: VerificationTokenRepository,
        password_reset_token_repository: PasswordResetTokenRepository,
        password_hasher: PasswordHasher,
        clock: Clock,
    ) -> None:
        self._identity_repository = identity_repository
        self._session_repository = session_repository
        self._verification_token_repository = verification_token_repository
        self._password_reset_token_repository = password_reset_token_repository
        self._password_hasher = password_hasher
        self._clock = clock

    def execute(self, identity_id: UUID, current_password: str) -> None:
        identity = self._identity_repository.get_by_id(identity_id)
        if identity is None:
            raise IdentityNotFoundError("Identity not found.")

        if not self._password_hasher.verify(current_password, identity.password_hash):
            raise InvalidCurrentPasswordError("Current password is incorrect.")

        identity.deactivate()
        self._identity_repository.update(identity)

        now = self._clock.utc_now()
        revoked_sessions = self._session_repository.revoke_all_for_identity(
            identity_id, now
        )
        self._verification_token_repository.invalidate_all_for_identity(
            identity_id, now
        )
        self._password_reset_token_repository.invalidate_all_for_identity(
            identity_id, now
        )

        logger.info(
            "Identity deactivated.",
            extra={
                "event": "identity.deactivated",
                "identity_id": str(identity_id),
                "revoked_sessions": revoked_sessions,
            },
        )
