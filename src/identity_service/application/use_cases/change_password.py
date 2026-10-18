import logging
from uuid import UUID

from identity_service.application.ports.clock import Clock
from identity_service.application.ports.identity_repository import IdentityRepository
from identity_service.application.ports.password_hasher import PasswordHasher
from identity_service.application.ports.session_repository import SessionRepository
from identity_service.application.ports.token_repository import (
    PasswordResetTokenRepository,
)
from identity_service.application.validators.password import validate_password
from identity_service.domain.exceptions import (
    IdentityNotFoundError,
    InvalidCurrentPasswordError,
)

logger = logging.getLogger(__name__)


class ChangePassword:
    """Change the password after confirming the current one.

    Security policy applied on success:

    * every session of the identity is revoked (the caller must log in
      again with the new password);
    * outstanding password-reset tokens are invalidated so a previously
      issued reset link can never roll the password back.
    """

    def __init__(
        self,
        *,
        identity_repository: IdentityRepository,
        session_repository: SessionRepository,
        password_reset_token_repository: PasswordResetTokenRepository,
        password_hasher: PasswordHasher,
        clock: Clock,
    ) -> None:
        self._identity_repository = identity_repository
        self._session_repository = session_repository
        self._password_reset_token_repository = password_reset_token_repository
        self._password_hasher = password_hasher
        self._clock = clock

    def execute(
        self, identity_id: UUID, current_password: str, new_password: str
    ) -> None:
        identity = self._identity_repository.get_by_id(identity_id)
        if identity is None:
            raise IdentityNotFoundError("Identity not found.")

        if not self._password_hasher.verify(current_password, identity.password_hash):
            raise InvalidCurrentPasswordError("Current password is incorrect.")

        validate_password(new_password)

        identity.change_password(self._password_hasher.hash(new_password))
        self._identity_repository.update(identity)

        now = self._clock.utc_now()
        revoked_sessions = self._session_repository.revoke_all_for_identity(
            identity_id, now
        )
        self._password_reset_token_repository.invalidate_all_for_identity(
            identity_id, now
        )

        logger.info(
            "Password changed.",
            extra={
                "event": "identity.password_changed",
                "identity_id": str(identity_id),
                "revoked_sessions": revoked_sessions,
            },
        )
