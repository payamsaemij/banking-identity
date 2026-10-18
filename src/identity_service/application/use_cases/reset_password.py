import logging

from identity_service.application.ports.clock import Clock
from identity_service.application.ports.identity_repository import IdentityRepository
from identity_service.application.ports.password_hasher import PasswordHasher
from identity_service.application.ports.session_repository import SessionRepository
from identity_service.application.ports.token_repository import (
    PasswordResetTokenRepository,
)
from identity_service.application.security import hash_token
from identity_service.application.validators.password import validate_password
from identity_service.domain.exceptions import IdentityNotFoundError, InvalidTokenError

logger = logging.getLogger(__name__)


class ResetPassword:
    """Complete a password reset with a single-use token.

    The new password is validated before the token is consumed, so a
    policy violation does not burn the link. On success every session of
    the identity is revoked. The lifecycle state is untouched: a
    deactivated identity stays deactivated.
    """

    def __init__(
        self,
        *,
        identity_repository: IdentityRepository,
        password_reset_token_repository: PasswordResetTokenRepository,
        session_repository: SessionRepository,
        password_hasher: PasswordHasher,
        clock: Clock,
    ) -> None:
        self._identity_repository = identity_repository
        self._password_reset_token_repository = password_reset_token_repository
        self._session_repository = session_repository
        self._password_hasher = password_hasher
        self._clock = clock

    def execute(self, raw_token: str, new_password: str) -> None:
        validate_password(new_password)

        token_hash = hash_token(raw_token)
        now = self._clock.utc_now()

        consumed = self._password_reset_token_repository.consume_by_token_hash(
            token_hash, now
        )
        if consumed is None:
            raise InvalidTokenError("Password reset token is invalid or expired.")

        identity = self._identity_repository.get_by_id(consumed.identity_id)
        if identity is None:
            raise IdentityNotFoundError("Identity not found.")

        identity.apply_password_reset(self._password_hasher.hash(new_password))
        self._identity_repository.update(identity)

        revoked_sessions = self._session_repository.revoke_all_for_identity(
            identity.id, now
        )

        logger.info(
            "Password reset completed.",
            extra={
                "event": "auth.password_reset_completed",
                "identity_id": str(identity.id),
                "revoked_sessions": revoked_sessions,
            },
        )
