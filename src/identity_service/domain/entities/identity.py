from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from identity_service.domain.enums.identity_status import IdentityStatus
from identity_service.domain.exceptions import (
    EmailAlreadyVerifiedError,
    IdentityNotActiveError,
    InvalidIdentityStateError,
)


@dataclass
class Identity:
    """Authentication identity owned by the Identity Service.

    The identity references a customer in the separate Customer Service
    through ``customer_id``; it never owns customer profile data. The
    reference is stable and immutable once assigned.
    """

    id: UUID
    email: str
    password_hash: str
    status: IdentityStatus = IdentityStatus.PENDING_VERIFICATION
    email_verified_at: datetime | None = None
    customer_id: UUID | None = None

    def verify_email(self, verified_at: datetime) -> None:
        """Activate a pending identity by verifying its email address.

        Verifying must never reactivate a deactivated identity, and can
        only happen once.
        """
        if self.status == IdentityStatus.DEACTIVATED:
            raise IdentityNotActiveError(
                "A deactivated identity cannot verify its email."
            )

        if self.email_verified_at is not None:
            raise EmailAlreadyVerifiedError("Email is already verified.")

        self.email_verified_at = verified_at
        self.status = IdentityStatus.ACTIVE

    def change_password(self, new_password_hash: str) -> None:
        """Replace the password hash of an active identity."""
        if self.status != IdentityStatus.ACTIVE:
            raise IdentityNotActiveError(
                "Only an active identity can change its password."
            )

        self.password_hash = new_password_hash

    def apply_password_reset(self, new_password_hash: str) -> None:
        """Replace the password hash through a valid reset token.

        A reset is allowed regardless of the identity's lifecycle state
        because it is driven by possession of a single-use token, and it
        never changes the lifecycle state: a deactivated identity stays
        deactivated, a pending identity stays pending.
        """
        self.password_hash = new_password_hash

    def deactivate(self) -> None:
        if self.status == IdentityStatus.DEACTIVATED:
            raise InvalidIdentityStateError("Identity is already deactivated.")

        self.status = IdentityStatus.DEACTIVATED

    def reactivate(self) -> None:
        """Explicitly reactivate a deactivated identity.

        Reverts to ACTIVE when the email is verified, otherwise back to
        PENDING_VERIFICATION. The previously verified email is preserved.
        """
        if self.status != IdentityStatus.DEACTIVATED:
            raise InvalidIdentityStateError(
                "Only a deactivated identity can be reactivated."
            )

        self.status = (
            IdentityStatus.ACTIVE
            if self.email_verified_at is not None
            else IdentityStatus.PENDING_VERIFICATION
        )

    def can_authenticate(self) -> bool:
        return (
            self.status == IdentityStatus.ACTIVE and self.email_verified_at is not None
        )
