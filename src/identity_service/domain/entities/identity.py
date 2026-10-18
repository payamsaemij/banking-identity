
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from identity_service.domain.enums.identity_status import IdentityStatus


@dataclass
class Identity:
    id: UUID
    email: str
    password_hash: str
    status: IdentityStatus = IdentityStatus.PENDING_VERIFICATION
    email_verified_at: datetime | None = None

    def verify_email(self, verified_at: datetime) -> None:
        if self.status == IdentityStatus.DEACTIVATED:
            raise ValueError("A deactivated identity cannot verify its email.")

        if self.email_verified_at is not None:
            raise ValueError("Email is already verified.")

        self.email_verified_at = verified_at
        self.status = IdentityStatus.ACTIVE

    def deactivate(self) -> None:
        self.status = IdentityStatus.DEACTIVATED

    def can_authenticate(self) -> bool:
        return (
            self.status == IdentityStatus.ACTIVE
            and self.email_verified_at is not None
        )
