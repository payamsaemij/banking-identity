from enum import StrEnum


class IdentityStatus(StrEnum):
    PENDING_VERIFICATION = "pending_verification"
    ACTIVE = "active"
    DEACTIVATED = "deactivated"