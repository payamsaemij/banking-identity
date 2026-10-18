from datetime import datetime
from typing import Protocol


class VerificationEmailSender(Protocol):
    """Contract for sending email-verification messages.

    Implementations raise ``EmailDeliveryError`` on failure; they must
    never log the raw token beyond what the chosen (dev-only) transport
    inherently displays.
    """

    def send_verification(
        self, to_email: str, raw_token: str, expires_at: datetime
    ) -> None: ...


class PasswordResetEmailSender(Protocol):
    """Contract for sending password-reset messages."""

    def send_password_reset(
        self, to_email: str, raw_token: str, expires_at: datetime
    ) -> None: ...
