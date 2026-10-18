import logging
import smtplib
from datetime import datetime
from email.message import EmailMessage

from identity_service.application.exceptions import EmailDeliveryError
from identity_service.infrastructure.config import Settings

logger = logging.getLogger(__name__)

_VERIFICATION_SUBJECT = "Verify your email address"
_RESET_SUBJECT = "Reset your password"


def _format_link(template: str, base_url: str, raw_token: str) -> str:
    return template.format(base_url=base_url, token=raw_token)


class ConsoleEmailSender:
    """Dev/test email transport: writes the message to the log.

    The verification/reset link (and therefore the raw token) is printed
    on purpose — this is the only way to complete flows locally without
    an SMTP server. The factory refuses to build this sender outside
    local/test environments.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def send_verification(
        self, to_email: str, raw_token: str, expires_at: datetime
    ) -> None:
        logger.info(
            "Verification email for %s: %s",
            to_email,
            _format_link(
                self._settings.email_verification_url_template,
                self._settings.public_base_url,
                raw_token,
            ),
            extra={
                "event": "email.sent_console",
                "flow": "verification",
                "expires_at": expires_at.isoformat(),
            },
        )

    def send_password_reset(
        self, to_email: str, raw_token: str, expires_at: datetime
    ) -> None:
        logger.info(
            "Password reset email for %s: %s",
            to_email,
            _format_link(
                self._settings.password_reset_url_template,
                self._settings.public_base_url,
                raw_token,
            ),
            extra={
                "event": "email.sent_console",
                "flow": "password_reset",
                "expires_at": expires_at.isoformat(),
            },
        )


class SmtpEmailSender:
    """Production email transport over stdlib smtplib.

    Delivery failures raise ``EmailDeliveryError``; use cases log them
    and keep the persistence transaction intact (see README: a database
    transaction and an email send are never treated as one atomic unit —
    the reliable-delivery upgrade path is a transactional outbox).
    """

    def __init__(self, settings: Settings) -> None:
        if not settings.smtp_host:
            raise ValueError("smtp_host is required for the SMTP email sender.")
        self._host = settings.smtp_host
        self._settings = settings

    def _send(self, to_email: str, subject: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = self._settings.smtp_from_address
        message["To"] = to_email
        message["Subject"] = subject
        message.set_content(body)

        try:
            with smtplib.SMTP(self._host, self._settings.smtp_port, timeout=10) as smtp:
                if self._settings.smtp_use_tls:
                    smtp.starttls()
                if self._settings.smtp_username and self._settings.smtp_password:
                    smtp.login(
                        self._settings.smtp_username, self._settings.smtp_password
                    )
                smtp.send_message(message)
        except (OSError, smtplib.SMTPException) as error:
            raise EmailDeliveryError("Email delivery failed.") from error

    def send_verification(
        self, to_email: str, raw_token: str, expires_at: datetime
    ) -> None:
        link = _format_link(
            self._settings.email_verification_url_template,
            self._settings.public_base_url,
            raw_token,
        )
        self._send(
            to_email,
            _VERIFICATION_SUBJECT,
            (
                "Welcome to the bank.\n\n"
                "Confirm your email address by opening the link below:\n"
                f"{link}\n\n"
                "The link is single-use and stops working at "
                f"{expires_at.isoformat()}.\n"
                "If you did not create an account, ignore this message.\n"
            ),
        )

    def send_password_reset(
        self, to_email: str, raw_token: str, expires_at: datetime
    ) -> None:
        link = _format_link(
            self._settings.password_reset_url_template,
            self._settings.public_base_url,
            raw_token,
        )
        self._send(
            to_email,
            _RESET_SUBJECT,
            (
                "A password reset was requested for your account.\n"
                f"Open the link below to choose a new password:\n{link}\n\n"
                "The link is single-use and stops working at "
                f"{expires_at.isoformat()}.\n"
                "If you did not request a reset, ignore this message and "
                "consider changing your password.\n"
            ),
        )


def build_email_senders(settings: Settings) -> ConsoleEmailSender | SmtpEmailSender:
    """Choose the email transport from settings, guarding dev modes."""
    if settings.email_sender == "smtp":
        return SmtpEmailSender(settings)
    if settings.environment in ("local", "test"):
        return ConsoleEmailSender(settings)
    raise ValueError(
        "Console email sender is only allowed in local/test environments; "
        "configure email_sender=smtp for staging/production."
    )
