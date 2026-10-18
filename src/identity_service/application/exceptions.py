from dataclasses import dataclass


class ApplicationError(Exception):
    """Base exception for application-level orchestration failures."""


class EmailDeliveryError(ApplicationError):
    """Raised by email senders when delivery fails.

    Deliberately not surfaced to clients: the persistence transaction and
    an external email send cannot form one atomic transaction, so the use
    cases log the failure and rely on the resend endpoints instead.
    """


class RateLimitExceededError(ApplicationError):
    """Raised when a sensitive operation exceeds its rate limit."""

    def __init__(self, scope: str, retry_after_seconds: int) -> None:
        self.scope = scope
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"Rate limit exceeded for {scope}.")


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int
