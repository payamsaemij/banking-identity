
class DomainError(Exception):
    """Base exception for domain-related errors."""


class IdentityAlreadyExistsError(DomainError):
    """Raised when an identity with the same email already exists."""


class InvalidEmailError(DomainError):
    """Raised when an email address is invalid."""


class IdentityNotActiveError(DomainError):
    """Raised when an inactive identity attempts an operation."""
