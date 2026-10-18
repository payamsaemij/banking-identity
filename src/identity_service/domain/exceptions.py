class DomainError(Exception):
    """Base exception for domain-related errors."""


class IdentityAlreadyExistsError(DomainError):
    """Raised when an identity with the same email already exists."""


class CustomerAlreadyLinkedError(DomainError):
    """Raised when the customer reference is already linked to an identity."""


class InvalidEmailError(DomainError):
    """Raised when an email address is invalid."""


class InvalidPasswordError(DomainError):
    """Raised when a password does not satisfy the password policy."""


class IdentityNotFoundError(DomainError):
    """Raised when a required identity does not exist."""


class IdentityNotActiveError(DomainError):
    """Raised when an inactive identity attempts an operation."""


class InvalidIdentityStateError(DomainError):
    """Raised when a requested state transition is not allowed."""


class EmailAlreadyVerifiedError(DomainError):
    """Raised when an already verified identity tries to verify again."""


class InvalidCurrentPasswordError(DomainError):
    """Raised when confirming the current password fails."""


class InvalidTokenError(DomainError):
    """Raised when a one-time token is unknown, expired, or already used.

    The three cases are deliberately not distinguished, because callers
    should treat every consumed, expired, or unknown token identically.
    """


class AuthenticationError(DomainError):
    """Raised when authentication fails.

    The error is intentionally generic: it must not reveal whether the
    email exists, the password was wrong, or the identity is inactive.
    """
