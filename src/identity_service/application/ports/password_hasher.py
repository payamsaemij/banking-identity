from typing import Protocol


class PasswordHasher(Protocol):
    """Password hashing contract (Argon2id in production).

    Implementations must never log passwords or hashes.
    """

    def hash(self, password: str) -> str: ...

    def verify(self, password: str, password_hash: str) -> bool: ...

    def needs_rehash(self, password_hash: str) -> bool:
        """Report whether a stored hash uses outdated parameters."""
        ...

    def verify_dummy(self, password: str) -> bool:
        """Perform a full-cost verification against a throwaway hash.

        Used when the principal is unknown so that the response time of a
        login attempt does not reveal whether the email exists. Always
        returns ``False``.
        """
        ...
