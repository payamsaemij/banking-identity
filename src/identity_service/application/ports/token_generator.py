from typing import Protocol


class TokenGenerator(Protocol):
    """Contract for generating cryptographically secure raw tokens."""

    def generate(self) -> str: ...
