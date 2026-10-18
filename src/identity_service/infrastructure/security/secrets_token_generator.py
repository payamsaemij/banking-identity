import secrets

from identity_service.application.ports.token_generator import TokenGenerator


class SecretsTokenGenerator(TokenGenerator):
    """Generates 256-bit URL-safe tokens from the system CSPRNG."""

    def generate(self) -> str:
        return secrets.token_urlsafe(32)
