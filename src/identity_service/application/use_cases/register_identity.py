from uuid import uuid4

from identity_service.application.ports.identity_repository import (
    IdentityRepository,
)
from identity_service.application.ports.password_hasher import PasswordHasher
from identity_service.application.ports.verification_sender import (
    VerificationSender,
)
from identity_service.domain.entities.identity import Identity
from identity_service.domain.exceptions import IdentityAlreadyExistsError


class RegisterIdentity:
    def __init__(
        self,
        repository: IdentityRepository,
        password_hasher: PasswordHasher,
        verification_sender: VerificationSender,
    ) -> None:
        self.repository = repository
        self.password_hasher = password_hasher
        self.verification_sender = verification_sender

    def execute(self, email: str, password: str) -> Identity:
        normalized_email = email.strip().lower()

        if self.repository.exists_by_email(normalized_email):
            raise IdentityAlreadyExistsError("Email is already registered.")

        identity = Identity(
            id=uuid4(),
            email=normalized_email,
            password_hash=self.password_hasher.hash(password),
        )

        self.repository.save(identity)
        self.verification_sender.send_verification(
            identity.id,
            identity.email,
        )

        return identity