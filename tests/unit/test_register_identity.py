from uuid import UUID

import pytest

from identity_service.application.use_cases.register_identity import (
    RegisterIdentity,
)
from identity_service.domain.entities.identity import Identity
from identity_service.domain.exceptions import IdentityAlreadyExistsError


class FakeIdentityRepository:
    def __init__(self) -> None:
        self.identities: dict[str, Identity] = {}

    def exists_by_email(self, email: str) -> bool:
        return email in self.identities

    def save(self, identity: Identity) -> None:
        self.identities[identity.email] = identity

    def get_by_id(self, identity_id: UUID) -> Identity | None:
        return next(
            (
                identity
                for identity in self.identities.values()
                if identity.id == identity_id
            ),
            None,
        )


class FakePasswordHasher:
    def hash(self, password: str) -> str:
        return f"hashed:{password}"


class FakeVerificationSender:
    def __init__(self) -> None:
        self.sent_to: list[str] = []

    def send_verification(self, identity_id: UUID, email: str) -> None:
        self.sent_to.append(email)


def test_register_identity() -> None:
    repository = FakeIdentityRepository()
    sender = FakeVerificationSender()

    use_case = RegisterIdentity(
        repository=repository,
        password_hasher=FakePasswordHasher(),
        verification_sender=sender,
    )

    identity = use_case.execute(
        email="  CUSTOMER@example.com ",
        password="StrongPassword123!",
    )

    assert identity.email == "customer@example.com"
    assert identity.password_hash == "hashed:StrongPassword123!"
    assert identity.email_verified_at is None
    assert sender.sent_to == ["customer@example.com"]
    assert repository.exists_by_email("customer@example.com")


def test_register_identity_rejects_duplicate_email() -> None:
    repository = FakeIdentityRepository()
    sender = FakeVerificationSender()

    use_case = RegisterIdentity(
        repository=repository,
        password_hasher=FakePasswordHasher(),
        verification_sender=sender,
    )

    use_case.execute("customer@example.com", "StrongPassword123!")

    with pytest.raises(IdentityAlreadyExistsError, match="already registered"):
        use_case.execute("CUSTOMER@example.com", "AnotherPassword123!")

    assert len(sender.sent_to) == 1