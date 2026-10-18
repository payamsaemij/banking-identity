
from typing import Protocol
from uuid import UUID

from identity_service.domain.entities.identity import Identity


class IdentityRepository(Protocol):
    def exists_by_email(self, email: str) -> bool:
        ...

    def save(self, identity: Identity) -> None:
        ...

    def get_by_id(self, identity_id: UUID) -> Identity | None:
        ...
