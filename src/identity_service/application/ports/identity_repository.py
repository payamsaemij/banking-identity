from typing import Protocol
from uuid import UUID

from identity_service.domain.entities.identity import Identity


class IdentityRepository(Protocol):
    """Persistence contract for identities.

    ``add`` inserts a new identity and raises
    ``IdentityAlreadyExistsError`` (or ``CustomerAlreadyLinkedError``)
    when a uniqueness constraint is violated, including when two
    concurrent requests race past the application-level check.
    Lookups return ``None`` when no row matches.
    """

    def add(self, identity: Identity) -> None: ...

    def get_by_id(self, identity_id: UUID) -> Identity | None: ...

    def get_by_email(self, email: str) -> Identity | None: ...

    def update(self, identity: Identity) -> None: ...
