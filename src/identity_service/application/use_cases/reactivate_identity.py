import logging
from uuid import UUID

from identity_service.application.ports.identity_repository import IdentityRepository
from identity_service.domain.entities.identity import Identity
from identity_service.domain.exceptions import IdentityNotFoundError

logger = logging.getLogger(__name__)


class ReactivateIdentity:
    """Reactivate a deactivated identity through the authorized policy.

    Authorization is enforced at the API boundary (an administrative
    service key); the use case itself only applies the domain transition:
    a deactivated identity with a verified email returns to ACTIVE,
    otherwise to PENDING_VERIFICATION.
    """

    def __init__(self, *, identity_repository: IdentityRepository) -> None:
        self._identity_repository = identity_repository

    def execute(self, identity_id: UUID) -> Identity:
        identity = self._identity_repository.get_by_id(identity_id)
        if identity is None:
            raise IdentityNotFoundError("Identity not found.")

        identity.reactivate()
        self._identity_repository.update(identity)

        logger.info(
            "Identity reactivated.",
            extra={"event": "identity.reactivated", "identity_id": str(identity_id)},
        )
        return identity
