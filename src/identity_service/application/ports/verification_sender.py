
from typing import Protocol
from uuid import UUID


class VerificationSender(Protocol):
    def send_verification(self, identity_id: UUID, email: str) -> None:
        ...
