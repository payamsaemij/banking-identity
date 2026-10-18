import contextlib
import logging

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

logger = logging.getLogger(__name__)

# A valid Argon2id hash of a throwaway value, used solely to give unknown
# principals the same verification cost as known ones on login.
_DUMMY_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$wx74UT9VnuZNqPqmaogGnQ"
    "$cAuH9AGR4CaMCgj6Uv2SZXkds8Yf8quUHJRBsMn2BLQ"
)


class Argon2PasswordHasher:
    """Argon2id password hashing (RFC 9106 recommended parameters).

    The PasswordHasher defaults (argon2id, m=64 MiB, t=3, p=4) are used:
    they are the library's maintained, memory-hard defaults. Hashes and
    passwords are never logged.
    """

    def __init__(self) -> None:
        self._hasher = PasswordHasher()

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, password: str, password_hash: str) -> bool:
        try:
            self._hasher.verify(password_hash, password)
            return True
        except VerifyMismatchError:
            return False
        except InvalidHashError:
            logger.warning(
                "Stored password hash is not a valid Argon2 hash.",
                extra={"event": "security.invalid_stored_hash"},
            )
            return False

    def needs_rehash(self, password_hash: str) -> bool:
        try:
            return self._hasher.check_needs_rehash(password_hash)
        except InvalidHashError:
            return True

    def verify_dummy(self, password: str) -> bool:
        with contextlib.suppress(VerifyMismatchError, InvalidHashError):
            self._hasher.verify(_DUMMY_HASH, password)
        return False
