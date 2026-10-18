import re

from identity_service.domain.exceptions import InvalidEmailError

# Pragmatic "obviously malformed" check (close to the WHATWG HTML5 email
# input rule). It rejects clearly broken addresses; it does not and cannot
# prove that an address actually exists or is deliverable.
_EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)

MAX_EMAIL_LENGTH = 254  # RFC 5321 practical limit
MAX_LOCAL_PART_LENGTH = 64  # RFC 5321


def normalize_email(email: str) -> str:
    """Apply the service-wide email normalization policy.

    Policy (documented in the README):

    * surrounding whitespace is trimmed;
    * the whole address is lowercased — the service treats email as
      case-insensitive, which is what virtually every provider does;
    * plus-addressing tags and dots are preserved untouched;
    * no other rewriting happens.

    The same normalization is applied before every lookup and insert, and
    the database unique constraint enforces it on the stored value.
    """
    return email.strip().lower()


def validate_email(email: str) -> str:
    """Validate a normalized email, returning it unchanged.

    Raises ``InvalidEmailError`` for malformed addresses.
    """
    if not email:
        raise InvalidEmailError("Email is required.")

    if len(email) > MAX_EMAIL_LENGTH:
        raise InvalidEmailError("Email is too long.")

    local_part, _, domain = email.partition("@")
    if not local_part or not domain:
        raise InvalidEmailError("Email must contain a local part and a domain.")

    if len(local_part) > MAX_LOCAL_PART_LENGTH:
        raise InvalidEmailError("Email local part is too long.")

    if _EMAIL_PATTERN.match(email) is None:
        raise InvalidEmailError("Email address is malformed.")

    return email


def normalize_and_validate_email(email: str) -> str:
    """Trim, lowercase, and validate an email address."""
    if not isinstance(email, str):
        raise InvalidEmailError("Email must be a string.")

    return validate_email(normalize_email(email))
