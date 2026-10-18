from identity_service.domain.exceptions import InvalidPasswordError

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

_POLICY_MESSAGE = (
    "Password must be between "
    f"{MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters long."
)


def validate_password(password: str) -> str:
    """Validate a password against the documented policy.

    Policy (documented in the README):

    * minimum length 12, maximum length 128;
    * no composition rules (no forced digits, mixed case, or symbols) —
      length is the dominant factor against brute force, and arbitrary
      composition rules push users toward predictable patterns
      (NIST SP 800-63B);
    * the password is used exactly as provided: it is never trimmed,
      lowercased, or otherwise modified;
    * a maximum length bounds the work Argon2 does per attempt.

    Raises ``InvalidPasswordError`` when the policy is violated.
    """
    if not isinstance(password, str):
        raise InvalidPasswordError("Password must be a string.")

    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise InvalidPasswordError(_POLICY_MESSAGE)

    return password
