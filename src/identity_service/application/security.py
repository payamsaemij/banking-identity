import hashlib


def hash_token(raw_token: str) -> str:
    """Return the persisted representation of a one-time or session token.

    Tokens carry 256 bits of cryptographically secure randomness, so a
    fast hash is appropriate: an attacker who steals the database learns
    nothing that lets them replay a token, while lookups stay cheap.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
