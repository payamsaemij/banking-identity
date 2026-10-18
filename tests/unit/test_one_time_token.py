from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from identity_service.domain.entities.one_time_token import OneTimeToken
from identity_service.domain.exceptions import InvalidTokenError


def make_token(expires_in_seconds: int = 3600) -> OneTimeToken:
    now = datetime.now(UTC)
    return OneTimeToken(
        id=uuid4(),
        identity_id=uuid4(),
        token_hash="a" * 64,
        created_at=now,
        expires_at=now + timedelta(seconds=expires_in_seconds),
    )


def test_fresh_token_is_available() -> None:
    token = make_token()

    assert token.used_at is None
    assert token.is_expired(datetime.now(UTC)) is False
    assert token.is_available(datetime.now(UTC)) is True


def test_consume_marks_token_used() -> None:
    token = make_token()
    now = datetime.now(UTC)

    token.consume(now)

    assert token.used_at == now
    assert token.is_available(now) is False


def test_token_cannot_be_reused() -> None:
    token = make_token()
    token.consume(datetime.now(UTC))

    with pytest.raises(InvalidTokenError):
        token.consume(datetime.now(UTC) + timedelta(seconds=1))


def test_expired_token_cannot_be_consumed() -> None:
    token = make_token(expires_in_seconds=60)

    with pytest.raises(InvalidTokenError):
        token.consume(datetime.now(UTC) + timedelta(seconds=61))


def test_invalidate_neutralizes_unused_token() -> None:
    token = make_token()
    now = datetime.now(UTC)

    token.invalidate(now)

    assert token.used_at == now


def test_invalidate_leaves_used_token_untouched() -> None:
    token = make_token()
    first_use = datetime.now(UTC)
    token.consume(first_use)

    token.invalidate(first_use + timedelta(seconds=1))

    assert token.used_at == first_use
