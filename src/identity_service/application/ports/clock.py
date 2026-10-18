from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    """Time source abstraction.

    Injected into use cases so expiry behaviour is tested with
    deterministic time instead of sleeping.
    """

    def utc_now(self) -> datetime: ...


class SystemClock:
    """Production clock: timezone-aware UTC."""

    def utc_now(self) -> datetime:
        return datetime.now(UTC)
