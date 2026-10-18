import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable

from identity_service.application.exceptions import RateLimitDecision


class InMemoryRateLimiter:
    """Sliding-window counter, per scope and key.

    Scope: a single process. Deployments running several replicas must
    swap this implementation for a shared-store one (e.g. Redis) behind
    the same ``RateLimiter`` port — the API boundary does not change.
    """

    def __init__(self, monotonic_clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = monotonic_clock
        self._lock = threading.Lock()
        self._events: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def check(
        self, scope: str, key: str, limit: int, window_seconds: int
    ) -> RateLimitDecision:
        now = self._clock()
        bucket_key = (scope, key)
        with self._lock:
            events = self._events[bucket_key]
            cutoff = now - window_seconds
            while events and events[0] <= cutoff:
                events.popleft()

            if len(events) >= limit:
                oldest = events[0]
                retry_after = max(1, int(oldest + window_seconds - now) + 1)
                return RateLimitDecision(allowed=False, retry_after_seconds=retry_after)

            events.append(now)
            return RateLimitDecision(allowed=True, retry_after_seconds=0)
