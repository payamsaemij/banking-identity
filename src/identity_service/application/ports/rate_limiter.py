from typing import Protocol

from identity_service.application.exceptions import RateLimitDecision


class RateLimiter(Protocol):
    """Contract for sliding-window rate limiting of sensitive operations.

    The production implementation is in-process and therefore per
    instance; deployments running multiple replicas should provide a
    shared-store implementation (e.g. Redis) with this same interface.
    """

    def check(
        self, scope: str, key: str, limit: int, window_seconds: int
    ) -> RateLimitDecision: ...
