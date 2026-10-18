from identity_service.infrastructure.rate_limit.in_memory import InMemoryRateLimiter


class FakeMonotonicClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_allows_events_up_to_the_limit() -> None:
    clock = FakeMonotonicClock()
    limiter = InMemoryRateLimiter(clock)

    decisions = [limiter.check("login", "login:1.2.3.4", 3, 60) for _ in range(3)]

    assert all(decision.allowed for decision in decisions)


def test_blocks_events_beyond_the_limit() -> None:
    clock = FakeMonotonicClock()
    limiter = InMemoryRateLimiter(clock)
    for _ in range(3):
        limiter.check("login", "login:1.2.3.4", 3, 60)

    decision = limiter.check("login", "login:1.2.3.4", 3, 60)

    assert decision.allowed is False
    assert decision.retry_after_seconds > 0


def test_window_slides_with_time() -> None:
    clock = FakeMonotonicClock()
    limiter = InMemoryRateLimiter(clock)
    for _ in range(3):
        limiter.check("login", "login:1.2.3.4", 3, 60)
    assert limiter.check("login", "login:1.2.3.4", 3, 60).allowed is False

    clock.advance(seconds=61)

    assert limiter.check("login", "login:1.2.3.4", 3, 60).allowed is True


def test_scopes_and_keys_are_independent() -> None:
    clock = FakeMonotonicClock()
    limiter = InMemoryRateLimiter(clock)
    for _ in range(3):
        limiter.check("login", "login:1.2.3.4", 3, 60)

    other_key = limiter.check("login", "login:5.6.7.8", 3, 60)
    other_scope = limiter.check("register", "register:1.2.3.4", 3, 60)

    assert other_key.allowed and other_scope.allowed


def test_retry_after_shrinks_as_the_window_slides() -> None:
    clock = FakeMonotonicClock()
    limiter = InMemoryRateLimiter(clock)
    for _ in range(3):
        limiter.check("login", "login:1.2.3.4", 3, 60)
    clock.advance(seconds=30)

    decision = limiter.check("login", "login:1.2.3.4", 3, 60)

    assert decision.allowed is False
    assert decision.retry_after_seconds <= 31
