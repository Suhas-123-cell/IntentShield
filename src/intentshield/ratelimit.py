from __future__ import annotations

import os
import time
from collections import OrderedDict


class RateLimiter:
    """In-memory token bucket per client key; one process, no shared state."""

    def __init__(self, per_minute: int, burst: int | None = None, max_clients: int = 10_000) -> None:
        self.max_clients = max_clients
        self.rate = per_minute / 60.0
        self.burst = float(burst or max(1, per_minute))
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    @classmethod
    def from_env(cls) -> "RateLimiter | None":
        try:
            per_minute = int(os.getenv("INTENTSHIELD_RATE_LIMIT_PER_MIN", "120"))
        except ValueError:
            per_minute = 120
        return cls(per_minute) if per_minute > 0 else None

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        tokens, last = self._buckets.get(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        allowed = tokens >= 1
        self._buckets[key] = (tokens - 1 if allowed else tokens, now)
        self._buckets.move_to_end(key)
        # Evict the least recently seen clients that are not throttled: dropping a throttled
        # bucket would hand that client a fresh burst, so a flood of new keys cannot reset one.
        for _ in range(min(len(self._buckets), 64)):  # bounded: a request never pays for the whole map
            if len(self._buckets) <= self.max_clients:
                break
            oldest, (left, seen) = next(iter(self._buckets.items()))
            if left + (now - seen) * self.rate < 1:
                self._buckets.move_to_end(oldest)
            else:
                del self._buckets[oldest]
        while len(self._buckets) > self.max_clients:
            self._buckets.popitem(last=False)
        return allowed
