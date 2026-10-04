from __future__ import annotations

import os
import time


class RateLimiter:
    """In-memory token bucket per client key; one process, no shared state."""

    def __init__(self, per_minute: int, burst: int | None = None) -> None:
        self.rate = per_minute / 60.0
        self.burst = float(burst or max(1, per_minute))
        self._buckets: dict[str, tuple[float, float]] = {}

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
        if len(self._buckets) > 10_000:
            self._buckets.clear()
        self._buckets[key] = (tokens - 1 if allowed else tokens, now)
        return allowed
