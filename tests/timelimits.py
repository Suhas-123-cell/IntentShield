"""Wall-clock limits for the tests that guard against slow (quadratic or backtracking) inputs.

Each limit is set on a developer machine. Shared CI runners are two to three times slower and stall now and then, so a
limit with no margin fails at random there (1.53 s against 1.5 s on a 3.12 runner). On CI (GitHub Actions sets CI)
every limit is three times longer. That is still far below what the inputs these tests were written for took, which
was seconds to minutes."""
from __future__ import annotations

import os
import time

SCALE = 3.0 if os.environ.get("CI") else 1.0


def limit(seconds: float) -> float:
    return seconds * SCALE


def within(seconds: float, fn, *args):
    """Call fn(*args), assert it finished inside limit(seconds), and return its result."""
    start = time.perf_counter()
    result = fn(*args)
    elapsed = time.perf_counter() - start
    assert elapsed < limit(seconds), f"{elapsed:.1f}s"
    return result


def fastest(fn, *args, repeats: int = 5) -> float:
    """The shortest of several runs of fn(*args), in seconds.

    A single sample swings with scheduler noise and a stalled shared runner. The minimum of a few runs is stable, so
    use it when one run is compared with another instead of with a fixed bound."""
    best = float("inf")
    for _ in range(repeats):
        start = time.perf_counter()
        fn(*args)
        best = min(best, time.perf_counter() - start)
    return best
