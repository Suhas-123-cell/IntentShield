"""Wall-clock limits for the tests that guard against slow (quadratic or backtracking) inputs.

Each limit is set on a developer machine. Shared CI runners are two to three times slower and stall now and then, so a
limit with no margin fails at random there (1.53 s against 1.5 s on a 3.12 runner). On CI (GitHub Actions sets CI)
every limit is three times longer. So it is when a test runs under coverage (``pytest --cov``, which CONTRIBUTING.md asks
for) or under a debugger: tracing every line roughly doubles the time of the parser, and a limit of one second then fails
on a laptop with CI unset. That is still far below what the inputs these tests were written for took, which was seconds
to minutes."""
from __future__ import annotations

import os
import sys
import time


def _traced() -> bool:
    """True while coverage or a debugger is measuring the lines that run."""
    if sys.gettrace() is not None:
        return True
    coverage = sys.modules.get("coverage")
    current = getattr(getattr(coverage, "Coverage", None), "current", None)
    return bool(current and current())


def limit(seconds: float) -> float:
    return seconds * (3.0 if os.environ.get("CI") or _traced() else 1.0)


def best_of_three(seconds: float, fn, *args):
    """Call fn(*args) until one call finishes inside limit(seconds), at most three times, and return its result. A single sample
    can lose a second to a stalled laptop or a shared runner (0.95 s measured against a 1.0 s limit while other jobs ran); the
    quadratic or backtracking input these limits guard against is slow on every run, so the best of three still fails it."""
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        result = fn(*args)
        best = min(best, time.perf_counter() - start)
        if best < limit(seconds):
            return result
    raise AssertionError(f"{best:.1f}s, the best of three runs, against {limit(seconds):.1f}s")


def within(seconds: float, fn, *args):
    """Call fn(*args), assert that the best of up to three calls finished inside limit(seconds), and return the result."""
    return best_of_three(seconds, fn, *args)


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
