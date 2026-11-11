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
