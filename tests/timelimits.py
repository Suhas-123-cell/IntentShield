"""Wall-clock limits for the tests that guard against slow (quadratic or backtracking) inputs.

Each limit is set on a developer machine. Shared CI runners are two to three times slower and stall now and then, so a
limit with no margin fails at random there (1.53 s against 1.5 s on a 3.12 runner). On CI (GitHub Actions sets CI)
every limit is three times longer. That is still far below what the inputs these tests were written for took, which
was seconds to minutes."""
from __future__ import annotations

import os

SCALE = 3.0 if os.environ.get("CI") else 1.0


def limit(seconds: float) -> float:
    return seconds * SCALE
