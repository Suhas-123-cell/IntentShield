"""What a session remembers of flagged outputs: bounded sets of values, oldest out."""
from __future__ import annotations

import itertools
from typing import Any

# What a session remembers of flagged outputs: values of one output are capped, and each set keeps the newest
# MAX_TAINTED, oldest out (like ``_observed``). Every call's rule check walks these sets under the lock the event
# loop also takes: 50,000 values cost 34 ms a call, 500,000 cost 450 ms, and one 2 MB page of distinct URLs added
# 60,000. A flagged output carries dozens of values, not thousands. Dropping a value is not safe by itself: a page
# can bury the address it sends data to under thousands of others. So a cap that drops anything sets
# ``_taint_incomplete``, and from then on a call carrying a value the user did not give is blocked, as one built
# on a tainted value is (the taint of that session can no longer say which values are clean).
MAX_TAINTED = 20_000
MAX_OUTPUT_TAINT = 2_000


class _RecentSet(set[str]):
    """A set that keeps the newest ``limit`` values, oldest out; a value seen again counts as new. Add with
    ``update`` (``|=`` and ``add`` would skip the bound)."""

    def __init__(self, limit: int = MAX_TAINTED) -> None:
        super().__init__()
        self.limit = limit
        self.evicted = False  # a value went out to make room: the set no longer holds everything it was given
        self._order: dict[str, None] = {}

    def update(self, *others: Any) -> None:
        for values in others:
            for value in values:
                self._order.pop(value, None)
                self._order[value] = None
                self.add(value)
        for stale in list(itertools.islice(self._order, max(0, len(self._order) - self.limit))):
            del self._order[stale]
            self.discard(stale)
            self.evicted = True


def _newest(values: set[str], limit: int = MAX_OUTPUT_TAINT) -> set[str]:
    """At most ``limit`` of one output's values (the first in sorted order: a set has no other)."""
    return values if len(values) <= limit else set(sorted(values)[:limit])
