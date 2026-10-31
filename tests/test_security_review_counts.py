"""docs/security-review.md: the 'Table counts' table equals the status column of the finding rows above it."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

DOC = Path(__file__).resolve().parents[1] / "docs" / "security-review.md"
COLUMNS = ("Fixed", "Fixed after 0.4.1", "Partly fixed", "Open", "Unverified")
AREAS = {"PX": "Proxy and control plane", "JG": "LLM judge", "HK": "Hook path and installer",
         "RP": "Detection and provenance"}


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _row_counts() -> dict[str, Counter]:
    text = DOC.read_text().split("### Table counts")[0]
    counts: dict[str, Counter] = defaultdict(Counter)
    for line in text.splitlines():
        match = re.match(r"\| (PX|JG|HK|RP)\d+ \|", line)
        if match:
            status = _cells(line)[3]
            counts[match.group(1)]["Fixed after 0.4.1" if status.startswith("Fixed (after") else status.split(" (")[0]] += 1
    return counts


def _table() -> dict[str, list[int]]:
    block = DOC.read_text().split("### Table counts")[1].split("\n\n")
    lines = next(b for b in block if b.startswith("| Area")).splitlines()
    assert tuple(_cells(lines[0])[2:]) == COLUMNS
    return {_cells(line)[0]: [int(re.match(r"\d+", c).group()) for c in _cells(line)[2:]] for line in lines[2:]}


def test_table_counts_equal_the_rows():
    rows, table = _row_counts(), _table()
    for key, name in AREAS.items():
        assert table[name] == [rows[key][c] for c in COLUMNS], name
    assert table["Total"] == [sum(rows[k][c] for k in AREAS) for c in COLUMNS]
    assert sum(sum(c.values()) for c in rows.values()) == 50
