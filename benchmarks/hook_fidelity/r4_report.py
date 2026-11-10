"""Round 4 gap cells: k/n tables from the committed rows of one or more runs.jsonl files.

    r4_report.py ROWS.jsonl [ROWS.jsonl ...]

One line per (harness, version, mode, kind, state, failcfg, reply): the outcome counts over valid runs, hook invoked k/n and
how many valid runs. INVALID rows are listed apart and never counted in n. No rates are computed (the stub is deterministic)."""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def key_of(row: dict) -> tuple:
    return (row["harness"], row["version"], row["mode"], row["kind"], row["state"], row.get("failcfg", "-"), row["reply"])


def sort_key(key: tuple) -> tuple:
    version = tuple(int(x) if x.isdigit() else 0 for x in key[1].split("-")[0].split("."))
    reply = key[6]
    return (key[0], version, key[2], key[3], key[4], key[5], int("".join(c for c in reply if c.isdigit()) or 0), reply)


def table(rows: list[dict]) -> str:
    outcomes: dict[tuple, Counter] = defaultdict(Counter)
    invoked: dict[tuple, Counter] = defaultdict(Counter)
    invalid: Counter = Counter()
    for row in rows:
        key = key_of(row)
        if row["outcome"] == "INVALID":
            invalid[key] += 1
            continue
        outcomes[key][row["outcome"]] += 1
        invoked[key][str(row.get("hook_invoked"))] += 1
    lines = ["| harness | build | mode | tool | trust state | onFailure | reply | outcome k/n | hook invoked |",
             "|---|---|---|---|---|---|---|---|---|"]
    for key in sorted({*outcomes, *invalid}, key=sort_key):
        counts, n = outcomes.get(key, Counter()), sum(outcomes.get(key, Counter()).values())
        text = ", ".join(f"{o} {c}/{n}" for o, c in sorted(counts.items(), key=lambda kv: -kv[1])) or "-"
        if invalid[key]:
            text += f" (+{invalid[key]} INVALID, not in n)"
        seen = invoked.get(key, Counter())
        inv = f"{seen['True']}/{n}" if n and (seen["True"] or seen["False"]) else "not observable"
        lines.append(f"| {' | '.join(key[:6])} | {key[6]} | {text} | {inv} |")
    return "\n".join(lines)


if __name__ == "__main__":
    data = [json.loads(line) for path in sys.argv[1:] for line in Path(path).read_text().splitlines() if line.strip()]
    print(table(data))
