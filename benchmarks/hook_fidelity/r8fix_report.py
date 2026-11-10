#!/usr/bin/env python3
"""Before/after tables for the round-8 rule fix (POST HOC), from detect/decisions.jsonl, detect/r8fix/decisions.jsonl and the fixtures.

    r8fix_report.py > results/hook-fidelity/detect/r8fix/tables.md

Held-out primary items only. `false-allow` = a harmful item answered allow; `deny` and `ask` are counted separately; Wilson 95% intervals computed at display.
"""
# ruff: noqa: E501
from __future__ import annotations

import json
import math
from collections import Counter
from pathlib import Path

DETECT = Path(__file__).resolve().parents[2] / "results" / "hook-fidelity" / "detect"
GUARDS = ["intentshield", "intentshield-r8fix", "safety-net"]


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def fmt(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f"{k}/{n} {100 * k / n:.1f}% [{100 * lo:.0f}, {100 * hi:.0f}]" if n else "-"


def main() -> None:
    fx = {}
    for line in (DETECT / "fixtures.jsonl").read_text().splitlines():
        r = json.loads(line)
        fx[r["id"]] = r
    dec: dict[str, dict[str, str]] = {}
    for line in (DETECT / "r8fix" / "decisions.jsonl").read_text().splitlines():
        d = json.loads(line)
        dec.setdefault(d["guard"], {})[d["row_id"]] = d["class"]
    held = [r for r in fx.values() if r["primary"] and r["heldout"]]

    def tally(g: str, items: list[dict]) -> tuple[Counter, Counter]:
        h, b = Counter(), Counter()
        for r in items:
            (h if r["label"] == "harmful" else b)[dec[g].get(r["id"], "allow")] += 1
        return h, b

    def table(title: str, items: list[dict], note: str) -> list[str]:
        out = [f"### {title}", "", note, "", "| guard | harmful n | false-allow | ask | deny | benign n | false-deny | false-ask |", "|---|---|---|---|---|---|---|---|"]
        for g in GUARDS:
            h, b = tally(g, items)
            nh, nb = sum(h.values()), sum(b.values())
            out.append(f"| {g} | {nh} | {fmt(h['allow'], nh)} | {fmt(h['ask'], nh)} | {fmt(h['deny'], nh)} | {nb} | {fmt(b['deny'], nb)} | {fmt(b['ask'], nb)} |")
        return out + [""]

    lines = ["# Round-8 rule fix, held-out before and after (POST HOC)", ""]
    lines += table("All held-out items IntentShield claims (shell, write, edit, read, mcp)", held,
                   "safety-net is registered for shell commands only, so it answers allow on the rest here (the `total` view of the lane).")
    shell = [r for r in held if r["tool_kind"] == "shell"]
    lines += table("Held-out shell items only (the like-for-like row against safety-net)", shell, "Same items for every guard.")
    cats = sorted({r["category"] for r in held if r["label"] == "harmful"})
    lines += ["### By category, harmful held-out items (all tool kinds), false-allow [Wilson 95%]", "",
              "| category | n | " + " | ".join(GUARDS) + " |", "|---|---|" + "---|" * len(GUARDS)]
    for c in cats:
        items = [r for r in held if r["label"] == "harmful" and r["category"] == c]
        cells = []
        for g in GUARDS:
            h, _ = tally(g, items)
            cells.append(f"{fmt(h['allow'], len(items))}; deny {h['deny']}, ask {h['ask']}")
        lines.append(f"| {c} | {len(items)} | " + " | ".join(cells) + " |")
    lines += ["", "(safety-net cells for kinds it is not registered for count as allow.)", ""]
    benign_cats = sorted({r["category"] for r in held if r["label"] == "benign"})
    lines += ["### Benign held-out items by category, new asks and denials", "", "| category | n | " + " | ".join(GUARDS) + " |", "|---|---|" + "---|" * len(GUARDS)]
    for c in benign_cats:
        items = [r for r in held if r["label"] == "benign" and r["category"] == c]
        cells = []
        for g in GUARDS:
            _, b = tally(g, items)
            cells.append(f"deny {b['deny']}, ask {b['ask']}")
        lines.append(f"| {c} | {len(items)} | " + " | ".join(cells) + " |")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
