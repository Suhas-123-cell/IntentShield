#!/usr/bin/env python3
"""The 214-call set's denies-alone comparison with the items grouped by where they came from.

`fresh_report.py` pairs IntentShield and a scoped guard item by item and runs an exact sign test on the items only one of them
denied (24 against 7 for safety-net, p = 0.0033, with the rules as they were when scored). That test treats the 85 items as
independent. They are not: one source write-up often supplies several items (44 write-ups for the 85), and the items of a write-up
share a technique. This script repeats the comparison with the write-up as the unit:

* one row per source write-up, from the `source` field of the fixture: the write-up counts for IntentShield when more of its items
  were denied only by IntentShield than only by the other guard, for the other guard in the opposite case, and is dropped as a tie
  otherwise; an exact two-sided sign test on the rows that are not ties;
* the same with one row per harmful category (six rows);
* a bootstrap over write-ups: resample the write-ups with replacement (10000 draws, fixed seed) and take the other guard's deny
  rate minus IntentShield's on the resampled items; the 95% percentile interval of that gap, and the share of draws in which
  IntentShield denies at least as many as the other guard.

Reads results/hook-fidelity/detect/fresh/{fixtures.jsonl,decisions.jsonl} (hash-checked by fresh_report.load_fixtures). Writes
nothing outside the directory given with --out. The scopes and the deny definition are those of `fresh_report.py`: safety-net's
shell items (85) and knox's items (73), a deny being the only reply every build treats as a stop.

    cluster_compare.py --out <directory>
    cluster_compare.py --out <directory> --current-rules

With --current-rules the same comparison is also made with IntentShield's decisions from the code in this checkout
(`detect_compare.decide_intentshield`, in process, nothing executed), beside the committed ones. The committed output is
`results/hook-fidelity/detect/fresh/cluster/`. The write-ups are the author's grouping of author-written items, so the figures
bound how much the clustering matters; they do not turn the set into a sample of anything.
"""
# ruff: noqa: E501
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import fresh_report as fr  # noqa: E402

SEED = 20261119
DRAWS = 10000


def denies(rows: list[dict], decisions: list[dict], guard: str) -> dict[str, bool]:
    """item id -> whether the guard denied the item's primary rendering. Rows the guard was never run on are left out."""
    by_row = {d["row_id"]: d["class"] for d in decisions if d["guard"] == guard and d.get("invoked", True)}
    return {r["item_id"]: by_row[r["id"]] == "deny" for r in rows if r["id"] in by_row}


def clusters(items: list[dict], is_deny: dict[str, bool], other_deny: dict[str, bool], key: str) -> dict[str, tuple[int, int, int]]:
    """cluster -> (items, denied only by IntentShield, denied only by the other guard), grouping the items by ``key``."""
    out: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for item in items:
        row = out[item[key]]
        row[0] += 1
        row[1] += is_deny[item["item_id"]] and not other_deny[item["item_id"]]
        row[2] += other_deny[item["item_id"]] and not is_deny[item["item_id"]]
    return {name: (a, b, c) for name, (a, b, c) in sorted(out.items())}


def sign_rows(table: dict[str, tuple[int, int, int]]) -> dict:
    """The sign test with one row per cluster: IntentShield's rows, the other guard's rows and ties."""
    only_is = sum(1 for _, a, b in table.values() if a > b)
    only_other = sum(1 for _, a, b in table.values() if b > a)
    return {"clusters": len(table), "ties": len(table) - only_is - only_other, "only_intentshield": only_is, "only_other": only_other,
            "sign_p": fr.sign_test_p(only_is, only_other)}


def bootstrap(table: dict[str, tuple[int, int, int]], draws: int = DRAWS, seed: int = SEED) -> dict:
    """Resample the clusters with replacement. The gap is the other guard's deny rate minus IntentShield's, in points; both guards
    are scored on the same resampled items, so it is (only other - only IntentShield) / items."""
    names = sorted(table)
    rng = random.Random(seed)
    gaps = []
    not_ahead = 0
    for _ in range(draws):
        n = a = b = 0
        for name in (names[rng.randrange(len(names))] for _ in names):
            n += table[name][0]
            a += table[name][1]
            b += table[name][2]
        gaps.append(100 * (b - a) / n)
        not_ahead += a >= b
    gaps.sort()
    lo, hi = gaps[int(0.025 * draws)], gaps[int(0.975 * draws) - 1]
    items = sum(v[0] for v in table.values())
    point = 100 * (sum(v[2] for v in table.values()) - sum(v[1] for v in table.values())) / items
    return {"draws": draws, "seed": seed, "gap_points": point, "gap_lo": lo, "gap_hi": hi, "share_intentshield_at_least_level": not_ahead / draws}


def compare(rows: list[dict], decisions: list[dict], is_guard: str = fr.IS) -> dict:
    """The comparison for both scoped guards. ``rows`` are the fixture renderings, ``decisions`` every guard's replies."""
    prim = [r for r in rows if r["primary"] and r["label"] == "harmful"]
    is_deny = denies(rows, decisions, is_guard)
    out: dict = {}
    for other in fr.COMPARE_ON_SCOPE:
        _, in_scope = fr.SCOPE[other]
        other_deny = denies(rows, decisions, other)
        items = [r for r in prim if in_scope(r) and r["item_id"] in other_deny and r["item_id"] in is_deny]
        item_only_is = sum(1 for r in items if is_deny[r["item_id"]] and not other_deny[r["item_id"]])
        item_only_other = sum(1 for r in items if other_deny[r["item_id"]] and not is_deny[r["item_id"]])
        by_source = clusters(items, is_deny, other_deny, "source")
        by_category = clusters(items, is_deny, other_deny, "category")
        out[other] = {
            "items": len(items),
            "item_level": {"only_intentshield": item_only_is, "only_other": item_only_other, "sign_p": fr.sign_test_p(item_only_is, item_only_other)},
            "by_source": {"rows": sign_rows(by_source), "bootstrap": bootstrap(by_source)},
            "by_category": {"rows": sign_rows(by_category), "table": {k: list(v) for k, v in by_category.items()}},
            "largest_sources": sorted(([k, v[0]] for k, v in by_source.items()), key=lambda x: (-x[1], x[0]))[:5],
        }
    return out


def render(result: dict) -> list[str]:
    lines = ["# Denies alone, with the source write-up as the unit", "",
             "Generated by `benchmarks/hook_fidelity/cluster_compare.py`; see its docstring for the method. A deny is the only reply every build "
             "treats as a stop. `only X` counts items (or, for the clustered rows, write-ups or categories) that X denied and the other guard did not.", ""]
    for variant, label in (("study_rules", "IntentShield with the rules as they were when the study scored them (committed decisions)"),
                           ("current_rules", "IntentShield with the rules in the checkout the file was generated from")):
        if variant not in result:
            continue
        lines += [f"## {label}", "", "| guard scope | items | write-ups | item level: only other / only IntentShield (p) | per write-up: only other / only IntentShield / ties (p) | "
                  "per category: only other / only IntentShield / ties (p) | bootstrap over write-ups: gap in deny rate, other minus IntentShield [95%] | draws with IntentShield at least level |",
                  "|---|---|---|---|---|---|---|---|"]
        for other, e in result[variant].items():
            i, s, c, b = e["item_level"], e["by_source"]["rows"], e["by_category"]["rows"], e["by_source"]["bootstrap"]
            lines.append(f"| {other} | {e['items']} | {s['clusters']} | {i['only_other']} / {i['only_intentshield']} ({i['sign_p']:.3g}) | "
                         f"{s['only_other']} / {s['only_intentshield']} / {s['ties']} ({s['sign_p']:.3g}) | "
                         f"{c['only_other']} / {c['only_intentshield']} / {c['ties']} ({c['sign_p']:.3g}) | "
                         f"{b['gap_points']:+.1f} [{b['gap_lo']:+.1f}, {b['gap_hi']:+.1f}] points | {b['share_intentshield_at_least_level']:.3f} |")
        lines.append("")
        net = result[variant]["safety-net"]
        lines += ["Per category on safety-net's items (items, only IntentShield, only safety-net):", "",
                  "| category | items | only IntentShield | only safety-net |", "|---|---|---|---|"]
        for name, (n, a, b) in net["by_category"]["table"].items():
            lines.append(f"| {name} | {n} | {a} | {b} |")
        lines.append("")
    lines += ["Bootstrap: 10000 draws of the write-ups with replacement, seed 20261119. The write-ups are the author's grouping of author-written items.", ""]
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, required=True,
                        help="directory to write cluster.json and cluster.md into (created if missing); the committed copies are "
                             "results/hook-fidelity/detect/fresh/cluster/, so give a scratch directory and diff against them")
    parser.add_argument("--current-rules", action="store_true", help="also compare with IntentShield's decisions from the code in this checkout")
    args = parser.parse_args(argv)
    rows = fr.load_fixtures()
    decisions = [json.loads(line) for line in (fr.FRESH / "decisions.jsonl").read_text(encoding="utf-8").splitlines()]
    result: dict = {"study_rules": compare(rows, decisions)}
    if args.current_rules:
        now = fr.decide_intentshield(rows, "intentshield")
        for decision in now:
            decision["guard"] = fr.IS
        result["current_rules"] = compare(rows, [d for d in decisions if d["guard"] != fr.IS] + now)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "cluster.json").write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    (args.out / "cluster.md").write_text("\n".join(render(result)) + "\n", encoding="utf-8")
    print(f"wrote cluster.json and cluster.md to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
