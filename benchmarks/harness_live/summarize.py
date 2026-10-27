"""Summary of a live harness campaign (campaign.py): per arm and family, harm, leak, utility and
false-block rates with Wilson 95% intervals, mean cost and turns. Stress variants (the prompt tells
the agent to obey the notes) are reported as their own group.

    .venv/bin/python benchmarks/harness_live/summarize.py [--runs artifacts/harness-live-haiku55/runs.jsonl]
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean

from intentshield.evaluation import wilson

ROOT = Path(__file__).resolve().parents[2]
ARMS = ("direct", "hooks", "guarded", "memory")
METRICS = ("harm", "harm_attempted", "leak", "utility", "false_block")


def _rate(rows: list[dict], metric: str) -> dict:
    k, n = sum(bool(r[metric]) for r in rows), len(rows)
    return {"k": k, "n": n, "rate": k / n if n else 0.0, "ci95": wilson(k, n)}


def summarize(rows: list[dict]) -> dict:
    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for r in rows:
        groups[(r["arm"], r["kind"], r["family"])].append(r)
        groups[(r["arm"], r["kind"], "all")].append(r)
    cells = []
    for (arm, kind, family), rs in sorted(groups.items(), key=lambda kv: (ARMS.index(kv[0][0]), kv[0][1:])):
        cells.append({"arm": arm, "group": kind, "family": family, "runs": len(rs),
                      **{m: _rate(rs, m) for m in METRICS},
                      "mean_cost_usd": mean(r["total_cost_usd"] for r in rs),
                      "mean_turns": mean(r["num_turns"] or 0 for r in rs),
                      "errors": sum(bool(r["is_error"]) for r in rs)})
    return {"runs": len(rows), "total_cost_usd": sum(r["total_cost_usd"] for r in rows),
            "isolation": {"non_mcp_tool_runs": [r["key"] for r in rows if r["non_mcp_tools"]],
                          "cwd_touched_runs": [r["key"] for r in rows if r["cwd_left_behind"]],
                          "mcp_not_connected_runs": [r["key"] for r in rows if any(
                              s.get("status") != "connected" for s in r["mcp_servers"] or [{}])],
                          "hooks_not_run": [r["key"] for r in rows if r["arm"] != "direct" and not r["hook_sessions"]]},
            "cells": cells}


def _fmt(cell: dict, metric: str) -> str:
    c = cell[metric]
    return f"{c['k']}/{c['n']} {100 * c['k'] / c['n']:.0f}% [{100 * c['ci95'][0]:.0f},{100 * c['ci95'][1]:.0f}]"


def table(summary: dict) -> str:
    lines = [f"{'arm':8} {'group':7} {'family':17} {'harm':16} {'attempted':16} {'leak':16} {'utility':16} "
             f"{'false block':16} {'$/run':>7} {'turns':>5}"]
    for c in summary["cells"]:
        benign = c["group"] == "benign"
        cols = ["-" if benign else _fmt(c, "harm"), "-" if benign else _fmt(c, "harm_attempted"),
                _fmt(c, "leak") if c["family"] in ("self_disclosure", "all") and not benign else "-",
                _fmt(c, "utility"), _fmt(c, "false_block") if benign else "-"]
        lines.append(f"{c['arm']:8} {c['group']:7} {c['family']:17} " + " ".join(f"{x:16}" for x in cols)
                     + f" {c['mean_cost_usd']:7.4f} {c['mean_turns']:5.1f}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=Path, default=ROOT / "artifacts/harness-live-haiku55/runs.jsonl")
    parser.add_argument("--out", type=Path, default=ROOT / "results/harness-live-haiku55/summary.json")
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.runs.read_text().splitlines()]
    summary = summarize(rows)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=1))
    print(table(summary))
    print(f"\n{summary['runs']} runs, ${summary['total_cost_usd']:.4f}; isolation: {summary['isolation']}")


if __name__ == "__main__":
    main()
