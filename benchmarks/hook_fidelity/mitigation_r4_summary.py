"""Tables for the round 4 mitigation cells (results/hook-fidelity/mitigation/eval-r4), computed from the raw rows.

    python benchmarks/hook_fidelity/mitigation_r4_summary.py [OUT_DIR] > table.md

The cells answer the mitigation critic's fatal objection: the round 3 scenarios (ask, deny, slow guard, dead hook) cannot tell
the translation from "refuse everything". So: ``allow`` (the call must RUN, through the shipped launcher and deadline, translation
off and on), the ``deny-all`` control (a hook that exits 2 on every call: it must be BLOCKED where the translation RUNS the call,
which shows the allow cell can tell the two apart), ``slowdefault`` (the shipped 30 s deadline, no handler timeout override, a
45 s guard) and ``norecord`` (a headless ask with no harness version recorded). n=1 per cell: the stub is deterministic, so a
cell is one observation, not a rate; counts are of distinct (harness, build, scenario, arm) cells.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

DEFAULT = Path(__file__).resolve().parents[2] / "results" / "hook-fidelity" / "mitigation" / "eval-r4"


def load(out: Path) -> list[dict]:
    return [json.loads(line) for line in (out / "runs.jsonl").read_text().splitlines() if line.strip()]


def native_gate(row: dict) -> bool:
    """A block that came from the harness's own gate and not from the hook: Claude Code's auto-mode classifier text."""
    return any("Auto mode could not evaluate" in t for t in row.get("tool_result_text") or [])


def tally(rows: list[dict]) -> dict:
    cells: dict[tuple, dict] = defaultdict(dict)
    for r in rows:
        cells[(r["harness"], r["version"], r["scenario"], bool(r.get("norecord")))][r["arm"]] = r
    allow = {k: v for k, v in cells.items() if k[2] == "allow"}
    evaluable = {k: v for k, v in allow.items() if not any(native_gate(r) for r in v.values())}
    return {
        "allow_cells": len(allow),
        "allow_native_gate": sorted(f"{k[0]} {k[1]}" for k in allow if k not in evaluable),
        "allow_ran_off": sum(v["off"]["outcome"] == "RAN" for v in evaluable.values()),
        "allow_ran_on": sum(v["on"]["outcome"] == "RAN" for v in evaluable.values()),
        "allow_evaluable": len(evaluable),
        "deny_all": [(k[0], k[1], v["deny-all"]["outcome"], v["on"]["outcome"]) for k, v in sorted(allow.items())
                     if "deny-all" in v],
        "slow": [(k[0], k[1], v["on"]["outcome"], v["on"]["wall_s"]) for k, v in sorted(cells.items()) if k[2] == "slowdefault"],
        "norecord": [(k[0], k[1], v["on"]["outcome"]) for k, v in sorted(cells.items()) if k[3]],
    }


def render(rows: list[dict]) -> str:
    t = tally(rows)
    out = [f"# Round 4 mitigation cells ({len(rows)} launches, n=1 per cell, stub model, headless, shell call)", "",
           "## Allow control (the call must run)", "",
           "| harness | build | translation off | translation on | deny-all control |", "|---|---|---|---|---|"]
    by_cell: dict[tuple, dict] = defaultdict(dict)
    for r in rows:
        if r["scenario"] == "allow":
            by_cell[(r["harness"], r["version"])][r["arm"]] = r
    for (harness, version), arms in sorted(by_cell.items(), key=lambda kv: (kv[0][0], tuple(map(int, kv[0][1].split("."))))):
        gate = " (native gate)" if any(native_gate(r) for r in arms.values()) else ""
        out.append(f"| {harness} | {version} | {arms['off']['outcome']}{gate} | {arms['on']['outcome']}{gate} | "
                   f"{arms['deny-all']['outcome'] if 'deny-all' in arms else 'not run'} |")
    blocked = sum(x[2] == "BLOCKED" for x in t["deny_all"])
    ran_on = sum(x[3] == "RAN" for x in t["deny_all"])
    out += ["", f"Evaluable allow cells {t['allow_evaluable']} of {t['allow_cells']}; native-gate cells excluded: "
            f"{', '.join(t['allow_native_gate']) or 'none'}. Translation off ran the call in {t['allow_ran_off']} of "
            f"{t['allow_evaluable']}; translation on ran it in {t['allow_ran_on']} of {t['allow_evaluable']}. The deny-all "
            f"control was BLOCKED in {blocked} of {len(t['deny_all'])} cells, where the translation ran the call in {ran_on} "
            f"of {len(t['deny_all'])}.", "",
            "## Shipped deadline (30 s, no handler timeout override, a 45 s guard)", "",
            "| harness | build | outcome | wall s |", "|---|---|---|---|"]
    out += [f"| {h} | {v} | {o} | {w} |" for h, v, o, w in t["slow"]]
    out += ["", "## Headless ask with no version recorded (translation on)", "", "| harness | build | outcome |", "|---|---|---|"]
    out += [f"| {h} | {v} | {o} |" for h, v, o in t["norecord"]]
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    sys.stdout.write(render(load(Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT)))
