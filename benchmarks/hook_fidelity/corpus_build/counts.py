"""Every number in the corpus document's headline section, derived from the guard records and nothing else.

    python3 counts.py [corpus.json]      prints the derived summary as JSON; exits 1 if the stored summary differs

``derive`` is also what build.py stores as ``summary`` and what the tests compare the document's text against, so a count
cannot drift from the data.
"""
from __future__ import annotations

import json
import statistics
import sys
from collections import Counter
from pathlib import Path

STATUSES = ("CONTRADICTS-GUARD-CLAIM", "DOCUMENTED-BY-GUARD", "HOLDS-BY-ACCIDENT", "HOLDS", "UNKNOWN", "NOT-APPLICABLE")
# Cursor-capable guards whose own config leaves a blocking entry without failClosed AND has no in-process fallback that
# denies. dcg is not here (its Cursor bridge denies in-process on crash or timeout); knox and riphook are not here (their
# error path was not established); block-no-verify's snippet is its README example, endor's repo is an example repo.
CURSOR_NO_FAILCLOSED = ("ggshield", "ai-guardian", "balerx", "block-no-verify", "endor-cursor-hooks")


def _median(values: list[int]):
    """The median, not the upper-middle element (the round-3 critic found 17 where 26 values give 13); a whole number prints as one."""
    if not values:
        return None
    m = statistics.median(values)
    return int(m) if float(m).is_integer() else m


def derive(data: dict) -> dict:
    guards = data["guards"]
    rules = data["rules"]
    used = {gap["rule"] for g in guards for gap in g["gaps"]}
    security = [g for g in guards if g["category"] == "security"]
    ask = [g for g in guards if g["ask_on"]]
    gaps = [(g, gap) for g in guards for gap in g["gaps"]]
    by_status = Counter(gap["status"] for _, gap in gaps)
    counted = [(g, gap) for g, gap in gaps if gap["status"] != "NOT-APPLICABLE"]
    return {
        "guards_total": len(guards), "guards_security": len(security), "guards_adjacent": len(guards) - len(security),
        "per_harness_in_study": {h: sum(1 for g in guards if h in g["study"]) for h in ("claude", "codex", "cursor", "gemini")},
        "emit_ask_to_a_harness": len(ask), "emit_ask_ids": [g["id"] for g in ask],
        "emit_ask_by_mode": dict(Counter(g["ask_mode"].split(" (")[0] for g in ask)),
        "emit_ask_claude": [g["id"] for g in guards if "claude" in g["ask_on"]],
        "emit_ask_cursor": [g["id"] for g in guards if "cursor" in g["ask_on"]],
        "codex_supporting": sum(1 for g in guards if "codex" in g["study"]),
        "codex_supporting_ids": [g["id"] for g in guards if "codex" in g["study"]],
        "codex_guards_that_avoid_ask": ["dcg", "safety-net", "defenseclaw", "knox", "oh-my-harness"],
        "cursor_guards_without_failclosed_on_a_blocking_entry": list(CURSOR_NO_FAILCLOSED),
        "rules_defined": len(rules), "rules_used_by_a_row": len(used),
        "rows_total": len(gaps), "rows_counted": len(counted), "rows_by_status": {s: by_status.get(s, 0) for s in STATUSES},
        "rows_by_evidence": dict(Counter(gap.get("evidence", "PREDICTED") for _, gap in counted)),
        "guards_with_a_contradicting_row": sorted({g["id"] for g, gap in counted if gap["status"] == "CONTRADICTS-GUARD-CLAIM"}),
        "security_guards_with_a_contradicting_row": sorted({g["id"] for g, gap in counted
                                                            if gap["status"] == "CONTRADICTS-GUARD-CLAIM" and g["category"] == "security"}),
        "contradicting_rows_by_harness": dict(Counter(gap["harness"] for _, gap in counted
                                                      if gap["status"] == "CONTRADICTS-GUARD-CLAIM")),
        "rows_measured_at_runner_layer": sum(1 for _, gap in counted if gap.get("evidence") == "MEASURED-RUNNER-LAYER"),
    }


def derive_measured(summary: dict, captures: list[dict], github: dict) -> dict:
    """Numbers of the measured section: guard-by-harness cells from guard_replay.py's summary.json, the byte captures, and the
    GitHub metadata. Nothing here is typed by hand."""
    cells = summary["cells"]
    live = [c for c in cells if c["tested"] and not c["probe"]]
    captured = [r for r in captures if not r.get("status")]
    not_captured = [r["guard"] for r in captures if r.get("status") == "NOT-CAPTURED"]
    ran = [c for c in live if c["guarded_call_ran"]]
    pairs: dict[tuple, bool] = {}
    for c in live:
        pairs[(c["guard"], c["harness"])] = pairs.get((c["guard"], c["harness"]), False) or c["guarded_call_ran"]
    ask = [c for c in live if c["intent"] == "ASK"]
    by_state = {}   # per run, not per cell: an untrusted Codex hook is a hook that never ran, not a verdict that was ignored
    for label, pick in (("codex untrusted", lambda c: c["harness"] == "codex" and c["state"] == "untrusted"),
                        ("codex trusted", lambda c: c["harness"] == "codex" and c["state"] != "untrusted"),
                        ("claude", lambda c: c["harness"] == "claude")):
        chosen = [c for c in live if pick(c)]
        by_state[label] = {"cells": len(chosen), "runs": sum(c["n_valid"] for c in chosen), "ran": sum(c["ran"] for c in chosen),
                           "hook_invoked_runs": sum(c["hook_invoked"] for c in chosen)}
    probes = {c["matcher"]: {"hook_invoked": c["hook_invoked"], "runs": c["n_valid"], "ran": c["ran"]} for c in cells if c["probe"]}
    controls_failed = sorted(k for k, v in summary["controls"].items() if not v["ran_all"])
    stars = {k: v["stars"] for k, v in github.items() if not k.startswith("_") and "stars" in v}
    return {
        "captured_guards": sorted({r["guard"] for r in captured}), "capture_records": len(captured), "not_captured_guards": sorted(not_captured),
        "live_cells_tested": len(live), "live_cells_ran": len(ran), "live_runs": sum(c["n_runs"] for c in cells if not c["probe"]),
        "live_cell_runs": sum(c["n_runs"] for c in live),
        "live_cells_by_cause": dict(Counter(c["cause"] for c in ran)),
        "live_by_state": by_state,
        "live_cells_by_harness": dict(Counter(c["harness"] for c in live)),
        "pairs_tested": len(pairs), "pairs_with_a_cell_that_ran": sum(pairs.values()),
        "ask_cells": len(ask), "ask_runs": sum(c["n_valid"] for c in ask), "ask_runs_where_call_ran": sum(c["ran"] for c in ask),
        "ask_builds_claude": sorted({c["build"] for c in ask if c["harness"] == "claude"}), "ask_modes": sorted({c["mode"] for c in ask}),
        "matcher_probe": probes, "control_groups": len(summary["controls"]), "control_groups_not_all_ran": controls_failed,
        "gemini_runner": summary.get("gemini_runner"),
        "stars_min": min(stars.values()) if stars else None, "stars_max": max(stars.values()) if stars else None,
        "stars_median": _median(list(stars.values())), "guards_with_under_20_stars": sum(1 for v in stars.values() if v < 20),
    }


def main(argv: list[str]) -> int:
    path = Path(argv[0]) if argv else Path(__file__).resolve().parents[3] / "results" / "hook-fidelity" / "corpus.json"
    data = json.loads(path.read_text())
    derived = derive(data)
    print(json.dumps(derived, indent=1))
    return 0 if derived == data.get("summary") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
