"""The denies-alone comparison with the source write-up as the unit (benchmarks/hook_fidelity/cluster_compare.py)."""
# ruff: noqa: E501
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmarks" / "hook_fidelity"))

import cluster_compare as cc  # noqa: E402
import fresh_report as fr  # noqa: E402

FRESH = ROOT / "results/hook-fidelity/detect/fresh"
COMMITTED = json.loads((FRESH / "cluster" / "cluster.json").read_text(encoding="utf-8"))


def _flat(name: str) -> str:
    return re.sub(r"\s+", " ", (ROOT / name).read_text(encoding="utf-8"))


def test_one_row_per_write_up_counts_ties_and_each_side():
    table = {"a": (3, 2, 0), "b": (1, 0, 1), "c": (2, 1, 1), "d": (1, 0, 0), "e": (4, 0, 3)}
    rows = cc.sign_rows(table)
    assert rows == {"clusters": 5, "ties": 2, "only_intentshield": 1, "only_other": 2, "sign_p": fr.sign_test_p(1, 2)}


def test_the_bootstrap_is_repeatable_and_its_point_estimate_is_the_paired_gap():
    table = {"a": (3, 0, 3), "b": (1, 0, 1), "c": (2, 1, 0), "d": (4, 0, 2)}
    first, again = cc.bootstrap(table, draws=500), cc.bootstrap(table, draws=500)
    assert first == again
    assert first["gap_points"] == 100 * (6 - 1) / 10
    assert first["gap_lo"] <= first["gap_hi"]


def test_the_committed_study_rules_output_is_what_the_committed_decisions_give():
    rows = fr.load_fixtures()
    decisions = [json.loads(line) for line in (FRESH / "decisions.jsonl").read_text(encoding="utf-8").splitlines()]
    assert cc.compare(rows, decisions) == COMMITTED["study_rules"]


def test_the_item_level_counts_are_the_ones_fresh_report_prints():
    summary = json.loads((FRESH / "summary.json").read_text(encoding="utf-8"))["same_items"]
    for guard in fr.COMPARE_ON_SCOPE:
        item, paired = COMMITTED["study_rules"][guard]["item_level"], summary[guard]["paired_deny_only"]
        assert (item["only_intentshield"], item["only_other"]) == (paired["only_intentshield"], paired["only_other"])
        assert item["sign_p"] == paired["sign_p"]
        assert COMMITTED["study_rules"][guard]["items"] == summary[guard]["harmful_n"]


def test_the_committed_current_rules_output_is_what_this_checkout_gives():
    """Fails when the dangerous-command rules changed after cluster/ was generated; regenerate it with `cluster_compare.py --out
    results/hook-fidelity/detect/fresh/cluster --current-rules` and update the sentence in section 5 of the report."""
    rows = fr.load_fixtures()
    decisions = [json.loads(line) for line in (FRESH / "decisions.jsonl").read_text(encoding="utf-8").splitlines()]
    now = fr.decide_intentshield(rows, "intentshield")
    for decision in now:
        decision["guard"] = fr.IS
    live = cc.compare(rows, [d for d in decisions if d["guard"] != fr.IS] + now)
    assert live == COMMITTED["current_rules"]


def test_the_report_quotes_the_clustered_figures_beside_the_item_level_p_values():
    report = _flat("docs/hook-fidelity-report.md")
    study, current = COMMITTED["study_rules"]["safety-net"], COMMITTED["current_rules"]["safety-net"]
    for e in (study, current):
        s, b = e["by_source"]["rows"], e["by_source"]["bootstrap"]
        assert f"{s['only_other']} to {s['only_intentshield']}" in report and f"p = {s['sign_p']:.3f}" in report
        assert f"{b['gap_points']:+.1f}".lstrip("+") in report
    assert f"The {study['items']} items come from {study['by_source']['rows']['clusters']} write-ups" in report


def test_the_as_shipped_table_in_the_report_is_the_committed_effective_protection_extrapolation():
    effective = json.loads((FRESH / "summary.json").read_text(encoding="utf-8"))["effective"]
    shipped, raw = effective[f"{fr.IS}+translation"], effective[fr.IS]
    net = effective["safety-net"]
    report = _flat("docs/hook-fidelity-report.md")
    assert "(extrapolated, not measured)" in report and "depends on what the harness does with an ask" in report
    for build, harness_label in (("claude-2.1.316", "Claude Code 2.1.316"), ("gemini-0.66.0-yolo", "Gemini CLI 0.66.0")):
        ours, theirs = shipped[build], net[build]
        line = next(x for x in (ROOT / "docs/hook-fidelity-report.md").read_text(encoding="utf-8").splitlines() if x.startswith(f"| {harness_label} |"))
        lo, hi = fr.wilson(ours["stopped"]["k"], ours["stopped"]["n"])
        nlo, nhi = fr.wilson(theirs["stopped"]["k"], theirs["stopped"]["n"])
        assert f"{ours['stopped']['k']}/{ours['stopped']['n']} [{100 * lo:.1f}, {100 * hi:.1f}]%" in line
        assert f"{theirs['stopped']['k']}/{theirs['stopped']['n']} [{100 * nlo:.1f}, {100 * nhi:.1f}]%" in line
        b_is, b_net = ours["benign_blocked"], theirs["benign_blocked"]
        assert f"{b_is['k']}/{b_is['n']} / {b_net['k']}/{b_net['n']}" in line
    for build in ("claude-2.1.84", "codex-0.166.0", "gemini-0.37.1-yolo"):
        assert f"{raw[build]['stopped']['k']}/{raw[build]['stopped']['n']}" in report
        assert f"{net[build]['stopped']['k']}/{net[build]['stopped']['n']}" in report
