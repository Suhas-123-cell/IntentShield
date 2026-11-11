"""Offline tests of the head-to-head runner (benchmarks/hook_fidelity/compare.py) and of the committed rows under
results/hook-fidelity/compare. No harness is launched."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
from hook_fidelity import compare  # noqa: E402

RESULTS = ROOT / "results" / "hook-fidelity" / "compare"


def test_plan_cells_and_unique_ids():
    cases = compare.plan()
    ids = [compare.case_id(c) for c in cases]
    assert len(set(ids)) == len(ids)
    by_cell: dict[str, int] = {}
    for c in cases:
        by_cell[c["cell"]] = by_cell.get(c["cell"], 0) + 1
    assert by_cell == {"ask": 30, "deny": 31, "slow": 36, "dead": 36, "crash": 36, "exit2empty": 8, "slowB": 12, "real": 6}
    assert {c["build"] for c in cases} == set(compare.BUILDS)


def test_every_guard_arm_has_the_bytes_it_needs(tmp_path):
    for case in compare.plan():
        if compare.is_arm(case["arm"]):
            continue
        guard = compare.arm_guard(case["build"], case["arm"])
        path = compare.replay_for(guard, case["cell"] if case["cell"] not in ("slowB", "dead") else "deny", tmp_path)
        record = json.loads(path.read_text())
        assert isinstance(record["exit_code"], int)
        if case["cell"] == "exit2empty":
            assert record["exit_code"] == 2 and record["stderr_b64"] == ""


def test_outcome_and_survival():
    def row(outcome):
        return {"outcome": outcome}

    assert compare.cell_outcome([row("BLOCKED"), row("BLOCKED")]) == ("BLOCKED 2/2", True)
    assert compare.cell_outcome([row("BLOCKED"), row("RAN")])[1] is False
    assert compare.cell_outcome([row("HUNG")])[1] is False
    assert compare.cell_outcome([row("INVALID")]) == ("INVALID", False)
    assert compare.cell_outcome([row("INVALID"), row("BLOCKED")]) == ("BLOCKED 1/1", True)


def test_prompt_refusal_is_reported_apart_from_a_blocked_call():
    rows = [{"outcome": "BLOCKED", "prompt_blocked": True, "invalid_reason": "prompt hook refused"}] * 2
    assert compare.row_outcome(rows[0]) == "BLOCKED_AT_PROMPT"
    assert compare.cell_outcome(rows) == ("BLOCKED_AT_PROMPT 2/2", True)
    mixed = [{"outcome": "BLOCKED", "prompt_blocked": True}, {"outcome": "BLOCKED", "prompt_blocked": False}]
    assert compare.cell_outcome(mixed) == ("BLOCKED 1/2 + BLOCKED_AT_PROMPT 1/2", True)
    assert compare.cell_outcome([{"outcome": "RAN", "prompt_blocked": False}])[1] is False


def test_classify():
    base = {
        "attested": False,
        "marker": False,
        "issued": True,
        "capped": False,
        "requests": 2,
        "call_events": [1],
        "prompt_blocked": False,
    }
    assert compare.classify(base) == ("BLOCKED", "")
    assert compare.classify({**base, "attested": True, "marker": True})[0] == "RAN"
    assert compare.classify({**base, "capped": True})[0] == "HUNG"
    assert compare.classify({**base, "marker": True})[0] == "INVALID"
    assert compare.classify({**base, "issued": False})[0] == "INVALID"
    assert compare.classify({**base, "issued": False, "prompt_blocked": True})[0] == "BLOCKED"


def _arm(survived, source="run"):
    return {"label": "x", "survived": survived, "n": 2, "source": source}


def test_headline_counts_pairs_where_a_third_party_failed():
    matrix = {
        ("b1", "slow"): {"IS-ON": _arm(True), "IS-OFF": _arm(False), "g1": _arm(False), "g2": _arm(False, "inherited")},
        ("b1", "deny"): {"IS-ON": _arm(True), "IS-OFF": _arm(True), "g1": _arm(True)},   # nobody failed: not a pair
        ("b2", "crash"): {"IS-ON": _arm(False), "IS-OFF": _arm(False), "g1": _arm(False)},
        ("b2", "exit2empty"): {"g1": _arm(False)},   # no IS-ON result: not a pair
        ("b2", "real"): {"IS-ON": _arm(True)},
    }
    head = compare.headline(matrix)
    assert [(p["build"], p["cell"]) for p in head["pairs"]] == [("b1", "slow"), ("b2", "crash")]
    assert head["is_on"] == {"k": 1, "n": 2} and head["is_off"] == {"k": 0, "n": 2} and head["is_on_only"] == {"k": 1, "n": 2}
    assert head["guards"]["g1"] == {"k": 0, "n": 2, "run_n": 2}
    assert head["guards"]["g2"]["run_n"] == 0
    assert head["guards_all_pairs"]["g1"] == {"k": 1, "n": 4}


def test_cross_harness_replays_never_make_a_pair():
    matrix = {
        ("b1", "ask"): {"IS-ON": _arm(True), "IS-OFF": _arm(True), "g1@codex": _arm(False)},
        ("b2", "ask"): {"IS-ON": _arm(True), "IS-OFF": _arm(False), "g1": _arm(False)},
    }
    head = compare.headline(matrix)
    assert [(p["build"], p["cell"]) for p in head["pairs"]] == [("b2", "ask")]
    assert head["cross_replays"] == [{"build": "b1", "cell": "ask", "arm": "g1@codex", "label": "x"}]
    assert head["by_mechanism"]["ask (translation)"] == {"n": 1, "is_on": 1, "is_off": 0, "is_on_only": 1}
    assert "g1@codex" not in head["guards"] and "g1@codex" not in head["guards_all_pairs"]


def test_failure_class_inheritance():
    rows = [{"build": "claude-2.1.316", "cell": "slow", "arm": a, "outcome": o}
            for a, o in (("IS-ON", "BLOCKED"), ("cc-safe-setup", "RAN"))]
    matrix = compare.cell_matrix(rows)
    arms = matrix[("claude-2.1.316", "slow")]
    assert arms["safety-net"]["source"] == "inherited" and arms["safety-net"]["survived"] is False
    assert arms["cc-safe-setup"]["source"] == "run"


def test_wrapper_replays_exit_code_and_logs_first(tmp_path):
    if not Path(compare.me.VENV_PYTHON).exists():
        pytest.skip("no project venv")
    guard = compare.guard_of("claude", "cc-safe-setup")
    case = {"build": "claude-2.1.316", "arm": "cc-safe-setup", "cell": "exit2empty", "regime": "A", "rep": 0}
    cfg = compare.cell_config(case, tmp_path, tmp_path, "nzt")
    program = compare.write_program(tmp_path, case, cfg)
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "x"}}
    done = subprocess.run([str(program)], input=json.dumps(event), capture_output=True, text=True)
    assert done.returncode == 2 and done.stderr == "" and guard.shape == "claude"
    assert "PreToolUse" in (tmp_path / "hooks.jsonl").read_text()
    crash = {**case, "cell": "crash"}
    program = compare.write_program(tmp_path, crash, compare.cell_config(crash, tmp_path, tmp_path, "nzt"))
    done = subprocess.run([str(program)], input=json.dumps(event), capture_output=True, text=True)
    assert done.returncode == 1 and "simulated hook crash" in done.stderr


def test_committed_rows_regenerate_the_summary():
    rows_path = RESULTS / "runs.jsonl"
    if not rows_path.exists():
        pytest.skip("no committed rows")
    all_rows = [json.loads(line) for line in rows_path.read_text().splitlines() if line.strip()]
    summary = json.loads((RESULTS / "summary.json").read_text())
    assert summary["runs"] == len(all_rows)
    rows = [r for r in all_rows if r.get("lane", "r6") == "r6"]   # lane r7-wrap rows: test_hook_fidelity_compare_arms
    assert len(rows) == 195
    head = compare.headline(compare.cell_matrix(all_rows))
    assert head["is_on"] == summary["headline"]["is_on"] and head["guards"] == summary["headline"]["guards"]
    assert all(r["outcome"] in ("RAN", "BLOCKED", "HUNG", "INVALID") for r in all_rows)
    assert summary["headline"]["is_on"] == {"k": 18, "n": 18} and summary["headline"]["is_off"] == {"k": 5, "n": 18}
    assert sum(compare.row_outcome(r) == "BLOCKED_AT_PROMPT" for r in rows) == 12
    assert not any(r["outcome"] == "INVALID" for r in rows)
