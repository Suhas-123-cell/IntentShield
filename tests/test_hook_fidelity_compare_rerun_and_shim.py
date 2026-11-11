"""compare.py: the re-run plan, the ``--on-empty allow`` failure cells and the detected-mode log of the shim script.
No harness is launched; the shim script runs against a stub guard."""
from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

HF = Path(__file__).resolve().parents[1] / "benchmarks" / "hook_fidelity"
sys.path.insert(0, str(HF.parent))
sys.path.insert(0, str(HF))

import compare  # noqa: E402

RESULTS = HF.parents[1] / "results" / "hook-fidelity" / "compare"


def test_r8_plan_ids_are_disjoint_from_earlier_rounds_and_within_the_caps():
    earlier = {compare.case_id(c) for c in compare.plan_all()}
    part1, part2 = compare.plan_r8("1"), compare.plan_r8("2")
    ids = [compare.case_id(c) for c in part1 + part2]
    assert len(set(ids)) == len(ids) and not set(ids) & earlier
    assert (len(part1), len(part2)) == (36, 15) and len(compare.plan_r8()) == 51
    assert all(c["round"] == "r8" for c in part1 + part2)
    assert {c["cell"] for c in part2} == set(compare.R8_EMPTY_ALLOW_CELLS)
    assert {c["build"] for c in part2} == set(compare.R8_EMPTY_ALLOW_BUILDS)
    assert {c["arm"] for c in part2} == {"ALLOW+wrap"} and {c["rep"] for c in part2} == {0}


def test_r8_case_id_of_a_case_without_a_round_is_unchanged():
    case = {"build": "claude-2.1.316", "arm": "IS-ON", "cell": "ask", "regime": "A", "rep": 1}
    assert compare.case_id(case) == "f776d41aca"   # the first row of the committed round 6 runs
    assert compare.case_id({**case, "round": "r8"}) != compare.case_id(case)


def test_r8_pair_arms_are_the_launched_wrapped_guards_of_the_twelve_round7_pairs():
    summary = json.loads((RESULTS / "summary.json").read_text())
    pairs = {(r["build"], r["cell"]): set(r["failed_unwrapped"]) for r in summary["round7"]["rows"]
             if r["cell"] in summary["round7"]["cells"] and r["failed_unwrapped"]}
    assert len(pairs) == 12
    launched = {(b, c) for b, a, c, _, _ in compare.R8_PAIR_ARMS}
    assert launched == set(pairs)
    r7 = {(c["build"], c["arm"], c["cell"], c["regime"]): sum(1 for x in compare.plan_r7() if
          (x["build"], x["arm"], x["cell"]) == (c["build"], c["arm"], c["cell"])) for c in compare.plan_r7()}
    for build, arm, cell, regime, reps in compare.R8_PAIR_ARMS:
        assert r7[(build, arm, cell, regime)] == reps                      # the same arm and reps as round 7
        assert compare.base_arm(arm) in pairs[(build, cell)]               # a guard that failed unwrapped
    for build, arm, reps in compare.R8_ASK_ARMS:
        assert r7[(build, arm, "ask", "A")] == reps


def test_r8_failure_cells_replay_the_silent_allow_and_one_malformed_reply(tmp_path):
    for cell in compare.R8_EMPTY_ALLOW_CELLS:
        for build in compare.R8_EMPTY_ALLOW_BUILDS:
            case = {"build": build, "arm": "ALLOW+wrap", "cell": cell, "regime": "A", "rep": 0, "round": "r8"}
            cfg = compare.cell_config(case, tmp_path, tmp_path, "nzt")
            record = json.loads(Path(cfg["replay"]).read_text())
            body = base64.b64decode(record["stdout_b64"]).decode()
            if cell == "malformed":
                assert record["exit_code"] == 0 and body and not body.endswith("}")
                with pytest.raises(ValueError):
                    json.loads(body)
            else:
                assert record["exit_code"] == 0 and body == ""             # the captured silent allow
            assert cfg["crash"] == (cell == "crash")
            assert cfg["latency"] == (compare.STALL_A_S if cell == "slow" else 0)
    flags = compare.shim_flags({"build": "codex-0.166.0", "arm": "ALLOW+wrap", "cell": "dead", "regime": "A"},
                               compare.arm_guard("codex-0.166.0", "ALLOW+wrap"))
    assert flags["on_empty"] == "allow" and flags["hook_timeout"] == 3.0


def test_shim_script_logs_what_the_detector_read_and_what_the_shim_sent(tmp_path):
    case = {"build": "claude-2.1.316", "arm": "ALLOW+wrap", "cell": "emptyexit0", "regime": "A", "rep": 0, "round": "r8"}
    program = compare.write_program(tmp_path, case, compare.cell_config(case, tmp_path, tmp_path, "nzt"))
    shim = program.parent / "wrap"
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "true"}}
    done = subprocess.run([str(shim), "--harness", "claude", "--version", "2.1.316", "--on-empty", "allow", "--", "true"],
                          input=json.dumps(event), capture_output=True, text=True, timeout=60)
    assert done.returncode == 0 and done.stdout == ""                      # a silent guard under --on-empty allow: nothing sent
    rows = [json.loads(line) for line in (tmp_path / "shim.jsonl").read_text().splitlines()]
    detected = rows[0]["detected"]
    assert detected["mode"] in ("interactive", "headless", "yolo", "unknown") and detected["how"]
    assert detected["source"] in ("proc", "libproc", "ps", "none") and isinstance(detected["depth"], int)
    assert rows[1]["shim_sent"] == "allow" and rows[1]["guard_exit"] == 0 and rows[1]["shim_mode"] is None
    denied = subprocess.run([str(shim), "--harness", "claude", "--version", "2.1.316", "--on-empty", "deny", "--", "true"],
                            input=json.dumps(event), capture_output=True, text=True, timeout=60)
    assert json.loads(denied.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_ledger_and_lane_names_of_round8():
    case = {"build": "claude-2.1.316", "arm": "ALLOW+wrap", "cell": "dead", "regime": "A", "rep": 0}
    assert compare.ledger_name(case) == "launches.jsonl"
    assert compare.ledger_name({**case, "round": "r8"}) == "launches-r8.jsonl"
    assert compare.LANE_R8 == "r8-close" and compare.ROUND8 == "r8"


def test_committed_round8_rows_regenerate_the_numbers():
    import r8_summary

    rows_path = RESULTS / "runs-r8.jsonl"
    if not rows_path.exists():
        pytest.skip("no committed round 8 rows")
    rows = [json.loads(line) for line in rows_path.read_text().splitlines() if line.strip()]
    committed = json.loads((RESULTS / "summary-r8.json").read_text())
    fresh = json.loads(json.dumps(r8_summary.summarize(RESULTS), default=str))
    assert fresh == committed
    assert len(rows) == 51 and not any(r["outcome"] == "INVALID" for r in rows)
    assert all(r["round"] == "r8" and r["lane"] == "r8-close" and not r["code_commit"].endswith("+dirty") for r in rows)
    ids = {r["run_id"] for r in rows}
    assert len(ids) == len(rows) and ids == {compare.case_id(c) for c in compare.plan_r8()}
    shim = [r for r in rows if r["shim_invoked"]]
    assert len(shim) == 51
    assert all(r["detected_mode"] and r["detected_how"] and r["detected_source"] == "libproc" for r in shim)
    p1 = committed["part1"]
    assert (p1["pairs"]["n"], p1["pairs"]["r8_survived"], p1["pairs"]["r7_survived"]) == (12, 12, 12)
    assert p1["groups_same"] == p1["groups_n"] == 20
    assert p1["ask"] == {"r8_blocked": 12, "r8_n": 12, "r7_blocked": 12, "r7_n": 12}
    p2 = committed["part2"]
    assert p2["ran"] == 3 and p2["by_cell"]["emptyexit0"] == {"ran": 3, "n": 3}
    assert all(v["ran"] == 0 for c, v in p2["by_cell"].items() if c != "emptyexit0")


def test_allow_fraction_is_the_shims_own_classification_of_the_captured_benign_bytes():
    import r8_summary

    fraction = r8_summary.allow_fraction()
    a = fraction["all_shapes"]
    assert (a["n"], a["silent"], a["explicit_allow"], a["guard_denied_or_failed"]) == (21, 12, 5, 4)
    assert (a["allows"], a["allows_blocked_by_default"], a["allows_blocked_by_on_empty_allow"]) == (17, 12, 0)
    pairs = fraction["by_pair_claude_codex_gemini"]
    assert (pairs["allow_pairs"], pairs["silent_allow_pairs"], pairs["silent_allow_pairs_excluding_fail_open"]) == (9, 6, 5)
    for item in fraction["items"]:
        assert (item["deny_default"] == "allow") == (item["kind"] == "explicit-allow")
        assert (item["on_empty_allow"] == "allow") == (item["kind"] in ("silent", "explicit-allow"))
