"""compare.py: the wrapped, ALLOW and DENY-ALL arms (plan, configuration, summary). No harness is launched."""
from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

import pytest

HF = Path(__file__).resolve().parents[1] / "benchmarks" / "hook_fidelity"
sys.path.insert(0, str(HF))

import compare  # noqa: E402

RESULTS = HF.parents[1] / "results" / "hook-fidelity" / "compare"


def test_r7_plan_is_disjoint_from_r6_and_within_the_cap():
    r6 = {compare.case_id(c) for c in compare.plan()}
    r7 = compare.plan_r7()
    ids = [compare.case_id(c) for c in r7]
    assert len(set(ids)) == len(ids) and not set(ids) & r6
    assert len(r7) == 169
    assert {c["cell"] for c in r7} == {"ask", "deny", "slow", "dead", "crash", "slowB", "exit2empty", "allow"}


def test_arm_kinds():
    k = compare.arm_kind
    arms = ("IS-ON", "IS-OFF", "ALLOW", "DENY-ALL", "ALLOW+wrap-json", "stub-ask", "stub-ask+wrap", "safety-net",
            "railway-guard@codex", "safety-net+wrap", "railway-guard@codex+wrap", "axonflow-codex+wrap-nohint",
            "safety-net+launcher")
    assert [k(a) for a in arms] == ["is", "is", "control", "control", "control", "control", "control", "third", "third",
                                    "wrapped", "wrapped", "wrapped", "launcher"]
    assert compare.base_arm("railway-guard@codex+wrap") == "railway-guard@codex"


def test_every_wrapped_and_allow_arm_has_its_bytes(tmp_path):
    for case in compare.plan_r7():
        if compare.is_hook_arm(case["arm"]):
            continue
        guard = compare.arm_guard(case["build"], case["arm"])
        h = compare.BUILDS[case["build"]].harness
        if case["arm"].startswith("ALLOW+"):
            path = compare.allow_replay(case["arm"], h)
        elif case["arm"].startswith("stub-ask"):
            path = compare.stub_ask_path(tmp_path)
        else:
            path = compare.replay_for(guard, case["cell"] if case["cell"] not in ("slowB", "dead") else "deny", tmp_path)
        assert isinstance(json.loads(path.read_text())["exit_code"], int)


def test_allow_replays_are_captured_allows_with_the_stated_shape():
    index = {e["id"]: e for e in compare._index()}
    for (kind, harness), rid in compare.ALLOW_REPLAYS.items():
        assert index[rid]["intent"] == "ALLOW"
        record = json.loads((compare.GUARDS_DIR / "replay" / f"{rid}.json").read_text())
        import base64
        out = base64.b64decode(record["stdout_b64"]).decode().strip()
        assert record["exit_code"] == 0 and (out == "" if kind == "silent" else out == "{}"), (kind, harness)


def test_wrapped_entry_carries_the_shim_the_guards_matcher_and_no_onfailure():
    case = {"build": "claude-2.1.316", "arm": "cc-safe-setup+wrap", "cell": "slow", "regime": "A", "rep": 0}
    entries = compare.hook_entries_for(case, Path("/x/hookbin/hook"))
    group = entries["PreToolUse"][0]
    handler = group["hooks"][0]
    assert group["matcher"] == "Bash" and handler["timeout"] == 3 and "onFailure" not in handler
    wanted = "/x/hookbin/wrap --harness claude --version 2.1.316 --hook-timeout 3 -- /x/hookbin/hook"
    assert wanted in handler["command"]
    assert handler["command"].endswith(compare.translation.LAUNCHER)
    ask = {**case, "build": "gemini-0.66.0-yolo", "arm": "stub-ask+wrap", "cell": "ask"}
    cmd = compare.hook_entries_for(ask, Path("/x/hookbin/hook"))["BeforeTool"][0]["hooks"][0]
    assert "--gemini-ask" in cmd["command"] and cmd["timeout"] == 3000 and cmd["name"] == "guard"


def test_regime_b_hint_follows_the_shipped_timeout():
    base = {"build": "codex-0.166.0", "cell": "slowB", "regime": "B", "rep": 0}
    program = Path("/x/hookbin/hook")
    hint = compare.hook_entries_for({**base, "arm": "axonflow-codex+wrap"}, program)["PreToolUse"][0]["hooks"][0]
    plain = compare.hook_entries_for({**base, "arm": "axonflow-codex+wrap-nohint"}, program)["PreToolUse"][0]["hooks"][0]
    assert "--hook-timeout 15" in hint["command"] and "--hook-timeout" not in plain["command"]
    assert hint["timeout"] == plain["timeout"] == 15


def test_allow_arms_flags_and_controls():
    flags = lambda arm, build="claude-2.1.316": compare.shim_flags(
        {"build": build, "arm": arm, "cell": "allow", "regime": "A", "rep": 0}, compare.arm_guard(build, arm))
    assert flags("ALLOW+wrap")["on_empty"] == "allow"
    assert "on_empty" not in flags("ALLOW+wrap-strict") and "on_empty" not in flags("ALLOW+wrap-json")
    cfg = compare.cell_config({"build": "claude-2.1.316", "arm": "DENY-ALL", "cell": "allow", "regime": "A", "rep": 0},
                              Path("/tmp"), Path("/tmp"), "nz")
    assert cfg["translate"] == "deny-all" and cfg["kind"] == "is"
    cfg = compare.cell_config({"build": "claude-2.1.316", "arm": "ALLOW", "cell": "allow", "regime": "A", "rep": 0},
                              Path("/tmp"), Path("/tmp"), "nz")
    assert cfg["verdict"] == "allow" and cfg["translate"] == "on"


def _arm(survived, label="x", source="run"):
    return {"label": label, "survived": survived, "n": 1, "source": source}


def test_round7_counts_fixed_regressed_and_deny_all():
    matrix = {
        ("b1", "dead"): {"IS-ON": _arm(True), "IS-OFF": _arm(False), "DENY-ALL": _arm(True), "g1": _arm(False),
                         "g1+wrap": _arm(True), "g2": _arm(False, source="inherited"), "g2+wrap": _arm(True, source="inherited")},
        ("b1", "slowB"): {"IS-ON": _arm(True), "g1": _arm(False), "g1+wrap": _arm(False), "g3": _arm(True),
                          "g3+wrap": _arm(False)},
        ("b1", "slow"): {"g1": _arm(False), "g1+wrap": _arm(True)},
        ("b1", "allow"): {"ALLOW": _arm(False, "RAN 2/2"), "DENY-ALL": _arm(True, "BLOCKED 1/1")},
    }
    r7 = compare.round7(matrix)
    assert r7["guard_entries_failed_unwrapped"] == {"k": 2, "n": 3}
    assert r7["guard_entries_failed_unwrapped_launched"] == {"k": 1, "n": 2}
    assert [e["guard"] for e in r7["regressed"]] == ["g3"]
    assert [e["guard"] for e in r7["not_fixed"]] == ["g1"]
    assert r7["slow_regime_A_excluded"] == {"k": 1, "n": 1}
    assert r7["pairs"]["n"] == 2 and r7["pairs"]["wrapped_all_survived"] == 1
    assert r7["pairs"]["deny_all"] == 1 and r7["pairs"]["deny_all_n"] == 1
    assert r7["allow"]["ALLOW"]["builds_ran_all_reps"] == 1 and r7["allow"]["DENY-ALL"]["builds_ran_all_reps"] == 0


def test_wrapped_arms_do_not_change_the_round6_headline():
    matrix = {("b1", "slow"): {"IS-ON": _arm(True), "IS-OFF": _arm(False), "g1": _arm(False), "g1+wrap": _arm(True),
                               "g1+launcher": _arm(False), "ALLOW": _arm(True), "stub-ask": _arm(False)}}
    head = compare.headline(matrix)
    assert list(head["guards"]) == ["g1"] and head["guards"]["g1"] == {"k": 0, "n": 1, "run_n": 1}


def test_wrapped_representative_is_inherited_per_variant():
    rows = [{"build": "claude-2.1.316", "cell": "dead", "arm": a, "outcome": o}
            for a, o in (("cc-safe-setup", "RAN"), ("cc-safe-setup+wrap", "BLOCKED"))]
    arms = compare.cell_matrix(rows)[("claude-2.1.316", "dead")]
    assert arms["safety-net"]["survived"] is False and arms["safety-net+wrap"]["survived"] is True
    assert arms["safety-net+wrap"]["source"] == "inherited"


def test_shim_script_is_written_only_for_wrapped_arms(tmp_path):
    if not Path(compare.me.VENV_PYTHON).exists():
        pytest.skip("no project venv")
    case = {"build": "claude-2.1.316", "arm": "cc-safe-setup+wrap", "cell": "deny", "regime": "A", "rep": 0}
    program = compare.write_program(tmp_path, case, compare.cell_config(case, tmp_path, tmp_path, "nz"))
    assert (program.parent / "wrap").exists() and shlex.quote(str(program.parent / "wrap"))
    other = tmp_path / "o"
    other.mkdir()
    case = {**case, "arm": "cc-safe-setup"}
    program = compare.write_program(other, case, compare.cell_config(case, other, other, "nz"))
    assert not (program.parent / "wrap").exists()


def test_launcher_only_arm_has_the_launcher_and_no_shim():
    case = {"build": "codex-0.166.0", "arm": "axonflow-codex+launcher", "cell": "exit2empty", "regime": "A", "rep": 0}
    handler = compare.hook_entries_for(case, Path("/x/hookbin/hook"))["PreToolUse"][0]["hooks"][0]
    assert handler["command"] == "/x/hookbin/hook " + compare.translation.LAUNCHER and "wrap" not in handler["command"]
    assert not compare.uses_shim(case["arm"])


def test_committed_round7_rows_regenerate_the_numbers():
    rows_path = RESULTS / "runs.jsonl"
    if not rows_path.exists():
        pytest.skip("no committed rows")
    rows = [json.loads(line) for line in rows_path.read_text().splitlines() if line.strip()]
    r7 = [r for r in rows if r.get("lane") == "r7-wrap"]
    if not r7:
        pytest.skip("no round 7 rows")
    summary = json.loads((RESULTS / "summary.json").read_text())
    assert summary["round7"] == json.loads(json.dumps(compare.round7(compare.cell_matrix(rows)), default=str))
    assert len(r7) == 169 and not any(r["outcome"] == "INVALID" for r in r7)
    assert all(r["shim_invoked"] for r in r7 if "+wrap" in r["arm"])
    assert {compare.case_id(r) for r in r7} == {compare.case_id(c) for c in compare.plan_r7()}
