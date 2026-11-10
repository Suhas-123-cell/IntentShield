"""Offline tests of the r3-claude lane: the Claude Code modes, the lane cells and their budget, the per-mode command lines,
the stub-arm helpers of run.py and the sign-off file. No test launches a harness."""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

import pytest

BENCH = Path(__file__).resolve().parents[1] / "benchmarks"
sys.path.insert(0, str(BENCH))
from hook_fidelity import cells, claude_lane, configs, run  # noqa: E402


def _cell(mode="M1h", kind="shell", reply="R1", state="-", failcfg="-", version="2.1.316"):
    return cells.Cell("claude", version, mode, kind, reply, state, failcfg, "plain", "S")


def _spec(tmp_path, cell, stub_url="http://127.0.0.1:18080"):
    paths = configs.make_paths(tmp_path / "run")
    return paths, configs.build(cell, paths, "00001-abcd", ["bin"], stub_url=stub_url)


# ---------------------------------------------------------------- modes and cells
def test_lane_modes_are_known_but_not_in_the_generated_matrix():
    assert set(cells.LANE_MODES) == {"M1h", "M0h"} <= set(cells.MODES["claude"])
    assert not any(c.mode in cells.LANE_MODES for c in cells.generate())
    assert cells.MODES["claude"]["M1"].prompts_refused and not cells.MODES["claude"]["M1h"].prompts_refused


def test_a_native_gate_is_declared_only_for_the_unapproved_mode():
    assert cells.native_gate_declared(("claude", "2.1.316", "M0h", "shell", "-", "-", "plain", "S"))
    assert not cells.native_gate_declared(("claude", "2.1.316", "M0h", "resource", "-", "-", "plain", "S"))
    assert not cells.native_gate_declared(("claude", "2.1.316", "M1h", "shell", "-", "-", "plain", "S"))


def test_lane_stages_fit_the_launch_budget_and_have_unique_cells():
    sizes = {}
    for name in claude_lane.STAGES:
        stage = claude_lane.stage(name)
        assert len({c.key for c in stage}) == len(stage) - (1 if name == "pilot" else 0)   # the pilot repeats R1 shell
        assert {c.arm for c in stage} == {"S"} and {c.harness for c in stage} == {"claude"}
        sizes[name] = sum(c.reps for c in stage)
    assert sizes["pilot"] == 10
    assert sum(sizes.values()) + 10 <= 600          # the smoke runs are on top, the lane's cap is 600 launches
    sweep_versions = {c.version for c in claude_lane.sweep()}
    assert sweep_versions == set(claude_lane.RELEASES) - {claude_lane.CURRENT} and len(sweep_versions) == 22
    assert {c.reply for c in claude_lane.sweep()} == set(claude_lane.SWEEP_REPLIES)


def test_core_covers_the_headline_cells():
    core = {(c.mode, c.kind, c.reply, c.state) for c in claude_lane.core()}
    for mode in ("M1h", "M2"):
        for kind in ("shell", "write", "mcp", "resource"):
            assert (mode, kind, "R3" if not (kind == "resource" and mode == "M1") else "R4", "-") in core
    assert ("M1h", "resource", "R4", "mcpwild") in core and ("M1h", "mcp", "R4", "mcpwild") in core
    assert ("M0h", "shell", "R2", "-") in core


def test_selection_filters_and_unknown_lane():
    assert len(claude_lane.selection("claude-all")) == sum(len(claude_lane.stage(s)) for s in ("core", "fail", "sweep"))
    with pytest.raises(ValueError, match="unknown lane"):
        claude_lane.selection("claude-nope")

    class Args:
        lane, max_tier, where, reps, harness, arm = "claude-core", 3, "mode=M1h,kind=resource|write,reply=R1", 1, "", ""

    chosen = run.selection_from(Args)
    assert chosen and {c.mode for c in chosen} == {"M1h"} and {c.kind for c in chosen} == {"resource", "write"}
    assert {c.reps for c in chosen} == {1}


# ---------------------------------------------------------------- command lines
@pytest.mark.parametrize("mode,allowed,prompts_none,skip", [("M1", True, True, False), ("M1h", True, False, False),
                                                           ("M0h", False, False, False), ("M2", False, False, True)])
def test_claude_flags_per_mode(tmp_path, mode, allowed, prompts_none, skip):
    _, spec = _spec(tmp_path, _cell(mode=mode))
    argv = spec.argv
    assert ("--allowedTools" in argv) is allowed
    assert ("--permission-prompts" in argv) is prompts_none
    assert ("--dangerously-skip-permissions" in argv) is skip
    assert spec.env["ANTHROPIC_BASE_URL"].startswith("http://127.0.0.1:") and spec.env["ENABLE_TOOL_SEARCH"] == "false"


def test_resource_cell_names_the_resource_tool_and_wildcard_matcher_is_a_state(tmp_path):
    _, spec = _spec(tmp_path, _cell(kind="resource"))
    assert spec.argv[spec.argv.index("--tools") + 1] == "ReadMcpResourceTool"
    paths, spec = _spec(tmp_path / "w", _cell(kind="resource", reply="R4", state="mcpwild"))
    settings = json.loads((paths.root / "settings.json").read_text())
    assert settings["hooks"]["PreToolUse"][0]["matcher"] == "mcp__.*"
    assert configs.lint_config(_cell(kind="resource", reply="R4", state="mcpwild"), paths, spec) == []
    paths, spec = _spec(tmp_path / "p", _cell(kind="resource", reply="R4"))
    assert json.loads((paths.root / "settings.json").read_text())["hooks"]["PreToolUse"][0]["matcher"] == "ReadMcpResourceTool"


def test_flags_an_old_release_lacks_are_dropped(tmp_path):
    _, new = _spec(tmp_path / "n", _cell())
    _, old = _spec(tmp_path / "o", _cell(version="2.0.41"))
    for flag in ("--no-session-persistence", "--max-budget-usd"):
        assert flag in new.argv and flag not in old.argv
    assert "0.25" not in old.argv and "--allowedTools" in old.argv
    assert configs.version_tuple("2.1.316") > configs.version_tuple("2.1.295") > configs.version_tuple("2.0.41")


def test_onfailure_key_is_written_only_for_the_block_variant(tmp_path):
    paths, _ = _spec(tmp_path / "a", _cell(reply="R5", failcfg="block"))
    hooks = json.loads((paths.root / "settings.json").read_text())["hooks"]["PreToolUse"][0]["hooks"][0]
    assert hooks["onFailure"] == "block" and hooks["timeout"] == configs.HOOK_TIMEOUT_S
    paths, _ = _spec(tmp_path / "b", _cell(reply="R5"))
    assert "onFailure" not in json.loads((paths.root / "settings.json").read_text())["hooks"]["PreToolUse"][0]["hooks"][0]


# ---------------------------------------------------------------- arm S helpers of run.py
def test_the_task_text_is_not_an_endpoint(tmp_path):
    _, spec = _spec(tmp_path, _cell(kind="resource"))
    assert "notes://plan" in spec.prompt and run.targets_local_stub(spec)
    spec.env["ANTHROPIC_BASE_URL"] = "https://api.example.com"
    assert not run.targets_local_stub(spec)


def test_arm_s_runs_a_real_stub_and_summarises_its_log(tmp_path):
    cell = _cell(kind="shell", reply="R4")
    paths = configs.make_paths(tmp_path / "run")
    stub = run.start_stub(cell, paths, "00001-abcd")
    try:
        nonce = configs.nonce_for("00001-abcd")
        body = {"model": "claude-haiku-5-5", "stream": True, "messages": [{"role": "user", "content": "x"}],
                "tools": [{"name": "Bash"}, {"name": "mcp__notes__search_notes"}]}
        post = urllib.request.Request(stub.url + "/v1/messages", json.dumps(body).encode(),
                                      {"content-type": "application/json", "user-agent": "claude-cli/9.9.9 (test)"})
        assert nonce.encode() in urllib.request.urlopen(post).read()
        again = dict(body, messages=body["messages"] + [{"role": "user", "content": [
            {"type": "tool_result", "is_error": True, "content": "PreToolUse:Bash hook error: x"}]}])
        urllib.request.urlopen(urllib.request.Request(stub.url + "/v1/messages", json.dumps(again).encode(),
                                                      {"content-type": "application/json"})).read()
        side = {"model": "m", "stream": False, "messages": [{"role": "user", "content": "classify this"}]}
        urllib.request.urlopen(urllib.request.Request(stub.url + "/v1/messages", json.dumps(side).encode(),
                                                      {"content-type": "application/json"})).read()
    finally:
        stub.stop()
    summary = run.stub_summary(paths.root / "requests.jsonl")
    assert summary["requests"] == 3 and summary["generate"] == 3 and summary["count_tokens"] == 0
    assert summary["by_path"] == {"POST /v1/messages": 3} and summary["tool_call_rows"] == 1
    assert summary["scripted_tool_offered"] and summary["call_index_max"] == 1
    assert summary["offered_tools"] == ["Bash", "mcp__notes__search_notes"]
    assert summary["tool_results"][0]["is_error"] and "hook error" in summary["tool_results"][0]["text"]
    assert len(summary["tool_less_calls"]) == 1 and summary["user_agent"].startswith("claude-cli/9.9.9")
    assert run.stub_summary(tmp_path / "missing.jsonl")["requests"] == 0


def test_arm_s_is_refused_for_unwired_harnesses_and_the_cap_is_for_real_models_only(monkeypatch, capsys, tmp_path):
    def boom(*a, **k):
        raise AssertionError("launch attempted")
    monkeypatch.setattr(run.subprocess, "Popen", boom)
    monkeypatch.setattr(run.subprocess, "run", boom)
    monkeypatch.setattr(run, "ARM_S_READY", ("claude",))   # pin it: an unwired harness is refused before any launch
    monkeypatch.setenv("HOOK_FIDELITY_GO", "100000")
    assert run.main(["run", str(tmp_path / "o"), "--execute", "--harness", "codex", "--max-tier", "0"]) == 2
    assert "arm S has no `run --execute` path for codex" in capsys.readouterr().err


def test_loopback_profile_denies_outbound_and_allows_loopback():
    text = run.LOOPBACK_PROFILE.read_text()
    assert "(deny network-outbound)" in text and 'remote ip "localhost:*"' in text


# ---------------------------------------------------------------- sign-offs and results
def test_claude_signoffs_are_complete_for_every_lane_stage():
    for name in ("core", "fail", "sweep"):
        assert run.signoff_gaps(claude_lane.stage(name), committer="someone else") == []
    assert run.signoff_gaps(claude_lane.stage("core"), committer="r3-claude lane agent")  # a reader may not be the committer
    entries = json.loads(run.SIGNOFF_FILE.read_text())
    for item_id, entry in entries.items():
        if item_id.startswith("_"):
            continue
        entry = entry["by_harness"].get("claude") if "by_harness" in entry else entry   # the lane's own entries only
        if entry is None or "claude" not in item_id and "r3-claude" not in entry.get("reader", ""):
            continue
        assert "agent" in entry["reader_kind"] and "not a human" in entry["reader_kind"].lower()
        archive = (configs.ROOT / entry["archive"]).read_text(errors="replace")
        for segment in entry["quote"].split(" ... "):
            assert segment.strip() in archive, (item_id, segment[:60])


def test_an_empty_selection_is_refused_not_run_silently(monkeypatch, capsys, tmp_path):
    def boom(*a, **k):
        raise AssertionError("launch attempted")
    monkeypatch.setattr(run.subprocess, "Popen", boom)
    monkeypatch.setenv("HOOK_FIDELITY_GO", "5")
    assert run.main(["run", str(tmp_path / "o"), "--execute", "--lane", "claude-sweep", "--where", "mode=NO-SUCH"]) == 2
    assert "selection is empty" in capsys.readouterr().err
