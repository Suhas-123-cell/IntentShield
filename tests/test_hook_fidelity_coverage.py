"""Offline tests of the coverage re-run tooling (benchmarks/hook_fidelity/coverage_*.py and the stub's marker search).
No harness is launched: logs are synthetic, written from the shapes the recorded runs produced."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1] / "benchmarks"
from hook_fidelity import coverage_run, coverage_summarize, stub_model  # noqa: E402
from hook_fidelity.coverage_probe_server import markers_for  # noqa: E402
from hook_fidelity.stub_model import Script, StubServer  # noqa: E402

HOOK = BENCH / "hook_fidelity" / "coverage_hook.py"


def test_locate_markers_names_the_section_and_block_kind():
    body = {"tools": [{"description": "x ISC-DESC-a"}], "system": "y ISC-INSTR-a",
            "messages": [{"role": "user", "content": [{"type": "tool_result", "content": "ISC-RESULT-a"},
                                                      {"type": "text", "text": "ISC-DESC-a again"}]}],
            "contents": [{"role": "user", "parts": [{"functionResponse": {"r": "ISC-RES-a"}}]}]}
    hits = stub_model.locate_markers(body, ["ISC-DESC-a", "ISC-INSTR-a", "ISC-RESULT-a", "ISC-RES-a", "ISC-ABSENT-a"])
    assert hits["ISC-DESC-a"] == ["messages[user:text]", "tools"]
    assert hits["ISC-INSTR-a"] == ["system"]
    assert hits["ISC-RESULT-a"] == ["messages[user:tool_result]"]
    assert hits["ISC-RES-a"] == ["contents[user:functionResponse]"]
    assert "ISC-ABSENT-a" not in hits


def test_stub_logs_marker_hits(tmp_path):
    script = Script.from_obj({"nonce": "n", "final_text": "done"})
    with StubServer(script, tmp_path / "log.jsonl", markers=["ISC-DESC-a"]) as stub:
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", stub.port)
        body = json.dumps({"model": "m", "tools": [{"name": "t", "description": "ISC-DESC-a"}],
                           "messages": [{"role": "user", "content": "hi"}]})
        conn.request("POST", "/v1/messages", body, {"content-type": "application/json"})
        conn.getresponse().read()
    row = json.loads((tmp_path / "log.jsonl").read_text().splitlines()[0])
    assert row["marker_hits"] == {"ISC-DESC-a": ["tools"]}


def run_hook(tmp_path, event: dict) -> dict:
    log = tmp_path / "hooks.jsonl"
    done = subprocess.run([sys.executable, str(HOOK), "claude", str(log)], input=json.dumps(event), text=True,
                          capture_output=True)
    assert done.returncode == 0 and done.stdout == "" and done.stderr == ""  # never changes a decision
    return json.loads(log.read_text().splitlines()[-1])


def test_hook_records_markers_paths_and_model_written_input(tmp_path):
    line = run_hook(tmp_path, {"hook_event_name": "PostToolUse", "tool_name": "mcp__probe__lookup_v",
                               "tool_input": {"word": "ISC-DESC-x1"},
                               "tool_response": {"content": "text ISC-RESULT-x1"}})
    assert line["markers"] == ["ISC-DESC-x1", "ISC-RESULT-x1"]
    assert line["marker_paths"]["ISC-RESULT-x1"] == ["tool_response.content"]
    assert line["in_tool_input"] == ["ISC-DESC-x1"]  # written by the model, so not a delivery


def test_hook_survives_garbage_stdin(tmp_path):
    log = tmp_path / "h.jsonl"
    done = subprocess.run([sys.executable, str(HOOK), "codex", str(log)], input="not json", text=True, capture_output=True)
    assert done.returncode == 0
    assert json.loads(log.read_text())["markers"] == []


def test_markers_are_unique_per_tag_and_surface():
    a, b = markers_for("nza"), markers_for("nzb")
    assert len(set(a.values())) == len(a) and not set(a.values()) & set(b.values())


def test_script_names_per_harness():
    tools = coverage_run.script_for("codex", "tools", "t")
    assert tools["by_api"]["openai"] == {"namespace": "mcp__probe", "name": "lookup_v", "args": {"word": "alpha"}}
    flat = coverage_run.script_for("codex", "tools", "t", codex_namespace="")
    assert flat["by_api"]["openai"]["name"] == "mcp__probe__lookup_v" and "namespace" not in flat["by_api"]["openai"]
    assert coverage_run.script_for("gemini", "resource", "t")["by_api"]["gemini"]["args"] == {"uri": "probe://notes"}
    assert "call" not in coverage_run.script_for("claude", "prompt", "t")


def test_event_sets_follow_the_build():
    assert "PreModelRequest" in coverage_run.event_set("codex", "0.166.0")
    assert "PreModelRequest" not in coverage_run.event_set("codex", "0.131.0")
    assert "PostToolBatch" in coverage_run.event_set("claude", "2.1.316")
    assert "PostToolBatch" not in coverage_run.event_set("claude", "2.1.69")


def synthetic(tag="nzt"):
    m = markers_for(tag)
    stub = [{"seq": 1, "ts_ns": 100, "kind": "generate", "offered_tools": ["lookup"], "scripted_tool": {"name": "x"},
             "scripted_tool_offered": True,
             "marker_hits": {m["DESC"]: ["tools"], m["INSTR"]: ["system"]}},
            {"seq": 2, "ts_ns": 300, "kind": "generate", "offered_tools": ["lookup"], "tool_results": [{"text": "r"}],
             "marker_hits": {m["DESC"]: ["tools"], m["RESULT"]: ["messages[user:tool_result]"]}}]
    probe = [{"method": "tools/list"}, {"method": "tools/call"}]
    hooks = [{"ts_ns": 50, "event": "PreToolUse", "tool": "mcp__probe__lookup_v", "markers": [], "marker_paths": {},
              "in_tool_input": []},
             {"ts_ns": 200, "event": "PostToolUse", "tool": "mcp__probe__lookup_v", "markers": [m["RESULT"]],
              "marker_paths": {m["RESULT"]: ["tool_response"]}, "in_tool_input": []}]
    return tag, stub, probe, hooks


def test_analyse_orders_hooks_against_the_model_request():
    tag, stub, probe, hooks = synthetic()
    res = coverage_run.analyse("claude", "tools", tag, stub, probe, hooks)
    s = res["surfaces"]
    assert res["valid"] and s["DESC"]["model_requests_carrying"] == 2 and not s["DESC"]["seen_by_any_hook"]
    assert s["RESULT"]["seen_by_result_hook"] and not s["RESULT"]["seen_by_decision_hook"]
    # the result marker reached the model at ts 300; the hook saw it at ts 200, before the model
    assert s["RESULT"]["seen_by_any_hook_before_model"]
    assert res["scripted_call_pre_hooked"] is True
    assert res["probe_requests"] == {"tools/list": 1, "tools/call": 1}


def test_analyse_flags_a_dead_hook_config_and_a_missing_tool():
    tag, stub, probe, _ = synthetic()
    res = coverage_run.analyse("claude", "tools", tag, stub, probe, [])
    assert not res["valid"] and "no hook event arrived (hook config dead or ignored)" in res["problems"]
    stub[0]["scripted_tool_offered"] = False
    res = coverage_run.analyse("claude", "tools", tag, stub, probe, [{"ts_ns": 1, "event": "SessionStart", "tool": "",
                                                                        "markers": [], "marker_paths": {}, "in_tool_input": []}])
    assert "the scripted tool was not among the tools the harness offered" in res["problems"]


def test_wilson_and_formatting_come_from_k_and_n():
    lo, hi = coverage_summarize.wilson(3, 3)
    assert hi == 1.0 and 0.43 < lo < 0.45
    assert coverage_summarize.fmt(0, 3) == "0/3 [0,56]"
    assert coverage_summarize.fmt(0, 0) == "-"


def test_summary_cells_count_valid_launches_only():
    tag, stub, probe, hooks = synthetic()
    good = {"harness": "claude", "version": "9.9", "variant": "base", "surface_run": "tools", "rep": 0, "valid": True,
            "probe_requests": {"tools/list": 1, "tools/call": 1},
            "scripted_call_pre_hooked": True,
            **{k: v for k, v in coverage_run.analyse("claude", "tools", tag, stub, probe, hooks).items()
               if k in ("surfaces",)}}
    bad = {**good, "rep": 1, "valid": False, "problems": ["x"]}
    cells, invalid = coverage_summarize.cells([good, bad])
    cell = cells[("claude", "9.9", "base", "tool_result")]
    assert (cell["n"], cell["k_model"], cell["k_result_hook"], cell["k_decision_hook"]) == (1, 1, 1, 0)
    assert len(invalid) == 1
    changed = cells[("claude", "9.9", "base", "changed_description")]
    assert changed["k_server_read"] == 0  # tools/list was requested once, never again after the change
