"""Coverage-study instrumentation: separates input delivery from model echo, handles both
harnesses' tool naming, and keeps prompts in separate working directories."""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

COVERAGE = Path(__file__).resolve().parents[1] / "benchmarks" / "coverage"
spec = importlib.util.spec_from_file_location("coverage_run", COVERAGE / "run.py")
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

DESC, RESULT, RES, PROMPT = (run.MARKERS[c] for c in ("description", "result", "resource", "prompt"))


def hook(event, markers=(), tool=None, server=None, in_tool_input=(), cwd=None):
    return {"event": event, "markers": list(markers), "tool": tool, "server": server,
            "in_tool_input": list(in_tool_input), "cwd": cwd}


def test_claude_stop_is_an_echo_not_a_delivery():
    found = run.classify_hooks([
        hook("SessionStart"), hook("UserPromptSubmit"),
        hook("PostToolUse", [RESULT], "mcp__probe__lookup", {"name": "probe"}),
        hook("PostToolBatch", [RESULT]),
        hook("Stop", [DESC, RESULT])])
    assert found["description"]["delivered_by"] == []
    assert found["description"]["echoed_in"] == ["Stop"]
    assert found["result"]["delivered_by"] == ["PostToolUse:mcp__probe__lookup"]
    assert found["result"]["echoed_in"] == ["Stop"]
    assert found["result"]["unattributed_in"] == ["PostToolBatch"]
    assert found["result"]["seen_by_hook_scoped_to_mcp_tools"] is True
    assert found["description"]["seen_by_hook_scoped_to_mcp_tools"] is False


def test_gemini_mcp_underscore_naming_is_mcp_scoped():
    found = run.classify_hooks([hook("SessionStart"), hook("AfterTool", [RESULT], "mcp_probe_lookup")])
    assert found["result"]["delivered_by"] == ["AfterTool:mcp_probe_lookup"]
    assert found["result"]["seen_by_hook_scoped_to_mcp_tools"] is True
    assert run.mcp_scoped(hook("AfterTool", tool="something", server="probe"))  # the server field alone
    assert not run.mcp_scoped(hook("AfterTool", tool="read_file"))


def test_resource_tool_delivers_but_is_not_mcp_scoped():
    found = run.classify_hooks([hook("PostToolUse", [RES], "ReadMcpResourceTool")])
    assert found["resource"]["delivered_by"] == ["PostToolUse:ReadMcpResourceTool"]
    assert found["resource"]["seen_by_hook_scoped_to_mcp_tools"] is False


def test_other_tools_and_model_written_arguments_are_echoes():
    found = run.classify_hooks([
        hook("BeforeTool", [DESC], "run_shell_command"),  # the model's own command
        hook("AfterTool", [DESC], "read_file"),  # a file the model wrote earlier
        hook("AfterTool", [RESULT], "mcp_probe_lookup", in_tool_input=[RESULT])])  # model passed the marker in
    assert found["description"]["delivered_by"] == []
    assert found["description"]["echoed_in"] == ["AfterTool:read_file", "BeforeTool:run_shell_command"]
    assert found["result"]["delivered_by"] == []
    assert found["result"]["seen_by_hook_scoped_to_mcp_tools"] is False


def test_prompt_events_deliver_and_gemini_model_hooks_replay_echoes():
    found = run.classify_hooks([
        hook("SessionStart"), hook("BeforeAgent", [PROMPT]), hook("BeforeModel", [PROMPT]),
        hook("AfterModel", [PROMPT]),
        hook("BeforeModel", [PROMPT]),  # replays the model's earlier output
        hook("SessionStart"),  # a new prompt starts clean
        hook("BeforeModel", [PROMPT])])
    prompt = found["prompt"]
    assert prompt["delivered_by"] == ["BeforeAgent", "BeforeModel"]
    assert prompt["echoed_in"] == ["AfterModel", "BeforeModel"]
    assert prompt["seen_by_hook_scoped_to_mcp_tools"] is False


def test_summarize_labels_proxy_requests_and_server_initiated_failures(tmp_path):
    probe = [{"method": "tools/list", "client": {"sampling": False}}, {"method": "tools/list"},
             {"method": "elicitation/error", "error": "NoBackChannelError(-32600, ...)"},
             {"method": "sampling/error", "error": "MCPError(-32601, 'Method not found', None)"}]
    hooks = [hook("SessionStart", cwd="/a"), hook("Stop", [DESC]), hook("SessionStart", cwd="/b")]
    (tmp_path / "probe.jsonl").write_text("\n".join(map(json.dumps, probe)))
    (tmp_path / "hooks.jsonl").write_text("\n".join(map(json.dumps, hooks)))
    summary = run.summarize(tmp_path, {"tools": f"I see {RESULT}"}, "proxy")
    assert summary["upstream_requests"]["tools/list"] == 2
    assert summary["upstream_requests_from"] == "proxy"
    assert summary["server_initiated"]["elicitation"] == {
        "status": "not_exercised", "results": 0, "failures": {"no_back_channel": 1}}
    assert summary["server_initiated"]["sampling"]["failures"] == {"method_not_found": 1}
    assert run.failure_kind("MCPError(-32600, 'Sampling not supported', None)") == "not_supported"
    assert summary["cwd_per_prompt"] is True
    assert summary["channels"]["result"]["reached_model_context"] is True
    assert summary["channels"]["description"]["reached_model_context"] is False
    assert summary["channels"]["description"]["echoed_in"] == ["Stop"]


def test_summarize_flags_a_shared_working_directory(tmp_path):
    hooks = [hook("SessionStart", cwd="/p"), hook("SessionStart", cwd="/p")]
    (tmp_path / "hooks.jsonl").write_text("\n".join(map(json.dumps, hooks)))
    summary = run.summarize(tmp_path, {})
    assert summary["cwd_per_prompt"] is False
    assert summary["server_initiated"]["elicitation"]["status"] == "not_attempted"


def test_each_prompt_gets_its_own_project_directory(tmp_path):
    dirs = {run.project_dir(tmp_path, name) for name in run.PROMPTS}
    assert len(dirs) == len(run.PROMPTS) and all(d.is_dir() for d in dirs)
    (run.project_dir(tmp_path, "tools") / "info.txt").write_text(RESULT)
    assert not list(run.project_dir(tmp_path, "resources").iterdir())


def test_marker_sets_agree_across_the_study_files():
    def found(name):
        return set(re.findall(r"ISC-[A-Z0-9]+-\d+", (COVERAGE / name).read_text()))
    assert found("run.py") == found("probe_server.py") == found("log_hook.py") == set(run.MARKERS.values())
