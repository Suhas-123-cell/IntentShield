"""Coverage study: which MCP channels does a third-party guard observe from harness hooks,
and which from a protocol-level proxy?

A benign probe server (probe_server.py) puts one marker in each channel; a passive hook
(log_hook.py) is registered on every relevant event; the harness runs headless with four
benign prompts, each in its own project directory. For each marker the summary records: did it
reach the model (transcript or answer); which hook events DELIVERED it (a tool result from the
probe's MCP tools or the harness's MCP resource tools, a prompt event, or the first
model-request event) versus which only ECHOED it (model output such as Stop/AfterModel/AfterAgent,
the model's own tool arguments, other tools' output); whether a hook scoped to MCP tool names
would have seen a delivery; and which requests reached the probe server. Through the proxy those
are the proxy's own upstream requests, so tools/list counts are its fan-out, not the harness's.

    .venv/bin/python benchmarks/coverage/run.py --harness claude --mode direct
    .venv/bin/python benchmarks/coverage/run.py --harness gemini --mode proxy --model gemini-3.1-flash-lite
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
PY = str(ROOT / ".venv/bin/python")
MARKERS = {"description": "ISC-DESC-41", "result": "ISC-RESULT-42", "resource": "ISC-RES-43",
           "prompt": "ISC-PROMPT-44", "changed_description": "ISC-DESC2-45", "elicitation": "ISC-ELICIT-46",
           "versioned_description": "ISC-DESCV-47"}
ASK = "Then quote every token that starts with ISC- that you can see anywhere in your context."
PROMPTS = {
    "tools": "Use the tool named lookup of the probe MCP server to look up the word alpha, then look up beta. "
             f"Then tell me the exact current description of the lookup tool. {ASK}",
    "rugpull": "Use the tool named lookup_v of the probe MCP server to look up the word gamma, then look up delta. "
               f"Then tell me the exact current description of the lookup_v tool. {ASK}",
    "resources": f"List the resources the probe MCP server offers and read probe://notes. {ASK}",
    "prompt": {"claude": "/mcp__probe__brief", "gemini": "/brief"},
    "elicitation": "Use the probe MCP server's subscribe tool once, then tell me what it returned.",
}
# Event classes for summarize(). Tool-result events count as delivery only for the probe's MCP
# tools or the harness's MCP resource tools; everything else carrying a marker is an echo.
MCP_PREFIXES = ("mcp__", "mcp_")  # Claude Code: mcp__probe__lookup; Gemini CLI: mcp_probe_lookup
RESOURCE_TOOLS = ("ReadMcpResourceTool", "ListMcpResourcesTool")
TOOL_RESULT_EVENTS = ("PostToolUse", "PostToolUseFailure", "AfterTool")
PROMPT_EVENTS = ("SessionStart", "UserPromptSubmit", "UserPromptExpansion", "Elicitation", "ElicitationResult",
                 "BeforeAgent")
REPLAY_EVENTS = ("BeforeModel", "BeforeToolSelection")  # carry the history so far, model echoes included
UNATTRIBUTED_EVENTS = ("PostToolBatch",)  # a batch of results with no tool name
# Everything else is model output or the model's own arguments: Stop, AfterModel, AfterAgent,
# PreToolUse, BeforeTool, PermissionRequest, Notification.
CLAUDE_EVENTS = ("SessionStart", "UserPromptSubmit", "UserPromptExpansion", "PreToolUse", "PostToolUse",
                 "PostToolUseFailure", "PostToolBatch", "PermissionRequest", "Elicitation", "ElicitationResult",
                 "Stop")
GEMINI_EVENTS = ("SessionStart", "BeforeAgent", "BeforeModel", "BeforeToolSelection", "BeforeTool", "AfterTool",
                 "AfterModel", "AfterAgent", "Notification")


def server_entry(mode: str, out: Path) -> dict:
    probe = {"command": PY, "args": [str(HERE / "probe_server.py"), str(out / "probe.jsonl")]}
    if mode == "direct":
        return probe
    (out / "proxy.json").write_text(json.dumps({
        "upstreams": [{"server_id": "probe", "transport": "stdio", **probe}],
        "database_path": str(out / "proxy.db")}))
    return {"command": PY, "args": ["-m", "intentshield.mcp_server", "--transparent", "--config", str(out / "proxy.json")],
            "env": {"PYTHONPATH": str(ROOT / "src")}}


def project_dir(out: Path, name: str) -> Path:
    """A fresh working directory per prompt, so one session's files never reach the next."""
    project = out / f"project-{name}"
    project.mkdir(parents=True, exist_ok=True)
    return project


def run_claude(out: Path, mode: str, model: str, name: str, prompt: str) -> str:
    hook = f"{PY} {HERE / 'log_hook.py'} claude {out / 'hooks.jsonl'}"
    entry = {"hooks": [{"type": "command", "command": hook}]}
    settings = {"hooks": {event: [{"matcher": "*", **entry} if "Tool" in event or event.startswith("Permission")
                                  else entry] for event in CLAUDE_EVENTS}}
    (out / "settings.json").write_text(json.dumps(settings))
    (out / "mcp.json").write_text(json.dumps({"mcpServers": {"probe": server_entry(mode, out)}}))
    project = project_dir(out, name)
    result = subprocess.run(
        ["claude", "-p", prompt, "--model", model, "--setting-sources", "project", "--strict-mcp-config",
         "--mcp-config", str(out / "mcp.json"), "--settings", str(out / "settings.json"), "--output-format", "json",
         "--allowedTools", "mcp__probe__lookup", "mcp__probe__lookup_v", "mcp__probe__subscribe", "ListMcpResourcesTool", "ReadMcpResourceTool"],
        cwd=project, capture_output=True, text=True, timeout=600)
    (out / f"answer-{name}.json").write_text(result.stdout or result.stderr)
    try:
        return json.loads(result.stdout).get("result", "")
    except ValueError:
        return result.stdout + result.stderr


def run_gemini(out: Path, mode: str, model: str, name: str, prompt: str) -> str:
    home = out / f"home-{name}"  # per prompt as well: Gemini keeps chats and memory under HOME
    (home / ".gemini").mkdir(parents=True, exist_ok=True)
    hook = f"{PY} {HERE / 'log_hook.py'} gemini {out / 'hooks.jsonl'}"
    entry = {"hooks": [{"type": "command", "command": hook}]}
    settings = {
        "security": {"auth": {"selectedType": "gemini-api-key"}},
        "mcpServers": {"probe": {**server_entry(mode, out), "trust": True}},
        "hooks": {event: [{"matcher": "*", **entry} if event in ("BeforeTool", "AfterTool") else entry]
                  for event in GEMINI_EVENTS},
    }
    (home / ".gemini" / "settings.json").write_text(json.dumps(settings))
    project = project_dir(out, name)
    env = {**os.environ, "HOME": str(home), "GEMINI_API_KEY": dotenv_values(ROOT / ".env").get("GEMINI_API_KEY", "")}
    result = subprocess.run(["gemini", "-p", prompt, "-m", model, "--approval-mode", "yolo", "-o", "json"],
                            cwd=project, env=env, capture_output=True, text=True, timeout=600)
    (out / f"answer-{name}.json").write_text(result.stdout + "\n--- stderr ---\n" + result.stderr[-3000:])
    try:
        return json.loads(result.stdout).get("response", "")
    except ValueError:
        return result.stdout + result.stderr


def mcp_scoped(hook: dict) -> bool:
    """Would a hook scoped to MCP tool calls have run for this event? Matches the tool name in either
    harness's naming, or the MCP server field."""
    return (hook.get("tool") or "").startswith(MCP_PREFIXES) or bool(hook.get("server"))


def classify(hook: dict, marker: str, echoed_before: bool) -> str:
    """Is this event's copy of the marker input delivered to the model, or an echo of it?"""
    event = hook["event"]
    if event in TOOL_RESULT_EVENTS:
        written_by_model = marker in hook.get("in_tool_input", [])
        return "delivery" if not written_by_model and (mcp_scoped(hook) or hook.get("tool") in RESOURCE_TOOLS) \
            else "echo"
    if event in PROMPT_EVENTS:
        return "delivery"
    if event in REPLAY_EVENTS:
        return "echo" if echoed_before else "delivery"
    return "unattributed" if event in UNATTRIBUTED_EVENTS else "echo"


def classify_hooks(hooks: list[dict]) -> dict[str, dict]:
    """Per channel: the hook events that delivered its marker, the ones that only echoed it, and
    whether an MCP-scoped hook would have seen a delivery. Hooks are in arrival order; a new
    SessionStart begins a new prompt, so an echo in one session never taints the next."""
    found = {channel: {"delivered_by": set(), "echoed_in": set(), "unattributed_in": set(), "scoped": False}
             for channel in MARKERS}
    echoed: set[tuple[int, str]] = set()
    session = 0
    for hook in hooks:
        session += hook["event"] == "SessionStart"
        label = f"{hook['event']}:{hook['tool']}" if hook.get("tool") else hook["event"]
        for channel, marker in MARKERS.items():
            if marker not in hook["markers"]:
                continue
            kind = classify(hook, marker, (session, marker) in echoed)
            if kind == "echo":
                echoed.add((session, marker))
            entry = found[channel]
            entry[{"delivery": "delivered_by", "echo": "echoed_in", "unattributed": "unattributed_in"}[kind]].add(label)
            entry["scoped"] |= kind == "delivery" and mcp_scoped(hook)
    return {channel: {"delivered_by": sorted(e["delivered_by"]), "echoed_in": sorted(e["echoed_in"]),
                      "unattributed_in": sorted(e["unattributed_in"]),
                      "seen_by_hook_scoped_to_mcp_tools": e["scoped"]} for channel, e in found.items()}


def failure_kind(error: str) -> str:
    return ("no_back_channel" if "NoBackChannel" in error else
            "method_not_found" if "-32601" in error or "Method not found" in error else
            "not_supported" if "not supported" in error else "other")


def server_initiated(requests: list[dict]) -> dict[str, dict]:
    """How each server-initiated request (elicitation, sampling) ended, by failure kind. A feature
    that always fails here was not exercised, which differs from exercised and not observed."""
    out = {}
    for feature in ("elicitation", "sampling"):
        results = [r for r in requests if r["method"] == f"{feature}/result"]
        errors = [r for r in requests if r["method"] == f"{feature}/error"]
        out[feature] = {"status": "exercised" if results else "not_exercised" if errors else "not_attempted",
                        "results": len(results),
                        "failures": dict(collections.Counter(failure_kind(r.get("error", "")) for r in errors))}
    return out


def summarize(out: Path, answers: dict[str, str], mode: str = "direct") -> dict:
    def lines(path: Path) -> list[dict]:
        return [json.loads(x) for x in path.read_text().splitlines() if x] if path.exists() else []

    requests, hooks = lines(out / "probe.jsonl"), lines(out / "hooks.jsonl")
    transcripts = {h["transcript"] for h in hooks if h.get("transcript")}
    context = "".join(Path(t).read_text(errors="replace") for t in transcripts if Path(t).exists())
    for home in out.glob("home*"):  # Gemini keeps its chat logs under the temporary home
        context += "".join(p.read_text(errors="replace") for p in home.rglob("*")
                           if p.is_file() and p.suffix in (".json", ".jsonl") and p.name != "settings.json")
    answer_text = "\n".join(answers.values())
    cwds = [h["cwd"] for h in hooks if h["event"] == "SessionStart" and h.get("cwd")]
    classes = classify_hooks(hooks)
    return {
        # Requests that reached the probe server. In proxy mode they come from the proxy, so
        # tools/list counts are its own fan-out to the upstream, not the harness's requests.
        "upstream_requests": dict(collections.Counter(r["method"] for r in requests)),
        "upstream_requests_from": "proxy" if mode == "proxy" else "harness",
        "client_capabilities": next((r["client"] for r in requests if r.get("client")), None),
        "server_initiated": server_initiated(requests),
        "session_cwds": cwds,
        "cwd_per_prompt": len(set(cwds)) == len(cwds) if cwds else None,
        "hook_events_fired": dict(collections.Counter(h["event"] for h in hooks)),
        "tools_seen_by_hooks": sorted({h["tool"] for h in hooks if h.get("tool")}),
        "channels": {channel: {
            "reached_model_context": marker in context or marker in answer_text, **classes[channel]}
            for channel, marker in MARKERS.items()},
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harness", choices=("claude", "gemini"), required=True)
    parser.add_argument("--mode", choices=("direct", "proxy"), required=True)
    parser.add_argument("--model", default=None, help="claude: haiku; gemini: a free-tier model")
    parser.add_argument("--prompts", default="tools,rugpull,resources,prompt,elicitation")
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts/coverage")
    args = parser.parse_args(argv)
    out = args.out / f"{args.harness}-{args.mode}"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    model = args.model or ("haiku" if args.harness == "claude" else "gemini-3.1-flash-lite")
    runner = run_claude if args.harness == "claude" else run_gemini
    answers = {}
    for name in args.prompts.split(","):
        prompt = PROMPTS[name][args.harness] if isinstance(PROMPTS[name], dict) else PROMPTS[name]
        answers[name] = runner(out, args.mode, model, name, prompt)
        print(f"{name}: {answers[name][:200]!r}", file=sys.stderr, flush=True)
    summary = {"harness": args.harness, "mode": args.mode, "model": model, **summarize(out, answers, args.mode)}
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
