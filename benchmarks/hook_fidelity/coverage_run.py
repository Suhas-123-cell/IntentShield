#!/usr/bin/env python3
"""Coverage re-run: which MCP surfaces reach a hook, and which reach the model, per harness build, with no model.

    HOOK_FIDELITY_GO=<n> coverage_run.py --harness claude --version 2.1.316 --binary /abs/claude \
        --surfaces tools,resource,prompt --reps 3 --work /abs/scratch/dir --out /abs/results/dir

For each launch it starts the stub model endpoint (stub_model.py, in this process, 127.0.0.1, random port) with a script that
makes the one tool call the surface needs (or none), starts nothing else, points the harness at the stub with a FAKE key
under a fresh HOME, gives it a loopback stdio MCP server (coverage_probe_server.py) carrying one marker per surface and a
passive hook on every event (coverage_hook.py), and then reads three independent logs:

* the stub's request log: ``marker_hits`` shows, per request, where each marker sat in what the model was sent (tool
  declarations, system prompt, a tool result, the user message), so "the model saw it" is read from the wire;
* the probe server's request log: which MCP requests the harness made (tools/list, resources/read, prompts/get ...);
* the hook log: which hook events carried which marker as INPUT, and when (same clock as the stub), so a hook event can be
  ordered against the first model request that carried the marker.

Surfaces ("tools" launch: DESC INSTR VDESC1 VDESC2 RESULT; "resource" launch: RES; "prompt" launch: PROMPT):

    tool_description   ISC-DESC       description of the stable tool ``lookup``
    server_instructions ISC-INSTR     ``instructions`` in the initialize result
    changed_description ISC-VDESC2    ``lookup_v`` description after its first call plus tools/list_changed
    tool_result        ISC-RESULT     text returned by the scripted ``lookup_v`` call
    resource_read      ISC-RES        text of ``probe://notes`` read through the harness's resource tool
    prompt_content     ISC-PROMPT     text of the MCP prompt ``brief`` used as a slash command

Nothing here touches the user's real harness directories: HOME and every config-dir variable point into the run directory,
the environment is an allowlist, proxies are removed, and the harness only ever gets the stub's loopback URL and a made-up
key. A harness that never calls the stub shows ``stub_requests: 0`` and the row is INVALID. Network traffic OTHER than to the
stub is NOT blocked or measured here (no sandbox profile), only discouraged with the vendors' telemetry opt-outs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
from hook_fidelity import configs  # noqa: E402
from hook_fidelity.coverage_probe_server import markers_for  # noqa: E402
from hook_fidelity.stub_model import Script, StubServer  # noqa: E402

PROBE = HERE / "coverage_probe_server.py"
HOOK = HERE / "coverage_hook.py"
STUB_KEY = "sk-stub-not-a-real-key"
MODELS = {"claude": "claude-haiku-4-5", "codex": "stub-model", "gemini": "gemini-2.5-flash"}
RUN_CAP_S = 150
DECISION_EVENTS = {"PreToolUse", "BeforeTool", "PermissionRequest"}
RESULT_EVENTS = {"PostToolUse", "AfterTool", "PostToolUseFailure"}

# Hook events registered per harness. A name an old build does not know can invalidate the whole settings file, so each
# build gets only the events its own binary or documentation names; the run is INVALID unless a PreToolUse-class event
# arrives for the scripted call (the liveness check), which catches a dead hook config.
EVENTS = {
    "claude": ["SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"],
    "claude-new": ["SessionStart", "UserPromptSubmit", "UserPromptExpansion", "PreToolUse", "PostToolUse",
                   "PostToolUseFailure", "PostToolBatch", "PermissionRequest", "Elicitation", "ElicitationResult", "Stop"],
    "codex": ["SessionStart", "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "Stop"],
    "codex-new": ["PreModelRequest", "PostModelRequest", "SessionStart", "UserPromptSubmit", "PreToolUse",
                  "PermissionRequest", "PostToolUse", "Stop"],
    "gemini": ["SessionStart", "BeforeAgent", "BeforeModel", "BeforeToolSelection", "BeforeTool", "AfterTool",
               "AfterModel", "AfterAgent"],
}
TOOL_EVENTS = {"PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest", "BeforeTool", "AfterTool"}


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split("-")[0].split(".") if p.isdigit())


def event_set(harness: str, version: str) -> list[str]:
    if harness == "claude":
        return EVENTS["claude-new"] if version_key(version) >= (2, 1, 118) else EVENTS["claude"]
    if harness == "codex":
        return EVENTS["codex-new"] if version_key(version) >= (0, 164, 0) else EVENTS["codex"]  # model-request hooks: 0.164
    return EVENTS["gemini"]


# --- stub script per harness and surface ---------------------------------------------------------------------------

def script_for(harness: str, surface: str, tag: str, codex_namespace: str = "mcp__probe") -> dict:
    """The one tool call (or none) the stub model issues. Names are the ones the model is shown."""
    if surface == "tools":
        word = {"word": "alpha"}
        # Codex 0.166 offers MCP tools as the namespace ``mcp__probe`` plus the bare name; 0.131 offers the flat name
        # ``mcp__probe__lookup_v`` (an empty --codex-namespace). The row's offered_tools settles which one a build used.
        openai = ({"namespace": codex_namespace, "name": "lookup_v", "args": word} if codex_namespace
                  else {"name": "mcp__probe__lookup_v", "args": word})
        return {"nonce": tag, "call": {"name": "mcp__probe__lookup_v", "args": word},
                "by_api": {"openai": openai,
                           "gemini": {"name": "mcp_probe_lookup_v", "args": word}}, "final_text": f"stub done {tag}"}
    if surface == "resource":
        return {"nonce": tag, "call": {"name": "ReadMcpResourceTool", "args": {"server": "probe", "uri": "probe://notes"}},
                "by_api": {"openai": {"name": "read_mcp_resource", "args": {"server": "probe", "uri": "probe://notes"}},
                           "gemini": {"name": "read_mcp_resource", "args": {"uri": "probe://notes"}}},
                "final_text": f"stub done {tag}"}
    if surface == "prompt":  # the MCP prompt is used as a slash command: no tool call at all
        return {"nonce": tag, "final_text": f"stub done {tag}"}
    raise ValueError(surface)


def prompt_for(harness: str, surface: str) -> str:
    if surface == "prompt":
        return {"claude": "/mcp__probe__brief", "gemini": "/brief", "codex": "/brief"}[harness]
    return {"tools": "Use the lookup_v tool of the probe server to look up the word alpha.",
            "resource": "Read the MCP resource probe://notes of the probe server."}[surface]


# --- configuration of each harness -----------------------------------------------------------------------------

def hook_cmd(harness: str, hooks_log: Path, raw_dir: Path) -> str:
    import shlex
    return shlex.join([sys.executable, str(HOOK), harness, str(hooks_log), "--raw-dir", str(raw_dir)])


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def base_env(home: Path, extra: dict[str, str]) -> dict[str, str]:
    keep = ("PATH", "LANG", "LC_ALL", "TERM", "TMPDIR", "USER", "LOGNAME", "SHELL")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env["HOME"] = str(home)
    env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost,::1"
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    env["XDG_DATA_HOME"] = str(home / ".local" / "share")
    env["XDG_CACHE_HOME"] = str(home / ".cache")
    env["npm_config_cache"] = str(home / ".npm")
    env.update(extra)
    return env


def build_launch(harness: str, version: str, binary: list[str], surface: str, tag: str, run: Path, stub_url: str,
                 hooks_log: Path, probe_log: Path, model: str = "",
                 drop_env: tuple[str, ...] = ()) -> tuple[list[str], dict[str, str], Path]:
    home, work = run / "home", run / "work"
    for d in (home, work):
        d.mkdir(parents=True, exist_ok=True)
    raw_dir = run / "hook-raw"
    command = hook_cmd(harness, hooks_log, raw_dir)
    probe = {"command": sys.executable, "args": [str(PROBE), "--log", str(probe_log), "--tag", tag]}
    prompt = prompt_for(harness, surface)
    events = event_set(harness, version)
    if harness == "claude":
        def group(event: str) -> dict:
            handler = {"hooks": [{"type": "command", "command": command, "timeout": 20}]}
            return {"matcher": "*", **handler} if event in TOOL_EVENTS else handler
        write(run / "settings.json", json.dumps({"hooks": {e: [group(e)] for e in events}}))
        write(run / "mcp.json", json.dumps({"mcpServers": {"probe": probe}}))
        argv = [*binary, "-p", prompt, "--model", model or MODELS["claude"], "--output-format", "stream-json", "--verbose",
                "--setting-sources", "project", "--strict-mcp-config", "--mcp-config", str(run / "mcp.json"),
                "--settings", str(run / "settings.json"), "--dangerously-skip-permissions"]
        extra = {"ANTHROPIC_BASE_URL": stub_url, "ANTHROPIC_API_KEY": STUB_KEY, "CLAUDE_CONFIG_DIR": str(home / "claude"),
                 "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1", "DISABLE_AUTOUPDATER": "1",
                 "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "ENABLE_TOOL_SEARCH": "false"}
    elif harness == "codex":
        chome = home / "codex-home"
        toml = (f'check_for_update_on_startup = false\nmodel = "{model or MODELS["codex"]}"\nmodel_provider = "stub"\n'
                'approval_policy = "never"\n\n[sandbox_workspace_write]\nnetwork_access = true\n\n'
                f"[mcp_servers.probe]\ncommand = {json.dumps(probe['command'])}\nargs = {json.dumps(probe['args'])}\n"
                'default_tools_approval_mode = "approve"\n\n[analytics]\nenabled = false\n\n[feedback]\nenabled = false\n\n'
                f'[model_providers.stub]\nname = "stub"\nbase_url = "{stub_url}/v1"\nenv_key = "STUB_API_KEY"\n'
                'wire_api = "responses"\nrequest_max_retries = 0\nstream_max_retries = 0\n\n')
        for event in events:
            matcher = 'matcher = "*"\n' if event in TOOL_EVENTS else ""
            toml += (f"[[hooks.{event}]]\n{matcher}[[hooks.{event}.hooks]]\ntype = \"command\"\n"
                     f"command = {json.dumps(command)}\ntimeout = 20\n\n")
        write(chome / "config.toml", toml)
        argv = [*binary, "exec", "--skip-git-repo-check", "--sandbox", "workspace-write", "--ephemeral",
                "--dangerously-bypass-hook-trust", "--json", prompt]
        extra = {"CODEX_HOME": str(chome), "STUB_API_KEY": STUB_KEY}
    elif harness == "gemini":
        gemini = home / ".gemini"
        hooks = {e: [{"matcher": "*", "hooks": [{"type": "command", "command": command, "timeout": 20000}]}
                     if e in TOOL_EVENTS else {"hooks": [{"type": "command", "command": command, "timeout": 20000}]}]
                 for e in events}
        settings = {"security": {"auth": {"selectedType": "gemini-api-key"}},
                    "general": {"disableAutoUpdate": True, "disableUpdateNag": True, "enableAutoUpdate": False,
                                "enableAutoUpdateNotification": False},
                    "privacy": {"usageStatisticsEnabled": False},
                    "mcpServers": {"probe": {**probe, "trust": True}}, "hooks": hooks}
        write(gemini / "settings.json", json.dumps(settings))
        write(gemini / "trustedFolders.json", json.dumps({str(work.resolve()): "TRUST_FOLDER"}))
        argv = [*binary, "-p", prompt, "-m", model or MODELS["gemini"], "--approval-mode", "yolo", "-o", "stream-json"]
        extra = {"GOOGLE_GEMINI_BASE_URL": stub_url, "GEMINI_API_KEY": STUB_KEY, "GEMINI_CLI_HOME": str(home),
                 "GEMINI_TELEMETRY_ENABLED": "false"}
    else:
        raise ValueError(harness)
    for name in drop_env:
        extra.pop(name, None)
    return argv, base_env(home, extra), work


def persist_codex_hook_trust(binary: list[str], env: dict[str, str], cwd: Path, config: Path) -> dict:
    """Make the inline hooks of ``config`` trusted the way a person does through /hooks: ask the harness's own app-server
    (``hooks/list``, no model, no network) for each hook's key and current hash, then write ``[hooks.state."<key>"]
    trusted_hash`` into config.toml. Codex 0.131 ran no untrusted inline hook under ``exec --dangerously-bypass-hook-trust``
    (7 of 7 launches, 0 hook events; ``hooks/list`` reports them ``untrusted``), so that build needs this."""
    import select
    proc = subprocess.Popen([*binary, "app-server"], cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, start_new_session=True)

    def send(obj: dict) -> None:
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()

    entries: list[dict] = []
    try:
        send({"id": 1, "method": "initialize", "params": {"clientInfo": {"name": "coverage", "title": None, "version": "0"}}})
        send({"method": "initialized"})
        send({"id": 2, "method": "hooks/list", "params": {"cwds": [str(cwd)]}})
        deadline = time.time() + 20
        while time.time() < deadline:
            ready, _, _ = select.select([proc.stdout], [], [], 1)
            if not ready:
                continue
            line = proc.stdout.readline()
            if not line:
                break
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if msg.get("id") == 2:
                entries = [h for d in msg.get("result", {}).get("data", []) for h in d.get("hooks", [])]
                break
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
    text = "".join(f'\n[hooks.state.{json.dumps(h["key"])}]\nenabled = true\ntrusted_hash = {json.dumps(h["currentHash"])}\n'
                   for h in entries)
    with config.open("a") as handle:
        handle.write(text)
    return {"hooks_listed": len(entries), "trust_status_before": sorted({h.get("trustStatus") for h in entries})}



def leaks(harness: str, run: Path, env: dict[str, str]) -> list[str]:
    problems = []
    if Path(env["HOME"]).resolve() != (run / "home").resolve():
        problems.append("HOME is not the run's home")
    for name in configs.CONFIG_DIR_VARS:
        value = env.get(name)
        if value and run.resolve() not in (Path(value).resolve(), *Path(value).resolve().parents):
            problems.append(f"{name} points outside the run directory")
    problems += [f"system-level config {p} exists" for p in configs.SYSTEM_CONFIG_FILES[harness] if Path(p).exists()]
    return problems


# --- reading the three logs --------------------------------------------------------------------------------------

def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(errors="replace").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def analyse(harness: str, surface: str, tag: str, stub: list[dict], probe: list[dict], hooks: list[dict]) -> dict:
    markers = markers_for(tag)
    gen = [r for r in stub if r.get("kind") in ("generate", "streamGenerateContent", "generateContent")]
    surfaces = {}
    for name, marker in markers.items():
        carrying = [r for r in gen if marker in (r.get("marker_hits") or {})]
        first_ts = min((r["ts_ns"] for r in carrying), default=None)
        hook_events = []
        for h in hooks:
            if marker in h.get("markers", []) and marker not in h.get("in_tool_input", []):
                hook_events.append({"event": h["event"], "tool": h["tool"], "paths": h["marker_paths"].get(marker, []),
                                    "before_first_model_request": first_ts is None or h["ts_ns"] < first_ts})
        surfaces[name] = {
            "marker": marker,
            "model_requests_carrying": len(carrying), "model_requests_total": len(gen),
            "first_model_request_seq": carrying[0]["seq"] if carrying else None,
            "model_sections": sorted({s for r in carrying for s in r["marker_hits"][marker]}),
            "hook_events": hook_events,
            "hook_event_names": sorted({e["event"] for e in hook_events}),
            "seen_by_decision_hook": any(e["event"] in DECISION_EVENTS for e in hook_events),
            "seen_by_result_hook": any(e["event"] in RESULT_EVENTS for e in hook_events),
            "seen_by_any_hook": bool(hook_events),
            "seen_by_any_hook_before_model": any(e["before_first_model_request"] for e in hook_events),
        }
    methods: dict[str, int] = {}
    for r in probe:
        methods[r["method"]] = methods.get(r["method"], 0) + 1
    scripted = [r for r in stub if r.get("scripted_tool")]
    offered_first = next((r["offered_tools"] for r in gen if r.get("offered_tools")), [])
    results = [t for r in stub for t in (r.get("tool_results") or [])]
    ua = next((r["headers"].get("user-agent") for r in stub if r.get("headers", {}).get("user-agent")), None)
    client_info = next((r["client"]["client_info"] for r in probe if r.get("client")), None)
    hook_events_all = {}
    for h in hooks:
        hook_events_all[h["event"]] = hook_events_all.get(h["event"], 0) + 1
    tool_calls_seen = [h for h in hooks if h["event"] in DECISION_EVENTS and h["event"] != "PermissionRequest"]
    needs_call = surface in ("tools", "resource")
    problems = []
    if not gen:
        problems.append("the stub received no model request")
    if needs_call and not scripted:
        problems.append("the stub never issued the scripted tool call")
    if needs_call and scripted and not scripted[0].get("scripted_tool_offered"):
        problems.append("the scripted tool was not among the tools the harness offered")
    if not hooks:
        problems.append("no hook event arrived (hook config dead or ignored)")
    return {
        "surfaces": surfaces, "probe_requests": methods, "hook_events_fired": hook_events_all,
        "offered_tools_first_request": offered_first, "scripted_tool": scripted[0]["scripted_tool"] if scripted else None,
        "scripted_tool_offered": scripted[0].get("scripted_tool_offered") if scripted else None,
        "tool_results": [{"is_error": t.get("is_error"), "text": t.get("text", "")[:160]} for t in results][:3],
        "stub_user_agent": ua, "probe_client_info": client_info, "stub_requests": len(stub),
        # Liveness is "some hook event arrived" (SessionStart, UserPromptSubmit, Stop ...). Whether the scripted tool call
        # itself reached a PreToolUse-class event is a RESULT, not a validity condition: a builtin resource tool that no
        # hook sees is the finding of the "resource" launch on that build.
        "scripted_call_pre_hooked": bool(tool_calls_seen) if needs_call and scripted else None,
        "valid": not problems, "problems": problems,
    }


# --- one launch --------------------------------------------------------------------------------------------------

def launch(harness: str, version: str, binary: list[str], surface: str, rep: int, work: Path, out: Path,
           order: int, codex_namespace: str = "mcp__probe", persist_trust: bool = False, model: str = "",
           drop_env: tuple[str, ...] = (), variant: str = "base") -> dict:
    tag = "nz" + hashlib.sha256(f"{harness}|{version}|{variant}|{surface}|{rep}|{order}".encode()).hexdigest()[:8]
    suffix = "" if variant == "base" else f"@{variant}"
    run = (work / f"{harness}-{version}{suffix}" / f"{surface}-rep{rep}").resolve()
    shutil.rmtree(run, ignore_errors=True)
    run.mkdir(parents=True)
    stub_log, hooks_log, probe_log = run / "stub.jsonl", run / "hooks.jsonl", run / "probe.jsonl"
    script = Script.from_obj(script_for(harness, surface, tag, codex_namespace))
    stub = StubServer(script, stub_log, dump_dir=run / "stub-dump", max_calls=1, markers=list(markers_for(tag).values()))
    stub.start()
    row: dict = {"harness": harness, "version": version, "surface_run": surface, "rep": rep, "tag": tag, "order": order,
                 "variant": variant, "model_id_sent": model or MODELS[harness], "dropped_env": list(drop_env),
                 "stub_url": stub.url}
    try:
        if urlparse(stub.url).hostname != "127.0.0.1":
            raise RuntimeError("stub is not on loopback")
        argv, env, cwd = build_launch(harness, version, binary, surface, tag, run, stub.url, hooks_log, probe_log,
                                      model, drop_env)
        row["env_leaks"] = leaks(harness, run, env)
        if row["env_leaks"]:
            row.update(valid=False, problems=["isolation check failed: " + "; ".join(row["env_leaks"])], launched=False)
            return row
        if persist_trust:
            row["codex_hook_trust"] = persist_codex_hook_trust(binary, env, cwd, run / "home" / "codex-home" / "config.toml")
        t0 = time.time()
        with (run / "stdout.txt").open("w") as so, (run / "stderr.txt").open("w") as se:
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=so, stderr=se,
                                    start_new_session=True)
            try:
                code = proc.wait(timeout=RUN_CAP_S)
                row["timed_out"] = False
            except subprocess.TimeoutExpired:
                code, row["timed_out"] = None, True
            try:  # the harness's children (the probe server, hook processes) go with it
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        row.update(launched=True, exit_code=code, seconds=round(time.time() - t0, 1), argv_head=[Path(argv[0]).name])
        time.sleep(0.3)
    finally:
        stub.stop()
    stub_rows, probe_rows, hook_rows = read_jsonl(stub_log), read_jsonl(probe_log), read_jsonl(hooks_log)
    row.update(analyse(harness, surface, tag, stub_rows, probe_rows, hook_rows))
    evidence = out / "evidence" / f"{harness}-{version}{suffix}" / f"{surface}-rep{rep}"
    evidence.mkdir(parents=True, exist_ok=True)
    for name in ("stub.jsonl", "probe.jsonl", "hooks.jsonl"):
        if (run / name).exists():
            shutil.copy(run / name, evidence / name)
    err = (run / "stderr.txt").read_text(errors="replace")[-600:] if (run / "stderr.txt").exists() else ""
    row["stderr_tail"] = err if not row["valid"] else ""
    return row


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--harness", required=True, choices=("claude", "codex", "gemini"))
    p.add_argument("--version", required=True)
    p.add_argument("--binary", required=True, nargs="+", help="the harness command (a .js file is run with node)")
    p.add_argument("--surfaces", default="tools,resource,prompt")
    p.add_argument("--reps", type=int, default=1)
    p.add_argument("--rep-start", type=int, default=0)
    p.add_argument("--work", required=True, type=Path, help="scratch directory outside the repo and the real HOME")
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--codex-namespace", default="mcp__probe",
                   help="namespace Codex gives the probe server's tools in the request (0.166: mcp__probe, no trailing __)")
    p.add_argument("--codex-persist-trust", action="store_true",
                   help="also write persisted hook trust (needed by 0.131); costs one model-free app-server launch per run")
    p.add_argument("--model", default="", help="model id to send (the stub ignores it; Codex picks tool exposure by slug)")
    p.add_argument("--drop-env", action="append", default=[], help="remove an env var the runner would set (repeatable)")
    p.add_argument("--variant", default="base", help="label for a non-default configuration (kept in rows and paths)")
    a = p.parse_args(argv)
    surfaces = [s for s in a.surfaces.split(",") if s]
    planned = len(surfaces) * a.reps * (2 if a.codex_persist_trust else 1)  # the trust step launches the harness binary too
    go = int(os.environ.get("HOOK_FIDELITY_GO", "0") or 0)
    if go < planned:
        print(f"refusing: this invocation plans {planned} launches, HOOK_FIDELITY_GO={go}", file=sys.stderr)
        return 2
    configs.check_root(a.work)
    binary = a.binary
    if len(binary) == 1 and binary[0].endswith(".js"):
        binary = [shutil.which("node") or "node", binary[0]]
    a.out.mkdir(parents=True, exist_ok=True)
    ledger = a.out / "ledger.jsonl"
    done = 0
    for rep in range(a.rep_start, a.rep_start + a.reps):
        for surface in surfaces:
            order = sum(1 for _ in ledger.open()) if ledger.exists() else 0
            row = launch(a.harness, a.version, binary, surface, rep, a.work, a.out, order, a.codex_namespace,
                         a.codex_persist_trust, a.model, tuple(a.drop_env), a.variant)
            done += row.get("launched", False)
            with (a.out / "rows.jsonl").open("a") as handle:
                handle.write(json.dumps(row) + "\n")
            with ledger.open("a") as handle:
                handle.write(json.dumps({"order": order, "harness": a.harness, "version": a.version, "surface_run": surface,
                                         "variant": a.variant, "rep": rep, "launched": row.get("launched", False),
                                         "valid": row["valid"],
                                         "hook_fidelity_go": go, "planned_this_invocation": planned,
                                         "ts": time.strftime("%Y-%m-%dT%H:%M:%S")}) + "\n")
            sc = row["surfaces"] if "surfaces" in row else {}
            print(f"{a.harness} {a.version} {surface} rep{rep}: valid={row['valid']} exit={row.get('exit_code')} "
                  f"stub_req={row.get('stub_requests')} problems={row.get('problems')} "
                  + " ".join(f"{k}:m{v['model_requests_carrying']}h{len(v['hook_event_names'])}" for k, v in sc.items()),
                  flush=True)
    print(f"launched {done} of {planned} planned (HOOK_FIDELITY_GO={go})", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
