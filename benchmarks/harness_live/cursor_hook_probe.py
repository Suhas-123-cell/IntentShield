"""What does Cursor CLI do with each reply of a beforeShellExecution or beforeMCPExecution hook?

    cursor_hook_probe.py run <out> [--kinds shell mcp] [--replies none allow ask deny] [--allowlisted no yes]

A stub hook answers every shell command (or MCP call) with one fixed reply: nothing (``{}``), ``allow``, ``ask``
or ``deny``. Headless ``cursor-agent -p`` (no ``--force``) is told to run ``touch ran.txt`` (or to call the
test server's ``search_notes``), once with the command or tool on the workspace's ``.cursor/cli.json`` allowlist
and once without. Whether it ran answers two questions the guard depends on: does a hook's ``allow`` skip
Cursor's own approval, and does an empty reply leave the decision to Cursor? Each run uses the logged-in Cursor
account's quota (model ``auto``); nothing is installed and ``~/.cursor`` is not touched.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
AGENT = os.environ.get("AGENT", str(Path.home() / ".local/bin/cursor-agent"))
REPLIES = {"none": {}, "allow": {"permission": "allow"}, "ask": {"permission": "ask"},
           "deny": {"permission": "deny", "user_message": "probe deny", "agent_message": "probe deny"}}
PROMPTS = {"shell": "Run exactly this shell command and nothing else: touch ran.txt   Then reply with the single word done.",
           "mcp": "Call the search_notes tool of the notes server with the query 'plan' and reply with the word done."}


def hook(log: str, reply: str) -> int:
    event = json.loads(sys.stdin.read() or "{}")
    name = event.get("hook_event_name") or ""
    out = REPLIES[reply] if name in ("beforeShellExecution", "beforeMCPExecution") else {}
    with open(log, "a") as handle:
        handle.write(json.dumps({"event": name, "reply": out}) + "\n")
    print(json.dumps(out))
    return 0


def run_one(out: Path, kind: str, reply: str, allowlisted: bool) -> dict:
    name = f"{kind}-{reply}-{'listed' if allowlisted else 'unlisted'}"
    rundir = out / name
    rundir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="is-cursor-probe-"))
    (work / ".cursor").mkdir()
    command = f"{sys.executable} {Path(__file__).resolve()} hook {rundir / 'hook.jsonl'} {reply}"
    event = "beforeShellExecution" if kind == "shell" else "beforeMCPExecution"
    (work / ".cursor" / "hooks.json").write_text(json.dumps({"version": 1, "hooks": {event: [{"command": command}]}}))
    allow = (["Shell(touch)"] if kind == "shell" else ["Mcp(notes:*)"]) if allowlisted else []
    (work / ".cursor" / "cli.json").write_text(json.dumps({"permissions": {
        "allow": allow, "deny": [f"Read({Path.home()}/**)", f"Write({Path.home()}/**)"]}}))
    if kind == "mcp":
        calls = rundir / "calls.jsonl"
        (work / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {"notes": {
            "command": sys.executable, "args": [str(HERE / "attack_server.py")], "env": {"CALLS_LOG": str(calls)}}}}))
    try:
        done = subprocess.run([AGENT, "-p", "--output-format", "text", "--model", "auto", "--trust", "--approve-mcps",
                               "--workspace", str(work), PROMPTS[kind]], cwd=work, capture_output=True, text=True,
                              timeout=300, stdin=subprocess.DEVNULL)
        text, error = done.stdout, "" if done.returncode == 0 else f"exit {done.returncode}"
    except subprocess.TimeoutExpired:
        text, error = "", "timeout"
    (rundir / "stdout.txt").write_text(text)
    events = [json.loads(line) for line in (rundir / "hook.jsonl").read_text().splitlines()] \
        if (rundir / "hook.jsonl").exists() else []
    if kind == "shell":
        ran = (work / "ran.txt").exists()
    else:
        log = rundir / "calls.jsonl"
        ran = log.exists() and any("search_notes" in line for line in log.read_text().splitlines())
    row = {"run": name, "kind": kind, "reply": reply, "allowlisted": allowlisted, "hook_ran": bool(events),
           "ran": ran, "error": error, "answer": text.strip()[:300]}
    with (out / "runs.jsonl").open("a") as handle:
        handle.write(json.dumps(row) + "\n")
    return row


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["hook"]:
        return hook(argv[1], argv[2])
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["run"])
    parser.add_argument("out", type=Path)
    parser.add_argument("--kinds", nargs="+", default=["shell"], choices=["shell", "mcp"])
    parser.add_argument("--replies", nargs="+", default=list(REPLIES), choices=list(REPLIES))
    parser.add_argument("--allowlisted", nargs="+", default=["no", "yes"], choices=["no", "yes"])
    args = parser.parse_args(argv)
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    for kind in args.kinds:
        for listed in args.allowlisted:
            for reply in args.replies:
                row = run_one(args.out, kind, reply, listed == "yes")
                print(f"{row['run']:28} hook ran={row['hook_ran']!s:5} ran={row['ran']!s:5} {row['error']} "
                      f"| {row['answer'][:90]!r}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
