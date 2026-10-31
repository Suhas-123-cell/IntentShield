"""``intentshield doctor``: is the guard actually in the path of the agent?

    intentshield doctor [--home DIR] [--db FILE]

For each harness it checks that the settings file holds every IntentShield hook, that the hook command names an
executable that exists, that a hosted judge has its API key, and that the harness has run a hook since the hooks
were installed (Codex skips hooks nobody has trusted, without a word). It also lists stdio MCP servers that are
not behind the transparent proxy, whose tool descriptions the hooks never see. Exit 1 on any problem. Reads
only; it changes nothing. Only the standard library is imported.
"""
from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import time
import tomllib
from contextlib import closing
from pathlib import Path
from typing import Any

from . import install

# The events whose hooks a guarded harness needs: the prompt (intent), the call and its result.
REQUIRED = {"claude": ("UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure"),
            "codex": ("UserPromptSubmit", "PreToolUse", "PostToolUse"),
            "cursor": ("beforeSubmitPrompt", "beforeMCPExecution", "afterMCPExecution"),
            "gemini": ("BeforeAgent", "BeforeTool", "AfterTool")}
_KEYS = {"groq": "GROQ_API_KEY", "gemini": "GEMINI_API_KEY", "deepseek": "DEEPSEEK_API_KEY",
         "openai": "OPENAI_API_KEY", "openrouter": "OPENROUTER_API_KEY", "custom": "INTENTSHIELD_JUDGE_API_KEY"}
# The oldest Gemini CLI on which a hook's ask was measured to be a prompt (in 0.37.1 yolo mode approved it).
GEMINI_ASK_TESTED = (0, 66, 0)


def gemini_version() -> tuple[int, ...] | None:
    """The installed Gemini CLI's version, or None when it cannot be read."""
    program = shutil.which("gemini")
    if not program:
        return None
    try:
        out = subprocess.run([program, "--version"], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    return tuple(int(part) for part in match.groups()) if match else None


class Report:
    def __init__(self) -> None:
        self.problems = 0

    def line(self, level: str, subject: str, message: str) -> None:
        self.problems += level == "FAIL"
        print(f"{level:<4} {subject}: {message}")


def _hooks(harness: str, path: Path) -> dict[str, list[dict[str, Any]]]:
    """Our handlers in a settings file, by event (each with its "command" and, where set, the group's matcher)."""
    if harness == "codex":
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    else:
        data = install._read_json(path)
    hooks = data.get("hooks") if isinstance(data, dict) else None
    found: dict[str, list[dict[str, Any]]] = {}
    for event, groups in (hooks.items() if isinstance(hooks, dict) else ()):
        for group in groups if isinstance(groups, list) else ():
            handlers = group.get("hooks") if isinstance(group, dict) and isinstance(group.get("hooks"), list) else [group]
            for handler in handlers:
                if install._ours(handler):
                    found.setdefault(event, []).append({"command": handler["command"],
                                                        "matcher": group.get("matcher") if isinstance(group, dict) else None})
    return found


def _stored_keys(home: Path) -> set[str]:
    try:
        lines = (home / ".intentshield" / ".env").read_text().splitlines()
    except OSError:
        return set()
    return {line.partition("=")[0].strip() for line in lines if "=" in line and line.partition("=")[2].strip()}


def _last_runs(db: Path) -> dict[str, float] | None:
    """When each harness last ran a hook, from the hooks' own database; None when it cannot tell."""
    if not db.exists():
        return {}
    try:
        with closing(sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)) as conn:
            return dict(conn.execute("SELECT harness, last FROM harness_events").fetchall())
    except sqlite3.Error:  # a database from before the hooks recorded runs
        return None


def _check_harness(report: Report, harness: str, path: Path, runs: dict[str, float] | None, home: Path) -> bool:
    """Checks one settings file; False when it holds none of our hooks."""
    subject = f"{harness} ({path})"
    try:
        hooks = _hooks(harness, path)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        report.line("FAIL", subject, f"cannot read the settings file: {exc}")
        return True
    if not hooks:
        return False
    missing = [event for event in REQUIRED[harness] if event not in hooks]
    if missing:
        report.line("FAIL", subject, f"no IntentShield hook for {', '.join(missing)}; run `intentshield install {harness}`")
    commands = {h["command"] for handlers in hooks.values() for h in handlers}
    for command in sorted(commands):
        argv = shlex.split(command)
        program = argv[0]
        if os.path.isabs(program):
            if not (os.path.isfile(program) and os.access(program, os.X_OK)):
                report.line("FAIL", subject, f"the hook executable {program} does not exist (a deleted environment?); "
                                             f"run `intentshield install {harness}` again from the one you use")
        else:
            where = shutil.which(program)
            report.line("FAIL", subject, f"the hook command names {program!r} without a path"
                        + (f" (here it is {where}, but the harness may run with another PATH)" if where else
                           ", and it is not on PATH") + f"; run `intentshield install {harness}` again")
        if "--judge" in argv:
            provider = argv[argv.index("--judge") + 1].partition(":")[0] if argv.index("--judge") + 1 < len(argv) else ""
            key = _KEYS.get(provider)
            if provider == "custom" and not os.getenv("INTENTSHIELD_JUDGE_URL") \
                    and "INTENTSHIELD_JUDGE_URL" not in _stored_keys(home):
                report.line("FAIL", subject, "the custom judge has no INTENTSHIELD_JUDGE_URL; every call runs on the "
                                             f"rules alone. Run `intentshield install {harness} --judge custom:<model> "
                                             "--judge-url <URL>`")
            if key and not os.getenv(key) and key not in _stored_keys(home):
                report.line("FAIL", subject, f"the {provider} judge has no {key} (neither set nor in "
                                             f"{home / '.intentshield' / '.env'}); every call runs on the rules alone. "
                                             f"Run `intentshield install {harness} --judge {provider}`")
        if "--builtin-tools" in argv and harness == "claude":
            matchers = [h.get("matcher") or "" for h in hooks.get("PreToolUse", [])]
            if not any("Bash" in m for m in matchers):
                report.line("FAIL", subject, "the hook reads built-in tools but its PreToolUse matcher does not send "
                                             "Bash; run `intentshield install claude --builtin-tools` again")
        if "--gemini-ask" in argv and harness == "gemini":
            _check_gemini_ask(report, subject)
    installed = path.stat().st_mtime
    last = (runs or {}).get(harness)
    if runs is None:
        report.line("warn", subject, "the hook database predates run records; cannot tell whether the hooks run")
    elif last is None or last < installed:
        hint = (" Codex skips hooks nobody has trusted: start `codex` and approve the IntentShield hooks."
                if harness == "codex" else f" Start {harness} once; if this stays, the harness is not running them.")
        report.line("FAIL", subject, "installed, but no hook has run since "
                    f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(installed))}.{hint}")
    elif not missing:
        report.line("ok", subject, f"hooks installed; last ran {time.strftime('%Y-%m-%d %H:%M', time.localtime(last))}")
    return True


def _check_gemini_ask(report: Report, subject: str) -> None:
    version = gemini_version()
    tested = ".".join(map(str, GEMINI_ASK_TESTED))
    if version is None:
        report.line("warn", subject, f"--gemini-ask is on, but the Gemini CLI version could not be read; it was "
                                     f"tested on {tested} and later only")
    elif version < GEMINI_ASK_TESTED:
        report.line("FAIL", subject, f"--gemini-ask is on, but Gemini CLI {'.'.join(map(str, version))} is older "
                                     f"than {tested}; on 0.37.1 yolo mode ran a call the hook asked about. Update "
                                     "Gemini CLI or run `intentshield install gemini` without --gemini-ask")
    else:
        report.line("warn", subject, "--gemini-ask is on: interactive sessions get a prompt, but a headless run "
                                     "(gemini -p) waits for an answer that never comes")


def _check_servers(report: Report, path: Path) -> None:
    try:
        groups = install._server_groups(install._read_json(path))
    except (OSError, ValueError) as exc:
        report.line("warn", str(path), f"cannot read MCP servers: {exc}")
        return
    bare = []
    for scope, entries in groups:
        for name, server in entries.items():
            if not isinstance(server, dict) or not server.get("command") or server.get("url"):
                continue
            label = install._label(name, scope)
            if install._is_wrapped(server):
                args = server.get("args") or []
                config = args[args.index("--config") + 1] if "--config" in args[:-1] else ""
                if not config or not Path(config).exists():
                    report.line("FAIL", f"{path}", f"{label} runs the proxy with a missing config {config!r}; "
                                                   f"run `intentshield unwrap` and `wrap` on {path}")
            else:
                bare.append(label)
    if bare:
        report.line("warn", str(path), f"{len(bare)} stdio server(s) not behind the transparent proxy, so their tool "
                                       f"descriptions go unchecked: {', '.join(sorted(bare))}. "
                                       f"Run `intentshield wrap {path}`")


def doctor(home: Path | None = None, cwd: Path | None = None, db: Path | None = None) -> int:
    home, cwd = home or Path.home(), cwd or Path.cwd()
    db = db or Path(os.getenv("INTENTSHIELD_HOOK_DB") or home / ".intentshield" / "hooks.db")
    report = Report()
    runs = _last_runs(db)
    guarded = []
    for harness in install.HARNESSES:
        paths = [install.settings_path(harness, "user", home, cwd)]
        if harness != "codex":
            paths.append(install.settings_path(harness, "project", home, cwd))
        for path in dict.fromkeys(paths):
            if path.exists() and _check_harness(report, harness, path, runs, home):
                guarded.append(harness)
    for harness in install.HARNESSES:
        if harness not in guarded:
            report.line("--", harness, f"no IntentShield hooks (run `intentshield install {harness}` if you use it)")
    for path in (home / ".claude.json", cwd / ".mcp.json", home / ".cursor" / "mcp.json", cwd / ".cursor" / "mcp.json",
                 home / ".gemini" / "settings.json", cwd / ".gemini" / "settings.json"):
        if path.exists():
            _check_servers(report, path)
    print(f"\n{report.problems} problem(s)" if report.problems else "\nno problems found")
    return 1 if report.problems else 0


def add_subcommand(sub: Any) -> None:
    p = sub.add_parser("doctor", help="check that the IntentShield hooks and proxies are installed and running")
    p.add_argument("--db", type=Path, default=None, help="the hooks' database (default ~/.intentshield/hooks.db)")


def run(args: argparse.Namespace) -> int:
    try:
        return doctor(db=args.db)
    except OSError as exc:
        print(f"intentshield doctor: {exc}", file=sys.stderr)
        return 1
