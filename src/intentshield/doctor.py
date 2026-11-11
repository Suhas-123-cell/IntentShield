"""``intentshield doctor``: is the guard actually in the path of the agent?

    intentshield doctor [--home DIR] [--db FILE]

For each harness it checks that the settings file holds every IntentShield hook, that the hook command names an
executable that exists, that a hosted judge has its API key, and that the harness has run a hook since the hooks
were installed (Codex skips hooks nobody has trusted, without a word). An event a person pipes into the hook by hand is
told from a run by the harness (the harness's own process is not among the hook's ancestors) and does not count; for Cursor
that cannot be told. It also lists stdio MCP servers that are
not behind the transparent proxy, whose tool descriptions the hooks never see. For each harness it records the
version it finds on PATH (``~/.intentshield/harness-versions.json``, which the hooks read to choose their replies) and
prints what the hook-fidelity study measured for that version. Exit 1 on any problem. Apart from that record it reads
only. Only the standard library is imported.
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

from . import install, translation

# The events whose hooks a guarded harness needs: the prompt (intent), the call and its result.
REQUIRED = {"claude": ("UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure"),
            "codex": ("UserPromptSubmit", "PreToolUse", "PostToolUse"),
            "cursor": ("beforeSubmitPrompt", "beforeMCPExecution", "afterMCPExecution"),
            "gemini": ("BeforeAgent", "BeforeTool", "AfterTool")}
_KEYS = {"groq": "GROQ_API_KEY", "gemini": "GEMINI_API_KEY", "deepseek": "DEEPSEEK_API_KEY",
         "openai": "OPENAI_API_KEY", "openrouter": "OPENROUTER_API_KEY", "custom": "INTENTSHIELD_JUDGE_API_KEY"}
# Kept for callers that import it; the check itself reads translation.RANGES.
GEMINI_ASK_TESTED = (0, 38, 2)


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
            inner = group.get("hooks") if isinstance(group, dict) else None
            handlers = inner if isinstance(inner, list) else [group]
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


class Runs:
    """When the hooks ran, from their own database: per harness, and per working directory (a project's settings
    file is only run for sessions inside that project)."""

    def __init__(self, events: dict[str, float], dirs: list[tuple[str, str, float]],
                 piped: dict[str, float] | None = None) -> None:
        self.events, self.dirs = events, dirs
        # Events that reached a hook from a process that is not the harness (hand-piped): not runs by the harness.
        self.piped = piped or {}

    def last(self, harness: str, project: Path | None = None) -> float | None:
        """The latest hook run of the harness, inside ``project`` for a project's settings file. A database that
        has no per-directory rows yet (older hooks) answers for the harness as a whole."""
        if project is not None and any(h == harness for h, _, _ in self.dirs):
            root = str(project).rstrip("/") + "/"
            return max((t for h, cwd, t in self.dirs if h == harness and (cwd + "/").startswith(root)), default=None)
        return self.events.get(harness)


def _last_runs(db: Path) -> Runs | None:
    """When each harness last ran a hook, from the hooks' own database; None when it cannot tell."""
    if not db.exists():
        return Runs({}, [])
    try:
        with closing(sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)) as conn:
            events = dict(conn.execute("SELECT harness, last FROM harness_events").fetchall())
            try:
                dirs = conn.execute("SELECT harness, cwd, last FROM harness_dirs").fetchall()
            except sqlite3.Error:  # written by hooks of an earlier version
                dirs = []
            try:
                piped = dict(conn.execute("SELECT harness, last FROM harness_piped").fetchall())
            except sqlite3.Error:  # hooks of an earlier version kept no such record
                piped = {}
            return Runs(events, dirs, piped)
    except sqlite3.Error:  # a database from before the hooks recorded runs
        return None


_EXEC_LINE = re.compile(r"(?:^|[\s;'\"])exec'?\s+(?:\"([^\"]+)\"|'([^']+)'|(\S+))")


def _dead_interpreter(program: str) -> str:
    """Why a hook executable cannot start though the file is there: a script whose ``#!`` line names an interpreter
    that is gone (a venv built on a Python that was upgraded or removed). Such a hook exits 126 with the shell's error
    text on stderr. Claude Code and Codex treat that as a hook that failed, not as a refusal, so the call runs unguarded
    (Claude Code from 2.1.295 on also with ``onFailure: block``, which IntentShield's install sets, blocks it).
    Gemini CLI differs by release. Measured on the CLI against a stub model (results/hook-fidelity/gemini, 28 releases, 2 runs
    each) and on its hook runner (results/hook-fidelity/gemini-core, 25 releases): the call runs through 0.29.7 and is DENIED
    from 0.30.0, because the runner takes the error text as a block reason; the boundary lies between those two releases and
    the runner's hookRunner.js is byte-identical across 0.29.0 to 0.29.7 and across 0.30.0 to 0.30.1. The Gemini documentation
    says other exit codes only warn, so it is wrong for 0.30.0 and later. Bash on macOS only; a hook that exits 126 with no
    output at all is allowed on every release. The hooks ``intentshield install`` writes run behind a launcher that turns the
    exit code into a refusal (translation.launcher), so this check matters for hooks installed without it."""
    try:
        with open(program, "rb") as handle:
            head = handle.read(4096)
    except OSError:
        return ""
    first = head.split(b"\n", 1)[0].rstrip(b"\r")
    if not first.startswith(b"#!"):
        return ""
    words = first[2:].decode("utf-8", "replace").split()
    if not words:
        return ""
    interpreter = words[0]
    if os.path.basename(interpreter) == "env":  # #!/usr/bin/env python3: found on the PATH the harness has
        names = [w for w in words[1:] if not w.startswith("-") and "=" not in w]
        return "" if not names or shutil.which(names[0]) else f"{names[0]} (not on PATH)"
    if not (os.path.isfile(interpreter) and os.access(interpreter, os.X_OK)):
        return interpreter
    if os.path.basename(interpreter) in ("sh", "bash", "dash", "zsh"):
        # pip and uv write a shell shebang that execs the real interpreter when the venv path is long or has a
        # space: a #!/bin/sh line, then a line like  exec "/path with space/bin/python" "$0" "$@"
        for line in head.decode("utf-8", "replace").splitlines()[1:8]:
            if line.lstrip().startswith("#"):
                continue
            m = _EXEC_LINE.search(line)
            target = m and next(g for g in m.groups() if g)
            if target and target.startswith("/") and not (os.path.isfile(target) and os.access(target, os.X_OK)):
                return target
    return ""


def _harness_version(harness: str, home: Path) -> tuple[int, ...] | None:
    """The harness's version: read from the one on PATH (and recorded, for the hooks) when there is one, else the recorded
    one."""
    if harness == "gemini":
        found = gemini_version()
        if found:
            translation.record_version("gemini", ".".join(map(str, found)), shutil.which("gemini") or "", home)
    else:
        found = translation.probe_and_record(harness, home)
    return found if found is not None else translation.recorded_version(harness, home)[0]


def _dead_effect(harness: str, version: tuple[int, ...] | None, hooks: dict[str, list[dict[str, Any]]]) -> tuple[str, str]:
    """(level, what happens to a call) when the hook executable cannot start, by what was measured for the version."""
    calls = [h for event in translation.CALL_EVENTS for h in hooks.get(event, [])]
    launched = bool(calls) and all(translation.LAUNCHER in h["command"] for h in calls)
    shown = ".".join(map(str, version)) if version else "of an unknown version"
    if harness == "gemini":
        cls = translation.lookup("gemini", "dead", version)
        effect = {"blocks": f"Gemini CLI {shown} blocks every call the hook covers",
                  "runs": f"Gemini CLI {shown} runs the call unguarded (releases before 0.30.0 do)",
                  }.get(cls, "Gemini CLI blocks every call the hook covers from 0.30.0 and runs it unguarded through 0.29.7 "
                              f"(this one, {shown}, is not measured exactly)")
    elif harness == "claude":
        effect = "Claude Code runs the call unguarded (unless `onFailure: block` is honoured, from 2.1.295)"
    else:
        effect = f"{'Codex CLI' if harness == 'codex' else harness} runs the call unguarded"
    if launched:
        return "warn", (f"{effect}, but the launcher in front of the hook turns that into a refusal of the call "
                        "(results and prompts go unchecked)")
    return "FAIL", effect


def _disabled(harness: str, path: Path, home: Path, cwd: Path | None = None) -> str:
    """Why Claude Code runs no hooks though the file has them: ``disableAllHooks`` (or ``allowManagedHooksOnly``)
    in this settings file, its ``.local`` sibling, the user's, or the current project's (which switches off the
    user's hooks for sessions there)."""
    if harness != "claude":
        return ""
    project = [cwd / ".claude" / "settings.json", cwd / ".claude" / "settings.local.json"] if cwd else []
    for candidate in dict.fromkeys([path, path.with_name("settings.local.json"), home / ".claude" / "settings.json",
                                    home / ".claude" / "settings.local.json", *project]):
        try:
            data = install._parse(candidate.read_text(encoding="utf-8"), candidate)
        except (OSError, ValueError):
            continue
        for key in ("disableAllHooks", "allowManagedHooksOnly"):
            if isinstance(data, dict) and data.get(key) is True:
                return f"{key} is true in {candidate}"
    return ""


# Tool names the harness gives an MCP tool: a hook whose matcher does not match one guards no MCP call.
_MCP_NAME = {"claude": "mcp__server__tool", "codex": "mcp__server__tool", "gemini": "mcp_server_tool"}
_CALL_EVENT = {"claude": "PreToolUse", "codex": "PreToolUse", "gemini": "BeforeTool"}
_RESULT_EVENT = {"claude": "PostToolUse", "codex": "PostToolUse", "gemini": "AfterTool"}


def _covers_mcp(harness: str, matcher: str) -> bool:
    """Whether a matcher sends MCP tools to the hook: it matches an MCP tool name, or one of its alternatives is
    narrowed to some servers (``mcp__github__.*``) and so starts with the MCP prefix."""
    try:
        if re.search(matcher, _MCP_NAME[harness]) is not None:
            return True
    except re.error:
        return True
    return any(re.match(r"\^?\(*(?:\?:)?mcp_", alt.strip()) for alt in matcher.split("|"))


def _check_harness(report: Report, harness: str, path: Path, runs: Runs | None, home: Path,
                   project: Path | None = None, cwd: Path | None = None) -> bool:
    """Checks one settings file; False when it holds none of our hooks."""
    subject = f"{harness} ({path})"
    try:
        hooks = _hooks(harness, path)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        report.line("FAIL", subject, f"cannot read the settings file: {exc}")
        return True
    if not hooks:
        return False
    problems_before = report.problems
    before, why_stale = translation.recorded_version(harness, home)
    version = _harness_version(harness, home)
    if before is None and why_stale and not why_stale.startswith("no version"):
        # What the hook saw until this run: it sent every ask as a refusal, because it could not trust the recorded version.
        report.line("warn", subject, f"the recorded harness version was stale ({why_stale.split(' (run')[0]}); refreshed now. "
                                     "Until then the hook sent every ask as a refusal")
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
            elif dead := _dead_interpreter(program):
                level, effect = _dead_effect(harness, version, hooks)
                report.line(level, subject, f"the hook executable {program} starts with #!{dead}, which does not "
                                            "exist (an environment whose Python was removed or upgraded?): it exits 126, so "
                                            f"{effect}; "
                                            f"run `intentshield install {harness}` again from the environment you use")
        else:
            where = shutil.which(program)
            report.line("FAIL", subject, f"the hook command names {program!r} without a path"
                        + (f" (here it is {where}, but the harness may run with another PATH)" if where else
                           ", and it is not on PATH") + f"; run `intentshield install {harness}` again")
        if "--judge" in argv:
            provider = argv[argv.index("--judge") + 1].partition(":")[0] if argv.index("--judge") + 1 < len(argv) else ""
            key = _KEYS.get(provider)
            stored = _stored_keys(home)
            # The hook is a child of the harness: what this shell exports is not proof that the hook sees it.
            if provider == "custom" and "INTENTSHIELD_JUDGE_URL" not in stored:
                report.line("warn" if os.getenv("INTENTSHIELD_JUDGE_URL") else "FAIL", subject,
                            "the custom judge has no INTENTSHIELD_JUDGE_URL in "
                            f"{home / '.intentshield' / '.env'}"
                            + (" (it is set in this shell only, which a harness started elsewhere does not inherit)"
                               if os.getenv("INTENTSHIELD_JUDGE_URL") else "; every call runs on the rules alone")
                            + f". Run `intentshield install {harness} --judge custom:<model> --judge-url <URL>`")
            if key and key not in stored:
                report.line("warn" if os.getenv(key) else "FAIL", subject,
                            f"the {provider} judge has no {key} in {home / '.intentshield' / '.env'}"
                            + (" (it is set in this shell only, which a harness started from the Dock or an IDE "
                               "does not inherit, so the hook may run on the rules alone)" if os.getenv(key) else
                               "; every call runs on the rules alone")
                            + f". Run `intentshield install {harness} --judge {provider}` to store it")
        if "--builtin-tools" in argv and harness == "claude":
            matchers = [h.get("matcher") or "" for h in hooks.get("PreToolUse", [])]
            if not any("Bash" in m for m in matchers):
                report.line("FAIL", subject, "the hook reads built-in tools but its PreToolUse matcher does not send "
                                             "Bash; run `intentshield install claude --builtin-tools` again")
        if "--gemini-ask" in argv and harness == "gemini":
            _check_gemini_ask(report, subject, version)
    if why := _disabled(harness, path, home, cwd):
        report.line("FAIL", subject, f"the hooks are installed but switched off: {why}")
    if harness in translation.LAUNCHER_HARNESSES:
        plain = [h for event in translation.CALL_EVENTS for h in hooks.get(event, []) if translation.LAUNCHER not in h["command"]]
        if plain:
            report.line("warn", subject, "the hook that checks calls was installed without the verdict translation (no launcher, "
                                         "no deadline): a hook that cannot start, or a slow one, lets the call run on every "
                                         f"harness measured; run `intentshield install {harness}` again")
    gemini_ask = any("--gemini-ask" in h["command"] for handlers in hooks.values() for h in handlers)
    for level, message in translation.findings(harness, version, gemini_ask):
        report.line(level, subject, message)
    for event, what in ((_CALL_EVENT.get(harness), "call is checked"),
                        (_RESULT_EVENT.get(harness), "result is scanned or tainted")):
        for handler in hooks.get(event or "", []):
            matcher = handler.get("matcher")
            if matcher is not None and not _covers_mcp(harness, matcher):
                report.line("FAIL", subject, f"the {event} matcher {matcher!r} does not match MCP tools, so no MCP "
                                             f"{what}; run `intentshield install {harness}` again")
    # When install last changed the hooks (not the file's modification time, which every unrelated edit moves).
    installed = install.installed_at(path, home) or path.stat().st_mtime
    last = runs.last(harness, project) if runs is not None else None
    if runs is None:
        report.line("warn", subject, "the hook database predates run records; cannot tell whether the hooks run")
    elif last is None or last < installed:
        piped = runs.piped.get(harness)
        if piped is not None and piped >= installed:
            # Something fed an event to the hook, but not the harness's own process (the process tree holds none): a person
            # piping an event in looks like this, and so does a harness an IDE starts under another name. Not a run, and
            # not called a failure either.
            report.line("warn", subject, "installed; the only events since "
                        f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(installed))} reached the hook from a process that is "
                        f"not {harness} (last at {time.strftime('%Y-%m-%d %H:%M', time.localtime(piped))}), which is what a "
                        f"hand-piped test event looks like, so it is not counted as a run. Start {harness} once and make a "
                        "tool call; if this stays, the harness is not running the hooks.")
        else:
            hint = (" Codex skips hooks nobody has trusted: start `codex` and approve the IntentShield hooks."
                    if harness == "codex" else f" Start {harness} once; if this stays, the harness is not running them.")
            report.line("FAIL", subject, "installed, but no hook has run since "
                        f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(installed))}.{hint}")
    elif report.problems == problems_before:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(last))
        note = " (Cursor's hooks cannot be told from an event piped in by hand)" if harness == "cursor" else ""
        report.line("ok", subject, f"hooks installed; last ran {when}{note}")
    return True


def _check_gemini_ask(report: Report, subject: str, version: tuple[int, ...] | None = None) -> None:
    """--gemini-ask by what was measured (translation.RANGES): a hook's ask ran the shell call in yolo mode through 0.37.2 and
    waits for ever in a headless yolo run from 0.38.0 (measured; so with the shell allow-listed). An interactive session was not
    run: it is expected to get a prompt from 0.38.0 on, and the hook
    sends an ask only there (it sends a refusal when it can tell the run is headless)."""
    version = version if version is not None else gemini_version()
    if version is None:
        report.line("warn", subject, "--gemini-ask is on, but the Gemini CLI version could not be read; it was measured on "
                                     "0.24.5 to 0.66.0 only")
        return
    shown = ".".join(map(str, version))
    cls = translation.lookup("gemini", "ask", version)
    if cls in ("dropped", "uncertain", "unmeasured"):
        ran = "ran" if cls == "dropped" else "may run"
        report.line("FAIL", subject, f"--gemini-ask is on, but Gemini CLI {shown} {ran} a call "
                                     "its hook asked about in yolo mode (measured: through 0.37.2 it did, 0.38.0 and later wait; "
                                     "the releases between are not measured). Update Gemini CLI or run `intentshield install "
                                     "gemini` without --gemini-ask")
    else:
        report.line("warn", subject, "--gemini-ask is on: interactive sessions get a prompt, but a headless run "
                                     "(gemini -p) waits for an answer that never comes (yolo, measured on 0.38.0 to 0.66.0)")


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
                    backup = install._backup_path(path, None)
                    how = (f"`intentshield unwrap {path}` restores it from {backup}"
                           if install._backed_up_server(path, scope, name) else
                           f"no copy of the original entry is kept, so edit {path} by hand (put the server's own "
                           "command and args back) or delete the entry")
                    report.line("FAIL", f"{path}", f"{label} runs the proxy with a missing config {config!r}; {how}")
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
            # a project's settings file (cwd/.claude/settings.json) is run for sessions inside that project only
            project = path.parent.parent if path != paths[0] else None
            if path.exists() and _check_harness(report, harness, path, runs, home, project, cwd):
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
