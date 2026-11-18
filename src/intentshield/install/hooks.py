"""The hook entries ``install`` writes for each harness, and the command each one runs."""
from __future__ import annotations

import json
import re
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any

from intentshield import translation

from .textedit import _TOML_BEGIN, _TOML_END

HARNESSES = ("claude", "codex", "cursor", "gemini")
_HOOK = "intentshield-hook"
_PROXY = "intentshield-mcp"
_MCP_MATCHER = "mcp__.*|ReadMcpResource(Dir)?(Tool)?|ListMcpResources(Tool)?"
# Claude Code's built-in tools the hook reads with --builtin-tools: calls it checks, results it scans.
_BUILTIN_CALLS = "Bash|PowerShell|Monitor|WebFetch|Read|Grep|Write|Edit|MultiEdit|NotebookEdit"
_BUILTIN_RESULTS = "Bash|PowerShell|WebFetch|WebSearch|Read|Grep"


def executable(name: str) -> str:
    """The absolute path of a console script installed in this environment (a venv, pipx or uvx
    environment), else the bare name for PATH lookup. ``sys.executable`` is not resolved: in a uv
    venv it is a symlink to an interpreter that has no scripts beside it."""
    for directory in (Path(sys.executable).parent, Path(sys.prefix) / "bin", Path(sys.prefix) / "Scripts"):
        for candidate in (directory / name, directory / f"{name}.exe"):
            if candidate.exists():
                return str(candidate)
    return shutil.which(name) or name


# Where `uvx`, `pipx run` and `npx` unpack a program for one run: a cache that is cleaned, so a path recorded there stops working.
_EPHEMERAL = re.compile(r"/(?:archive-v\d+|builds-v\d+|environments-v\d+|\.cache/uv|uv/cache|pipx/\.cache|"
                        r"\.local/pipx/\.cache|_npx|\.npm/_npx|npx-cache)/", re.I)


def ephemeral_location(path: str) -> bool:
    """True when ``path`` lies in the cache of a run-once launcher (uvx, pipx run, npx)."""
    return bool(_EPHEMERAL.search(str(path).replace("\\", "/")))


def _refuse_ephemeral(path: str, what: str, dry_run: bool, allowed: bool) -> None:
    """A command installed from a run-once cache (``uvx --from intentshield-mcp intentshield install claude``) would name a
    path that a cache clean deletes, after which every MCP call is refused. Refused, with the way to install it for good;
    ``allowed`` (--allow-ephemeral) installs it anyway, and a dry run only warns."""
    if allowed or not ephemeral_location(path):
        return
    message = (f"{path} is in the cache of a run-once launcher (uvx, pipx run, npx), which is cleaned: the {what} recorded "
               "there would stop working and every guarded call would be refused. Install IntentShield first "
               "(`uv tool install intentshield-mcp` or `pipx install intentshield-mcp`) and run the command from that "
               "install; --allow-ephemeral records it anyway.")
    if dry_run:
        print(f"warning: {message}", file=sys.stderr)
        return
    raise ValueError(message)


def settings_path(harness: str, scope: str, home: Path | None = None, cwd: Path | None = None) -> Path:
    home = home or Path.home()
    cwd = cwd or Path.cwd()
    if scope == "project":
        if harness == "codex":
            raise ValueError("Codex CLI reads hooks from ~/.codex/config.toml only; use --scope user")
        # settings.local.json is Claude Code's file for one machine, and the hook command holds this machine's paths
        return cwd / {"claude": ".claude/settings.local.json", "cursor": ".cursor/hooks.json",
                      "gemini": ".gemini/settings.json"}[harness]
    return home / {"claude": ".claude/settings.json", "codex": ".codex/config.toml",
                   "cursor": ".cursor/hooks.json", "gemini": ".gemini/settings.json"}[harness]


_JUDGE_SPEC = re.compile(r"(ollama|groq|gemini|deepseek|openai|openrouter|custom|on|default)(:[A-Za-z0-9_.:/-]+)?")
_NEEDS_MODEL = ("openai", "openrouter", "custom")  # the user's own key: they name the model they pay for


def hook_command(harness: str, hook: str = _HOOK, review: str | None = None, judge: str | None = None,
                 judge_outputs: bool = False, builtin_tools: bool = False, gemini_ask: bool = False,
                 deadline: float | None = None) -> str:
    """The shell command the harness runs on every event. Every piece is quoted and validated:
    the harness hands the string to a shell."""
    command = f"{shlex.quote(hook)} {harness}"
    if review:
        if review not in ("tainted", "always", "never"):
            raise ValueError(f"--review must be tainted, always or never, not {review!r}")
        command += f" --review {shlex.quote(review)}"
    if judge:
        if not _JUDGE_SPEC.fullmatch(judge):
            raise ValueError(f"--judge must be groq, gemini, deepseek or ollama[:model], or openai, openrouter or "
                             f"custom:<model>, not {judge!r}")
        provider, _, model = judge.partition(":")
        if provider in _NEEDS_MODEL and not model:
            raise ValueError(f"--judge {provider} needs a model: --judge {provider}:<model>")
        command += f" --judge {shlex.quote(judge)}"
        if judge_outputs:
            command += " --judge-outputs"
    if builtin_tools:
        command += " --builtin-tools"
    if gemini_ask:
        if harness != "gemini":
            raise ValueError("--gemini-ask is for Gemini CLI only")
        command += " --gemini-ask"
    if deadline is not None:
        if not 0 < deadline < 3600:
            raise ValueError(f"--deadline must be between 0 and 3600 seconds, not {deadline!r}")
        command += f" --deadline {deadline:g}"
    return command


def hook_entries(harness: str, command: str, builtin_tools: bool = False, translate: bool = True) -> dict[str, Any]:
    """The hook configuration for one harness, as ``configs/harness/`` ships it. ``builtin_tools`` also sends
    the harness's own shell, file and web tools to the hook (whose command must carry --builtin-tools). With ``translate``
    the hooks that check a call run behind translation.launcher, so a hook that cannot start refuses the call."""
    if translate:
        entries = hook_entries(harness, command, builtin_tools, translate=False)
        guarded = translation.launcher(command) if harness in translation.LAUNCHER_HARNESSES else command
        for event in translation.CALL_EVENTS:
            for group in entries.get(event, []):
                hooks = group["hooks"] if "hooks" in group else [group]
                for hook in hooks:
                    if hook.get("command") == command:
                        hook["command"] = guarded
        return entries
    if harness == "claude":
        calls = f"{_MCP_MATCHER}|{_BUILTIN_CALLS}" if builtin_tools else _MCP_MATCHER
        results = f"{_MCP_MATCHER}|{_BUILTIN_RESULTS}" if builtin_tools else _MCP_MATCHER
        return {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": command}]}],
                "PreToolUse": [{"matcher": calls,
                                "hooks": [{"type": "command", "command": command, "onFailure": "block"}]}],
                "PostToolUse": [{"matcher": results, "hooks": [{"type": "command", "command": command}]}],
                # A tool result with isError:true arrives here instead of PostToolUse; its text is as
                # attacker-controlled as any other.
                "PostToolUseFailure": [{"matcher": results, "hooks": [{"type": "command", "command": command}]}]}
    if harness == "gemini":
        return {"BeforeAgent": [{"hooks": [{"type": "command", "command": command}]}],
                "BeforeTool": [{"matcher": ".*", "hooks": [{"type": "command", "command": command}]}],
                "AfterTool": [{"matcher": ".*", "hooks": [{"type": "command", "command": command}]}]}
    if harness == "cursor":
        entries = {"beforeSubmitPrompt": [{"command": command}],
                   "beforeMCPExecution": [{"command": command, "failClosed": True}],
                   "afterMCPExecution": [{"command": command}]}
        if builtin_tools:
            # beforeShellExecution: measured on Cursor CLI, a hook's ask or deny holds the command and its
            # empty reply (no objection) leaves it to Cursor's own approval.
            entries.update(beforeShellExecution=[{"command": command, "failClosed": True}],
                           beforeReadFile=[{"command": command, "failClosed": True}],
                           afterShellExecution=[{"command": command}])
        return entries
    if harness == "codex":
        # Codex has named its shell tool several ways; the hook ignores the tools it does not know.
        matcher = ".*" if builtin_tools else "mcp__.*"
        return {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": command}]}],
                "PreToolUse": [{"matcher": matcher, "hooks": [{"type": "command", "command": command}]}],
                "PostToolUse": [{"matcher": matcher, "hooks": [{"type": "command", "command": command}]}]}
    raise ValueError(f"Unknown harness: {harness}")


def _ours(entry: Any) -> bool:
    """Whether a hook entry runs intentshield-hook: its command's program is that executable, not
    merely a command that mentions it."""
    if not isinstance(entry, dict) or not isinstance(entry.get("command"), str):
        return False
    try:
        argv = shlex.split(entry["command"])
    except ValueError:
        return False
    return bool(argv) and Path(argv[0]).stem == _HOOK


def _without_ours(groups: list[Any]) -> list[Any]:
    """The groups with our handlers removed; a group that held other handlers too keeps them."""
    kept = []
    for group in groups:
        if _ours(group):
            continue
        if isinstance(group, dict) and isinstance(group.get("hooks"), list):
            handlers = [hook for hook in group["hooks"] if not _ours(hook)]
            if not handlers:
                continue
            group = {**group, "hooks": handlers}
        kept.append(group)
    return kept


def merge_hooks(settings: dict[str, Any], entries: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Put the entries in ``settings["hooks"]``, replacing any IntentShield handler already there
    (so a stale path from a deleted environment is repaired, not kept)."""
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("'hooks' is not an object")
    changed = False
    for event, groups in entries.items():
        existing = hooks.setdefault(event, [])
        if not isinstance(existing, list):
            raise ValueError(f"hooks.{event} is not a list")
        merged = _without_ours(existing) + groups
        if merged != existing:
            hooks[event] = merged
            changed = True
    # An event an earlier install used and this one does not (Cursor's beforeReadFile without --builtin-tools).
    for event in [e for e in hooks if e not in entries and isinstance(hooks[e], list)]:
        kept = _without_ours(hooks[event])
        if kept != hooks[event]:
            changed = True
            if kept:
                hooks[event] = kept
            else:
                del hooks[event]
    return settings, changed


def remove_hooks(settings: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return settings, False
    changed = False
    for event in list(hooks):
        groups = hooks[event]
        if not isinstance(groups, list):
            continue
        kept = _without_ours(groups)
        if kept != groups:
            changed = True
            if kept:
                hooks[event] = kept
            else:
                del hooks[event]
    if not hooks:
        del settings["hooks"]
    return settings, changed


def codex_toml(command: str, builtin_tools: bool = False, translate: bool = True) -> str:
    """The Codex CLI hook block, between markers so it can be removed again."""
    lines = [_TOML_BEGIN]
    for event, groups in hook_entries("codex", command, builtin_tools, translate).items():
        for group in groups:
            lines.append(f"[[hooks.{event}]]")
            if "matcher" in group:
                lines.append(f'matcher = "{group["matcher"]}"')
            for hook in group["hooks"]:
                lines.append(f"[[hooks.{event}.hooks]]")
                lines.append(f'type = "{hook["type"]}"')
                lines.append(f"command = {json.dumps(hook['command'])}")  # a TOML basic string; escapes a Windows path
            lines.append("")
    lines.append(_TOML_END)
    return "\n".join(lines) + "\n"


def _hook_flags(commands: list[str]) -> set[str]:
    """The options (with their values) of the ``intentshield-hook`` commands: ``--builtin-tools``, ``--review always``."""
    flags: set[str] = set()
    for command in commands:
        try:
            words = shlex.split(command)
        except ValueError:
            continue
        for k, word in enumerate(words):
            if word.startswith("--"):
                following = words[k + 1] if k + 1 < len(words) else ""
                value = "" if following.startswith("--") or word == "--builtin-tools" else following
                flags.add(f"{word} {value}".strip())
    return flags


def _our_commands(settings: Any) -> list[str]:
    """The hook commands of ``settings`` that run intentshield-hook."""
    found: list[str] = []
    hooks = settings.get("hooks") if isinstance(settings, dict) else None
    for groups in (hooks.values() if isinstance(hooks, dict) else ()):
        for group in (groups if isinstance(groups, list) else ()):
            for entry in [group, *(group.get("hooks") or [] if isinstance(group, dict) and isinstance(group.get("hooks"), list)
                                   else [])]:
                if _ours(entry):
                    found.append(entry["command"])
    return found


def _say_what_was_replaced(old: list[str], new: str) -> None:
    """A reinstall replaces the hooks as they were, so an option given the first time and not now is gone: say so."""
    gone = sorted(_hook_flags(old) - _hook_flags([new]))
    if gone:
        print(f"replaced the previous install; no longer set: {', '.join(gone)}. Give the option again to keep it.")
