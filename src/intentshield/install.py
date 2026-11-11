"""Install IntentShield into an agent harness, or wrap MCP servers in the transparent proxy.

    intentshield install claude|codex|cursor|gemini [--scope user|project]
    intentshield uninstall claude|codex|cursor|gemini [--scope user|project]
    intentshield wrap <mcp config JSON> [--server NAME ...]
    intentshield unwrap <mcp config JSON> [--server NAME ...]

``install`` merges the hook entries (the same ones as ``configs/harness/``) into the harness's own
settings file, naming the ``intentshield-hook`` executable that sits next to this interpreter, so
the harness finds it without PATH changes. ``wrap`` rewrites every stdio server in an
``mcpServers`` file (Claude Code ``.mcp.json``, Cursor ``mcp.json``, Gemini CLI ``settings.json``,
or any client that uses that layout) to launch ``intentshield-mcp --transparent`` in front of it,
with one generated proxy config per server. Both are idempotent and reversible. Only the standard
library is imported, so the commands start fast.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import shlex
import shutil
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Any, Callable

from . import translation

HARNESSES = ("claude", "codex", "cursor", "gemini")
_HOOK = "intentshield-hook"
_PROXY = "intentshield-mcp"
_MCP_MATCHER = "mcp__.*|ReadMcpResource(Dir)?(Tool)?|ListMcpResources(Tool)?"
# Claude Code's built-in tools the hook reads with --builtin-tools: calls it checks, results it scans.
_BUILTIN_CALLS = "Bash|PowerShell|Monitor|WebFetch|Read|Grep|Write|Edit|MultiEdit|NotebookEdit"
_BUILTIN_RESULTS = "Bash|PowerShell|WebFetch|WebSearch|Read"
_SERVER_ID = re.compile(r"[^A-Za-z0-9_.-]")


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


_KEY_FOR = {"groq": "GROQ_API_KEY", "gemini": "GEMINI_API_KEY", "deepseek": "DEEPSEEK_API_KEY",
            "openai": "OPENAI_API_KEY", "openrouter": "OPENROUTER_API_KEY", "custom": "INTENTSHIELD_JUDGE_API_KEY"}


def ensure_judge_key(judge: str, home: Path | None = None, api_key: str | None = None,
                     ask: Callable[[str], str] = getpass.getpass, judge_url: str | None = None,
                     dry_run: bool = False) -> Path | None:
    """The key a hosted judge needs, stored in ``~/.intentshield/.env`` (0600) where every hook
    process reads it. A key that is only exported in this shell is stored too, since a harness started
    elsewhere would not have it. Asks on the terminal when it is neither given nor set. A custom
    judge's endpoint (``judge_url``) is stored beside it. Returns the file written, or None when
    nothing was needed. With ``dry_run`` the arguments are checked exactly as for a real install (a custom judge's
    endpoint, ``--judge-url`` on another judge) but nothing is stored, asked for or printed."""
    provider = judge.partition(":")[0]
    env = _KEY_FOR.get(provider)
    if env is None:  # ollama: local, no key
        return None
    if provider == "custom":
        from .judge import JUDGE_URL_ENV, checked_judge_url
        if judge_url:
            checked = checked_judge_url(judge_url)
            if not dry_run:
                _store_env(home, JUDGE_URL_ENV, checked)
        elif not _read_env(home).get(JUDGE_URL_ENV):
            if not os.getenv(JUDGE_URL_ENV):
                raise ValueError("--judge custom needs --judge-url <OpenAI-compatible chat completions URL>")
            # Exported in this shell only: stored, and checked now, like the key (a hook does not see this shell).
            checked = checked_judge_url(os.environ[JUDGE_URL_ENV])
            if not dry_run:
                stored_url = _store_env(home, JUDGE_URL_ENV, checked)
                print(f"{JUDGE_URL_ENV} is set in this shell only; storing it in {stored_url}, which every hook reads")
    elif judge_url:
        raise ValueError("--judge-url is for --judge custom only")
    stored = _read_env(home)
    if not api_key and stored.get(env):
        return None
    if dry_run:  # what a real install would fail on without a terminal to ask at
        if not api_key and not os.getenv(env) and not sys.stdin.isatty() and ask is getpass.getpass:
            raise ValueError(f"{env} is not set; pass --api-key or export it before `install --judge {provider}`")
        return None
    path = _env_path(home)
    if not api_key and os.getenv(env):
        # Exported in this shell. A hook runs as a child of the harness, and one started from the Dock or an IDE
        # does not inherit this shell's variables, so the key is stored where every hook reads it.
        api_key = os.environ[env]
        print(f"{env} is set in this shell only; storing it in {path}, which every hook reads "
              "(a harness started from the Dock or an IDE does not see this shell's variables)")
    if not api_key:
        if ask is getpass.getpass and not sys.stdin.isatty():
            raise ValueError(f"{env} is not set; pass --api-key or export it before `install --judge {provider}`")
        api_key = ask(f"{env} for the {provider} judge (stored in {path}, never printed): ").strip()
        if not api_key:
            raise ValueError(f"no {env} given")
    return _store_env(home, env, api_key)


def _private_dir(directory: Path) -> None:
    """Creates ``directory``; ``~/.intentshield`` (API keys, prompts, backups) is readable by its owner only."""
    translation.private_dir(directory)


def _env_path(home: Path | None) -> Path:
    path = (home or Path.home()) / ".intentshield" / ".env"
    if path.is_symlink():  # the key would land wherever the link points
        raise ValueError(f"{path} is a symbolic link; replace it with a regular file before storing a key")
    return path


def _read_env(home: Path | None) -> dict[str, str]:
    path = _env_path(home)
    stored = {}
    for line in (path.read_text().splitlines() if path.exists() else []):
        key, sep, value = line.strip().partition("=")
        if sep and not key.startswith("#"):
            stored[key] = value
    return stored


def _store_env(home: Path | None, env: str, value: str) -> Path:
    """Sets one KEY=value line in ``~/.intentshield/.env`` (0600), every other line as it was."""
    if "\n" in value or "\r" in value:
        raise ValueError(f"{env} must be one line")
    path = _env_path(home)
    lines = path.read_text().splitlines() if path.exists() else []
    stored = _read_env(home)
    # Every other line (comments, other keys) stays as it was; only this key's line changes.
    entry = f"{env}={value}"
    replaced = [entry if line.strip().partition("=")[0] == env else line for line in lines]
    lines = replaced if env in stored else [*lines, entry]
    _private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".env.")  # created 0600: the key is never readable by others
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write("\n".join(lines) + "\n")
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    print(f"stored {env} in {path}")
    return path


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


_TOML_BEGIN, _TOML_END = "# >>> intentshield hooks >>>", "# <<< intentshield hooks <<<"


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


def _strip_toml_block(text: str) -> tuple[str, bool]:
    """``text`` without our block. Only a well-formed BEGIN..END pair is cut: a lone marker or one in the
    wrong order is a file somebody edited, and cutting between them would take their lines too."""
    start, end = text.find(_TOML_BEGIN), text.find(_TOML_END)
    if (start < 0) != (end < 0) or end < start:
        raise ValueError(f"the IntentShield block markers are damaged ({_TOML_BEGIN!r} and {_TOML_END!r} must "
                         "both be present, in that order); fix or delete them by hand")
    if start < 0:
        return text, False
    before = text[:start].rstrip("\n")
    after = text[end + len(_TOML_END):].lstrip("\n")
    if before and after:
        return before + "\n\n" + after, True
    return (before + "\n" if before else after), True


# The text each settings file had when this process read it: a harness (Claude Code rewrites ~/.claude.json
# all the time) may write the file between our read and our write, and its change must not be overwritten.
_SEEN: dict[Path, str] = {}


class ChangedMeanwhile(OSError):
    pass


def strip_json_comments(text: str) -> str:
    """``text`` without ``//`` and ``/* */`` comments and trailing commas (outside strings), as Gemini CLI reads its settings; a
    comment becomes blanks, so the positions in an error message still point at the right place."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(ch if ch in "\r\n" else " " for ch in text[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return _drop_trailing_commas("".join(out))


def _drop_trailing_commas(text: str) -> str:
    """``text`` with the comma before a closing ``}`` or ``]`` (outside strings) blanked: ``{"a": 1,}`` as JSONC allows it."""
    out, i, n = list(text), 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            i += 1
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                out[i] = " "
            i += 1
        else:
            i += 1
    return "".join(out)


def _has_comments(path: Path) -> bool:
    """Gemini CLI and VS Code read their settings with comments allowed; every other client's file is strict JSON."""
    return path.parent.name in (".gemini", ".vscode") or (path.parent.name == "User" and path.parent.parent.name in ("Code",
        "Code - Insiders"))


def _parse(text: str, path: Path) -> Any:
    return json.loads(strip_json_comments(text) if _has_comments(path) else text)


_COMMENTED: set[Path] = set()  # files read with comments in them: writing them back drops the comments


class _NotJSON(json.JSONDecodeError):
    """A settings file that does not parse, with a message that says what to do."""

    def __init__(self, text: str, exc: json.JSONDecodeError) -> None:
        super().__init__(exc.msg, exc.doc, exc.pos)
        self.text = text

    def __str__(self) -> str:
        return self.text


def _exact_text(path: Path) -> str:
    """The file's text with its line endings as they are (``read_text`` would turn CRLF into LF)."""
    return path.read_bytes().decode("utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    _SEEN[path.resolve()] = text
    if not text.strip():
        return {}
    try:
        data = _parse(text, path)
    except json.JSONDecodeError as exc:
        how = ("fix that line" if _has_comments(path) else
               "remove its comments and trailing commas (this file is read as strict JSON)")
        if text.startswith("\ufeff"):
            how = "save it as UTF-8 without a byte order mark (it starts with one, which JSON does not allow)"
        raise _NotJSON(f"{path} is not valid JSON ({exc.msg}, line {exc.lineno} column {exc.colno}); {how}, or add the entries "
                       "by hand from the output of `intentshield install <harness> --dry-run`", exc) from None
    if _has_comments(path) and strip_json_comments(text) != text:
        _COMMENTED.add(path.resolve())
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a JSON object")
    return data


def _is_toml(path: Path) -> bool:
    return path.suffix.lower() == ".toml"


def _client_data(text: str, path: Path) -> dict[str, Any]:
    """The servers of a client file's text in the layout ``_server_groups`` reads: a Codex CLI ``config.toml`` keeps them in
    ``[mcp_servers.NAME]`` tables, which are the ``mcpServers`` object of the JSON clients."""
    if _is_toml(path):
        servers = tomllib.loads(text).get("mcp_servers")
        return {"mcpServers": servers} if isinstance(servers, dict) else {}
    data = _parse(text, path)
    return data if isinstance(data, dict) else {}


def _read_client(path: Path) -> dict[str, Any]:
    """Like ``_read_json``, for a TOML client file too."""
    if not _is_toml(path):
        return _read_json(path)
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    _SEEN[path.resolve()] = text
    try:
        return _client_data(text, path)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"{path} is not valid TOML ({exc}); fix it, or add the entries by hand "
                         "(see docs/gateway.md#real-mcp-proxy)") from None


def _write(path: Path, text: str, dry_run: bool) -> None:
    """Atomic: the user's settings file is never left truncated."""
    if dry_run:
        print(f"--- would write {path}\n{text}", end="")
        return
    if path.is_symlink():  # a dotfiles link: write its target, not a regular file in its place
        path = path.resolve()
    _private_dir(path.parent)
    if path.resolve() in _COMMENTED and strip_json_comments(text) == text:  # JSON has nowhere to keep them
        print(f"warning: {path} has comments or trailing commas, which are not kept when it is rewritten; its original "
              "text is saved and `intentshield uninstall` (or `unwrap`) puts it back, comments included.", file=sys.stderr)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        if path.exists():
            os.chmod(tmp, path.stat().st_mode & 0o777)
        seen = _SEEN.get(path.resolve())
        if seen is not None and (path.read_text(encoding="utf-8") if path.exists() else "") != seen:
            raise ChangedMeanwhile(f"{path} changed while IntentShield was editing it (the harness wrote it?); "
                                   "nothing was written. Run the command again.")
        os.replace(tmp, path)
        _SEEN[path.resolve()] = text
        _COMMENTED.discard(path.resolve())
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _json_text(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def _backup_path(path: Path, home: Path | None) -> Path:
    key = hashlib.sha256(str(path.resolve()).encode()).hexdigest()[:16]
    return (home or Path.home()) / ".intentshield" / "backups" / f"{key}.json"


def _keep_original(path: Path, home: Path | None, dry_run: bool) -> None:
    """Before the first change to a user's JSON file, keep its exact bytes: JSON keeps no formatting to
    round-trip, so undoing the change puts these back when nothing else changed meanwhile."""
    backup = _backup_path(path, home)
    if path.exists() and not dry_run and not backup.exists():
        _write(backup, json.dumps({"path": str(path.resolve()), "text": _exact_text(path)}), False)


def _remember_servers(path: Path, servers: dict[str, dict[str, Any]]) -> None:
    """Add the entries a wrap is about to rewrite (key: JSON of [scope, name]) to the backup, so a later unwrap
    restores the command and args each had at its latest wrap, not the ones of the first wrap in the file."""
    backup = _backup_path(path, None)
    try:
        saved = json.loads(backup.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if isinstance(saved, dict):
        known = saved.get("servers")
        saved["servers"] = {**(known if isinstance(known, dict) else {}), **servers}
        _write(backup, json.dumps(saved), False)


def _without_empty_hooks(data: Any) -> Any:
    return {k: v for k, v in data.items() if not (k == "hooks" and v == {})} if isinstance(data, dict) else data


def _undone_text(path: Path, data: dict[str, Any], home: Path | None) -> tuple[str, bool]:
    """The file's text with our change undone: its original bytes (True) when the rest is as it was."""
    backup = _backup_path(path, home)
    if backup.exists():
        original = json.loads(backup.read_text(encoding="utf-8"))["text"]
        try:
            # An empty "hooks" object the file had is dropped when the last hook goes (remove_hooks), which is not a change
            # of the user's: compared without it, the original text, comments included, comes back.
            if _without_empty_hooks(_parse(original or "{}", path)) == _without_empty_hooks(data):
                return original, True
        except json.JSONDecodeError:
            pass
    return _json_text(data), False


def _undone_toml(path: Path, text: str, home: Path | None) -> tuple[str, bool]:
    """``text`` of a TOML file with our change undone, or the file's original bytes (True) when it holds what the original did."""
    backup = _backup_path(path, home)
    if backup.exists():
        try:
            original = json.loads(backup.read_text(encoding="utf-8"))["text"]
            if tomllib.loads(original) == tomllib.loads(text):
                return original, True
        except (OSError, ValueError, KeyError, TypeError):
            pass
    return text, False


def _backup_holds_servers(backup: Path) -> bool:
    """The backup of a file records servers a ``wrap`` rewrote: ``unwrap`` still needs it."""
    try:
        return bool(json.loads(backup.read_text(encoding="utf-8")).get("servers"))
    except (OSError, ValueError, AttributeError):
        return False


# --- Codex CLI: [mcp_servers.NAME] tables of ~/.codex/config.toml ---------------------------------------------------------
# TOML is edited as text, line by line, so that the rest of the file (comments, order, spacing) stays as it is. Only an entry
# written
# as a table of its own, with ``command`` (and ``args``) on lines of that table, is edited; the result is parsed again and must be
# the
# old file with that command and those args changed, or nothing is written.

_TOML_HEADER = re.compile(r"^[ \t]*\[(?!\[)(.+?)\][ \t]*(?:#.*)?$")
_TOML_ANY_HEADER = re.compile(r"^[ \t]*\[")


def _toml_path(header: str) -> tuple[str, ...]:
    """The key path a table header names (``mcp_servers."my server"`` is ``("mcp_servers", "my server")``)."""
    node: Any = tomllib.loads(f"[{header}]\n")
    path: list[str] = []
    while isinstance(node, dict) and len(node) == 1:
        key, node = next(iter(node.items()))
        path.append(key)
    return tuple(path)


def _toml_value_end(lines: list[str], start: int) -> int:
    """The index after the last line of the TOML value that begins on ``lines[start]`` (an array may run over several lines)."""
    for end in range(start + 1, min(len(lines), start + 200) + 1):
        try:
            tomllib.loads("".join(lines[start:end]))
            return end
        except tomllib.TOMLDecodeError:
            continue
    raise ValueError("a value that does not end")


def _toml_set(text: str, edits: dict[str, tuple[str, list[str] | None]]) -> str:
    """``text`` with ``command`` and ``args`` of each ``[mcp_servers.NAME]`` table of ``edits`` replaced (``args`` of ``None``:
    the
    line removed). Raises ``ValueError`` naming the server that cannot be edited this way."""
    lines = text.splitlines(keepends=True)
    done: set[str] = set()
    i = 0
    while i < len(lines):
        header = _TOML_HEADER.match(lines[i].rstrip("\r\n"))
        try:
            path = _toml_path(header[1]) if header else ()
        except tomllib.TOMLDecodeError:
            path = ()
        if len(path) != 2 or path[0] != "mcp_servers" or path[1] not in edits:
            i += 1
            continue
        name = path[1]
        end = next((k for k in range(i + 1, len(lines)) if _TOML_ANY_HEADER.match(lines[k])), len(lines))
        command, args = edits[name]
        where: dict[str, tuple[int, int]] = {}
        k = i + 1
        while k < end:
            key = re.match(r"^[ \t]*(command|args)[ \t]*=", lines[k])
            stop = _toml_value_end(lines, k) if key else k + 1
            if key:
                where[key[1]] = (k, stop)
            k = stop
        if "command" not in where:
            raise ValueError(f"{name}: the table has no `command` line")
        command_line = lines[where["command"][0]]
        eol = (re.search(r"\r?\n$", command_line) or ["\n"])[0]
        indent = re.match(r"^[ \t]*", command_line)[0]  # type: ignore[index]
        new_command = f"{indent}command = {json.dumps(command, ensure_ascii=False)}{eol}"
        new_args = None if args is None else f"{indent}args = {json.dumps(args, ensure_ascii=False)}{eol}"
        c0, c1 = where["command"]
        a0, a1 = where.get("args", (c1, c1))
        pieces = [(c0, c1, [new_command])]
        pieces.append((a0, a1, [] if new_args is None else [new_args]))
        size = len(lines)
        for start, stop, replacement in sorted(pieces, reverse=True):
            lines[start:stop] = replacement
        done.add(name)
        i = end + len(lines) - size
    if missing := sorted(set(edits) - done):
        raise ValueError(f"{', '.join(missing)}: not written as a [mcp_servers.NAME] table")
    new = "".join(lines)
    before, after = tomllib.loads(text), tomllib.loads(new)
    servers = before.get("mcp_servers", {})
    for name, (command, args) in edits.items():
        entry = servers[name]
        entry["command"] = command
        if args is None:
            entry.pop("args", None)
        else:
            entry["args"] = list(args)
    if before != after:
        raise ValueError("the edit would change more than command and args")
    return new


def _installs_path(home: Path | None) -> Path:
    return (home or Path.home()) / ".intentshield" / "installs.json"


def installed_at(path: Path, home: Path | None = None) -> float | None:
    """When ``install`` last changed this settings file's hooks, or None for a file it has no record of (one set up
    by hand, or by an older version). `doctor` compares it with the last hook run; the file's own modification
    time moves with every unrelated edit the user or the harness makes."""
    try:
        when = json.loads(_installs_path(home).read_text(encoding="utf-8")).get(str(path.resolve()))
    except (OSError, ValueError, AttributeError):
        return None
    return float(when) if isinstance(when, (int, float)) else None


def _record_install(path: Path, home: Path | None, when: float | None = None) -> None:
    """Keeps (or, with ``when`` None, forgets) the time of this install in ``~/.intentshield/installs.json``."""
    record = _installs_path(home)
    try:
        known = json.loads(record.read_text(encoding="utf-8")) if record.exists() else {}
        if not isinstance(known, dict):
            known = {}
        if when is None:
            known.pop(str(path.resolve()), None)
        else:
            known[str(path.resolve())] = when
        _private_dir(record.parent)
        record.write_text(json.dumps(known, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError):  # evidence for doctor only: it falls back to the file's modification time
        pass


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


def install(harness: str, scope: str = "user", review: str | None = None, hook: str | None = None,
            dry_run: bool = False, home: Path | None = None, cwd: Path | None = None,
            judge: str | None = None, api_key: str | None = None,
            ask: Callable[[str], str] = getpass.getpass,
            judge_outputs: bool = False, builtin_tools: bool = False, gemini_ask: bool = False,
            judge_url: str | None = None, translate: bool = True, allow_ephemeral: bool = False) -> Path:
    """Register the hooks in the harness's settings file. Returns the file touched. With ``translate`` (the default) the hooks
    that check a call carry the hook's own deadline and the fail-closed launcher (translation.py), and the harness's version
    is recorded for the hook."""
    path = settings_path(harness, scope, home, cwd)
    legacy = legacy_project_settings(harness, cwd) if scope == "project" else None
    if legacy is not None and _holds_our_hooks(legacy):
        # Both files are read by Claude Code, so a hook left in the shared one would run next to the new one.
        _uninstall_file(harness, legacy, dry_run, home)
    hook = hook or executable(_HOOK)
    _refuse_ephemeral(hook, "hook command", dry_run, allow_ephemeral)
    command = hook_command(harness, hook, review, judge, judge_outputs, builtin_tools, gemini_ask,
                           deadline=translation.DEFAULT_DEADLINE_S if translate else None)
    if judge:  # after the spec is checked, so a refused --judge stores nothing; a dry run checks the same, stores nothing
        ensure_judge_key(judge, home, api_key, ask, judge_url, dry_run=dry_run)
    elif judge_url:
        raise ValueError("--judge-url is for --judge custom only")
    if harness == "codex":
        text = path.read_text() if path.exists() else ""
        try:
            tomllib.loads(text)  # refuse to append to a file Codex could not read either
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"{path} is not valid TOML ({exc}); Codex CLI cannot read it either. Fix it, then run `intentshield "
                             "install codex` again (`--dry-run` prints the block it adds)") from None
        stripped, had_block = _strip_toml_block(text)  # replace an earlier block instead of stacking a second
        new = (stripped.rstrip("\n") + "\n\n" if stripped.strip() else "") + codex_toml(command, builtin_tools, translate)
        tomllib.loads(new)
        if new == text:
            print(f"already installed: {path}")
            return path
        if had_block:
            block = text[text.find(_TOML_BEGIN):text.find(_TOML_END)]
            _say_what_was_replaced([json.loads(c) for c in re.findall(r'^command = (".*")\s*$', block, re.M)], command)
        _keep_original(path, home, dry_run)
        _write(path, new, dry_run)
        if not dry_run:
            _record_install(path, home, time.time())
    else:
        existed = path.exists()
        try:
            current = _read_json(path)
            previous = _our_commands(current)
            settings, changed = merge_hooks(current, hook_entries(harness, command, builtin_tools, translate))
        except ValueError as exc:
            if str(path) in str(exc):
                raise
            raise ValueError(f"{path}: {exc}") from None
        if not changed:
            print(f"already installed: {path}")
            return path
        if previous:
            _say_what_was_replaced(previous, command)
        if harness == "cursor" and not existed:  # a file Cursor wrote already has it; uninstall restores theirs
            settings.setdefault("version", 1)
        _keep_original(path, home, dry_run)
        _write(path, _json_text(settings), dry_run)
        if not dry_run:
            _record_install(path, home, time.time())
    print(f"{'would install' if dry_run else 'installed'} {harness} hooks in {path}")
    if translate and not dry_run:
        seen = translation.probe_and_record(harness, home)
        if seen:
            print(f"{harness} version {'.'.join(map(str, seen))} recorded: the hook picks its replies for it "
                  "(`intentshield doctor` shows what is measured)")
        else:
            print(f"{harness} was not found on PATH, so its version is not recorded: asks are sent as refusals until "
                  "`intentshield doctor` records it")
    if harness == "codex":
        # Measured 2026-10-29 with Codex CLI 0.165: hooks nobody has trusted are skipped, and the
        # session runs unguarded with no warning from Codex.
        print("Codex runs a new hook only after you trust it: start `codex` once and approve the IntentShield "
              "hooks when it asks. Until then Codex is NOT guarded by them.")
    if scope == "project" and not dry_run:
        print(f"note: {path} now holds absolute paths of this machine (the hook command): do not commit it, and do not share it "
              "with a team that has the tools elsewhere.")
    if not builtin_tools:
        print("This guards MCP calls only, not the shell or the file tools. To guard those too: "
              f"intentshield install {harness} --builtin-tools")
    if not dry_run:
        print(f"Next: {NEXT_STEP.format(harness=harness)} Until the harness has run a hook, `doctor` says \"no hook has run "
              "yet\" as a warning: that is expected right after an install.")
    return path


def legacy_project_settings(harness: str, cwd: Path | None = None) -> Path | None:
    """The shared ``.claude/settings.json`` of the project, where 0.4.3 and earlier wrote Claude Code's project-scope hooks (now
    ``settings.local.json``); None for any other harness."""
    return (cwd or Path.cwd()) / ".claude" / "settings.json" if harness == "claude" else None


def _holds_our_hooks(path: Path) -> bool:
    try:
        return path.exists() and bool(_our_commands(_read_json(path)))
    except ValueError:
        return False


def uninstall(harness: str, scope: str = "user", dry_run: bool = False,
              home: Path | None = None, cwd: Path | None = None) -> Path:
    path = settings_path(harness, scope, home, cwd)
    legacy = legacy_project_settings(harness, cwd) if scope == "project" else None
    if legacy is not None and _holds_our_hooks(legacy):
        _uninstall_file(harness, legacy, dry_run, home)  # a hook an earlier version put in the shared file
    return _uninstall_file(harness, path, dry_run, home)


def _uninstall_file(harness: str, path: Path, dry_run: bool, home: Path | None) -> Path:
    if not path.exists():
        print(f"nothing to remove: {path}")
        return path
    backup = _backup_path(path, home)  # this install is being undone either way
    existed_before = backup.exists()  # the file was there before the first install: it is put back, not deleted
    if harness == "codex":
        text, changed = _strip_toml_block(_exact_text(path))
        if changed:
            text, _ = _undone_toml(path, text, home)
    else:
        settings, changed = remove_hooks(_read_json(path))
        text, _ = _undone_text(path, settings, home)
    if not changed:
        print(f"nothing to remove: {path}")
        return path
    emptied = not text.strip() or text.strip() in ("{}", json.dumps({"version": 1}, indent=2))
    if emptied and not existed_before and not path.is_symlink():  # a file only `install` created: leave nothing behind
        if not dry_run:
            path.unlink()
            backup.unlink(missing_ok=True)
            _record_install(path, home)
        print(f"{'would remove' if dry_run else 'removed'} {path} (it held only IntentShield's hooks)")
        return path
    _write(path, text, dry_run)
    if not dry_run:
        if not _backup_holds_servers(backup):  # wrap's record of the servers it rewrote is still needed
            backup.unlink(missing_ok=True)
        _record_install(path, home)
    print(f"{'would remove' if dry_run else 'removed'} {harness} hooks from {path}")
    return path


def server_stem(name: str, config: Path | None = None) -> str:
    """A server id or file stem for a server name: the name itself when it is already a valid id and no client file is given, else
    sanitized plus a short hash of the name and the client file it came from. The proxy config and the audit database of a wrapped
    server are named by that stem, so "my server" and "my-server", or "github" in two clients' files, never share either. The
    server id
    stays the plain name, because the hook finds the tool catalog by the name the harness shows; a catalog of the same name in two
    clients' files is therefore one file."""
    stem = _SERVER_ID.sub("-", name).strip("-.").replace("__", "-") or "server"
    if not re.match(r"^[A-Za-z0-9]", stem):
        stem = "s-" + stem
    if stem != name or config is not None:
        key = f"{config.resolve() if config else ''}\0{name}".encode()
        stem = f"{stem}-{hashlib.sha256(key).hexdigest()[:8]}"
    return stem


def proxy_config(name: str, server: dict[str, Any], out_dir: Path, scope: str = "", stem: str | None = None) -> dict[str, Any]:
    """A transparent-proxy config for one stdio server of an ``mcpServers`` file. Literal ``env``
    values stay in the harness's file (it sets them on the proxy process), and the proxy forwards
    them by name, so no secret is copied. The threat memory is the file the hooks use too
    (``~/.intentshield/threats.db`` with the default ``out_dir``), so what one layer learns the other knows."""
    server_id = server_stem(f"{name}@{scope}" if scope else name)  # one id per project's server of that name
    database = out_dir / f"{stem or server_id}.db"
    if (before := out_dir / f"{server_id}.db").exists():
        database = before  # 0.4.3 named the database by the server id: a wrapped server keeps the audit log it already has
    env = server.get("env") or {}
    upstream: dict[str, Any] = {"server_id": server_id, "transport": "stdio", "command": server["command"]}
    if "args" in server:  # kept exactly (even empty) so unwrap restores the entry as it was
        upstream["args"] = list(server.get("args") or [])
    if env:
        # An empty value is not forwarded: the proxy refuses to start on an empty referenced variable.
        forwarded = {key: key for key, value in env.items() if str(value).strip()}
        if forwarded:
            upstream["env_from_env"] = forwarded
    return {"upstreams": [upstream], "database_path": str(database),
            "threat_memory_path": os.getenv("INTENTSHIELD_THREAT_DB") or str(out_dir.parent / "threats.db"),
            # The hooks read this for tool hints and the operator's read-only decisions, and every
            # proxy reads the others' files for cross-server shadowing.
            "tool_catalog_dir": os.getenv("INTENTSHIELD_HOOK_CATALOG") or str(out_dir.parent / "tools")}


_INTERPOLATION = re.compile(r"\$\{|\$[A-Za-z_]|%[A-Za-z_]\w*%")


def _interpolated(server: dict[str, Any]) -> str:
    """"command" or "args" when it holds ``${...}``, ``$VAR`` (Gemini CLI expands it too) or ``%VAR%``, which the
    client would expand and the proxy's config cannot."""
    if _INTERPOLATION.search(str(server.get("command", ""))):
        return "command"
    args = server.get("args")
    return "args" if isinstance(args, list) and any(_INTERPOLATION.search(str(a)) for a in args) else ""


def _is_wrapped(server: dict[str, Any]) -> bool:
    return Path(str(server.get("command", ""))).stem == _PROXY and "--transparent" in (server.get("args") or [])


def _server_groups(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """The server objects of a client file, each with its scope ("" for the first one): ``mcpServers`` (Claude Code, Cursor,
    Gemini
    CLI, Windsurf, Claude Desktop), ``servers`` (VS Code's ``mcp.json``) and ``mcp.servers`` (VS Code's ``settings.json``). Claude
    Code's ``~/.claude.json`` also keeps a project's own servers under ``projects.<path>.mcpServers``."""
    groups: list[tuple[str, dict[str, Any]]] = []
    if isinstance(data.get("mcpServers"), dict):
        groups.append(("", data["mcpServers"]))
    if isinstance(data.get("servers"), dict):
        groups.append(("servers" if groups else "", data["servers"]))
    nested = data.get("mcp")
    if isinstance(nested, dict) and isinstance(nested.get("servers"), dict):
        groups.append(("mcp.servers" if groups else "", nested["servers"]))
    projects = data.get("projects")
    for project, body in (projects.items() if isinstance(projects, dict) else ()):
        if isinstance(body, dict) and isinstance(body.get("mcpServers"), dict):
            groups.append((str(project), body["mcpServers"]))
    return groups


def _label(name: str, scope: str) -> str:
    return f"{name} [{scope}]" if scope else name


def _entry_problem(server: Any) -> str:
    """Why a stdio server entry cannot be put behind the proxy, or "": its command is not text, its args are not a list of
    text, its env is not an object of text."""
    if not isinstance(server.get("command"), str):
        return "command must be a string"
    args = server.get("args")
    if args is not None and not (isinstance(args, list) and all(isinstance(a, str) for a in args)):
        return "args must be a list of strings"
    env = server.get("env")
    if env is not None and not isinstance(env, dict):
        return "env must be an object"
    return ""


def _require_file(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"{path} was not found: the file does not exist. Servers added with `claude mcp add` are in "
                                "~/.claude.json; a project's are in .mcp.json")


SUPPORTED = ("a JSON file with an 'mcpServers' object (Claude Code, Cursor, Gemini CLI, Windsurf, Claude Desktop), a "
             "'servers' object "
             "(VS Code mcp.json) or 'mcp.servers' (VS Code settings.json), or a Codex CLI config.toml with "
             "[mcp_servers.NAME] tables")


def _no_servers(path: Path) -> str:
    """Why a file holds no servers to wrap, and what to do for a client this does not read."""
    return (f"{path} has no servers wrap can read. Supported: {SUPPORTED}. For another client, put the proxy in front of a "
            "server by hand: set the entry's command to `intentshield-mcp` and its args to `--transparent --config FILE`, "
            "where FILE is a proxy config naming the server's own command (docs/gateway.md#real-mcp-proxy)")


def _in_repository(path: Path) -> bool:
    """The file lies inside a git working tree, where it may be committed."""
    return any((d / ".git").exists() for d in (path.resolve().parent, *path.resolve().parents))


NEXT_STEP = "Start {harness} and send any prompt, then run `intentshield doctor`."


def _inside(path: Path, directory: Path) -> bool:
    """``path`` lies in ``directory`` (a project's own file, which ``doctor --connect`` starts only with --connect-project)."""
    try:
        path.resolve().relative_to(directory.resolve())
    except ValueError:
        return False
    return True


class Wrapped(list[str]):
    """The servers ``wrap`` put behind the proxy, by label; ``skipped`` is true when it left a stdio server unwrapped because its
    entry could not be (an unreadable command line, a ``${...}`` interpolation, a form the proxy does not take)."""
    skipped = False


def wrap(path: Path, servers: list[str] | None = None, out_dir: Path | None = None, proxy: str | None = None,
         dry_run: bool = False, allow_ephemeral: bool = False) -> Wrapped:
    """Put the transparent proxy in front of each stdio server in an ``mcpServers`` file, the project-scoped
    ones of ``~/.claude.json`` included. Every entry is checked first and one the proxy cannot take is skipped with its reason;
    the proxy configs are written only then, and removed again when the client file cannot be written."""
    out_dir = (out_dir or Path.home() / ".intentshield" / "proxies").expanduser()
    _require_file(path)
    data = _read_client(path)
    groups = _server_groups(data)
    if not groups:
        raise ValueError(_no_servers(path))
    if servers:
        missing = sorted(set(servers) - {name for _, entries in groups for name in entries})
        if missing:
            raise ValueError(f"no such server in {path}: {', '.join(missing)}")
    proxy = proxy or executable(_PROXY)
    _refuse_ephemeral(proxy, "proxy command", dry_run, allow_ephemeral)
    from .mcp_proxy import MCPProxyConfig  # the proxy must accept each config before the client file changes
    plan: list[tuple[dict[str, Any], str, str, dict[str, Any], Path, dict[str, Any]]] = []
    skipped = False
    for scope, entries in groups:
        for name, server in entries.items():
            if servers and name not in servers:
                continue
            if not isinstance(server, dict) or not server.get("command") or server.get("url"):
                # HTTP servers are not launched by the client, so there is no process to stand in front of.
                print(f"skipped {_label(name, scope)}: not a stdio server (guard HTTP servers with the gateway, "
                      "see https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/gateway.md#real-mcp-proxy)")
                continue
            if _is_wrapped(server):
                continue
            if interpolated := _interpolated(server):
                # The client expands ${VAR} and ${workspaceFolder} only in the entry it launches, which after
                # wrapping is the proxy: the server would get the text as written.
                print(f"skipped {_label(name, scope)}: its command line ({interpolated}) uses ${{...}}, "
                      "$VAR or %VAR% interpolation, which the client "
                      "expands only for the program it starts; replace it with the value (or move it to 'env', "
                      "which is kept) and wrap again")
                skipped = True
                continue
            if problem := _entry_problem(server):
                print(f"skipped {_label(name, scope)}: {problem}")
                skipped = True
                continue
            if _is_toml(path):
                try:
                    _toml_set(_exact_text(path), {name: (proxy, ["--transparent", "--config", "x"])})
                except ValueError as exc:
                    print(f"skipped {_label(name, scope)}: wrap edits only a [mcp_servers.NAME] table with its own `command` "
                          f"line ({exc}). Write the entry as such a table, or add the proxy by hand: "
                          "command = \"intentshield-mcp\", args = [\"--transparent\", \"--config\", FILE] "
                          "(docs/gateway.md#real-mcp-proxy)")
                    skipped = True
                    continue
            stem = server_stem(_label(name, scope), path)
            config_path = out_dir / f"{stem}.json"
            generated = proxy_config(name, server, out_dir, scope, stem)
            try:
                MCPProxyConfig.model_validate(generated)
            except ValueError as exc:  # pydantic's ValidationError: the first problem, in a line
                errors: list[Any] = getattr(exc, "errors", lambda: [])()
                why = (f"{'.'.join(str(x) for x in errors[0].get('loc', ()))}: {errors[0].get('msg', '')}" if errors
                       else str(exc).splitlines()[0])
                print(f"skipped {_label(name, scope)}: the proxy would not accept it ({why})")
                skipped = True
                continue
            plan.append((entries, name, scope, server, config_path, generated))
    wrapped = Wrapped()
    wrapped.skipped = skipped
    before: dict[str, dict[str, Any]] = {}
    edits: dict[str, tuple[str, list[str] | None]] = {}
    created: list[Path] = []
    try:
        for entries, name, scope, server, config_path, generated in plan:
            if not dry_run and not config_path.exists():
                created.append(config_path)
            _write(config_path, json.dumps(generated, indent=2) + "\n", dry_run)
            before[json.dumps([scope, name])] = {"command": server["command"],
                                                 **({"args": server["args"]} if "args" in server else {})}
            entries[name] = {**server, "command": proxy, "args": ["--transparent", "--config", str(config_path)]}
            edits[name] = (proxy, entries[name]["args"])
            wrapped.append(_label(name, scope))
        if wrapped:
            text = _toml_set(_exact_text(path), edits) if _is_toml(path) else _json_text(data)
            _keep_original(path, None, dry_run)
            if not dry_run:
                _remember_servers(path, before)
            _write(path, text, dry_run)
    except BaseException:
        for config_path in created:  # the client file was not changed: no config of this run is left behind
            config_path.unlink(missing_ok=True)
            _SEEN.pop(config_path.resolve(), None)
        raise
    if wrapped:
        print(f"{'would wrap' if dry_run else 'wrapped'} {len(wrapped)} server(s) in {path}: {', '.join(wrapped)}")
        if not dry_run and _in_repository(path):
            print(f"note: {path} now holds absolute paths of this machine (the proxy and its config): do not commit it, or "
                  "run `intentshield unwrap` on it first.")
        if not dry_run:
            local = _inside(path, Path.cwd())
            closing_note = (" (close it before wrapping ~/.claude.json, which Claude Code rewrites)"
                            if path.name == ".claude.json" else "")
            print(f"Next: restart the MCP client that reads {path}{closing_note}, then run "
                  f"`intentshield doctor --connect{'-project' if local else ''}` to check that each wrapped server starts "
                  "through the proxy.")
    elif any(isinstance(s, dict) and _is_wrapped(s) for _, entries in groups for s in entries.values()):
        print(f"already wrapped: {path}")
    elif not skipped:
        print(f"nothing to wrap in {path}: no stdio servers")
    return wrapped


def _backed_up_server(path: Path, scope: str, name: str) -> dict[str, Any] | None:
    """The command and args the server had in the copy of the file taken before the first wrap, when that copy has
    it (it is the only record left once the proxy's generated config is gone)."""
    try:
        saved = json.loads(_backup_path(path, None).read_text(encoding="utf-8"))
        entry = (saved.get("servers") or {}).get(json.dumps([scope, name]))
        if entry is None:  # a backup from before entries were recorded: the file's text at the first wrap
            entry = dict(_server_groups(_client_data(saved["text"], path)))[scope][name]
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    if not isinstance(entry, dict) or not entry.get("command") or _is_wrapped(entry):
        return None
    return {"command": entry["command"], **({"args": entry["args"]} if "args" in entry else {})}


def unwrap(path: Path, servers: list[str] | None = None, dry_run: bool = False) -> list[str]:
    """Restore the servers a previous ``wrap`` rewrote, from their generated proxy configs."""
    _require_file(path)
    data = _read_client(path)
    groups = _server_groups(data)
    if not groups:
        raise ValueError(_no_servers(path))
    restored: list[str] = []
    edits: dict[str, tuple[str, list[str] | None]] = {}
    missing: list[str] = []
    residue: list[Path] = []
    for scope, entries in groups:
        for name, server in entries.items():
            if (servers and name not in servers) or not isinstance(server, dict) or not _is_wrapped(server):
                continue
            args = server.get("args") or []
            if "--config" not in args or args.index("--config") + 1 >= len(args):
                missing.append(f"{_label(name, scope)} (its entry names no --config)")
                continue
            config = Path(str(args[args.index("--config") + 1]))
            if args != ["--transparent", "--config", str(config)]:
                shown = " ".join(map(str, args))
                print(f"warning: {_label(name, scope)} has other arguments than the ones wrap wrote ({shown}); "
                      "unwrap restores the server's original command and arguments, so those changes are dropped.",
                      file=sys.stderr)
            try:
                generated = json.loads(config.read_text())
                upstream = generated["upstreams"][0]
            except (OSError, ValueError, KeyError, IndexError, TypeError):
                generated = {}
                upstream = _backed_up_server(path, scope, name)
            # wrap writes one upstream per config; a config with several is hand-written, and restoring its
            # first upstream would drop the proxy, the other upstreams and their policy.
            if isinstance(generated, dict) and len(generated.get("upstreams") or []) > 1:
                missing.append(f"{_label(name, scope)} (its proxy config {config} has several upstreams, so wrap "
                               "did not write it; edit the entry by hand)")
                continue
            if upstream is None:
                missing.append(f"{_label(name, scope)} (its proxy config {config} is missing or unreadable, and "
                               f"{_backup_path(path, None)} holds no copy of the entry)")
                continue
            # The entry's own key order is kept: only command and args are swapped back in place.
            original = {}
            for key, value in server.items():
                if key == "command":
                    original["command"] = upstream["command"]
                elif key == "args":
                    if "args" in upstream:
                        original["args"] = list(upstream["args"])
                else:
                    original[key] = value
            residue.append(config)
            if generated.get("database_path"):
                residue.append(Path(generated["database_path"]))
            entries[name] = original
            edits[name] = (original["command"], list(original["args"]) if "args" in original else None)
            restored.append(_label(name, scope))
    if restored:
        if _is_toml(path):
            text, exact = _undone_toml(path, _toml_set(_exact_text(path), edits), None)
        else:
            text, exact = _undone_text(path, data, None)
        _write(path, text, dry_run)
        if exact and not dry_run:
            _backup_path(path, None).unlink()
        print(f"{'would unwrap' if dry_run else 'unwrapped'} {len(restored)} server(s) in {path}: {', '.join(restored)}")
        kept = [str(p) for p in residue if p.exists()]
        if kept:
            print(f"kept (the proxy's config and audit database; delete them if the server is gone): {', '.join(kept)}")
    elif not missing:
        print(f"nothing to unwrap in {path}")
    if missing:  # what was written above stays; these entries still start a proxy that cannot find its config
        raise ValueError("cannot restore " + "; ".join(missing) + f". Edit {path} by hand: put the server's own "
                         "command and args back, or delete the entry.")
    return restored


def add_subcommands(sub: Any) -> None:
    for verb in ("install", "uninstall"):
        p = sub.add_parser(verb, help=f"{verb} the IntentShield hooks in an agent harness")
        p.add_argument("harness", choices=HARNESSES, help="the agent harness whose settings file to edit")
        p.add_argument("--scope", choices=("user", "project"), default="user",
                       help="user: the harness's home settings; project: its settings in the current directory")
        p.add_argument("--dry-run", action="store_true", help="print the file instead of writing it")
        if verb == "install":
            p.add_argument("--review", choices=("tainted", "always", "never"), default=None,
                           help="pass --review to the hook (Codex and Gemini CLI cannot ask, so 'always' denies)")
            p.add_argument("--judge", nargs="?", const="groq", default=None, metavar="PROVIDER[:MODEL]",
                           help="turn on the LLM judge: groq (default, free tier, asks for GROQ_API_KEY once), "
                                "gemini, deepseek, ollama (local), or your own key with openai:<model>, "
                                "openrouter:<model> or custom:<model> (with --judge-url)")
            p.add_argument("--api-key", default=None,
                           help="the judge's API key, instead of being asked (replaces a stored one)")
            p.add_argument("--judge-url", default=None, metavar="URL",
                           help="with --judge custom:<model>: your OpenAI-compatible chat completions endpoint")
            p.add_argument("--builtin-tools", action="store_true",
                           help="also guard the harness's own shell, file and web tools (Bash, PowerShell, Monitor, "
                                "WebFetch, Read, Write...); off by default until its review load is measured")
            p.add_argument("--gemini-ask", action="store_true",
                           help="Gemini CLI 0.66 or later, interactive sessions only: ask instead of refusing. "
                                "Headless runs (gemini -p) then hang on an ask; check with `intentshield doctor`")
            p.add_argument("--no-translate", action="store_true",
                           help="send the guard's verdicts as they are, with no deadline and no fail-closed launcher "
                                "(the hook as it was before the verdict translation)")
            p.add_argument("--allow-ephemeral", action="store_true",
                           help="record the hook's path even when it lies in the cache of uvx, pipx run or npx, which is "
                                "cleaned (install refuses that by default)")
            p.add_argument("--judge-outputs", action="store_true",
                           help="the judge also reads each tool result the rules pass (catches plain-language "
                                "injections; one request per result, about 1 s locally, 4 s on Gemini)")
    for verb in ("wrap", "unwrap"):
        p = sub.add_parser(verb, help=f"{verb} stdio MCP servers of a client's MCP file "
                                      f"{'in' if verb == 'wrap' else 'from'} the transparent proxy")
        p.add_argument("config", type=Path,
                       help="e.g. .mcp.json or ~/.claude.json (Claude Code), .cursor/mcp.json, ~/.gemini/settings.json, "
                            "~/.codex/config.toml (Codex CLI), .vscode/mcp.json (VS Code)")
        p.add_argument("--server", action="append", dest="servers", metavar="NAME",
                       help="only this server (repeatable)")
        p.add_argument("--dry-run", action="store_true", help="print the files instead of writing them")
        if verb == "wrap":
            p.add_argument("--out-dir", type=Path, default=None,
                           help="where generated proxy configs and databases go (default ~/.intentshield/proxies)")
            p.add_argument("--allow-ephemeral", action="store_true",
                           help="record the proxy's path even when it lies in the cache of uvx, pipx run or npx, which is "
                                "cleaned (wrap refuses that by default)")


def run(args: argparse.Namespace) -> int:
    try:
        if args.command == "install":
            if args.judge_outputs and not args.judge:
                raise ValueError("--judge-outputs needs --judge")
            install(args.harness, args.scope, args.review, dry_run=args.dry_run, judge=args.judge,
                    api_key=args.api_key, judge_url=args.judge_url, judge_outputs=args.judge_outputs,
                    builtin_tools=args.builtin_tools, gemini_ask=args.gemini_ask,
                    translate=not args.no_translate, allow_ephemeral=args.allow_ephemeral)
        elif args.command == "uninstall":
            uninstall(args.harness, args.scope, dry_run=args.dry_run)
        elif args.command == "wrap":
            done = wrap(args.config, args.servers, args.out_dir, dry_run=args.dry_run, allow_ephemeral=args.allow_ephemeral)
            if done.skipped:  # a script that expects every server wrapped must not read this as a success
                print("intentshield wrap: at least one server was skipped (see above), so it is not behind the proxy",
                      file=sys.stderr)
                return 1
        elif args.command == "unwrap":
            unwrap(args.config, args.servers, dry_run=args.dry_run)
        else:
            return 2
    except (OSError, ValueError, KeyError, IndexError, tomllib.TOMLDecodeError) as exc:
        print(f"intentshield {args.command}: {exc}", file=sys.stderr)
        return 1
    return 0

