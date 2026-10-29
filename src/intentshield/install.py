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
import tomllib
from pathlib import Path
from typing import Any

HARNESSES = ("claude", "codex", "cursor", "gemini")
_HOOK = "intentshield-hook"
_PROXY = "intentshield-mcp"
_MCP_MATCHER = "mcp__.*|ReadMcpResource(Dir)?(Tool)?|ListMcpResources(Tool)?"
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


def settings_path(harness: str, scope: str, home: Path | None = None, cwd: Path | None = None) -> Path:
    home = home or Path.home()
    cwd = cwd or Path.cwd()
    if scope == "project":
        if harness == "codex":
            raise ValueError("Codex CLI reads hooks from ~/.codex/config.toml only; use --scope user")
        return cwd / {"claude": ".claude/settings.json", "cursor": ".cursor/hooks.json",
                      "gemini": ".gemini/settings.json"}[harness]
    return home / {"claude": ".claude/settings.json", "codex": ".codex/config.toml",
                   "cursor": ".cursor/hooks.json", "gemini": ".gemini/settings.json"}[harness]


_JUDGE_SPEC = re.compile(r"(ollama|groq|gemini|on|default)(:[A-Za-z0-9_.:/-]+)?")


def hook_command(harness: str, hook: str = _HOOK, review: str | None = None, judge: str | None = None,
                 judge_outputs: bool = False) -> str:
    """The shell command the harness runs on every event. Every piece is quoted and validated:
    the harness hands the string to a shell."""
    command = f"{shlex.quote(hook)} {harness}"
    if review:
        if review not in ("tainted", "always", "never"):
            raise ValueError(f"--review must be tainted, always or never, not {review!r}")
        command += f" --review {shlex.quote(review)}"
    if judge:
        if not _JUDGE_SPEC.fullmatch(judge):
            raise ValueError(f"--judge must be ollama[:model], groq[:model] or gemini[:model], not {judge!r}")
        command += f" --judge {shlex.quote(judge)}"
        if judge_outputs:
            command += " --judge-outputs"
    return command


_KEY_FOR = {"groq": "GROQ_API_KEY", "gemini": "GEMINI_API_KEY"}


def ensure_judge_key(judge: str, home: Path | None = None, api_key: str | None = None,
                     ask=getpass.getpass) -> Path | None:
    """The key a hosted judge needs, stored in ``~/.intentshield/.env`` (0600) where every hook
    process reads it. Asks on the terminal when it is neither given nor already set. Returns the
    file written, or None when nothing was needed."""
    provider = judge.partition(":")[0]
    env = _KEY_FOR.get(provider)
    if env is None:  # ollama: local, no key
        return None
    path = (home or Path.home()) / ".intentshield" / ".env"
    if path.is_symlink():  # the key would land wherever the link points
        raise ValueError(f"{path} is a symbolic link; replace it with a regular file before storing a key")
    lines = path.read_text().splitlines() if path.exists() else []
    stored = {}
    for line in lines:
        key, sep, value = line.strip().partition("=")
        if sep and not key.startswith("#"):
            stored[key] = value
    if not api_key and (os.getenv(env) or stored.get(env)):
        return None
    if not api_key:
        if ask is getpass.getpass and not sys.stdin.isatty():
            raise ValueError(f"{env} is not set; pass --api-key or export it before `install --judge {provider}`")
        api_key = ask(f"{env} for the {provider} judge (stored in {path}, never printed): ").strip()
        if not api_key:
            raise ValueError(f"no {env} given")
    # Every other line (comments, other keys) stays as it was; only this key's line changes.
    entry = f"{env}={api_key}"
    replaced = [entry if line.strip().partition("=")[0] == env else line for line in lines]
    lines = replaced if env in stored else [*lines, entry]
    path.parent.mkdir(parents=True, exist_ok=True)
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


def hook_entries(harness: str, command: str) -> dict[str, Any]:
    """The hook configuration for one harness, as ``configs/harness/`` ships it."""
    if harness == "claude":
        return {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": command}]}],
                "PreToolUse": [{"matcher": _MCP_MATCHER,
                                "hooks": [{"type": "command", "command": command, "onFailure": "block"}]}],
                "PostToolUse": [{"matcher": _MCP_MATCHER, "hooks": [{"type": "command", "command": command}]}],
                # A tool result with isError:true arrives here instead of PostToolUse; its text is as
                # attacker-controlled as any other.
                "PostToolUseFailure": [{"matcher": _MCP_MATCHER, "hooks": [{"type": "command", "command": command}]}]}
    if harness == "gemini":
        return {"BeforeAgent": [{"hooks": [{"type": "command", "command": command}]}],
                "BeforeTool": [{"matcher": ".*", "hooks": [{"type": "command", "command": command}]}],
                "AfterTool": [{"matcher": ".*", "hooks": [{"type": "command", "command": command}]}]}
    if harness == "cursor":
        return {"beforeSubmitPrompt": [{"command": command}],
                "beforeMCPExecution": [{"command": command, "failClosed": True}],
                "afterMCPExecution": [{"command": command}]}
    if harness == "codex":
        return {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": command}]}],
                "PreToolUse": [{"matcher": "mcp__.*", "hooks": [{"type": "command", "command": command}]}],
                "PostToolUse": [{"matcher": "mcp__.*", "hooks": [{"type": "command", "command": command}]}]}
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


def codex_toml(command: str) -> str:
    """The Codex CLI hook block, between markers so it can be removed again."""
    lines = [_TOML_BEGIN]
    for event, groups in hook_entries("codex", command).items():
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


def _read_json(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise json.JSONDecodeError(f"{path} is not valid JSON: {exc.msg}", exc.doc, exc.pos) from None
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a JSON object")
    return data


def _write(path: Path, text: str, dry_run: bool) -> None:
    """Atomic: the user's settings file is never left truncated."""
    if dry_run:
        print(f"--- would write {path}\n{text}", end="")
        return
    if path.is_symlink():  # a dotfiles link: write its target, not a regular file in its place
        path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        if path.exists():
            os.chmod(tmp, path.stat().st_mode & 0o777)
        os.replace(tmp, path)
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
        _write(backup, json.dumps({"path": str(path.resolve()), "text": path.read_text(encoding="utf-8")}), False)


def _undone_text(path: Path, data: dict[str, Any], home: Path | None) -> tuple[str, bool]:
    """The file's text with our change undone: its original bytes (True) when the rest is as it was."""
    backup = _backup_path(path, home)
    if backup.exists():
        original = json.loads(backup.read_text(encoding="utf-8"))["text"]
        if json.loads(original or "{}") == data:
            return original, True
    return _json_text(data), False


def install(harness: str, scope: str = "user", review: str | None = None, hook: str | None = None,
            dry_run: bool = False, home: Path | None = None, cwd: Path | None = None,
            judge: str | None = None, api_key: str | None = None, ask=getpass.getpass,
            judge_outputs: bool = False) -> Path:
    """Register the hooks in the harness's settings file. Returns the file touched."""
    path = settings_path(harness, scope, home, cwd)
    if judge and not dry_run:
        ensure_judge_key(judge, home, api_key, ask)
    command = hook_command(harness, hook or executable(_HOOK), review, judge, judge_outputs)
    if harness == "codex":
        text = path.read_text() if path.exists() else ""
        tomllib.loads(text)  # refuse to append to a file Codex could not read either
        stripped, _ = _strip_toml_block(text)  # replace an earlier block instead of stacking a second
        new = (stripped.rstrip("\n") + "\n\n" if stripped.strip() else "") + codex_toml(command)
        tomllib.loads(new)
        if new == text:
            print(f"already installed: {path}")
            return path
        _write(path, new, dry_run)
    else:
        existed = path.exists()
        settings, changed = merge_hooks(_read_json(path), hook_entries(harness, command))
        if not changed:
            print(f"already installed: {path}")
            return path
        if harness == "cursor" and not existed:  # a file Cursor wrote already has it; uninstall restores theirs
            settings.setdefault("version", 1)
        _keep_original(path, home, dry_run)
        _write(path, _json_text(settings), dry_run)
    print(f"{'would install' if dry_run else 'installed'} {harness} hooks in {path}")
    if harness == "codex":
        # Measured 2026-10-29 with Codex CLI 0.165: hooks nobody has trusted are skipped, and the
        # session runs unguarded with no warning from Codex.
        print("Codex runs a new hook only after you trust it: start `codex` once and approve the IntentShield "
              "hooks when it asks. Until then Codex is NOT guarded by them.")
    return path


def uninstall(harness: str, scope: str = "user", dry_run: bool = False,
              home: Path | None = None, cwd: Path | None = None) -> Path:
    path = settings_path(harness, scope, home, cwd)
    if not path.exists():
        print(f"nothing to remove: {path}")
        return path
    backup = _backup_path(path, home)  # this install is being undone either way
    if harness == "codex":
        text, changed = _strip_toml_block(path.read_text())
    else:
        settings, changed = remove_hooks(_read_json(path))
        text, _ = _undone_text(path, settings, home)
    if not changed:
        print(f"nothing to remove: {path}")
        return path
    emptied = not text.strip() or text.strip() in ("{}", json.dumps({"version": 1}, indent=2))
    if emptied and not path.is_symlink():  # a file only `install` created: leave nothing behind
        if not dry_run:
            path.unlink()
            backup.unlink(missing_ok=True)
        print(f"{'would remove' if dry_run else 'removed'} {path} (it held only IntentShield's hooks)")
        return path
    _write(path, text, dry_run)
    if not dry_run:
        backup.unlink(missing_ok=True)
    print(f"{'would remove' if dry_run else 'removed'} {harness} hooks from {path}")
    return path


def server_stem(name: str, config: Path | None = None) -> str:
    """A server id and file stem for a server name: the name itself when it is already a valid id and
    the stem is only for the id, else sanitized plus a short hash of the name and the client file it
    came from, so "my server" and "my-server", or "github" in two clients' files, never share a file."""
    stem = _SERVER_ID.sub("-", name).strip("-.").replace("__", "-") or "server"
    if not re.match(r"^[A-Za-z0-9]", stem):
        stem = "s-" + stem
    if stem != name or config is not None:
        key = f"{config.resolve() if config else ''}\0{name}".encode()
        stem = f"{stem}-{hashlib.sha256(key).hexdigest()[:8]}"
    return stem


def proxy_config(name: str, server: dict[str, Any], out_dir: Path, scope: str = "") -> dict[str, Any]:
    """A transparent-proxy config for one stdio server of an ``mcpServers`` file. Literal ``env``
    values stay in the harness's file (it sets them on the proxy process), and the proxy forwards
    them by name, so no secret is copied. The threat memory is the file the hooks use too
    (``~/.intentshield/threats.db`` with the default ``out_dir``), so what one layer learns the other knows."""
    server_id = server_stem(f"{name}@{scope}" if scope else name)  # one id per project's server of that name
    env = server.get("env") or {}
    upstream: dict[str, Any] = {"server_id": server_id, "transport": "stdio", "command": server["command"]}
    if "args" in server:  # kept exactly (even empty) so unwrap restores the entry as it was
        upstream["args"] = list(server.get("args") or [])
    if env:
        upstream["env_from_env"] = {key: key for key in env}
    return {"upstreams": [upstream], "database_path": str(out_dir / f"{server_id}.db"),
            "threat_memory_path": os.getenv("INTENTSHIELD_THREAT_DB") or str(out_dir.parent / "threats.db"),
            # The hooks read this for tool hints and the operator's read-only decisions, and every
            # proxy reads the others' files for cross-server shadowing.
            "tool_catalog_dir": os.getenv("INTENTSHIELD_HOOK_CATALOG") or str(out_dir.parent / "tools")}


def _is_wrapped(server: dict[str, Any]) -> bool:
    return Path(str(server.get("command", ""))).stem == _PROXY and "--transparent" in (server.get("args") or [])


def _server_groups(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """The ``mcpServers`` objects of a client file, each with its scope ("" for the top level): Claude Code's
    ``~/.claude.json`` also keeps a project's own servers under ``projects.<path>.mcpServers``."""
    groups = [("", data["mcpServers"])] if isinstance(data.get("mcpServers"), dict) else []
    projects = data.get("projects")
    for project, body in (projects.items() if isinstance(projects, dict) else ()):
        if isinstance(body, dict) and isinstance(body.get("mcpServers"), dict):
            groups.append((str(project), body["mcpServers"]))
    return groups


def _label(name: str, scope: str) -> str:
    return f"{name} [{scope}]" if scope else name


def wrap(path: Path, servers: list[str] | None = None, out_dir: Path | None = None, proxy: str | None = None,
         dry_run: bool = False) -> list[str]:
    """Put the transparent proxy in front of each stdio server in an ``mcpServers`` file, the project-scoped
    ones of ``~/.claude.json`` included."""
    out_dir = (out_dir or Path.home() / ".intentshield" / "proxies").expanduser()
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist")
    data = _read_json(path)
    groups = _server_groups(data)
    if not groups:
        raise ValueError(f"{path} has no 'mcpServers' object")
    if servers:
        missing = sorted(set(servers) - {name for _, entries in groups for name in entries})
        if missing:
            raise ValueError(f"no such server in {path}: {', '.join(missing)}")
    proxy = proxy or executable(_PROXY)
    wrapped: list[str] = []
    for scope, entries in groups:
        for name, server in entries.items():
            if servers and name not in servers:
                continue
            if not isinstance(server, dict) or not server.get("command") or server.get("url"):
                # HTTP servers are not launched by the client, so there is no process to stand in front of.
                print(f"skipped {_label(name, scope)}: not a stdio server (guard HTTP servers with the gateway, "
                      "see docs/guide.md)")
                continue
            if _is_wrapped(server):
                continue
            config_path = out_dir / f"{server_stem(_label(name, scope), path)}.json"
            generated = proxy_config(name, server, out_dir, scope)
            from .mcp_proxy import MCPProxyConfig  # the proxy must accept it before the client file changes
            MCPProxyConfig.model_validate(generated)
            _write(config_path, json.dumps(generated, indent=2) + "\n", dry_run)
            entries[name] = {**server, "command": proxy, "args": ["--transparent", "--config", str(config_path)]}
            wrapped.append(_label(name, scope))
    if wrapped:
        _keep_original(path, None, dry_run)
        _write(path, _json_text(data), dry_run)
        print(f"{'would wrap' if dry_run else 'wrapped'} {len(wrapped)} server(s) in {path}: {', '.join(wrapped)}")
    elif any(isinstance(s, dict) and _is_wrapped(s) for _, entries in groups for s in entries.values()):
        print(f"already wrapped: {path}")
    else:
        print(f"nothing to wrap in {path}: no stdio servers")
    return wrapped


def unwrap(path: Path, servers: list[str] | None = None, dry_run: bool = False) -> list[str]:
    """Restore the servers a previous ``wrap`` rewrote, from their generated proxy configs."""
    data = _read_json(path)
    groups = _server_groups(data)
    if not groups:
        raise ValueError(f"{path} has no 'mcpServers' object")
    restored: list[str] = []
    residue: list[Path] = []
    for scope, entries in groups:
        for name, server in entries.items():
            if (servers and name not in servers) or not isinstance(server, dict) or not _is_wrapped(server):
                continue
            args = server.get("args") or []
            config = Path(args[args.index("--config") + 1])
            generated = json.loads(config.read_text())
            upstream = generated["upstreams"][0]
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
            restored.append(_label(name, scope))
    if restored:
        text, original = _undone_text(path, data, None)
        _write(path, text, dry_run)
        if original and not dry_run:
            _backup_path(path, None).unlink()
        print(f"{'would unwrap' if dry_run else 'unwrapped'} {len(restored)} server(s) in {path}: {', '.join(restored)}")
        kept = [str(p) for p in residue if p.exists()]
        if kept:
            print(f"kept (the proxy's config and audit database; delete them if the server is gone): {', '.join(kept)}")
    else:
        print(f"nothing to unwrap in {path}")
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
                           help="turn on the LLM judge: groq (default, asks for GROQ_API_KEY once), gemini, "
                                "or ollama (local)")
            p.add_argument("--api-key", default=None, help="the judge's API key, instead of being asked")
            p.add_argument("--judge-outputs", action="store_true",
                           help="the judge also reads each tool result the rules pass (catches plain-language "
                                "injections; one request per result, about 1 s locally, 4 s on Gemini)")
    for verb in ("wrap", "unwrap"):
        p = sub.add_parser(verb, help=f"{verb} stdio MCP servers of an mcpServers file "
                                      f"{'in' if verb == 'wrap' else 'from'} the transparent proxy")
        p.add_argument("config", type=Path,
                       help="e.g. .mcp.json (Claude Code), .cursor/mcp.json, ~/.gemini/settings.json")
        p.add_argument("--server", action="append", dest="servers", metavar="NAME",
                       help="only this server (repeatable)")
        p.add_argument("--dry-run", action="store_true", help="print the files instead of writing them")
        if verb == "wrap":
            p.add_argument("--out-dir", type=Path, default=None,
                           help="where generated proxy configs and databases go (default ~/.intentshield/proxies)")


def run(args: argparse.Namespace) -> int:
    try:
        if args.command == "install":
            if args.judge_outputs and not args.judge:
                raise ValueError("--judge-outputs needs --judge")
            install(args.harness, args.scope, args.review, dry_run=args.dry_run, judge=args.judge,
                    api_key=args.api_key, judge_outputs=args.judge_outputs)
        elif args.command == "uninstall":
            uninstall(args.harness, args.scope, dry_run=args.dry_run)
        elif args.command == "wrap":
            wrap(args.config, args.servers, args.out_dir, dry_run=args.dry_run)
        elif args.command == "unwrap":
            unwrap(args.config, args.servers, dry_run=args.dry_run)
        else:
            return 2
    except (OSError, ValueError, KeyError, IndexError, tomllib.TOMLDecodeError) as exc:
        print(f"intentshield {args.command}: {exc}", file=sys.stderr)
        return 1
    return 0

