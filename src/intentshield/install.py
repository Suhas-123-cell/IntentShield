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
import json
import re
import shutil
import sys
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


def hook_command(harness: str, hook: str = _HOOK, review: str | None = None) -> str:
    command = f"{hook} {harness}"
    return f"{command} --review {review}" if review else command


def hook_entries(harness: str, command: str) -> dict[str, Any]:
    """The hook configuration for one harness, as ``configs/harness/`` ships it."""
    if harness == "claude":
        return {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": command}]}],
                "PreToolUse": [{"matcher": _MCP_MATCHER,
                                "hooks": [{"type": "command", "command": command, "onFailure": "block"}]}],
                "PostToolUse": [{"matcher": _MCP_MATCHER, "hooks": [{"type": "command", "command": command}]}]}
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
    """Whether a hook group or hook entry runs intentshield-hook."""
    if not isinstance(entry, dict):
        return False
    if _HOOK in str(entry.get("command", "")):
        return True
    hooks = entry.get("hooks")
    return isinstance(hooks, list) and any(_ours(hook) for hook in hooks)


def merge_hooks(settings: dict[str, Any], entries: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Add the entries to ``settings["hooks"]`` where no IntentShield hook is registered yet."""
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("'hooks' is not an object")
    changed = False
    for event, groups in entries.items():
        existing = hooks.setdefault(event, [])
        if not isinstance(existing, list):
            raise ValueError(f"hooks.{event} is not a list")
        if not any(_ours(group) for group in existing):
            existing.extend(groups)
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
        kept = [group for group in groups if not _ours(group)]
        if len(kept) != len(groups):
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
                lines.append(f'command = "{hook["command"]}"')
            lines.append("")
    lines.append(_TOML_END)
    return "\n".join(lines) + "\n"


def _strip_toml_block(text: str) -> tuple[str, bool]:
    start, end = text.find(_TOML_BEGIN), text.find(_TOML_END)
    if start < 0 or end < 0:
        return text, False
    before = text[:start].rstrip("\n")
    after = text[end + len(_TOML_END):].lstrip("\n")
    if before and after:
        return before + "\n\n" + after, True
    return (before + "\n" if before else after), True


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.read_text().strip():
        return {}
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a JSON object")
    return data


def _write(path: Path, text: str, dry_run: bool) -> None:
    if dry_run:
        print(f"--- would write {path}\n{text}", end="")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def install(harness: str, scope: str = "user", review: str | None = None, hook: str | None = None,
            dry_run: bool = False, home: Path | None = None, cwd: Path | None = None) -> Path:
    """Register the hooks in the harness's settings file. Returns the file touched."""
    path = settings_path(harness, scope, home, cwd)
    command = hook_command(harness, hook or executable(_HOOK), review)
    if harness == "codex":
        text = path.read_text() if path.exists() else ""
        if _TOML_BEGIN in text:
            print(f"already installed: {path}")
            return path
        tomllib.loads(text)  # refuse to append to a file Codex could not read either
        _write(path, (text.rstrip("\n") + "\n\n" if text.strip() else "") + codex_toml(command), dry_run)
    else:
        settings, changed = merge_hooks(_read_json(path), hook_entries(harness, command))
        if not changed:
            print(f"already installed: {path}")
            return path
        if harness == "cursor":
            settings.setdefault("version", 1)
        _write(path, json.dumps(settings, indent=2) + "\n", dry_run)
    print(f"{'would install' if dry_run else 'installed'} {harness} hooks in {path}")
    return path


def uninstall(harness: str, scope: str = "user", dry_run: bool = False,
              home: Path | None = None, cwd: Path | None = None) -> Path:
    path = settings_path(harness, scope, home, cwd)
    if not path.exists():
        print(f"nothing to remove: {path}")
        return path
    if harness == "codex":
        text, changed = _strip_toml_block(path.read_text())
    else:
        settings, changed = remove_hooks(_read_json(path))
        text = json.dumps(settings, indent=2) + "\n"
    if changed:
        _write(path, text, dry_run)
        print(f"{'would remove' if dry_run else 'removed'} {harness} hooks from {path}")
    else:
        print(f"nothing to remove: {path}")
    return path


def proxy_config(name: str, server: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """A transparent-proxy config for one stdio server of an ``mcpServers`` file. Literal ``env``
    values stay in the harness's file (it sets them on the proxy process), and the proxy forwards
    them by name, so no secret is copied."""
    server_id = _SERVER_ID.sub("-", name).strip("-.") or "server"
    if not re.match(r"^[A-Za-z0-9]", server_id):
        server_id = "s-" + server_id
    env = server.get("env") or {}
    upstream: dict[str, Any] = {"server_id": server_id, "transport": "stdio", "command": server["command"],
                               "args": list(server.get("args") or [])}
    if env:
        upstream["env_from_env"] = {key: key for key in env}
    return {"upstreams": [upstream], "database_path": str(out_dir / f"{server_id}.db"),
            "threat_memory_path": str(out_dir / "threats.db")}


def _is_wrapped(server: dict[str, Any]) -> bool:
    return Path(str(server.get("command", ""))).name == _PROXY and "--transparent" in (server.get("args") or [])


def wrap(path: Path, servers: list[str] | None = None, out_dir: Path | None = None, proxy: str | None = None,
         dry_run: bool = False) -> list[str]:
    """Put the transparent proxy in front of each stdio server in an ``mcpServers`` file."""
    out_dir = (out_dir or Path.home() / ".intentshield" / "proxies").expanduser()
    data = _read_json(path)
    entries = data.get("mcpServers")
    if not isinstance(entries, dict):
        raise ValueError(f"{path} has no 'mcpServers' object")
    if servers:
        missing = sorted(set(servers) - set(entries))
        if missing:
            raise ValueError(f"no such server in {path}: {', '.join(missing)}")
    proxy = proxy or executable(_PROXY)
    wrapped: list[str] = []
    for name, server in entries.items():
        if servers and name not in servers:
            continue
        if not isinstance(server, dict) or not server.get("command") or server.get("url"):
            continue  # HTTP servers are not launched by the harness; guard those with the gateway
        if _is_wrapped(server):
            continue
        config_path = out_dir / f"{_SERVER_ID.sub('-', name)}.json"
        _write(config_path, json.dumps(proxy_config(name, server, out_dir), indent=2) + "\n", dry_run)
        entries[name] = {**server, "command": proxy, "args": ["--transparent", "--config", str(config_path)]}
        wrapped.append(name)
    if wrapped:
        _write(path, json.dumps(data, indent=2) + "\n", dry_run)
    print(f"{'would wrap' if dry_run else 'wrapped'} {len(wrapped)} server(s) in {path}: {', '.join(wrapped) or '-'}")
    return wrapped


def unwrap(path: Path, servers: list[str] | None = None, dry_run: bool = False) -> list[str]:
    """Restore the servers a previous ``wrap`` rewrote, from their generated proxy configs."""
    data = _read_json(path)
    entries = data.get("mcpServers")
    if not isinstance(entries, dict):
        raise ValueError(f"{path} has no 'mcpServers' object")
    restored: list[str] = []
    for name, server in entries.items():
        if (servers and name not in servers) or not isinstance(server, dict) or not _is_wrapped(server):
            continue
        args = server.get("args") or []
        config = Path(args[args.index("--config") + 1])
        upstream = json.loads(config.read_text())["upstreams"][0]
        original = {key: value for key, value in server.items() if key not in ("command", "args")}
        original["command"] = upstream["command"]
        if upstream.get("args"):
            original["args"] = list(upstream["args"])
        entries[name] = original
        restored.append(name)
    if restored:
        _write(path, json.dumps(data, indent=2) + "\n", dry_run)
    print(f"{'would unwrap' if dry_run else 'unwrapped'} {len(restored)} server(s) in {path}: "
          f"{', '.join(restored) or '-'}")
    return restored


def add_subcommands(sub: Any) -> None:
    for verb in ("install", "uninstall"):
        p = sub.add_parser(verb, help=f"{verb} the IntentShield hooks in an agent harness")
        p.add_argument("harness", choices=HARNESSES)
        p.add_argument("--scope", choices=("user", "project"), default="user",
                       help="user: the harness's home settings; project: its settings in the current directory")
        p.add_argument("--dry-run", action="store_true", help="print the file instead of writing it")
        if verb == "install":
            p.add_argument("--review", choices=("tainted", "always", "never"), default=None,
                           help="pass --review to the hook (Codex and Gemini CLI cannot ask, so 'always' denies)")
    for verb in ("wrap", "unwrap"):
        p = sub.add_parser(verb, help=f"{verb} stdio MCP servers of an mcpServers file "
                                      f"{'in' if verb == 'wrap' else 'from'} the transparent proxy")
        p.add_argument("config", type=Path,
                       help="e.g. .mcp.json (Claude Code), .cursor/mcp.json, ~/.gemini/settings.json")
        p.add_argument("--server", action="append", dest="servers", metavar="NAME",
                       help="only this server (repeatable)")
        p.add_argument("--dry-run", action="store_true")
        if verb == "wrap":
            p.add_argument("--out-dir", type=Path, default=None,
                           help="where generated proxy configs and databases go (default ~/.intentshield/proxies)")


def run(args: argparse.Namespace) -> int:
    try:
        if args.command == "install":
            install(args.harness, args.scope, args.review, dry_run=args.dry_run)
        elif args.command == "uninstall":
            uninstall(args.harness, args.scope, dry_run=args.dry_run)
        elif args.command == "wrap":
            wrap(args.config, args.servers, args.out_dir, dry_run=args.dry_run)
        elif args.command == "unwrap":
            unwrap(args.config, args.servers, dry_run=args.dry_run)
        else:
            return 2
    except (OSError, ValueError, KeyError, tomllib.TOMLDecodeError) as exc:
        print(f"intentshield {args.command}: {exc}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="intentshield", description=__doc__.split("\n\n")[0])
    add_subcommands(parser.add_subparsers(dest="command", required=True))
    return run(parser.parse_args(argv))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
