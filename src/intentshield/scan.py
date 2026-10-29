"""``intentshield scan``: find the MCP servers installed in agent harnesses and check them, offline.

It reads the MCP configs of Claude Code, Claude Desktop, Cursor, Gemini CLI, Codex CLI, Windsurf and VS Code
(or the files given), starts each server as its client would, lists its tools and checks them with the
guard's own rules. Nothing is sent anywhere and no API key is needed.

- **Config:** credentials written into it (``credentials``), and a file holding one that others can read.
- **Tools:** the poisoning rules on each description and schema, an instruction split across one server's
  tools, parameters that ask for the agent's own model, prompt or conversation, a tool naming another
  server's tool (shadowing) and a tool name two servers share.
- **Toxic flow:** one client that can read untrusted content, reach private data and send data out (the
  "lethal trifecta"). It is a property of the setup, not an attack: the hooks and the proxy break it at run
  time by tracking what an injected output touched.
- **Changes since the last scan:** a tool description that changed after it was first seen (rug pull).
  The hashes are kept in ``~/.intentshield/scan-pins.json``.

Starting a server runs its code, as the client would, with a minimal environment (no API keys of yours);
``--no-connect`` checks the configs only. A server named by a config in the current directory is code the
repository chose, so it is started only with ``--connect-project``.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import shlex
import stat
import sys
import tempfile
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import credentials
from .harness import is_mutation
from .install import _HOOK, server_stem
from .mcp_inspect import scan_description, scan_server, self_disclosure_fields, tool_text

ERROR, WARNING, NOTE = "error", "warning", "note"
# What each finding means, for the text report and the SARIF rules.
RULES = {
    "tool_poisoning": (ERROR, "A tool's description or schema tries to instruct the agent."),
    "split_poisoning": (ERROR, "An instruction is split across one server's tool descriptions."),
    "self_disclosure": (ERROR, "A parameter asks for the agent's own model, prompt or conversation."),
    "shadowing": (ERROR, "A tool's description names another server's tool."),
    "rug_pull": (ERROR, "A tool's description or schema changed since the last scan."),
    "hardcoded_credential": (ERROR, "A credential is written into the MCP config."),
    "config_readable": (WARNING, "The config holds a credential and other users can read the file."),
    "name_clash": (WARNING, "Two servers of one client offer a tool with the same name."),
    "toxic_flow": (WARNING, "One client can read untrusted content, reach private data and send data out."),
    "not_scanned": (NOTE, "The server could not be started or listed, or was not started (project config)."),
}

# Where each client keeps its MCP servers: (client, path relative to home or cwd, key holding the servers).
_USER_CONFIGS = (
    ("claude-code", ".claude.json", "mcpServers"),
    ("claude-desktop", "Library/Application Support/Claude/claude_desktop_config.json", "mcpServers"),
    ("claude-desktop", ".config/Claude/claude_desktop_config.json", "mcpServers"),
    ("cursor", ".cursor/mcp.json", "mcpServers"),
    ("gemini-cli", ".gemini/settings.json", "mcpServers"),
    ("windsurf", ".codeium/windsurf/mcp_config.json", "mcpServers"),
    ("codex", ".codex/config.toml", "mcp_servers"),
)
_PROJECT_CONFIGS = (
    ("claude-code", ".mcp.json", "mcpServers"),
    ("cursor", ".cursor/mcp.json", "mcpServers"),
    ("gemini-cli", ".gemini/settings.json", "mcpServers"),
    ("vscode", ".vscode/mcp.json", "servers"),
)
# Where the IntentShield hooks would be registered for a client, to say whether it is guarded.
_HOOK_SETTINGS = {"claude-code": ".claude/settings.json", "cursor": ".cursor/hooks.json",
                  "gemini-cli": ".gemini/settings.json", "codex": ".codex/config.toml"}

# Words that place a tool in a role of the toxic flow, from its name and description. A heuristic, as any
# reading of a tool's purpose from its text is; MCP's annotations win where the server sets them.
_UNTRUSTED = re.compile(r"\b(?:fetch|browse|browser|scrape|crawl|web|url|webpage|page|website|rss|feed|inbox|"
                        r"e-?mails?|mail|messages?|issues?|comments?|tickets?|slack|discord|tweets?|reviews?|"
                        r"pull[_ ]requests?|search(?:es)?)\b", re.I)
_PRIVATE = re.compile(r"\b(?:files?|director(?:y|ies)|folders?|filesystem|fs|database|db|sql|query|tables?|notes?|"
                      r"calendar|contacts?|drive|documents?|docs|repos?|repository|secrets?|credentials?|env|"
                      r"passwords?|vault|memory|accounts?|bank|payments?|customers?|records?|crm)\b", re.I)
_SINK = re.compile(r"\b(?:send|email|mail|post|publish|upload|share|comment|message|reply|forward|webhook|"
                   r"request|push|tweet|transfer|pay|create_issue|create_pull_request|http)\b", re.I)


@dataclass
class Server:
    client: str
    path: Path
    name: str
    entry: dict[str, Any]
    tools: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    project: bool = False         # named by a config in the working directory, not by the user's own
    skipped: str | None = None    # why it was not started


@dataclass
class Finding:
    rule: str
    path: Path
    server: str
    message: str
    tool: str | None = None

    @property
    def level(self) -> str:
        return RULES[self.rule][0]

    def as_dict(self) -> dict[str, Any]:
        return {"rule": self.rule, "level": self.level, "config": str(self.path), "server": self.server,
                "tool": self.tool, "message": self.message}


def discover(home: Path, cwd: Path, files: list[Path] | None = None) -> list[Server]:
    """The MCP servers of every config found, or of ``files`` (``mcpServers`` or ``servers`` JSON)."""
    found: list[Server] = []
    if files:
        sources = [("file", path, "", False) for path in files]
    else:
        sources = [(c, home / rel, key, False) for c, rel, key in _USER_CONFIGS] + \
                  [(c, cwd / rel, key, True) for c, rel, key in _PROJECT_CONFIGS]
    seen: set[Path] = set()
    for client, path, key, project in sources:
        if not path.is_file() or (resolved := path.resolve()) in seen:  # in the home directory, a project file is the user's
            continue
        seen.add(resolved)
        try:
            data = tomllib.loads(path.read_text("utf-8")) if path.suffix == ".toml" else \
                json.loads(path.read_text("utf-8"))
        except (OSError, ValueError) as exc:
            found.append(Server(client, path, "(config)", {}, error=f"unreadable: {exc}", project=project))
            continue
        if not isinstance(data, dict):
            continue
        groups = [data.get(key)] if key else [data.get("mcpServers"), data.get("servers")]
        if client == "claude-code" and path.name == ".claude.json":
            # Claude Code's local scope: the servers it starts in this project.
            project = (data.get("projects") or {}).get(str(cwd))
            groups.append(project.get("mcpServers") if isinstance(project, dict) else None)
        for group in groups:
            for name, entry in (group or {}).items() if isinstance(group, dict) else ():
                if isinstance(entry, dict):
                    found.append(Server(client, path, str(name), entry, project=project))
    return found


# What a server may inherit from the scanning shell, as the MCP SDK's own default list: enough to find its
# interpreter and temp directory, none of the API keys in the environment.
_SAFE_ENV = ("PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TEMP", "TMP",
             "SystemRoot", "SYSTEMROOT", "SYSTEMDRIVE", "APPDATA", "LOCALAPPDATA", "USERPROFILE", "USERNAME",
             "HOMEDRIVE", "HOMEPATH", "PROCESSOR_ARCHITECTURE", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME")


def safe_environment() -> dict[str, str]:
    return {key: os.environ[key] for key in _SAFE_ENV if key in os.environ}


def upstream_config(server: Server) -> dict[str, Any] | None:
    """The proxy's upstream config to start ``server`` as its client would, or None for a transport the
    proxy cannot speak (SSE). A server ``wrap`` put behind the proxy is started directly."""
    entry = server.entry
    command, args = entry.get("command"), [str(a) for a in entry.get("args") or []]
    if command and Path(str(command)).stem == "intentshield-mcp" and "--config" in args:
        try:
            upstream = json.loads(Path(args[args.index("--config") + 1]).read_text())["upstreams"][0]
            command, args = upstream["command"], upstream.get("args", [])
        except (OSError, ValueError, KeyError, IndexError, TypeError):
            return None
    config: dict[str, Any] = {"server_id": server_stem(server.name), "timeout_seconds": 20, "read_timeout_seconds": 20}
    if command:
        env = {str(k): str(v) for k, v in (entry.get("env") or {}).items()}
        return {**config, "transport": "stdio", "command": str(command), "args": args, "env": {**safe_environment(), **env}}
    url = entry.get("url") or entry.get("httpUrl") or entry.get("serverUrl")
    if url and entry.get("type") != "sse" and not str(url).rstrip("/").endswith("/sse"):
        return {**config, "transport": "streamable_http", "url": str(url),
                "headers": {str(k): str(v) for k, v in (entry.get("headers") or {}).items()}}
    return None


async def _list_tools(server: Server, timeout: float) -> None:
    from .mcp_upstream import MCPUpstream, MCPUpstreamConfig

    config = upstream_config(server)
    if config is None:
        server.error = "no stdio command or Streamable HTTP URL (SSE servers are not scanned)"
        return
    # The proxy's config refuses literal credentials so that none is written into its file; the scan writes
    # none, and starts the server with the entry's own environment and headers over a minimal inherited one.
    secrets = {key: config.pop(key) for key in ("env", "headers") if key in config}
    try:
        async with asyncio.timeout(timeout):
            validated = MCPUpstreamConfig.model_validate(config).model_copy(update=secrets)
            async with MCPUpstream(validated) as upstream:
                server.tools = [{"name": t.name, "title": t.title, "description": t.description or "",
                                 "input_schema": t.input_schema, "annotations": t.annotations or {}}
                                for t in await upstream.list_tools()]
    except Exception as exc:  # one broken server must not stop the scan of the others
        server.error = f"{type(exc).__name__}: {credentials.mask(str(exc))[:200]}"


def _config_findings(servers: list[Server]) -> list[Finding]:
    findings: list[Finding] = []
    readable_paths: set[Path] = set()
    for server in servers:
        for credential, kind in credentials.find(server.entry).items():
            findings.append(Finding("hardcoded_credential", server.path, server.name,
                                    f"{credentials.masked(credential, kind)} in the server's config entry; "
                                    "reference an environment variable instead"))
            if os.name == "posix" and server.path.stat().st_mode & (stat.S_IRGRP | stat.S_IROTH):
                readable_paths.add(server.path)
    findings += [Finding("config_readable", path, "(config)", f"chmod 600 {path}") for path in sorted(readable_paths)]
    return findings


def _roles(tool: dict[str, Any]) -> set[str]:
    text = f"{re.sub(r'[_\-.]', ' ', tool['name'])} {tool.get('title') or ''} {tool['description'][:400]}"
    hints = tool.get("annotations") or {}
    read_only = hints.get("readOnlyHint")
    writes = is_mutation(tool["name"]) if read_only is None else not read_only
    roles = set()
    if not writes and (_UNTRUSTED.search(text) or hints.get("openWorldHint")):
        roles.add("untrusted")
    if not writes and _PRIVATE.search(text):
        roles.add("private")
    if writes and (_SINK.search(text) or hints.get("openWorldHint")):
        roles.add("sink")
    return roles


def _tool_findings(servers: list[Server], pins: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    by_client: dict[str, list[Server]] = {}
    for server in servers:
        by_client.setdefault(server.client, []).append(server)
    for client, group in by_client.items():
        owners: dict[str, list[str]] = {}
        for server in group:
            for tool in server.tools:
                owners.setdefault(tool["name"], []).append(server.name)
        for server in group:
            others = [name for name, where in owners.items() if any(s != server.name for s in where)]
            texts = []
            for tool in server.tools:
                text = tool_text(tool["description"], tool["input_schema"], tool.get("title"))
                texts.append(text)
                hits = scan_description(text, others)
                if rules := [hit for hit in hits if hit != "shadowing"]:
                    findings.append(Finding("tool_poisoning", server.path, server.name,
                                            f"rules: {', '.join(rules)}", tool["name"]))
                if "shadowing" in hits:
                    findings.append(Finding("shadowing", server.path, server.name,
                                            "its description names another server's tool", tool["name"]))
                if fields := self_disclosure_fields(tool["input_schema"]):
                    findings.append(Finding("self_disclosure", server.path, server.name,
                                            f"parameters: {', '.join(sorted(fields))}", tool["name"]))
                key = f"{client}|{server.path}|{server.name}|{tool['name']}"
                digest = hashlib.sha256(text.encode()).hexdigest()
                # A changed tool keeps its old hash, so it is reported on every scan until accepted.
                if pins.setdefault(key, digest) != digest:
                    findings.append(Finding("rug_pull", server.path, server.name,
                                            "changed since the last scan; read it, then accept it with "
                                            "--update-pins", tool["name"]))
            if split := scan_server(texts):
                findings.append(Finding("split_poisoning", server.path, server.name, f"rules: {', '.join(split)}"))
        for name, where in owners.items():
            if len(set(where)) > 1:
                findings.append(Finding("name_clash", group[0].path, ", ".join(sorted(set(where))),
                                        f"{name} is offered by {len(set(where))} servers", name))
        roles: dict[str, list[str]] = {"untrusted": [], "private": [], "sink": []}
        for server in group:
            for tool in server.tools:
                for role in _roles(tool):
                    roles[role].append(f"{server.name}:{tool['name']}")
        if all(roles.values()):
            examples = "; ".join(f"{role}: {', '.join(tools[:3])}" for role, tools in roles.items())
            findings.append(Finding("toxic_flow", group[0].path, f"({client})", examples))
    return findings


def _hook_commands(node: Any) -> Iterator[Any]:
    """Every hook entry (a dict with a ``command``) of a settings file's ``hooks`` value, however the client
    nests them: a list of groups each holding a ``hooks`` list (Claude Code, Gemini CLI, Codex CLI), or a list
    of entries (Cursor)."""
    if isinstance(node, dict):
        if "command" in node:
            yield node
        for child in node.values():
            yield from _hook_commands(child)
    elif isinstance(node, list):
        for child in node:
            yield from _hook_commands(child)


def guarded(client: str, home: Path) -> bool:
    """Whether a hook entry of ``client`` runs ``intentshield-hook``: the settings are parsed, so a file that
    only mentions the name (a comment, a removed entry's note) does not count."""
    rel = _HOOK_SETTINGS.get(client)
    if not rel:
        return False
    try:
        path = home / rel
        text = path.read_text("utf-8")
        data = tomllib.loads(text) if path.suffix == ".toml" else json.loads(text)
    except (OSError, ValueError):
        return False
    hooks = data.get("hooks") if isinstance(data, dict) else None
    for entry in _hook_commands(hooks):
        try:
            argv = shlex.split(entry["command"]) if isinstance(entry["command"], str) else []
        except ValueError:
            continue
        if argv and Path(argv[0]).stem == _HOOK:
            return True
    return False


def scan(servers: list[Server], *, connect: bool = True, timeout: float = 30.0,
         pins: dict[str, str] | None = None, connect_project: bool = False) -> list[Finding]:
    """Findings for ``servers``; ``pins`` (tool key to hash) is compared and gains the tools first seen.
    A server of a project config is only started with ``connect_project``."""
    for server in servers:
        if server.project and not connect_project and server.error is None:
            server.skipped = ("named by a config in the current directory, so not started "
                              "(pass --connect-project to start it)")
    if connect:
        for server in servers:
            if server.error is None and server.skipped is None:
                asyncio.run(_list_tools(server, timeout))
    findings = _config_findings(servers) + _tool_findings(servers, {} if pins is None else pins)
    findings += [Finding("not_scanned", s.path, s.name, s.error or s.skipped) for s in servers
                 if s.error or (s.skipped and connect)]
    return findings


def sarif(findings: list[Finding]) -> dict[str, Any]:
    from . import __version__

    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "intentshield scan", "version": __version__,
                            "informationUri": "https://github.com/Suhas-123-cell/IntentShield",
                            "rules": [{"id": rule, "shortDescription": {"text": text},
                                       "defaultConfiguration": {"level": level}}
                                      for rule, (level, text) in RULES.items()]}},
        "results": [{"ruleId": f.rule, "level": f.level,
                     "message": {"text": f"{f.server}{':' + f.tool if f.tool else ''}: {f.message}"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path.resolve().as_uri()}}}]}
                    for f in findings]}]}


def report(servers: list[Server], findings: list[Finding], home: Path, connected: bool = True) -> str:
    lines = []
    for client in dict.fromkeys(s.client for s in servers):
        group = [s for s in servers if s.client == client]
        state = "hooks installed" if guarded(client, home) else "no IntentShield hooks"
        tools = f", {sum(len(s.tools) for s in group)} tool(s)" if connected else ""
        lines.append(f"{client} ({state}): {len(group)} server(s){tools}")
        for server in group:
            status = f"not scanned: {server.error}" if server.error else \
                f"not started: {server.skipped}" if server.skipped and connected else \
                f"{len(server.tools)} tool(s)" if connected else "config only"
            lines.append(f"  {server.name}  {server.path}  [{status}]")
    for f in sorted(findings, key=lambda f: ("error", "warning", "note").index(f.level)):
        if f.rule != "not_scanned":
            lines.append(f"{f.level.upper():7} {f.rule}: {f.server}{':' + f.tool if f.tool else ''}: {f.message}")
    errors = sum(f.level == ERROR for f in findings)
    warnings = sum(f.level == WARNING for f in findings)
    lines.append(f"{len(servers)} server(s) checked: {errors} error(s), {warnings} warning(s)" if servers
                 else "no MCP configs found")
    return "\n".join(lines)


def add_subcommand(sub: Any) -> None:
    p = sub.add_parser("scan", help="find the MCP servers your agents use and check them offline")
    p.add_argument("files", nargs="*", type=Path, help="MCP config files to scan instead of the installed ones")
    p.add_argument("--no-connect", action="store_true", help="check the configs only; start no server")
    p.add_argument("--connect-project", action="store_true",
                   help="also start the servers named by configs in the current directory (.mcp.json, ...): "
                        "code the repository chose, run with your user rights")
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("--timeout", type=float, default=30.0, help="seconds per server (default 30)")
    p.add_argument("--pins", type=Path, default=Path.home() / ".intentshield" / "scan-pins.json",
                   help="where tool hashes are kept between scans")
    p.add_argument("--no-pins", action="store_true", help="neither read nor update the pins")
    p.add_argument("--update-pins", action="store_true", help="accept every tool as it is now")


def load_pins(path: Path) -> dict[str, str]:
    """The saved tool hashes. A file that cannot be read as a {key: hash} object is not trusted as a baseline
    and is not lost either: it is copied to ``.bak`` before the next save replaces it, and the user is told."""
    try:
        text = path.read_text()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        print(f"intentshield scan: cannot read {path} ({exc}); starting without a baseline", file=sys.stderr)
        return {}
    try:
        data = json.loads(text)
        if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
            raise ValueError("not an object of tool keys and hashes")
    except ValueError as exc:
        backup = path.with_name(path.name + ".bak")
        try:
            backup.write_text(text)
        except OSError:
            pass
        print(f"intentshield scan: {path} is not a valid pins file ({exc}); its tools are treated as new, "
              f"and the old file is kept as {backup}", file=sys.stderr)
        return {}
    return data


def save_pins(path: Path, pins: dict[str, str]) -> None:
    """Atomic and private (0600): a scan interrupted or run twice at once never leaves half a baseline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(json.dumps(pins, indent=1, sort_keys=True))
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def run(args: argparse.Namespace) -> int:
    home, cwd = Path.home(), Path.cwd()
    servers = discover(home, cwd, args.files or None)
    pins = load_pins(args.pins) if not args.no_pins and not args.update_pins else {}
    findings = scan(servers, connect=not args.no_connect, timeout=args.timeout, pins=pins,
                    connect_project=args.connect_project)
    skipped = [s for s in servers if s.skipped and not args.no_connect]
    if skipped:
        print("intentshield scan: not started (config in the current directory; --connect-project starts them): "
              + ", ".join(f"{s.name} ({s.path})" for s in skipped), file=sys.stderr)
    if not args.no_pins and not args.no_connect and any(s.tools for s in servers):
        save_pins(args.pins, pins)
    if args.format == "json":
        print(json.dumps({"servers": [{"client": s.client, "config": str(s.path), "name": s.name,
                                       "tools": len(s.tools), "error": s.error, "skipped": s.skipped}
                                      for s in servers],
                          "findings": [f.as_dict() for f in findings]}, indent=2))
    elif args.format == "sarif":
        print(json.dumps(sarif(findings), indent=2))
    else:
        print(report(servers, findings, home, connected=not args.no_connect))
    return 1 if any(f.level == ERROR for f in findings) else 0
