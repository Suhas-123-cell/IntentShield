"""``wrap`` and ``unwrap``: put the transparent proxy in front of the stdio servers of a client's MCP file, and take it away."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any

# ``records._write``, ``records._json_text`` and ``hooks.executable`` are called through their modules, not imported by name, so a
# name patched on the ``intentshield.install`` package (see its ``__init__``) is the one used here.
from . import hooks, records
from .hooks import _PROXY, _refuse_ephemeral
from .records import (
    _SEEN,
    GATEWAY_DOC,
    _backup_path,
    _client_data,
    _exact_text,
    _is_toml,
    _keep_original,
    _read_client,
    _remember_servers,
    _undone_text,
    _undone_toml,
)
from .settings import client_config_files
from .textedit import _toml_set

_SERVER_ID = re.compile(r"[^A-Za-z0-9_.-]")
_MAX_STEM = 100  # a file name holds 255 bytes: the stem, a hash, and ".json" or ".db" must fit, whatever the server is called


def server_stem(name: str, config: Path | None = None) -> str:
    """A server id or file stem for a server name: the name itself when it is already a valid id and no client file is given, else
    sanitized plus a short hash of the name and the client file it came from. The proxy config and the audit database of a wrapped
    server are named by that stem, so "my server" and "my-server", or "github" in two clients' files, never share either. The
    server id
    stays the plain name, because the hook finds the tool catalog by the name the harness shows; a catalog of the same name in two
    clients' files is therefore one file. A stem is cut to ``_MAX_STEM`` characters (the hash keeps it unique), so that the files
    named by it fit the file system's limit on a name."""
    stem = _SERVER_ID.sub("-", name).strip("-.").replace("__", "-") or "server"
    if not re.match(r"^[A-Za-z0-9]", stem):
        stem = "s-" + stem
    stem = stem[:_MAX_STEM].rstrip("-.")
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
            f"where FILE is a proxy config naming the server's own command (see {GATEWAY_DOC})")


def _in_repository(path: Path) -> bool:
    """The file lies inside a git working tree, where it may be committed."""
    return any((d / ".git").exists() for d in (path.resolve().parent, *path.resolve().parents))


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


def _plan_wrap(path: Path, groups: list[tuple[str, dict[str, Any]]], servers: list[str] | None, proxy: str,
               out_dir: Path) -> tuple[list[tuple[dict[str, Any], str, str, dict[str, Any], Path, dict[str, Any]]], bool]:
    """Each stdio server to wrap, with the config the proxy gets for it; one it cannot take is said and skipped. True when
    one was skipped for a reason the user can fix."""
    from intentshield.mcp_proxy import MCPProxyConfig  # the proxy must accept each config before the client file changes
    plan: list[tuple[dict[str, Any], str, str, dict[str, Any], Path, dict[str, Any]]] = []
    skipped = False
    for scope, entries in groups:
        for name, server in entries.items():
            if servers and name not in servers:
                continue
            if not isinstance(server, dict) or not server.get("command") or server.get("url"):
                # HTTP servers are not launched by the client, so there is no process to stand in front of.
                print(f"skipped {_label(name, scope)}: not a stdio server (guard HTTP servers with the gateway, "
                      f"see {GATEWAY_DOC})")
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
                          f"(see {GATEWAY_DOC})")
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
    return plan, skipped


def _say_wrapped(path: Path, wrapped: Wrapped, groups: list[tuple[str, dict[str, Any]]], skipped: bool,
                 dry_run: bool) -> None:
    """What a wrap did, and the next step."""
    if wrapped:
        print(f"{'would wrap' if dry_run else 'wrapped'} {len(wrapped)} server(s) in {path}: {', '.join(wrapped)}")
        if not dry_run and _in_repository(path):
            print(f"note: {path} now holds absolute paths of this machine (the proxy and its config): do not commit it, or "
                  "run `intentshield unwrap` on it first.")
        if not dry_run:
            local = _inside(path, Path.cwd())
            closing_note = (" (close it before wrapping ~/.claude.json, which Claude Code rewrites)"
                            if path.name == ".claude.json" else "")
            known = {p.resolve() for files in client_config_files(Path.home(), Path.cwd()) for p in files}
            if path.resolve() in known:
                check = (f"`intentshield doctor --connect{'-project' if local else ''}` to check that each wrapped server "
                         "starts through the proxy.")
            else:   # doctor reads only the usual client files, so it would not list this one
                check = (f"`intentshield scan {shlex.quote(str(path))}` to start each wrapped server through the proxy and "
                         "check its tools (`intentshield doctor` reads only the usual client files, not this one).")
            print(f"Next: restart the MCP client that reads {path}{closing_note}, then run {check}")
    elif any(isinstance(s, dict) and _is_wrapped(s) for _, entries in groups for s in entries.values()):
        print(f"already wrapped: {path}")
    elif not skipped:
        print(f"nothing to wrap in {path}: no stdio servers")


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
    proxy = proxy or hooks.executable(_PROXY)
    _refuse_ephemeral(proxy, "proxy command", dry_run, allow_ephemeral)
    plan, skipped = _plan_wrap(path, groups, servers, proxy, out_dir)
    wrapped = Wrapped()
    wrapped.skipped = skipped
    before: dict[str, dict[str, Any]] = {}
    edits: dict[str, tuple[str, list[str] | None]] = {}
    created: list[Path] = []
    try:
        for entries, name, scope, server, config_path, generated in plan:
            if not dry_run and not config_path.exists():
                created.append(config_path)
            records._write(config_path, json.dumps(generated, indent=2) + "\n", dry_run)
            before[json.dumps([scope, name])] = {"command": server["command"],
                                                 **({"args": server["args"]} if "args" in server else {})}
            entries[name] = {**server, "command": proxy, "args": ["--transparent", "--config", str(config_path)]}
            edits[name] = (proxy, entries[name]["args"])
            wrapped.append(_label(name, scope))
        if wrapped:
            text = _toml_set(_exact_text(path), edits) if _is_toml(path) else records._json_text(data)
            _keep_original(path, None, dry_run)
            if not dry_run:
                _remember_servers(path, before)
            records._write(path, text, dry_run)
    except BaseException:
        for config_path in created:  # the client file was not changed: no config of this run is left behind
            config_path.unlink(missing_ok=True)
            _SEEN.pop(config_path.resolve(), None)
        raise
    _say_wrapped(path, wrapped, groups, skipped, dry_run)
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
                generated = json.loads(config.read_text(encoding="utf-8"))
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
        records._write(path, text, dry_run)
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
