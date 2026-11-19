"""Reading and writing the settings files: the atomic write, the copy of a file's original text, and the record of installs."""
from __future__ import annotations

import hashlib
import json
import math
import os
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

from intentshield import translation

from .textedit import strip_json_comments


def _private_dir(directory: Path) -> None:
    """Creates ``directory``; ``~/.intentshield`` (API keys, prompts, backups) is readable by its owner only."""
    translation.private_dir(directory)


# The text each settings file had when this process read it: a harness (Claude Code rewrites ~/.claude.json
# all the time) may write the file between our read and our write, and its change must not be overwritten.
_SEEN: dict[Path, str] = {}


class ChangedMeanwhile(OSError):
    pass


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


# Where the manual way of putting the proxy in front of a server is written down (the wheel carries no docs/ directory).
GATEWAY_DOC = "https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/gateway.md#real-mcp-proxy"
# What a file that does not parse is told to do instead: `install` prints hook entries, which only the hooks need.
_BY_HAND_HOOKS = "or add the entries by hand from the output of `intentshield install <harness> --dry-run`"
_BY_HAND_DRY_RUN = "or add the entries printed above by hand"  # the same command with --dry-run has just printed them
_BY_HAND_UNINSTALL = "or remove the entries whose command runs intentshield-hook by hand"
_BY_HAND_PROXY = f"then run the command again (to put the proxy in front of a server by hand instead, see {GATEWAY_DOC})"


def _holds_non_finite(data: Any) -> bool:
    """Whether a parsed file holds NaN, Infinity or a number too large for a float (``1e400``): ``json.dumps`` would write each as
    a bare word, which is not JSON, so a file that holds one cannot be written back."""
    stack = [data]
    while stack:
        item = stack.pop()
        if isinstance(item, float) and not math.isfinite(item):
            return True
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False


def _read_json(path: Path, by_hand: str = _BY_HAND_HOOKS, rewriting: bool = True) -> dict[str, Any]:
    """The file as a dict. With ``rewriting`` (the default) a file that holds a number JSON cannot write back is refused;
    ``doctor`` only reads, so it passes False."""
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    _SEEN[path.resolve()] = text
    if not text.strip():
        return {}
    try:
        data = _parse(text, path)
    except json.JSONDecodeError as exc:
        if _has_comments(path):
            how = "fix that line"
        elif strip_json_comments(text) != text:  # it has comments or trailing commas, which this file's reader does not take
            how = "remove its comments and trailing commas (this file is read as strict JSON)"
        else:
            how = "fix the syntax error at that position"
        if text.startswith("\ufeff"):
            how = "save it as UTF-8 without a byte order mark (it starts with one, which JSON does not allow)"
        where = f"line {exc.lineno} column {exc.colno}"
        raise _NotJSON(f"{path} is not valid JSON ({exc.msg}, {where}); {how}, {by_hand}", exc) from None
    if _has_comments(path) and strip_json_comments(text) != text:
        _COMMENTED.add(path.resolve())
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a JSON object (the file must start with {{ and end with }}); fix it or move it "
                         "aside, then run the command again")
    if rewriting and _holds_non_finite(data):
        raise ValueError(f"{path} holds a number that JSON cannot write back (NaN, Infinity, or one too large such as 1e400), "
                         "so it cannot be rewritten safely and was left unchanged; change that number, then run it again")
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


def _read_client(path: Path, rewriting: bool = True) -> dict[str, Any]:
    """Like ``_read_json``, for a TOML client file too; what it says to do about a file that does not parse fits ``wrap``,
    ``unwrap`` and ``doctor``, which read MCP client files, not a hook settings file."""
    if not _is_toml(path):
        return _read_json(path, _BY_HAND_PROXY, rewriting)
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    _SEEN[path.resolve()] = text
    try:
        return _client_data(text, path)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"{path} is not valid TOML ({exc}); fix it, or add the entries by hand "
                         f"(see {GATEWAY_DOC})") from None


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
    try:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    except OSError as exc:  # name the directory that cannot be written, not the temporary file in it
        raise OSError(exc.errno, exc.strerror, str(path.parent)) from None
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
    return json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


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
