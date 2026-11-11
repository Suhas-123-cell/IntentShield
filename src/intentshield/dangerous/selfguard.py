"""The guard's own surface: the hook settings and the state a command must not delete, edit or switch off."""
from __future__ import annotations

import os
import posixpath
import re
from pathlib import Path

from .core import _PATH_CAP, _PATH_CAP_WHY, _WORKDIR, ASK, DENY, Hit, _bin, _Stage
from .parsing import _INTERPRETERS
from .paths import _clean_path, _cred_level, _norm, _pathlike, persistence_path

# --- the guard's own surface -------------------------------------------------------------------------------------

_GUARD_SURFACE = re.compile(
    r"(?:^|/)(?:\.claude/(?:settings[\w.-]*\.json|hooks/)|\.codex/(?:config\.toml|hooks\.json)|\.cursor/hooks\.json|"
    r"\.gemini/settings\.json|\.intentshield(?:/|$)|claude-code/managed-settings[\w.-]*\.json|claudecode/managed-settings\.json)",
                            re.I)
# IntentShield's programs (``bin/intentshield-hook``, ``bin/intentshield-mcp``), its installed package, and the MCP client
# files that hold a server behind its proxy: a write to any of them stops the hook or the proxy from running as installed.
_PROGRAM = re.compile(r"(?:^|/)(?:bin|Scripts)/intentshield[\w-]*(?:\.exe)?$", re.I)
_SITE_PACKAGE = re.compile(r"(?:^|/)(?:site|dist)-packages/(?:intentshield(?:/|$)|"
                           r"intentshield_mcp-[\w.]+\.(?:dist|egg)-info(?:/|$))", re.I)
_CLIENT_FILES = frozenset({".mcp.json", "mcp.json", ".claude.json", "claude_desktop_config.json", "settings.json"})
_PACKAGE_DIR = posixpath.normpath(str(Path(__file__).resolve().parents[1]))
_WHY_PROGRAM = "IntentShield's own program or installed package, which is how the guard is switched off"
_WHY_CLIENT = "an MCP client file that sends its servers through the IntentShield proxy, which is how the proxy is bypassed"
_SELF_FILES = re.compile(r"(?:^|[;&|(\n]\s{0,5})(?:sudo\s+)?(?:rm|mv|unlink|chmod|chown|truncate|shred|rmdir)\b[^;&|\n]{0,200}"
                         r"(?:\.intentshield\b|\b(?:hooks|threats)\.db\b|(?:bin/|Scripts/|which\s+|command\s+-v\s+|type\s+-p\s+)"
                         r"intentshield[\w-]*)")
_SELF_SQL = re.compile(r"(?:^|[;&|(\n]\s{0,5})sqlite3?\b[^\n]{0,1200}\b(?:hooks|threats)\.db\b", re.I)
_SQL_WRITE = re.compile(r"\b(?:delete\s+from|drop\s+(?:table|index|view)|update\s+\w|insert\s+(?:or\s+\w+\s+)?into|replace"
                        r"\s+into|"
                        r"alter\s+table|vacuum)\b", re.I)
_PACKAGE_MANAGERS = frozenset({"pip", "pip3", "pipx", "uv", "conda", "mamba", "poetry", "pdm", "brew", "python", "python3"})
_SELF_WRITE_CODE = re.compile(r"\b(?:write|dump|unlink|remove|rmtree|replace|rename|truncate|write_text|copyfile|move)\b|"
                              r"open\([^)]{0,200}['\"][wa]", re.I)


def _absolute(path: str) -> str:
    """``path`` as an absolute path (a relative one from the call's working directory), or "" when it cannot be told."""
    if path.startswith(("~", "$")):
        home = _norm(path)
        return str(Path.home()) + home[1:] if home.startswith("~") else ""
    try:
        base = _WORKDIR.get() or os.getcwd()
    except OSError:
        return ""
    return posixpath.normpath(posixpath.join(base, path))


def _wrapped_client_file(path: str) -> bool:
    """The file exists and holds a server that starts the transparent proxy."""
    try:
        with open(path, "rb") as handle:
            text = handle.read(1_000_000).decode("utf-8", "replace").lower()
    except OSError:
        return False
    return "--transparent" in text and "intentshield" in text


def guard_surface(path: str) -> tuple[str, str] | None:
    """(decision, why) when ``path`` holds the hook settings of a harness, IntentShield's own state (database, API key), its
    programs, its installed package or an MCP client file that runs a server behind its proxy: what an agent would change to
    switch the guard off."""
    p = _clean_path(path.strip().strip("\"'").replace("\\", "/"))
    if not p:
        return None
    if len(p) > _PATH_CAP:
        return (ASK, _PATH_CAP_WHY) if _pathlike(p) else None
    n = _norm(p) if p.startswith(("~", "$", "/")) else posixpath.normpath(p)
    if _GUARD_SURFACE.search(n):
        return ASK, "the hook settings of a harness or IntentShield's own state, which is how the guard is switched off"
    if _PROGRAM.search(n) or _SITE_PACKAGE.search(n):
        return ASK, _WHY_PROGRAM
    absolute = _absolute(p)
    if absolute and (absolute == _PACKAGE_DIR or absolute.startswith(_PACKAGE_DIR + "/")):
        return ASK, _WHY_PROGRAM
    if absolute and posixpath.basename(n) in _CLIENT_FILES and _wrapped_client_file(absolute):
        return ASK, _WHY_CLIENT
    return None


def _guard_text(data: str, text: str) -> Hit | None:
    """Commands that delete or change IntentShield's own files or programs, or edit its database, by their text (a command
    that starts with the program, so a commit message that names them does not count)."""
    if _SELF_FILES.search(data):
        return Hit(ASK, "this deletes or changes IntentShield's own files or programs, which switches the guard off.")
    if _SELF_SQL.search(text) and _SQL_WRITE.search(text):
        return Hit(ASK, "this edits IntentShield's own database (sessions, taint, threat memory).")
    return None


def _guard_hit(name: str, argv: list[str], stage: _Stage) -> Hit | None:
    """A program that deletes, empties or moves a file of the guard's own surface (a harness's hook settings, the state
    directory, the programs, the package). Writes by redirect, ``tee``, ``cp``, ``ln``, ``dd``, ``sed -i`` are read by
    ``_persist_hit``."""
    words = [_bin(a) for a in argv[:5]]
    if "intentshield" in words:
        rest = argv[words.index("intentshield") + 1:]
        if rest and rest[0] in ("uninstall", "unwrap", "install", "wrap") and "--dry-run" not in argv:
            return Hit(ASK, f"intentshield {rest[0]} changes or removes the guard.")
    if name in _PACKAGE_MANAGERS and any(a in ("uninstall", "remove") for a in argv[1:4]) and any(
            a.lower().startswith("intentshield") for a in argv[1:]):
        return Hit(ASK, f"{name} uninstalls the IntentShield package, which removes the guard.")
    if name in ("rm", "unlink", "rmdir", "truncate", "shred", "mv", "chmod", "chown", "chgrp"):
        args = [a for a in argv[1:] if not a.startswith("-")]
        for a in args[:-1] if name == "mv" and len(args) > 1 else args:
            if (hit := guard_surface(a)):
                return Hit(hit[0], f"{name} changes {a}, {hit[1]}.", a)
    if name in ("cp", "mv", "install", "ln", "rsync", "ditto"):  # a file named like the program, put into a bin directory
        args = [a for a in argv[1:] if not a.startswith("-")]
        if len(args) > 1 and re.search(r"(?:^|/)(?:bin|Scripts)/?$", args[-1]) and any(
                posixpath.basename(a.rstrip("/")).lower().startswith("intentshield") for a in args[:-1]):
            return Hit(ASK, f"{name} puts a program named like IntentShield's into {args[-1]}, which can replace the guard.",
                       args[-1])
    if name in _INTERPRETERS:
        joined = " ".join(argv[1:])
        if _GUARD_SURFACE.search(joined.replace("\\", "/")) and _SELF_WRITE_CODE.search(joined):
            return Hit(ASK,
                       "this program's code writes or deletes a file of the guard's own surface (hook settings, IntentShie"
                       "ld's state).")
    return None


def _erase_hit(name: str, argv: list[str]) -> Hit | None:
    """rm, unlink, truncate, shred or mv of a key, a cloud credential or an access file: not a read, but a way to lose one."""
    if name not in ("rm", "unlink", "truncate", "shred", "mv"):
        return None
    args = [a for a in argv[1:] if not a.startswith("-")]
    for a in args[:-1] if name == "mv" and len(args) > 1 else args:
        cred, pers = _cred_level(a), persistence_path(a)
        found = cred if cred and cred[0] == DENY else pers if pers and pers[0] == DENY else None
        if found:
            return Hit(ASK, f"{name} removes or empties {a}, {found[1]}.", a)
    return None
