"""The guard's own surface: the hook settings and the state a command must not delete, edit or switch off."""
from __future__ import annotations

import posixpath
import re

from .core import _PATH_CAP, _PATH_CAP_WHY, ASK, DENY, Hit, _bin, _Stage
from .parsing import _INTERPRETERS
from .paths import _clean_path, _cred_level, _norm, _pathlike, persistence_path

# --- the guard's own surface -------------------------------------------------------------------------------------

_GUARD_SURFACE = re.compile(
    r"(?:^|/)(?:\.claude/(?:settings[\w.-]*\.json|hooks/)|\.codex/(?:config\.toml|hooks\.json)|\.cursor/hooks\.json|"
    r"\.gemini/settings\.json|\.intentshield(?:/|$)|claude-code/managed-settings[\w.-]*\.json|claudecode/managed-settings\.json)",
                            re.I)
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


def guard_surface(path: str) -> tuple[str, str] | None:
    """(decision, why) when ``path`` holds the hook settings of a harness or IntentShield's own state (database, API key):
    what an agent would change to switch the guard off."""
    p = _clean_path(path.strip().strip("\"'").replace("\\", "/"))
    if not p:
        return None
    if len(p) > _PATH_CAP:
        return (ASK, _PATH_CAP_WHY) if _pathlike(p) else None
    n = _norm(p) if p.startswith(("~", "$", "/")) else posixpath.normpath(p)
    if _GUARD_SURFACE.search(n):
        return ASK, "the hook settings of a harness or IntentShield's own state, which is how the guard is switched off"
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
    directory). Writes by redirect, ``tee``, ``cp``, ``sed -i`` are read by ``_persist_hit``."""
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
