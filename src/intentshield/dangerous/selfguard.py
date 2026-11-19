"""The guard's own surface: the hook settings and the state a command must not delete, edit or switch off."""
from __future__ import annotations

import fnmatch
import os
import posixpath
import re
from pathlib import Path

from .core import _PATH_CAP, _PATH_CAP_WHY, _WORKDIR, ASK, DENY, Hit, _bin, _is_opt, _note_cap, _Stage
from .parsing import _INTERPRETERS
from .paths import _clean_path, _cred_level, _ends_in_glob, _glob_hits, _home_or_above, _norm, _pathlike, persistence_path
from .writes import _find_roots

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
_SQL_WRITE = re.compile(r"\b(?:delete\s+from|drop\s+(?:table|index|view|trigger)|update\s+(?:or\s+\w+\s+)?\w+|"
                        r"insert\s+(?:or\s+\w+\s+)?into|replace\s+into|alter\s+table|vacuum|pragma\s+writable_schema|"
                        r"create\s+(?:temp(?:orary)?\s+)?(?:unique\s+|virtual\s+)?(?:table|trigger|view|index)|"
                        r"reindex|analyze)\b|\bpragma\s+\w+\s*=", re.I)
# sqlite3's own commands that run or load a script it cannot be seen to hold (``.read FILE``).
_SQL_DOT = re.compile(r"(?<![\w.])\.(?:read|restore|import)\b|(?<![\w-])-init\b", re.I)
# sqlite3 fed a script on its standard input, by a redirect from a file or a pipe: what the script holds is not in the command.
_DB = r"\b(?:hooks|threats)\.db\b"
_SQL_STDIN = re.compile(
    r"(?:^|[;&|(\n]\s{0,5})sqlite3?\b[^\n;&|]{0,1200}" + _DB + r"[^\n;&|]{0,1200}(?<!<)<(?!<)|"
    r"(?:^|[;&|(\n]\s{0,5})sqlite3?\b[^\n;&|]{0,1200}(?<!<)<(?!<)[^\n;&|]{0,1200}" + _DB + r"|"
    r"(?<!\|)\|\s{0,5}sqlite3?\b[^\n;&|]{0,1200}" + _DB + r"['\"]?\s{0,5}(?:$|[;&|)\n<>])", re.I)
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


# The files of a harness's settings directory that hold its hooks, as paths inside the directory.
_RELOCATED_FILE = re.compile(r"(?:settings[\w.-]*\.json|config\.toml|hooks\.json|hooks(?:/.*)?)", re.I)


_RELOCATING = ("CLAUDE_CONFIG_DIR", "CODEX_HOME")
_RELOCATING_WORD = re.compile(r"^\$(?:\{(" + "|".join(_RELOCATING) + r")\}|(" + "|".join(_RELOCATING) + r")(?![A-Za-z0-9_]))")


def _real(path: str) -> str:
    """``path`` with its symbolic links followed (``/tmp`` is ``/private/tmp`` on macOS), or as it is when that cannot be done."""
    try:
        return os.path.realpath(path).replace("\\", "/")
    except (OSError, ValueError):
        return path


def _relocated_dirs() -> tuple[str, ...]:
    """The directories ``CLAUDE_CONFIG_DIR`` and ``CODEX_HOME`` name, as absolute paths in lower case, as written and with their
    links followed. The hook inherits them from the harness that started it, and that harness reads its hook settings there
    and not in ``~/.claude`` or ``~/.codex``."""
    found: list[str] = []
    for name in _RELOCATING:
        value = os.environ.get(name, "").strip()
        if value and "\n" not in value:
            written = posixpath.normpath(os.path.expanduser(value).replace("\\", "/"))
            found += [written, _real(written)]
    return tuple(dict.fromkeys(d.lower() for d in found if d.startswith("/") and d.strip("/")))


def _relocated_spellings(path: str) -> tuple[str, ...]:
    """``path`` as absolute paths in lower case to compare with ``_relocated_dirs``: ``$CLAUDE_CONFIG_DIR`` or ``$CODEX_HOME`` at
    its start is replaced by the directory it names, and the path is given as written and with its links followed. Empty when
    it cannot be told."""
    named = _RELOCATING_WORD.match(path)
    if named:
        value = os.environ.get(named[1] or named[2], "").strip()
        path = os.path.expanduser(value).replace("\\", "/") + path[named.end():] if value else path
    absolute = _absolute(path)
    return tuple(dict.fromkeys(p.lower() for p in (absolute, _real(absolute)))) if absolute else ()


def _relocated_settings(path: str) -> bool:
    """``path`` is a hook settings file in a directory that ``CLAUDE_CONFIG_DIR`` or ``CODEX_HOME`` names."""
    moved = _relocated_dirs()
    return bool(moved) and any(spelled.startswith(d + "/") and _RELOCATED_FILE.fullmatch(spelled[len(d) + 1:])
                               for spelled in _relocated_spellings(path) for d in moved)


def guard_surface(path: str) -> tuple[str, str] | None:
    """(decision, why) when ``path`` holds the hook settings of a harness, IntentShield's own state (database, API key), its
    programs, its installed package or an MCP client file that runs a server behind its proxy: what an agent would change to
    switch the guard off."""
    p = _clean_path(path.strip().strip("\"'").replace("\\", "/"))
    if not p:
        return None
    if len(p) > _PATH_CAP:
        if not _pathlike(p):
            return None
        _note_cap(_PATH_CAP_WHY)
        return ASK, _PATH_CAP_WHY
    n = _norm(p) if p.startswith(("~", "$", "/")) else posixpath.normpath(p)
    if _GUARD_SURFACE.search(n):
        return ASK, "the hook settings of a harness or IntentShield's own state, which is how the guard is switched off"
    if _PROGRAM.search(n) or _SITE_PACKAGE.search(n):
        return ASK, _WHY_PROGRAM
    if _relocated_settings(p):
        return ASK, "the hook settings of a harness or IntentShield's own state, which is how the guard is switched off"
    absolute = _absolute(p)
    if absolute and (absolute == _PACKAGE_DIR or absolute.startswith(_PACKAGE_DIR + "/")):
        return ASK, _WHY_PROGRAM
    if absolute and posixpath.basename(n) in _CLIENT_FILES and _wrapped_client_file(absolute):
        return ASK, _WHY_CLIENT
    return None


# The directories that hold the hook settings above, and the files in them that a pattern for names must not reach: removing
# or moving the directory removes the settings file in it, so it is judged as the file is.
_GUARD_DIR = re.compile(r"(?:^|/)(?:\.claude|\.codex|\.cursor|\.gemini|\.intentshield|\.claude/hooks|etc/claude-code|"
                        r"application support/claudecode|programdata/claudecode)$", re.I)
_GUARD_DIR_PATHS = ("~/.claude", "~/.codex", "~/.cursor", "~/.gemini", "~/.intentshield", "~/.claude/hooks", "/etc/claude-code")
_GUARD_FILE_NAMES = ("settings.json", "settings.local.json", "hooks", "config.toml", "hooks.json", "managed-settings.json")
_WHY_DIR = ("a directory that holds the hook settings of a harness or IntentShield's own state, which is how the guard is "
            "switched off")


def guard_dir(path: str, whole: bool = True) -> tuple[str, str] | None:
    """(decision, why) when removing, moving or (recursively) changing ``path`` takes the hook settings with it: the directory
    that holds them (``~/.claude``, ``.codex``, ``.cursor``, ``.gemini``, ``.claude/hooks``), spelled alone (when ``whole``: the
    operation takes the whole directory, as ``rm -r``, ``mv`` and ``find -delete`` do), with a glob over everything in it
    (``~/.claude/*``) or with a glob over names that can be the settings file (``~/.claude/set*``). A path inside the directory
    (``.claude/worktrees/x``, ``.claude/commands/x.md``) is not."""
    p = _clean_path(path.strip().strip("\"'").replace("\\", "/"))
    if not p or len(p) > _PATH_CAP:
        return None
    moved = _relocated_dirs()   # the directories CLAUDE_CONFIG_DIR and CODEX_HOME name
    for spelled in _relocated_spellings(p) if moved else ():
        parent, _, last = spelled.rpartition("/")
        if any(c in last for c in "*?["):
            if parent in moved and (_ends_in_glob(spelled) or any(fnmatch.fnmatchcase(name, last) for name in _GUARD_FILE_NAMES)):
                return ASK, _WHY_DIR
            if any(posixpath.dirname(d) == parent and fnmatch.fnmatchcase(posixpath.basename(d), last) for d in moved):
                return ASK, _WHY_DIR   # ``rm -rf ~/.config/cc-w*`` can be the directory itself
        elif spelled in moved and (whole or _ends_in_glob(p)):
            return ASK, _WHY_DIR
    rooted = p.startswith(("~", "$", "/"))
    n = _norm(p) if rooted else posixpath.normpath(p)
    parent, _, last = n.rpartition("/")
    if any(c in last for c in "*?["):
        if _GUARD_DIR.search(parent) and (_ends_in_glob(n) or any(fnmatch.fnmatchcase(name, last.lower())
                                                                 for name in _GUARD_FILE_NAMES)):
            return ASK, _WHY_DIR
        return (ASK, _WHY_DIR) if rooted and _glob_hits(p, _GUARD_DIR_PATHS) else None   # ``~/.cl*`` can be ``~/.claude``
    return (ASK, _WHY_DIR) if _GUARD_DIR.search(n) and (whole or _ends_in_glob(p)) else None


def _takes_dir(name: str, argv: list[str]) -> list[tuple[str, bool]]:
    """(path, whole) of the arguments of ``name`` that it removes, moves or changes everything in: ``whole`` is True when it takes
    the directory itself (``rm -r``, ``rmdir``, a ``mv`` source, ``chmod -R``), False when it takes the files of the directory
    only if the path ends in a glob (``rm ~/.claude/*``)."""
    flags = [a for a in argv[1:] if a.startswith("-") and len(a) > 1 and a != "--"]
    args = [a for a in argv[1:] if not a.startswith("-")]
    recursive = any(_is_opt(a, "--recursive") or (not a.startswith("--") and "r" in a[1:].lower()) for a in flags)
    if name == "mv":
        return [(a, True) for a in args[:-1]] if len(args) > 1 else []
    if name == "rmdir" or (name in ("chmod", "chown", "chgrp") and recursive):
        return [(a, True) for a in args]
    if name in ("trash", "trash-put", "rmtrash", "gtrash"):   # moves what it is given to the trash
        return [(a, True) for a in args]
    if name == "rm":   # ``-d`` removes a directory that is empty, as ``rmdir`` does
        return [(a, recursive or any(not a.startswith("--") and "d" in a[1:] for a in flags)) for a in args]
    return []


def _find_deletes(args: list[str]) -> bool:
    """The ``find`` deletes what it matches (``-delete``, or ``-exec rm``)."""
    return "-delete" in args or ("-exec" in args and any(_bin(a) in ("rm", "shred", "unlink") for a in args))


def _find_reaches_settings(args: list[str]) -> bool:
    """False only when every test on the name that limits the ``find`` is one that the settings files cannot pass (``-name
    '*.jsonl'``). No test on the name, a test on age or size alone, ``-o``, ``!`` or ``-not`` can reach them."""
    if any(a in ("-o", "-or", "!", "-not") for a in args):
        return True
    names = [args[k + 1].lower() for k, a in enumerate(args[:-1]) if a in ("-name", "-iname")]
    return not names or any(fnmatch.fnmatchcase(name, pattern) for pattern in names for name in _GUARD_FILE_NAMES)


def _guard_text(data: str, text: str) -> Hit | None:
    """Commands that delete or change IntentShield's own files or programs, or edit its database, by their text (a command
    that starts with the program, so a commit message that names them does not count)."""
    if _SELF_FILES.search(data):
        return Hit(ASK, "this deletes or changes IntentShield's own files or programs, which switches the guard off.")
    if _SELF_SQL.search(text) and (_SQL_WRITE.search(text) or _SQL_DOT.search(text) or _SQL_STDIN.search(text)):
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
    for a, whole in _takes_dir(name, argv):
        if (hit := guard_dir(a, whole)):
            return Hit(hit[0], f"{name} takes {a}, {hit[1]}.", a)
    if name == "find" and _find_deletes(argv[1:]) and _find_reaches_settings(argv[1:]):
        for start in _find_roots(argv[1:]):
            if (hit := guard_dir(start)):
                return Hit(hit[0], f"find deletes under {start}, {hit[1]}.", start)
            if _home_or_above(start):   # the directories of the settings lie below it
                return Hit(ASK, f"find deletes under {start}, which holds the hook settings of a harness, and its test can match "
                                "a settings file.", start)
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
        if re.search(_DB, joined, re.I) and _SQL_WRITE.search(joined):
            return Hit(ASK, "this program's code edits IntentShield's own database (sessions, taint, threat memory).")
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
