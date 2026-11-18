"""Symbolic links: the path a name really leads to, so that a rule judges what a call touches and not only what it says.

The rules read the text of a path. A link made by an earlier call (``ln -s ~ h``, then ``cat h/.ssh/id_rsa``) or one that was
there before (``notes.txt`` that points at a key) gives a path that looks harmless and is not. For a path that exists on disk the
real path is read as well, and the stricter verdict of the two counts. For a glob, or a file that is not there yet, it is the real
path of the directory it lies in that is read, so a write through a link to a directory is seen too.

A path that passes through a link without leaving the place it was in keeps its verdict: ``/tmp``, ``/var`` and ``/etc`` are links
into ``/private`` on macOS, and a home directory may itself lie behind a link (``_norm`` reads both ends as the same ``~``).
Nothing here raises: a loop of links, a name too long for the file system, a directory that cannot be read, or a name that is not
a path leaves the path as it was. The reading is bounded: one file system call per path component, at most ``_BUDGET`` different
paths in one call, and past that the call is asked about."""
from __future__ import annotations

import os
import posixpath
import re
from contextvars import ContextVar, Token

from .core import _PATH_CAP
from .paths import _HOME_HEAD, _head_home, _norm

_BUDGET = 20000   # different paths whose links are read in one call (the most words one command is read for); more is asked about
_GLOB_CHARS = frozenset("*?[")
# macOS: /tmp, /var and /etc are links into /private, and /home and the like are firmlinks into the data volume. A path that
# passes through one of these is in the place it was written in.
_ALIAS = re.compile(r"/(?:private(?=/(?:tmp|var|etc)(?:/|$))|System/Volumes/Data(?=/|$))")

TOO_MANY_LINKS = (f"the call names more than {_BUDGET} different paths, too many to check for symbolic links; check what they "
                  "lead to.")

# True while a variant of a command is read with its paths replaced by their real paths (see ``variables._moved_stages``).
FOLLOW: ContextVar[bool] = ContextVar("intentshield_follow_links", default=False)
# True for the programs that act on a link itself and not on what it leads to (``rm h`` removes the link ``h``, ``mv h x`` moves
# it): the last part of a path stays as it was written. A trailing slash (``rm -rf h/``) names what the link leads to.
KEEP_LAST: ContextVar[bool] = ContextVar("intentshield_keep_last_link", default=False)


class _Seen:
    """The paths read in one call and what each led to, so that a word repeated a thousand times is read once."""

    __slots__ = ("over", "paths")

    def __init__(self) -> None:
        self.paths: dict[tuple[str, str, bool], str | None] = {}
        self.over = False


_SEEN: ContextVar[_Seen | None] = ContextVar("intentshield_links_seen", default=None)


def start() -> Token[_Seen | None]:
    """Begin a call: the paths read from now on are counted. Pass what it returns to ``finish``."""
    return _SEEN.set(_Seen())


def over_budget() -> bool:
    seen = _SEEN.get()
    return bool(seen and seen.over)


def finish(token: Token[_Seen | None]) -> None:
    _SEEN.reset(token)


def _absolute(cwd: str) -> str | None:
    """The directory ``cwd`` as an absolute path (it may be written with ``~``), or None when it is not known."""
    if cwd.startswith("/"):
        return cwd
    head = _HOME_HEAD.match(cwd)
    return _head_home(head[0]) + cwd[head.end():] if head else None


def _spelled(arg: str, cwd: str) -> str | None:
    """``arg`` as an absolute path, not yet normalised (a ``..`` stays, since it is made on the real directory), or None when it
    is not a path that can be read here: a flag, an address, a word with a variable in it."""
    path = arg.strip().strip("\"'")
    if not path or path.startswith("-") or "://" in path or "\x00" in path or len(path) > _PATH_CAP:
        return None
    head = _HOME_HEAD.match(path)
    if head:
        path = _head_home(head[0]) + path[head.end():]
    elif not path.startswith("/"):
        base = _absolute(cwd) if cwd else None
        if base is None:
            return None
        path = base.rstrip("/") + "/" + path
    return None if "$" in path or "`" in path or len(path) > _PATH_CAP + 1024 else path


def _resolve(spelled: str, keep_last: bool = False) -> str:
    """The real path of ``spelled``; of the directory before the first glob when it has one. With ``keep_last`` a last part that
    is a name (not ``.``, ``..`` or empty) is not followed."""
    parts = spelled.split("/")
    cut = next((i for i, part in enumerate(parts) if _GLOB_CHARS & set(part)), len(parts))
    if keep_last and cut == len(parts) and parts[-1] not in ("", ".", ".."):
        return os.path.realpath("/".join(parts[:-1]) or "/").rstrip("/") + "/" + parts[-1]
    head = "/".join(parts[:cut]) or "/"
    real = os.path.realpath(head)
    tail = "/".join(parts[cut:])
    return real.rstrip("/") + "/" + tail if tail else real


def real_path(arg: str, cwd: str = "") -> str | None:
    """The absolute path ``arg`` leads to when a link on the way takes it somewhere else than the text says, else None.
    ``cwd`` is the directory a relative ``arg`` is read from."""
    seen = _SEEN.get()
    keep_last = KEEP_LAST.get()
    key = (cwd, arg, keep_last)
    if seen is not None and key in seen.paths:
        return seen.paths[key]
    spelled = _spelled(arg, cwd)
    if spelled is None:
        return None
    if seen is not None:
        if len(seen.paths) >= _BUDGET:
            seen.over = True
            return None
    result: str | None = None
    try:
        target = posixpath.normpath(_resolve(spelled, keep_last))
        written = posixpath.normpath(spelled)
        if (alias := _ALIAS.match(target)) and not written.startswith(alias[0]):
            target = target[alias.end():] or "/"   # /tmp/x is /private/tmp/x on macOS, and the same place
        if target != written and _norm(target) != _norm(written):
            result = target
    except (OSError, ValueError, RuntimeError, UnicodeError):
        result = None
    if seen is not None:
        seen.paths[key] = result
    return result
