"""Variables a command assigns itself, read as far as their values can be known."""
from __future__ import annotations

import re
import shlex
from pathlib import PurePosixPath

from .lexical import _DECLARE, _KEYWORDS, _MAX_EXPANSION, _WORD_SPECIAL, _WRAPPERS, _state, _step

_ASSIGN = re.compile(r"([A-Za-z_]\w*)(\+?)=")
_USE = re.compile(r"\$(?:\{([A-Za-z_]\w*)(\}?)|([A-Za-z_]\w*))")
_BRACED = re.compile(r"\$\{([^}${]{0,300})\}")  # bounded: an unclosed ${ must not make every later one rescan
_USE_ASSIGN = re.compile(r"\$\{[A-Za-z_]\w*:?=")
_OPTION_LETTERS = re.compile(r"-([A-Za-z]*)")
_USE_DEFAULT = re.compile(r"\$\{([A-Za-z_]\w*):?[-=][^}]{0,300}\}")  # ${name:-default}: the value when there is one


def _option_letters(arg: str) -> str:
    """The letters of a ``-abc`` option cluster; the pattern matches any word that starts with ``-``."""
    m = _OPTION_LETTERS.match(arg)
    return m[1] if m else ""


# Commands that give a variable a value this does not follow: read H, mapfile H, getopts o H, printf -v H, unset H;
# eval and source can set any of them.
_SETTERS = frozenset({"read", "mapfile", "readarray", "getopts", "printf", "unset", "eval", "source", "."})
_NAME = re.compile(r"([A-Za-z_]\w*)(?:\[.*\])?")


def _word_end(text: str, i: int) -> int:
    """Where the shell word that starts at ``i`` ends: at blank space or an operator outside quotes and ``$(...)``."""
    stack: list[str] = []
    n = len(text)
    while i < n:
        if not stack:
            m = _WORD_SPECIAL.search(text, i)
            if m is None:
                return n
            if m.start() > i:
                i = m.start()
                continue
            if text[i] in " \t\n;&|()":
                return i
        i = _step(text, i, stack)
    return n


class _TooBig(Exception):
    """Writing the variables out would take more text than ``_MAX_EXPANSION``."""


def _spend(size: int) -> None:
    left = getattr(_state, "budget", _MAX_EXPANSION) - size
    _state.budget = left
    if left < 0:
        raise _TooBig


class _Stale:
    """Names whose value may have changed behind the parser's back: set by a builtin (``read H``), or by
    ``eval`` and ``source``, which can set any name assigned before them."""

    def __init__(self, known: dict[str, str]) -> None:
        self.names: set[str] = set()
        self.born = dict.fromkeys(known, 0)  # when each name was given its value
        self.tick = 0
        self.cut = -1  # names given their value at or before this are stale (the last eval or source)

    def assigned(self, name: str) -> None:
        self.tick += 1
        self.born[name] = self.tick

    def everything(self) -> None:
        self.cut = self.tick

    def add(self, name: str) -> None:
        self.names.add(name)

    def __contains__(self, name: str) -> bool:
        return name in self.names or self.born.get(name, self.tick + 1) <= self.cut


def _expand_word(word: str, values: dict[str, str], used: set[str], stale: _Stale | None = None,
                 hits: set[str] | None = None) -> str:
    """``word`` with the variables it uses written out, except inside single quotes. A use of a name in
    ``stale`` (a builtin gave it a value that is not known), or of an assigned one in a form that is not
    written out (``${H[0]}``, ``${H%x}``), goes into ``hits``."""
    if "$" not in word:
        return word
    out: list[str] = []
    k, n, single, double = 0, len(word), False, False
    while k < n:
        c = word[k]
        if single:
            single = c != "'"
        elif c == "\\":
            out.append(word[k:k + 2])
            k += 2
            continue
        elif c == "'" and not double:
            single = True
        elif c == '"':
            double = not double
        elif c == "$":
            m = _USE.match(word, k)
            if m:
                name = m[1] or m[3]
                used.add(name)
                value = values.get(name)
                if hits is not None and stale is not None and m[1] and _USE_ASSIGN.match(word, k):
                    stale.add(name)  # ${H:=x} sets H when it has no value yet
                if hits is not None and stale is not None and (name in stale or (m[1] and not m[2] and value is not None)):
                    default = _USE_DEFAULT.match(word, k)
                    if default and name not in stale and value:  # ${name:-default} is the value
                        _spend(len(value))
                        out.append(value)
                        k = default.end()
                        continue
                    hits.add(name)
                    value = None
                if value is not None:
                    _spend(len(value))
                out.append(m[0] if value is None else value)
                k = m.end()
                continue
        out.append(c)
        k += 1
    return "".join(out)


def _unquote(value: str) -> str:
    try:
        parts = shlex.split(value)
    except ValueError:
        return value
    return " ".join(parts)


def _expand(command: str, env: dict[str, str]) -> tuple[str, dict[str, str], bool]:
    """Like ``_expand_all``, but a command whose variables would grow past ``_MAX_EXPANSION`` is left as it is
    and counts as one whose variables are not known."""
    try:
        return _expand_all(command, env)
    except _TooBig:
        return command, dict(env), True


def _expand_all(command: str, env: dict[str, str]) -> tuple[str, dict[str, str], bool]:
    """``command`` with the variables it assigns itself written out in the order it runs them, so that
    ``C="curl -F f=@x URL"; $C`` and ``U=URL; curl -d @x $U`` read as what they run; a variable from elsewhere
    stays as it is. Returns the text, the values, and whether a variable is assigned more than once or after
    it was used (a loop, a condition: its value at a use is not known)."""
    values = dict(env)
    seen = dict.fromkeys(env, 1)
    used: set[str] = set()
    contested: set[str] = set()
    stale = _Stale(values)  # names a builtin (read, eval ...) may have given another value
    hits: set[str] = set()  # of those, the ones used afterwards
    setter, previous = "", ""
    out: list[str] = []
    i, n, lead = 0, len(command), True
    while i < n:
        c = command[i]
        if c in " \t\n":
            out.append(c)
            i += 1
        elif c in ";&|()":
            out.append(c)
            i += 1
            lead, setter = True, ""
        else:
            j = _word_end(command, i)
            word = command[i:j]
            i = j
            m = _ASSIGN.match(word) if lead else None
            if m:
                name = m[1]
                if name in used or name in seen:
                    contested.add(name)
                seen[name] = seen.get(name, 0) + 1
                value = _expand_word(word[m.end():], values, used, stale, hits)
                stale.assigned(name)
                if "$(" in value or "`" in value:  # the output of a command is not known text: $NAME stays a variable
                    values.pop(name, None)
                else:
                    values[name] = (values.get(name, "") if m[2] else "") + _unquote(value)
                    _spend(len(values[name]) if m[2] else 0)
                out.append(word[:m.end()] + value)
            else:
                out.append(_expand_word(word, values, used, stale, hits))
                if setter:  # read -r H, getopts o H, printf -v H x, unset H: the names it sets
                    name = _NAME.fullmatch(_unquote(word))
                    if name and (setter != "printf" or previous == "-v") and setter not in ("eval", "source", "."):
                        stale.add(name[1])
                    elif setter == "printf" and word.startswith("-v") and len(word) > 2:  # printf -vH x
                        stale.add(word[2:])
                elif lead and word in _SETTERS and (word != "printf" or re.match(r"\s+-v", command[j:j + 4])):
                    setter = word
                    if word in ("eval", "source", "."):  # it can set any of them
                        stale.everything()
                lead = lead and (word in _KEYWORDS or word in _DECLARE or word.startswith("-")
                                 or PurePosixPath(word).name in _WRAPPERS)
                previous = word
    return "".join(out), values, bool(contested & used) or bool(hits)


def _program(argv: list[str]) -> list[str]:
    """``argv`` without leading assignments and wrappers (``sudo -u x``, ``env A=1``, ``timeout 5``)."""
    i = 0
    while i < len(argv):
        word = argv[i]
        name = PurePosixPath(word).name
        if re.fullmatch(r"[A-Za-z_]\w*=.*", word, re.S) or word in _KEYWORDS:
            i += 1
        elif word == "function":  # function f { curl ...; }: the body is on the same line as the name
            i += 2
        elif name in _WRAPPERS:
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                split = re.fullmatch(r"-[iv0]*S(.*)|--split-string(?:=(.*))?", argv[i], re.S) if name == "env" else None
                if split and (split[1] or split[2] or i + 1 < len(argv)):
                    # env -S 'curl -d @f URL', env -S'curl ...', env -iS'..', env --split-string='curl ...': the command
                    attached = split[1] or split[2]
                    string, rest = (attached, argv[i + 1:]) if attached else (argv[i + 1], argv[i + 2:])
                    try:
                        argv = argv[:i] + shlex.split(string) + rest
                    except ValueError:
                        i += 2
                    break
                i += 2 if argv[i] in ("-u", "-g", "-n") else 1
            if i < len(argv) and re.search(r"\s", argv[i]) and not argv[i].startswith("-"):
                try:  # watch 'curl ...': one word that is the command
                    argv = argv[:i] + shlex.split(argv[i]) + argv[i + 1:]
                except ValueError:
                    pass
        elif name in ("timeout", "gtimeout"):
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                i += 1
            i += 1  # the duration
        elif name == "xargs":
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                i += 2 if argv[i] in ("-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a") else 1
        else:
            break
    return argv[i:]
