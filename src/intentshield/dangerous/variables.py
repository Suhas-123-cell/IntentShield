"""Variables, brace lists and the working directory of one command line, which change what a stage names."""
from __future__ import annotations

import re
from typing import Any

from .core import _bin, _Stage
from .parsing import _ASSIGN
from .paths import _READERS, _norm, _pathlike
from .runners import _unwrap

# --- variables, brace expansion and the working directory of one command line ----------------------------------

_VAR_REF = re.compile(r"\$(?:\{(\w{1,40})\}|(\w{1,40}))")
_MAX_VARIANTS = 32   # words of one for loop that are followed; the variants of a stage are capped at twice this
_MANY = ["\x00many"]   # what a variable holds after a loop over more words than that: not followed
_DECLARERS = frozenset({"export", "declare", "readonly", "local", "typeset"})
_BRACE = re.compile(r"(?<!\$)\{([^{}\s]{0,100},[^{}\s]{0,100})\}")
_BRACE_LONG = re.compile(r"(?<!\$)\{[^{}\s]*,[^{}\s]*\}")
# Programs whose arguments are paths that a brace list (``rm -rf {/,}``, ``cat ~/.ssh/{id_rsa,x}``) may spell.
_EXPANDED = frozenset({"rm", "rmdir", "unlink", "chmod", "chown", "chgrp", "mv", "shred", "truncate", "find"}) | _READERS


_BRACE_ARG, _BRACE_ALTS, _BRACE_WORDS, _BRACE_DEPTH = 300, 16, 64, 4


def _braces(arg: str, depth: int = 0, cut: list[bool] | None = None) -> list[str]:
    """The words bash makes of ``arg`` when it holds a brace list: ``{/,}`` is ``/`` and the empty word. A list that is past a
    limit
    (an argument of more than 300 characters, 16 alternatives, 64 words or 4 levels) is not expanded in full: ``cut`` gets a
    ``True``."""
    m = _BRACE.search(arg)
    if not m:
        if cut is not None and "{" in arg and "," in arg and _BRACE_LONG.search(arg) and (_pathlike(arg) or arg.startswith("{")):
            cut.append(True)   # a list too long for ``_BRACE`` to match is not expanded
        return [arg]
    alts = m[1].split(",")
    if depth >= _BRACE_DEPTH or len(arg) > _BRACE_ARG or len(alts) > _BRACE_ALTS:
        if cut is not None and (_pathlike(arg) or arg.startswith("{")):
            cut.append(True)
        if depth >= _BRACE_DEPTH or len(arg) > _BRACE_ARG:
            return [arg]
    out: list[str] = []
    for alt in alts[:_BRACE_ALTS]:
        out.extend(_braces(arg[:m.start()] + alt + arg[m.end():], depth + 1, cut))
        if len(out) >= _BRACE_WORDS:
            if cut is not None:
                cut.append(True)
            break
    return out[:_BRACE_WORDS]


def _under(cwd: str, arg: str) -> str:
    """``arg`` as a path from the directory ``cwd`` when it is relative, else as it is."""
    if not arg or arg.startswith(("-", "/", "~", "$")) or "://" in arg:
        return arg
    return _norm(cwd + "/" + arg)


def _in_dir(cwd: str, name: str, argv: list[str]) -> list[str]:
    """``argv`` with the relative paths of the program resolved against ``cwd``, for the programs whose target a
    ``cd`` before them decides."""
    head, args = argv[0], argv[1:]
    if name in ("chmod", "chown", "chgrp"):
        out, skipped = [], False
        for a in args:
            if not skipped and not a.startswith("-"):
                skipped = True
                out.append(a)  # the mode or the owner
            else:
                out.append(_under(cwd, a))
        return [head, *out]
    if name == "find":
        out, stopped = [], False
        for a in args:
            stopped = stopped or a.startswith("-") or a in ("(", "!", ")")
            out.append(a if stopped else _under(cwd, a))
        return [head, *out]
    return [head, *(a if "=" in a or "@" in a else _under(cwd, a) for a in args)]


def _cd_target(argv: list[str], cwd: str | None) -> str | None:
    """The directory a ``cd`` or ``pushd`` moves to: None when it is not known (``cd -``, a variable, a relative path from an
    unknown directory)."""
    args = [a for a in argv[1:] if a != "--" and not (a.startswith("-") and a != "-")]
    if not args:
        return "~" if _bin(argv[0]) == "cd" else cwd
    target = args[0]
    if target == "-" or "$" in target.replace("$HOME", "").replace("${HOME}", "") or "`" in target or "*" in target:
        return None
    if target.startswith(("/", "~", "$HOME", "${HOME}")):
        return _norm(target)
    return _norm(cwd + "/" + target) if cwd else None


def _track(st: _Stage, env: dict[str, list[str]], where: dict[str, Any]) -> None:
    """What one stage changes for the stages after it: variables it sets (``X=v``, ``export X=v``, ``for x in a b``) and
    the directory a ``cd``, ``pushd`` or ``popd`` moves to."""
    bare, _ = _unwrap(st)
    if not bare.argv:
        for a in bare.assigns:
            key, _, value = a.partition("=")
            if "$" in value or "`" in value:
                env.pop(key, None)
            else:
                env[key] = [value]
        return
    name = _bin(bare.argv[0])
    if name in _DECLARERS:
        for a in bare.argv[1:]:
            if _ASSIGN.match(a):
                key, _, value = a.partition("=")
                if "$" in value or "`" in value:
                    env.pop(key, None)
                else:
                    env[key] = [value]
    elif name == "for" and len(bare.argv) >= 4 and bare.argv[2] == "in":
        words = bare.argv[3:]
        if any("$" in w or "`" in w for w in words):
            env.pop(bare.argv[1], None)
        elif len(words) > _MAX_VARIANTS:
            env[bare.argv[1]] = _MANY
        else:
            env[bare.argv[1]] = list(words)
    elif name in ("read", "unset") or name == "mapfile":
        for a in bare.argv[1:]:
            env.pop(a, None)
    elif name in ("cd", "pushd"):
        if name == "pushd":
            where.setdefault("stack", []).append(where.get("cwd"))
        where["cwd"] = _cd_target(bare.argv, where.get("cwd"))
    elif name == "popd":
        stack = where.setdefault("stack", [])
        where["cwd"] = stack.pop() if stack else None


def _expand_vars(st: _Stage, env: dict[str, list[str]], notes: list[str] | None = None) -> list[_Stage]:
    """The stage with the variables set earlier in the same command line replaced by their values (one stage for each value
    a ``for`` variable takes): ``RM=rm; $RM -rf /`` is ``rm -rf /``."""
    if not env:
        return [st]
    names = {n for a in [*st.argv, *(t for _, t in st.redirects)] for m in _VAR_REF.finditer(a) for n in (m[1] or m[2],)
             if n in env}
    if not names:
        return [st]
    if notes is not None and any(env[n] is _MANY for n in names):
        notes.append(f"a variable set by a loop over more than {_MAX_VARIANTS} words")
    names = {n for n in names if env[n] is not _MANY}
    if not names:
        return [st]
    combos: list[dict[str, str]] = [{}]
    for n in sorted(names):
        combos = [{**c, n: v} for c in combos for v in env[n]]
        if len(combos) > 2 * _MAX_VARIANTS:
            combos = combos[:2 * _MAX_VARIANTS]
            if notes is not None:
                notes.append("variables that hold too many combinations of values")

    def fill(text: str, values: dict[str, str]) -> str:
        return _VAR_REF.sub(lambda m: values.get(m[1] or m[2], m[0]), text)

    return [_Stage([fill(a, c) for a in st.argv], [(op, fill(t, c)) for op, t in st.redirects], st.piped, st.pipeline,
                   st.sudo, list(st.assigns), st.xargs) for c in combos]
