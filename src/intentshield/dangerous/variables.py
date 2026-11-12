"""Variables, brace lists and the working directory of one command line, which change what a stage names."""
from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from .core import _bin, _Stage
from .parsing import _ASSIGN, _INTERPRETERS, _SHELLS
from .paths import _READERS, _as_written, _norm, _pathlike
from .powershell import _POWERSHELLS
from .runners import _unwrap
from .writes import _FIND_FILE_OUTPUT, _FIND_RUNS

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


# Programs whose words are not paths to resolve against the working directory: ``su`` and ``eval`` run the text they are given
# (which is read with the working directory as it is), ``ssh`` names a host, ``xargs`` and ``fd`` run another command, and ``cd``
# is followed on its own.
_NO_PATHS = frozenset({"su", "eval", "exec", "ssh", "xargs", "fd", "fdfind", "cd", "pushd", "popd"})
# Shells and interpreters take path arguments like any program (``python3 script.py id_rsa``), and they run text too: a word of
# code is not a path, so a word that holds a space, a quote or a shell operator is left as it is, and so is the word that
# follows ``-c``, ``-e`` and the like, which is code or a module name.
_CODE_RUNNERS = _SHELLS | _INTERPRETERS | _POWERSHELLS
_CODE_WORD = re.compile(r"[\s()'\"`;&|<>]")
_CODE_OPTION = re.compile(r"-[A-Za-z0-9]*[ceE]|-[pPrmM]|--(?:eval|print|require|command|module)|-(?:Command|EncodedCommand)",
                          re.I)
# The option that names a directory, for the programs that take it written next to its letter (``-tDIR``, ``-dDIR``).
_DIRECTORY_OPTION = {"cp": "t", "mv": "t", "install": "t", "ln": "t", "unzip": "d", "tar": "C"}
_DISK_COPIERS = frozenset({"dd", "dcfldd", "dc3dd"})   # ``if=FILE`` and ``of=FILE`` name the files
_UPLOADERS = frozenset({"curl", "wget", "http", "https", "xh"})   # ``@FILE`` and ``name=@FILE`` name the file sent
_FILE_FIELD = re.compile(r"((?:[^=@\s]{1,40}=)?@)(.+)")
# ``host:path`` and ``user@host:path`` are not local paths.
_REMOTE_WORD = re.compile(r"^(?:[\w.+-]{1,64}@)?[\w.-]{1,255}:(?!//)")


def _under(cwd: str, arg: str) -> str:
    """``arg`` as a path from the directory ``cwd`` when it is relative, else as it is."""
    if not arg or arg.startswith(("-", "/", "~", "$")) or "://" in arg:
        return arg
    return _norm(cwd + "/" + arg)


def _resolved_word(cwd: str, name: str, arg: str) -> str:
    """One word of a command with the path it holds read from ``cwd``: a plain word, the value of ``--option=VALUE``, the files
    ``dd`` names with ``if=`` and ``of=`` and the file a ``curl -d @FILE`` sends. A flag, a remote name and any other word
    that is not a relative path is left as it is."""
    if arg.startswith("--") and "=" in arg:
        option, _, value = arg.partition("=")
        return f"{option}={_under(cwd, value)}" if value else arg
    if arg.startswith("-") and not arg.startswith("--") and name in _DIRECTORY_OPTION:
        if m := re.fullmatch(rf"(-[A-Za-z]{{0,10}}?{_DIRECTORY_OPTION[name]})(.+)", arg):
            return m[1] + _under(cwd, m[2])   # the directory written next to its option: -tDIR, -atDIR, -dDIR, -CDIR
    if not arg or arg.startswith("-"):
        return arg
    if name in _DISK_COPIERS and "=" in arg:
        key, _, value = arg.partition("=")
        return f"{key}={_under(cwd, value)}" if key in ("if", "of") else arg
    if name in _UPLOADERS and (field := _FILE_FIELD.fullmatch(arg)):
        return field[1] + _under(cwd, field[2])
    if "=" in arg or "@" in arg or _REMOTE_WORD.match(arg):
        return arg
    return _under(cwd, arg)


def _in_dir(cwd: str, name: str, argv: list[str]) -> list[str]:
    """``argv`` with the relative paths of the program resolved against ``cwd``, which is where it runs: the one step that gives
    every rule that reads a path the same path as the absolute spelling."""
    head, args = argv[0], argv[1:]
    if name in ("chmod", "chown", "chgrp") and not any(a.startswith("--reference") for a in args):
        out, skipped = [], False
        for a in args:
            if not skipped and not a.startswith("-"):
                skipped = True
                out.append(a)  # the mode or the owner
            else:
                out.append(_resolved_word(cwd, name, a))
        return [head, *out]
    if name == "find":   # the roots, the files -fprint makes and the words of a command that -exec runs
        out, stopped, running, program, prev = [], False, False, False, ""
        for a in args:
            if running:
                if a == ";" or (a == "+" and prev.endswith("{}")):
                    running = False
                    out.append(a)
                elif program:
                    program = False
                    out.append(a)
                else:
                    out.append(a if a.startswith("-") or "{" in a else _under(cwd, a))
            elif a in _FIND_RUNS:
                running = program = True
                out.append(a)
            elif prev in _FIND_FILE_OUTPUT:
                out.append(_under(cwd, a))
            else:
                stopped = stopped or a.startswith("-") or a in ("(", "!", ")")
                out.append(a if stopped else _under(cwd, a))
            prev = a
        return [head, *out]
    if name == "chattr":   # ``+i``, ``=a`` and ``-i`` are attributes; every other word is a file
        return [head, *(a if a.startswith(("+", "=")) else _resolved_word(cwd, name, a) for a in args)]
    if name in _CODE_RUNNERS:
        out, code = [], False
        for a in args:
            out.append(a if code or _CODE_WORD.search(a) else _resolved_word(cwd, name, a))
            code = bool(_CODE_OPTION.fullmatch(a))
        return [head, *out]
    return [head, *(_resolved_word(cwd, name, a) for a in args)]


_PER_WORD = 8   # relative words of one command that are each tried on their own; a command with more is tried whole


def _moved_stages(stage: _Stage, cwd: str) -> list[_Stage]:
    """The versions of the stage with its relative paths read from ``cwd``: all of them at once, and (up to ``_PER_WORD`` of
    them) each one alone, since a word that is not a path (``mklabel`` of ``parted``, a mode, a pattern) must stay as it is for
    the rules that read it. A program that only runs the text it is given (``su``, ``eval``, ``ssh``) has none. The rules that
    look at a path read it from here as well as as written, so ``../../../dev/sda`` from ``/Users/x/proj`` is ``/dev/sda`` for
    every program that names a path, not only for those with a rule of their own for a relative one."""
    bare, _ = _unwrap(stage)
    name = _bin(bare.argv[0]) if bare.argv else ""
    if name in _NO_PATHS:
        return []
    argv = _in_dir(cwd, name, bare.argv) if bare.argv else []
    redirects = [(op, t if op == "<<<" or t.isdigit() else _under(cwd, t)) for op, t in bare.redirects]
    words = [i for i, (before, after) in enumerate(zip(bare.argv, argv)) if before != after]
    targets = [i for i, (before, after) in enumerate(zip(bare.redirects, redirects)) if before != after]
    if not words and not targets:
        return []
    whole = replace(bare, argv=argv, redirects=redirects)
    if len(words) + len(targets) == 1:
        return [whole]
    if len(words) + len(targets) > _PER_WORD:
        pathlike = [after if "/" in before or before.startswith(".") else before for before, after in zip(bare.argv, argv)]
        return [whole, replace(bare, argv=pathlike, redirects=redirects)]
    out = [whole]
    for i in words:
        out.append(replace(bare, argv=[*bare.argv[:i], argv[i], *bare.argv[i + 1:]]))
    for i in targets:
        out.append(replace(bare, redirects=[*bare.redirects[:i], redirects[i], *bare.redirects[i + 1:]]))
    return out


def _cd_target(argv: list[str], cwd: str | None) -> str | None:
    """The directory a ``cd`` or ``pushd`` moves to: None when it is not known (``cd -``, a variable, a relative path from an
    unknown directory)."""
    args = [a for a in argv[1:] if a != "--" and not (a.startswith("-") and a != "-")]
    if not args:
        return "~" if _bin(argv[0]) == "cd" else cwd
    target = args[0]
    if target == "-" or "$" in target.replace("$HOME", "").replace("${HOME}", "") or "`" in target or "*" in target:
        return None
    if target.startswith("/"):
        return _as_written(target)   # as written: a later climb is made on this path, not on the home of the process
    if target.startswith(("~", "$HOME", "${HOME}")):
        return _norm(target)
    if not cwd:
        return None
    return _as_written(cwd + "/" + target) if cwd.startswith("/") else _norm(cwd + "/" + target)


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
