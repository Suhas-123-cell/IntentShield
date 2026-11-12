"""Which programs only read: the options that make a program write or run code, and the development tools a build or test runs."""
from __future__ import annotations

import re
from pathlib import PurePosixPath

from .expand import _option_letters
from .lexical import (
    _GIT_BRANCH_LISTING,
    _GIT_BRANCH_VALUED,
    _GIT_READ_ONLY,
    _GIT_UNSAFE,
    _INTERPRETERS,
    _READ_ONLY,
    _UNSAFE_OPTIONS,
)
from .network import _GIT_ELSEWHERE, _git_sub, _has_option, _positionals

# ``tool --version`` runs the tool and prints a line: asking is not worth it for these.
_VERSION_FLAGS = frozenset({"--version", "-V", "--help", "-version"})
_VERSION_TOOLS = frozenset({"python", "python3", "pip", "pip3", "node", "npm", "npx", "pnpm", "yarn", "deno", "bun", "uv",
                        "cargo", "rustc", "go", "java", "javac", "ruby", "perl", "php", "gcc", "g++", "clang", "make",
                        "cmake", "docker", "gh", "ruff", "pytest", "tsc", "mypy", "black", "tox", "brew", "kubectl",
                        "terraform", "ollama"})
_FIND_ACTIONS = frozenset({"-exec", "-execdir", "-delete", "-ok", "-okdir", "-fprint", "-fls", "-fprintf", "-fprint0"})
# One sed command that only prints: an address, then p, d, q, = ... or a substitution without the w and e flags.
_SED_ADDRESS = r"(?:(?:\d+|\$|/(?:[^/\\]|\\.)*/I?)(?:,(?:\d+|\$|/(?:[^/\\]|\\.)*/))?!?)?"
_SED_PRINTS = re.compile(r"\s*" + _SED_ADDRESS + r"\s*(?:[pPdq=nNlgGhHx]|s/(?:[^/\\]|\\.)*/(?:[^/\\]|\\.)*/[gIip0-9]*)\s*")
_AWK_RISKY = re.compile(r"[>|@]|\bsystem\b|\bgetline\b|\bENVIRON\b|\bclose\b")  # @include and @load are gawk's


def _sed_reads_only(args: list[str]) -> bool:
    """sed that prints text: no -i, no script file, and a script of the simple commands above (``w file`` writes,
    ``e`` and the ``s///e`` flag run a program)."""
    scripts, plain, i = [], [], 0
    while i < len(args):
        arg = args[i]
        if arg in ("-e", "--expression") and i + 1 < len(args):
            scripts.append(args[i + 1])
            i += 2
            continue
        if arg.startswith("--expression="):
            scripts.append(arg.partition("=")[2])
        elif arg.startswith("-") and len(arg) > 1:
            if arg not in ("-n", "-E", "-r", "-s", "-u", "-z", "--quiet", "--silent", "--regexp-extended", "--posix",
                           "--separate", "--null-data", "--unbuffered"):
                return False
        else:
            plain.append(arg)
        i += 1
    if not scripts:
        scripts = plain[:1]
    return bool(scripts) and all(_SED_PRINTS.fullmatch(part) for text in scripts for part in re.split(r"[;\n]", text))


def _awk_reads_only(args: list[str]) -> bool:
    """awk over text: no program file, include, extension or inline ``-e`` text, and a program that neither writes
    (``>``, ``|``), runs (``system``, ``getline``) nor reads the environment."""
    if any(a.startswith(("-f", "-i", "-l", "-E", "-e", "-W", "--file", "--include", "--load", "--exec", "--source"))
           for a in args if a.startswith("-")):
        return False
    program = _positionals(args, "Fv")[:1]
    return bool(program) and not _AWK_RISKY.search(program[0])


# Build, test and local version-control commands: they change files of the project and reach nowhere. They are
# what a session does all day, so after a result that tried to instruct the agent they are not what the review
# is for (sends, secrets, persistence and values from that result are, and are read separately).
_DEV_GIT = frozenset({"add", "commit", "switch", "checkout", "stash", "merge", "tag", "init", "branch", "mv",
                      "cherry-pick"})  # not rebase: -x and --exec run a command
_DEV_PROGRAMS = frozenset({"make", "gmake", "ninja", "cmake", "ctest", "pytest", "py.test", "tox", "nox", "jest",
                           "vitest", "mocha", "rspec", "gradle", "gradlew", "mvn", "mvnw", "tsc", "ruff", "black",
                           "mypy", "flake8", "pylint", "isort", "prettier", "eslint", "mkdir", "touch"})
_DEV_SUBCOMMANDS = {"npm": {"test", "t", "run", "run-script", "build"}, "pnpm": {"test", "run", "build", "lint"},
                    "yarn": {"test", "run", "build", "lint"}, "bun": {"test", "run", "build"},
                    "cargo": {"build", "test", "check", "clippy", "fmt", "doc", "bench"},  # not run: it runs written code
                    "go": {"build", "test", "vet", "fmt"}}
_DEV_MODULES = frozenset({"unittest", "pytest", "mypy", "ruff", "black", "flake8", "pylint", "isort", "compileall"})
_SHIPS = re.compile(r"install|deploy|publish|release|upload|push|login", re.I)  # a target that sends or installs
_BUILD_TOOLS = frozenset({"make", "gmake", "ninja", "cmake", "gradle", "gradlew", "mvn", "mvnw"})  # run targets by name
_RUNS_PROGRAM = re.compile(r"--?(?:exec|vettool|toolexec|exec-path|runner|script-shell|config|init-hook|init-script|"
                           r"load-plugins|rcfile|override-ini|preload|require|eval|file|makefile|noxfile|settings|"
                           r"global-settings|settings-file|build-file|toolchains|template|setupfiles\w*)\b", re.I)
# Short options that load code or a build script from a path, per tool: ``cmake -E env python3 x.py`` runs a program,
# ``make -f x.mk`` and ``pytest -p plugin`` read code the agent may have written. Matched as a prefix (``-fx.mk``) or,
# for the letter sets, anywhere in a cluster (``-kf x.mk``).
_CODE_PREFIXES = {"cmake": ("-E", "-P", "-C"), "ninja": ("-f",), "nox": ("-f",), "gradle": ("-I", "-c", "-b"),
                  "gradlew": ("-I", "-c", "-b"), "mvn": ("-f", "-s", "-gs", "-t"), "mvnw": ("-f", "-s", "-gs", "-t"),
                  "pytest": ("-c", "-o"), "py.test": ("-c", "-o"), "bun": ("-r",), "mocha": ("-r",)}
_CODE_LETTERS = {"make": "f", "gmake": "f"}
# Where a program word may point and still be the program the tables know: a bare name (found on PATH) or a system
# directory. ``./bin/pytest`` and ``/tmp/x/git`` are files of the project or a scratch directory, which the agent
# may have written itself.
_SYSTEM_BIN = ("/usr/bin/", "/usr/local/bin/", "/opt/homebrew/bin/", "/bin/", "/usr/sbin/", "/sbin/")


def _known_program(word: str) -> bool:
    return "/" not in word or word.startswith(_SYSTEM_BIN)


def _loads_code(name: str, args: list[str]) -> bool:
    """An option of this build or test tool that makes it read code or a build script from a path, or run a program."""
    args = args[:args.index("--")] if "--" in args else args
    prefixes, letters = _CODE_PREFIXES.get(name, ()), _CODE_LETTERS.get(name, "")
    for k, arg in enumerate(args):
        if arg.startswith("--") or not arg.startswith("-") or len(arg) < 2:
            continue
        if prefixes and arg.startswith(prefixes):
            return True
        if letters and any(c in letters for c in _option_letters(arg)):
            return True
        if name in ("pytest", "py.test") and arg.startswith("-p") and not (
                arg[2:].startswith("no:") or arg == "-p" and args[k + 1:k + 2] and args[k + 1].startswith("no:")):
            return True
    return False


def _discards_work(sub: str, rest: list[str]) -> bool:
    """A git command that throws away uncommitted work or a branch, which git reset --hard and git clean already
    are not ordinary for: checkout -f or -- PATH, switch --discard-changes, stash drop or clear, branch -D, tag -d."""
    if sub in ("checkout", "switch"):
        return any(a in ("-f", "--force", "--discard-changes", "--", ".") or a.startswith("--ours")
                   or a.startswith("--theirs") or (a.startswith("-") and not a.startswith("--") and "f" in a)
                   for a in rest)
    if sub == "stash":
        return bool(rest) and rest[0] in ("drop", "clear")
    if sub in ("branch", "tag"):
        return any(a in ("-d", "-D", "--delete") or a.startswith("--delete")
                   or (a.startswith("-") and not a.startswith("--") and ("d" in a or "D" in a)) for a in rest)
    return False


def _local_dev(name: str, args: list[str], whole: list[str]) -> bool:
    """Whether the program is a build, test or local version-control command that changes the project only."""
    if PurePosixPath(whole[0]).name in ("sudo", "doas") or any(_RUNS_PROGRAM.match(a) for a in args) \
            or _loads_code(name, args):
        return False
    if name == "uv":  # uv run pytest: the program it runs must itself be an ordinary one
        rest = args[1:]
        return (args[:1] == ["run"] and bool(rest) and not rest[0].startswith("-") and rest[0] in _DEV_PROGRAMS
                and _local_dev(rest[0], rest[1:], rest))
    if name == "bun" and args[:1] == ["run"] and any("/" in a or a.endswith((".ts", ".js", ".mjs", ".tsx")) for a in args[1:2]):
        return False  # bun run FILE runs that file: only a package script name is ordinary
    if name == "git":
        sub, rest, configs = _git_sub(args)
        if sub == "merge" and any(a.startswith("--strategy") or a.startswith("-s") and not a.startswith("--")
                                  for a in rest):
            return False  # -s NAME runs git-merge-NAME from the path
        return (sub in _DEV_GIT and not configs and not _discards_work(sub, rest)
                and not any(a.startswith(_GIT_ELSEWHERE) for a in args[:len(args) - len(rest)]))
    if name in _DEV_SUBCOMMANDS:
        return bool(args) and args[0] in _DEV_SUBCOMMANDS[name] and not (
            name in ("npm", "pnpm", "yarn", "bun") and _SHIPS.search(" ".join(args[:2])))  # npm run deploy
    if name in _INTERPRETERS and name.startswith("python"):
        return args[:1] == ["-m"] and len(args) > 1 and args[1] in _DEV_MODULES
    # -DNAME=value only sets a variable (-DCMAKE_BUILD_TYPE=Release is not a release)
    return name in _DEV_PROGRAMS and not (
        name in _BUILD_TOOLS and bool(_SHIPS.search(" ".join(x for x in args if not x.startswith("-D")))))


def _read_only(name: str, args: list[str]) -> bool:
    """Whether the program, with these arguments, only reads."""
    if name == "git":
        sub, rest, configs = _git_sub(args)
        if configs or any(a.startswith(_GIT_ELSEWHERE) for a in args[:len(args) - len(rest)]):
            return False
        if sub == "branch":  # listing only: any other option changes a branch or the configuration
            return all(a in _GIT_BRANCH_LISTING or a.startswith(_GIT_BRANCH_VALUED) for a in rest)
        return (sub in _GIT_READ_ONLY and not _has_option(rest, _GIT_UNSAFE, "O" if sub == "grep" else ""))
    if name in _VERSION_TOOLS and len(args) == 1 and args[0] in _VERSION_FLAGS:
        return True
    if name in ("npm", "pnpm", "yarn") and args[:1] in (["ls"], ["list"]) \
            or name in ("pip", "pip3") and args[:1] in (["list"], ["show"], ["freeze"], ["check"]):
        return True
    if name not in _READ_ONLY:
        return False
    if name in _UNSAFE_OPTIONS and _has_option(args, *_UNSAFE_OPTIONS[name]):
        return False
    if name == "find":  # -exec runs a program, -delete and -fprint* change files
        return not any(a in _FIND_ACTIONS for a in args)
    if name == "sed":
        return _sed_reads_only(args)
    if name == "awk":
        return _awk_reads_only(args)
    if name in ("more", "less") and any(a.startswith("+!") for a in args):  # +!cmd runs a shell command
        return False
    if name == "uniq":  # uniq IN OUT writes OUT
        return len(_positionals(args, "fsw")) < 2
    if name == "xxd":  # -r writes binary, and so does xxd IN OUT
        return not any(a in ("-r", "-revert") or re.fullmatch(r"-[a-z]{1,3}", a) and "r" in a for a in args) \
            and len(_positionals(args, "slcgon")) < 2
    if name == "hostname":
        return not _positionals(args)
    if name == "bat":  # bat cache --build writes the cache
        return "cache" not in args[:1]
    if name == "printf":  # printf -v NAME sets a variable, and a subscript of NAME is evaluated
        return not any(a.startswith("-v") for a in args)
    if name in ("test", "["):  # test -v 'a[$(cmd)]' evaluates the subscript
        return not any(a in ("-v", "-R") for a in args)
    if name == "date":
        return all(a.startswith("+") for a in _positionals(args, "dfr"))
    if name == "history":
        return all(a.isdigit() for a in args)
    return True
