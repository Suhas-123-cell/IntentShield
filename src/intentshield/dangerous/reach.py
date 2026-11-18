"""What a command reaches by name, pattern or search: a link to a protected directory, a search that starts above the credential
stores, and a ``find`` that runs a reader on every file that matches a pattern.

The rules for a path read the path. A call can reach the same files without writing their names: it links to a directory
(``ln -s ~ h``), searches one (``grep -r . ~``), or gives ``find`` a pattern that matches the names of keys (``-name 'id_*'``).
Each is judged here like the spelling it stands for: the pattern by the very name test that reads ``cat ~/.ssh/id_*``, a search by
the rule for a search of the whole home directory."""
from __future__ import annotations

import fnmatch
import os
import re
from functools import lru_cache

from .core import ASK, DENY, Hit, _bin, _is_opt
from .parsing import _SHELLS
from .paths import _READERS, _cred_level, _protected, search_root
from .rules import _NET_SINKS
from .writes import _find_roots

# --- ln -s of a protected directory -----------------------------------------------------------------------------------------


def link_hit(name: str, argv: list[str]) -> Hit | None:
    """``ln -s`` of the home directory, a root or a system directory: the link makes a path that later calls read through
    (``cat h/.ssh/id_rsa``), where the rules see a harmless name. A link to a key or a credential directory is asked about by the
    rule that reads any program given one."""
    if name != "ln":
        return None
    args = argv[1:]
    flags = [a for a in args if a.startswith("-") and len(a) > 1 and a != "--"]
    symbolic = any(_is_opt(a, "--symbolic") or (not a.startswith("--") and "s" in a[1:]) for a in flags)
    if not symbolic:
        return None
    operands, into, skip = [], False, False
    for a in args:
        if skip:
            skip = False
        elif a in ("-t", "-S", "--suffix") or (a.startswith("--") and _is_opt(a, "--target-directory") and "=" not in a):
            into, skip = into or a != "-S", True   # the directory the links go to (or a suffix) is not what they point at
        elif a.startswith("--target-directory="):
            into = True
        elif not a.startswith("-"):
            operands.append(a)
    targets = operands if into or len(operands) == 1 else operands[:-1]
    for target in targets:
        if _protected(target):
            return Hit(ASK, f"ln -s of {target}, a directory the rules protect (the home, a root or a system directory), makes a "
                            "path that later calls read through as that directory; confirm it.", target)
    return None


# --- recursive searches of the home directory -------------------------------------------------------------------------------

_SEARCHERS = frozenset({"grep", "egrep", "fgrep", "rg", "ag", "ack", "ugrep", "ug"})
_RECURSIVE_BY_DEFAULT = frozenset({"rg", "ag", "ack"})
_VALUED_SHORT = {"grep": "efmABCdD", "egrep": "efmABCdD", "fgrep": "efmABCdD", "ugrep": "efmABCdD", "ug": "efmABCdD",
                 "rg": "efgtTmABCjMdEr", "ag": "GABCmpgd", "ack": "ABCm"}
_VALUED_LONG = frozenset({"regexp", "file", "glob", "iglob", "type", "type-not", "max-count", "max-depth", "threads", "replace",
                          "encoding", "colors", "sort", "sortr", "pre", "pre-glob", "context", "after-context", "before-context",
                          "ignore-file", "max-filesize", "include", "exclude", "exclude-dir", "include-dir", "exclude-from",
                          "label", "binary-files", "directories", "devices", "color", "colour", "ignore", "depth",
                          "path-to-ignore", "file-search-regex", "ignore-dir", "type-add", "type-clear", "dfa-size-limit",
                          "regex-size-limit", "engine", "hostname-bin", "hyperlink-format", "max-columns",
                          "field-context-separator"})
_LISTS_ONLY = frozenset("lLcq")   # names or counts, not the lines
_LISTS_ONLY_LONG = ("files-with-matches", "files-without-match", "count", "quiet", "silent", "files", "type-list", "list-files",
                    "count-matches")


def _search_operands(name: str, args: list[str]) -> tuple[list[str], bool, bool]:
    """(the path operands, a recursive flag was given, the search only lists names or counts) of a searcher's arguments."""
    valued, paths, flags, pattern_given, only_names, recursive = _VALUED_SHORT.get(name, ""), [], True, False, False, False
    positional: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if a == "--" and flags:
            flags = False
        elif flags and a.startswith("--") and len(a) > 2:
            head = a[2:].partition("=")[0]
            if head in ("recursive", "dereference-recursive"):
                recursive = True
            if head in ("regexp", "file"):
                pattern_given = True
            if any(_is_opt(a, f"--{long}") for long in _LISTS_ONLY_LONG):
                only_names = True
            if head in ("directories",) and a.partition("=")[2] == "recurse":
                recursive = True
            if head in _VALUED_LONG and "=" not in a and i < len(args):
                if head == "directories" and args[i] == "recurse":
                    recursive = True
                i += 1
        elif flags and a.startswith("-") and len(a) > 1:
            body = a[1:]
            for k, c in enumerate(body):
                if c in "rR" and name not in ("rg", "ag"):   # for rg, -r is --replace
                    recursive = True
                if (c in _LISTS_ONLY and not (name == "rg" and c == "L")) or (c == "g" and name == "ag") or (
                        c == "f" and name == "ack"):   # for rg, -L follows links
                    only_names = True
                if c in "ef" and name not in ("ack", "ag"):
                    pattern_given = True
                if c in valued:
                    if k == len(body) - 1 and i < len(args):
                        if c == "d" and args[i] == "recurse":
                            recursive = True
                        i += 1
                    break
        else:
            positional.append(a)
    paths = positional if pattern_given else positional[1:]
    return paths, recursive, only_names


def search_hit(name: str, argv: list[str], cwd: str | None, piped: bool = False) -> Hit | None:
    """A recursive search (``grep -r``, ``rg``, ``ag``, ``ack``) that starts at the home directory, a directory above it, or the
    directory that holds the credential stores of several tools, asks, as a search of the home by the Grep tool does: it reaches
    ``~/.ssh`` and ``~/.aws``. A search inside a project does not. With no path the search starts at the working directory."""
    if name not in _SEARCHERS:
        return None
    operands, recursive, only_names = _search_operands(name, argv[1:])
    if only_names or not (recursive or name in _RECURSIVE_BY_DEFAULT):
        return None
    for start in operands or ([cwd] if cwd and not piped else []):   # fed by a pipe, a searcher reads that and not the directory
        if (why := search_root(start)) is not None:
            return Hit(ASK, f"{name} searches {start if operands else 'the working directory'}, {why}; confirm it.", start)
    return None


# --- find with a reader: the pattern against the names of keys ---------------------------------------------------------------

_NAME_TESTS = {"-name": "name", "-iname": "name", "-lname": "name", "-ilname": "name", "-path": "path", "-ipath": "path",
               "-wholename": "path", "-iwholename": "path", "-regex": "regex", "-iregex": "regex"}
_NEGATIONS = ("!", "-not")
# Paths of files that the rules guard, one of each kind: a name pattern is tried against these, and the stricter verdict of the
# paths it matches is the verdict of the pattern, as for the exact name.
_SAMPLES = ("~/.ssh/id_rsa", "~/.ssh/id_dsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ed25519", "~/.ssh/id_ecdsa_sk",
            "~/.ssh/id_ed25519_sk",
            "~/.ssh/identity", "~/.ssh/work_rsa", "~/.ssh/work_ed25519", "~/.ssh/id_rsa.bak", "~/.aws/credentials", "~/.netrc",
            "~/.vault-token", "~/.git-credentials", "~/.npmrc", "~/.pypirc", "~/.pgpass", "~/.kube/config",
            "~/.docker/config.json",
            "~/.config/gh/hosts.yml", "~/proj/.env",
            "~/proj/.env.local", "~/proj/.env.production", "~/proj/prod.env", "~/proj/key.pem", "~/proj/private.key",
            "~/proj/cert.p12", "~/proj/credentials.json", "~/proj/client_secret.json", "~/proj/secrets.yaml",
            "~/proj/terraform.tfstate", "~/proj/prod.tfvars")


@lru_cache(maxsize=1)
def _guarded() -> tuple[tuple[str, str, str], ...]:
    """(sample path, decision, what) of the samples the file rules guard."""
    found = []
    for sample in _SAMPLES:
        level = _cred_level(sample)
        if level:
            found.append((sample, level[0], level[1]))
    return tuple(found)


def _emacs_regex(pattern: str) -> str:
    """The regular expression of ``find -regex`` (emacs syntax: ``\\(``, ``\\|`` and ``\\{`` group and alternate) as Python's."""
    return re.sub(r"\\([(){}|+?])", r"\1", pattern)


def _matches(kind: str, pattern: str, sample: str) -> bool:
    low, base = pattern.lower(), sample.rpartition("/")[2]
    if kind == "name":
        return fnmatch.fnmatchcase(base.lower(), low)
    full = ["/home/user" + sample[1:], os.path.expanduser(sample).lower(), sample]
    if kind == "path":
        return any(fnmatch.fnmatchcase(path.lower(), low) for path in full)
    try:
        regex = re.compile(_emacs_regex(low), re.I)
    except re.error:
        return True   # a pattern that cannot be read may match anything
    return any(regex.search(path) for path in full)


def _pattern_tests(args: list[str]) -> tuple[list[tuple[str, str]], bool]:
    """(the name tests of a ``find`` that are not negated, True when a negated one is there): ``-name 'id_*'`` is a test that a
    key can pass, ``! -name 'id_*'`` is one that keeps keys out."""
    tests, negated = [], False
    for k, a in enumerate(args):
        if a in _NAME_TESTS and k + 1 < len(args):
            if k and args[k - 1] in _NEGATIONS:
                negated = True
            else:
                tests.append((_NAME_TESTS[a], args[k + 1]))
    return tests, negated


def _reads(words: list[str]) -> str | None:
    """The program of a command that ``find`` runs when it shows or sends what is in the files it is given, else None."""
    if not words:
        return None
    name = _bin(words[0])
    if name in _SHELLS:
        for k, a in enumerate(words[1:], 1):
            if a.startswith("-") and not a.startswith("--") and "c" in a[1:] and k + 1 < len(words):
                inner = re.split(r"[\s;|&()]+", words[k + 1])
                return next((_bin(w) for w in inner if _bin(w) in (_READERS | _NET_SINKS) - {"find", "xargs"}), None)
        return None
    if name in ("find", "xargs") or name not in _READERS | _NET_SINKS:
        return None
    if name in ("grep", "egrep", "fgrep", "rg", "ag", "ack") and _search_operands(name, words[1:])[2]:
        return None   # a list of names or counts
    return name


def find_reader_hit(argv: list[str], runs: list[list[str]], cwd: str | None = None) -> Hit | None:
    """``find START ... -exec READER`` (or ``find START ... | xargs READER``, with ``runs`` the words of the reader) from the home
    directory, a directory above it or a directory of credential stores. A name test on a pattern is judged against the names of
    keys and credential files: when it can match one, by the verdict of that name, as ``cat ~/.ssh/id_*`` is. No test on the name
    (``-type f``, ``-mtime -1``, ``-name '*'``) reads every file, keys among them, and asks."""
    program = next((p for words in runs if (p := _reads(words))), None)
    if program is None:
        return None
    args = argv[1:]
    starts = _find_roots(args) or ([cwd] if cwd else [])
    start = next((s for s in starts if search_root(s) is not None), None)
    if start is None:
        return None
    tests, negated = _pattern_tests(args)
    guarded = _guarded()
    verdict: tuple[str, str, str, str] | None = None   # decision, what, sample, test
    broad = not tests
    for kind, pattern in tests:
        matched = [(sample, level, what) for sample, level, what in guarded if _matches(kind, pattern, sample)]
        if matched and len(matched) == len(guarded):
            broad = True
        for sample, level, what in matched:
            if verdict is None or (level == DENY and verdict[0] != DENY):
                verdict = (level, what, sample, pattern)
    if verdict is not None and not broad:
        decision, what, sample, pattern = verdict
        return Hit(decision, f"find {start} runs {program} on the files that match {pattern!r}, which can be {what} "
                             f"(such as {sample}).", start)
    if broad:
        return Hit(ASK, f"find {start} runs {program} on every file under it, which holds ~/.ssh and ~/.aws; confirm it.", start)
    return None
