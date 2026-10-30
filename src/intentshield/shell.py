"""What a shell command does, as far as the guard needs to know: where it reaches over the network,
whether it carries data there, which secrets it reads, and whether it only reads.

Best effort: a shell is a programming language, and this reads the common forms (pipelines, ``&&``,
redirections, ``sh -c``, ``$(...)``, ``sudo``/``env`` prefixes). What it cannot read counts as not
read-only, never as harmless. Only the standard library and ``mcp_inspect`` are imported, so the hook
starts fast.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from .mcp_inspect import _SENSITIVE, _parse, distinctive_values

SECRET = re.compile(_SENSITIVE + r"|(?:^|[^\w.])\.env(?:\.[\w-]+)?$|(?:^|/)\.git-credentials$", re.I)
# Commands that print secrets with no file argument to match.
_SECRET_COMMANDS = {("printenv",), ("gh", "auth", "token"), ("security", "find-generic-password"),
                    ("security", "find-internet-password"), ("aws", "configure", "export-credentials")}
_NETWORK = frozenset({"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "rsync",
                      "ftp", "http", "https", "xh", "aria2c", "mail", "mailx", "mutt", "sendmail", "dig",
                      "nslookup", "host", "ping"})
# Tools whose every connection carries data the command chose.
_ALWAYS_SENDS = frozenset({"nc", "ncat", "netcat", "socat", "telnet", "ssh", "sftp", "ftp", "mail", "mailx",
                           "mutt", "sendmail"})
_GIT_FETCH = frozenset({"clone", "fetch", "pull", "ls-remote", "submodule"})
_GIT_SEND = frozenset({"push", "send-email", "request-pull"})
_INTERPRETERS = frozenset({"python", "python3", "node", "perl", "ruby", "php", "deno", "bun"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish"})
_KEYWORDS = frozenset({"do", "then", "else", "elif", "if", "while", "until", "!", "{", "}"})
_WRAPPERS = frozenset({"sudo", "doas", "env", "time", "nohup", "command", "exec", "nice", "stdbuf", "caffeinate"})
_READ_ONLY = frozenset({
    "ls", "ll", "la", "cat", "bat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "ag", "ack",
    "fd", "pwd", "echo", "printf", "wc", "sort", "uniq", "cut", "tr", "diff", "cmp", "comm", "stat", "file", "du",
    "df", "tree", "which", "whereis", "type", "whoami", "id", "uname", "hostname", "date", "cal", "true", "false",
    "test", "[", "basename", "dirname", "realpath", "readlink", "jq", "yq", "column", "nl", "od", "xxd", "hexdump",
    "strings", "md5", "md5sum", "shasum", "sha1sum", "sha256sum", "ps", "cd", "pushd", "popd", "sleep", "man",
    "uptime", "lsof", "history", "tac", "rev", "fold", "fmt", "expand", "seq",
})
_GIT_READ_ONLY = frozenset({"status", "diff", "log", "show", "blame", "rev-parse", "ls-files", "describe",
                            "shortlog", "grep", "ls-tree", "cat-file", "rev-list", "merge-base", "whatchanged"})
# Commands that name a file without reading what is in it.
_NAMES_ONLY = frozenset({"ls", "stat", "test", "[", "[[", "file", "du", "find", "touch", "mkdir", "chmod", "chown",
                         "rm", "mv", "which", "basename", "dirname", "realpath", "readlink", "echo", "printf"})
# Inline code reaches the network only through a client library, and sends data only through one of these.
_NET_CALL = re.compile(r"\b(?:requests|httpx|aiohttp|urllib\d?|urlopen|http\.client|socket|fetch|axios|XMLHttpRequest|"
                       r"smtplib|ftplib|paramiko|net/http|Net::HTTP|LWP|HTTP::Tiny|file_get_contents|curl_exec)\b")
_SEND_CALL = re.compile(r"\.(?:post|put|patch|send|sendall|sendmail|upload)\s*\(|\b(?:data|json|files|body)\s*[=:]|"
                        r"method\s*[:=]\s*['\"](?:POST|PUT|PATCH)|urlopen\([^)]*,", re.I)
_OPERATORS = frozenset({"|", "||", "&&", ";", "&", "|&", ";;", "(", ")", "\n"})
_REDIRECTS = frozenset({">", ">>", ">|", "&>", "&>>", "<", "<<", "<<<", ">&", "<&", "<>"})
_SUBSTITUTION = re.compile(r"\$\(((?:[^()]|\([^()]*\))*)\)|`([^`]*)`")
_LOOPBACK = re.compile(r"^(?:localhost|127(?:\.\d+){3}|0\.0\.0\.0|\[?::1\]?|[\w.-]+\.(?:localhost|local|internal))$",
                       re.I)


@dataclass
class Command:
    destinations: set[str] = field(default_factory=set)  # canonical URLs, hosts and emails it reaches
    sends: bool = False          # it carries data to a destination (an upload, a POST, stdin into a network tool)
    secrets: list[str] = field(default_factory=list)     # credential stores read, or commands that print secrets
    read_only: bool = True       # every part is a known read-only command or a plain download, and no file is written
    runs_fetched: bool = False   # a network tool's output is piped into a shell or an interpreter
    remote: bool = False         # its output comes from elsewhere: a remote address, or a code host's issues and PRs


def is_loopback(value: str) -> bool:
    """A destination on this machine (a dev server), which no output can make the attacker's."""
    kind, host, _ = _parse(value)
    return kind in ("url", "host", "email") and bool(_LOOPBACK.match(host))


def host(value: str) -> str:
    """The host of a canonical URL, host or email."""
    return _parse(value)[1] or value


def _tokens(command: str) -> list[str] | None:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:  # unbalanced quotes
        return None


def _program(argv: list[str]) -> list[str]:
    """``argv`` without leading assignments and wrappers (``sudo -u x``, ``env A=1``, ``timeout 5``)."""
    i = 0
    while i < len(argv):
        word = argv[i]
        if re.fullmatch(r"[A-Za-z_]\w*=.*", word, re.S) or word in _KEYWORDS:
            i += 1
        elif PurePosixPath(word).name in _WRAPPERS:
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                i += 2 if argv[i] in ("-u", "-g", "-n") else 1
        elif PurePosixPath(word).name in ("timeout", "gtimeout"):
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                i += 1
            i += 1  # the duration
        elif PurePosixPath(word).name == "xargs":
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                i += 2 if argv[i] in ("-I", "-n", "-P", "-L", "-d", "-E", "-s") else 1
        else:
            break
    return argv[i:]


def network_values(text: str) -> set[str]:
    return {v for v in distinctive_values(text) if _parse(v)[0] in ("url", "host", "email")}


def _curl_sends(args: list[str]) -> bool:
    for i, arg in enumerate(args):
        if arg.startswith(("--data", "--form", "--upload-file", "--json", "--post")):
            return True
        if arg in ("-X", "--request") and i + 1 < len(args) and args[i + 1].upper() in ("POST", "PUT", "PATCH"):
            return True
        if re.fullmatch(r"-(?:X|-request=)(?:POST|PUT|PATCH)", arg, re.I):
            return True
        # -d, -F, -T, alone, glued to their value (-d@file) or last in a cluster (-sSd)
        if re.fullmatch(r"-[a-zA-Z]*[dFT]", arg) or re.match(r"-[dFT].", arg):
            return True
    return False


def _wget_sends(args: list[str]) -> bool:
    return any(arg.startswith(("--post-", "--body-", "--method=P", "--method=p")) or arg == "--method" for arg in args)


# curl options that write a file or read options from one; a short cluster ending in o, O, c, D or K does too.
_CURL_WRITES = ("--output", "--remote-name", "--cookie-jar", "--dump-header", "--trace", "--libcurl", "--config",
                "--etag-save", "--hsts", "--alt-svc", "--stderr", "--create-dirs")
# wget saves a file unless told to print the page: only these options are known not to write one.
_WGET_PRINTS = frozenset({"-q", "--quiet", "-O-", "-qO-", "-nv", "--no-verbose", "-S", "--server-response",
                          "--spider"})


def _downloads(name: str, args: list[str]) -> bool:
    """A plain download: a GET or HEAD whose page goes to stdout, carrying no data and writing no file. It
    changes nothing here, so it counts as read-only; the guard still checks where it goes."""
    if any("$" in a or "`" in a for a in args):  # an address built at run time may carry data
        return False
    if name == "curl":
        for i, arg in enumerate(args):
            following = args[i + 1] if i + 1 < len(args) else ""
            if arg in ("-X", "--request") and following.upper() not in ("GET", "HEAD"):
                return False
            if re.fullmatch(r"-(?:X|-request=)(?!GET$|HEAD$).+", arg, re.I):
                return False
            if arg in ("-D", "--dump-header") and following == "-":
                continue
            if arg.startswith(_CURL_WRITES) or re.fullmatch(r"-[a-zA-Z]*[oOcDK]", arg) or re.match(r"-[oOcDK].", arg):
                return False
        return not _curl_sends(args)
    if name == "wget":
        options = [a for a in args if a.startswith("-") or a == "-"]
        printed = any(a in ("-O-", "-qO-", "--spider", "--output-document=-") for a in args) or any(
            a in ("-O", "-qO", "--output-document") and args[i + 1:i + 2] == ["-"] for i, a in enumerate(args))
        allowed = _WGET_PRINTS | {"-O", "-qO", "--output-document", "--output-document=-", "-"}
        return printed and all(a in allowed for a in options) and not _wget_sends(args)
    return False


def _httpie_sends(args: list[str]) -> bool:
    return any(arg.upper() in ("POST", "PUT", "PATCH") or (not arg.startswith("-") and "://" not in arg and
               bool(re.match(r"[\w.-]+(?::=|=|@)", arg))) for arg in args)


def _segment(argv: list[str], piped_in: bool, found: Command, depth: int) -> tuple[str, bool]:
    """Reads one simple command into ``found``; returns its program name ("" if none) and whether it runs a
    program it reads on stdin (``sh``, ``python -``, not ``python3 -c '...'``, which reads data there)."""
    if PurePosixPath(argv[0]).name in ("env", "set") and all("=" in a or a.startswith("-") for a in argv[1:]):
        found.secrets.append(argv[0])  # with no command to run, env and set print every variable
    whole, argv = argv, _program(argv)
    if not argv:
        return "", False
    name = PurePosixPath(argv[0]).name.lower()
    args = argv[1:]
    if name not in _NAMES_ONLY:
        found.secrets += [a for a in whole if SECRET.search(a)]
    runs_stdin = (name in _SHELLS or name in _INTERPRETERS) and all(a.startswith("-") and a not in ("-c", "-e")
                                                                    or a == "-" for a in args)
    if any(tuple(a.lower() for a in argv[:len(cmd)]) == cmd for cmd in _SECRET_COMMANDS):
        found.secrets.append(" ".join(argv[:3]))
    read_only = name in _READ_ONLY or (name == "git" and bool(args) and args[0] in _GIT_READ_ONLY)
    if name == "find" and any(a in ("-exec", "-execdir", "-delete", "-ok", "-okdir", "-fprint", "-fls") for a in args):
        read_only = False
    if name == "sed" and any(a.startswith(("-i", "--in-place")) for a in args):
        read_only = False
    if name == "git" and args and args[0] == "branch" and not any(a.startswith(("-d", "-D", "-m", "-M", "-c", "-C",
                                                                                   "--delete", "--move", "--copy"))
                                                                  for a in args[1:]):
        read_only = len(args) == 1 or all(a.startswith("-") for a in args[1:])
    if not read_only and not (_downloads(name, args) and not piped_in):
        found.read_only = False
    flag = next((i for i, a in enumerate(args) if re.fullmatch(r"-[a-z]*c", a)), None)  # -c, -lc
    if name in _SHELLS and flag is not None and depth < 3:
        _merge(found, parse(args[flag + 1] if flag + 1 < len(args) else "", depth + 1))
        return name, False
    if name == "eval" and depth < 3:  # its arguments are a command
        _merge(found, parse(" ".join(args), depth + 1))
        return name, False
    text = " ".join(args)
    if name in _NETWORK or (name == "git" and args and (args[0] in _GIT_FETCH | _GIT_SEND or args[0] == "remote")):
        destinations = network_values(text)
        if name in ("scp", "rsync"):  # user@host:path, host:path
            remotes = [a for a in args if re.match(r"(?:[\w.+-]+@)?[\w.-]+\.[\w.-]+:", a) and "://" not in a]
            destinations |= {v for a in remotes for v in network_values(a.partition(":")[0])}
            found.sends |= bool(remotes) and remotes[-1] == args[-1]
        found.destinations |= destinations
        found.remote |= any(not is_loopback(v) for v in destinations)
        found.sends |= (
            name in _ALWAYS_SENDS or piped_in
            or (name == "curl" and _curl_sends(args)) or (name == "wget" and _wget_sends(args))
            or (name in ("http", "https", "xh") and _httpie_sends(args))
            or (name == "git" and bool(args) and (args[0] in _GIT_SEND or args[0] == "remote" and len(args) > 1
                                                  and args[1] in ("add", "set-url")))
            or (name in ("dig", "nslookup", "host", "ping") and bool(re.search(r"\$[\w{(]|`", text))))
    elif name in ("gh", "glab") and not (args and args[0] in ("auth", "config", "alias", "completion")):
        found.remote = True  # issues, pull requests, CI logs: text anyone can write
    elif name in _INTERPRETERS and any(a in ("-c", "-e", "--eval", "-r") for a in args):
        _code(text, found)
    return name, runs_stdin


def _code(code: str, found: Command) -> None:
    """Inline program text: the addresses it reaches when it calls a network client, and whether it sends data.
    A URL in a string (a docs link, a constant) is not a request."""
    if not _NET_CALL.search(code):
        return
    destinations = network_values(code)
    found.destinations |= destinations
    found.remote |= any(not is_loopback(v) for v in destinations)
    found.sends |= bool(destinations) and bool(_SEND_CALL.search(code))


def _merge(found: Command, inner: Command) -> None:
    found.destinations |= inner.destinations
    found.sends |= inner.sends
    found.secrets += inner.secrets
    found.read_only &= inner.read_only
    found.runs_fetched |= inner.runs_fetched
    found.remote |= inner.remote


_HEREDOC = re.compile(r"(?<!<)<<(?!<)-?\s*(['\"]?)([\w.-]+)\1")


def _heredocs(command: str, found: Command, depth: int) -> str:
    """``command`` without its here-document bodies. A body is data (``cat > file <<EOF``), except one fed to a
    shell or an interpreter, which is code and is read as such into ``found``."""
    lines, kept, i = command.split("\n"), [], 0
    while i < len(lines):
        line = lines[i]
        kept.append(line)
        i += 1
        for match in _HEREDOC.finditer(line):
            body = []
            while i < len(lines) and lines[i].strip() != match.group(2):
                body.append(lines[i])
                i += 1
            i += 1
            words = _program(re.split(r"[|;&]", line[:match.start()])[-1].split())
            name = PurePosixPath(words[0]).name.lower() if words else ""
            if name in _SHELLS and depth < 3:
                _merge(found, parse("\n".join(body), depth + 1))
            elif name in _INTERPRETERS:
                _code("\n".join(body), found)
    return "\n".join(kept)


# NAME=value as the command assigns it: quoted, or one word.
_ASSIGNMENT = re.compile(r"(?:^|[\s;&|(])([A-Za-z_]\w*)=(\"[^\"]*\"|'[^']*'|[^\s;&|()]*)")


def _expanded(command: str) -> str:
    """``command`` with the variables it assigns itself written out, so that ``C="curl -F f=@x URL"; $C`` and
    ``U=URL; curl -d @x $U`` read as what they run. One pass; a variable from elsewhere stays as it is."""
    values = {name: value[1:-1] if value[:1] in "\"'" else value for name, value in _ASSIGNMENT.findall(command)}
    if not values:
        return command
    return re.sub(r"\$\{?([A-Za-z_]\w*)\}?", lambda m: values.get(m[1], m[0]), command)


def parse(command: str, depth: int = 0) -> Command:
    found = Command()
    command = _expanded(command)
    if "<<" in command:
        command = _heredocs(command, found, depth)
    for match in _SUBSTITUTION.finditer(command):  # $(...) and `...` run first, and their output goes anywhere
        if depth < 3:
            _merge(found, parse(match.group(1) if match.group(1) is not None else match.group(2), depth + 1))
    tokens = _tokens(command)
    if tokens is None:  # unreadable: whatever it is, it is not known to be read-only
        found.read_only = False
        found.destinations |= network_values(command)
        found.remote = any(not is_loopback(v) for v in found.destinations)
        found.secrets += [w for w in command.split() if SECRET.search(w)]
        return found
    argv: list[str] = []
    piped_in, previous = False, ""
    i = 0
    while i <= len(tokens):
        token = tokens[i] if i < len(tokens) else ";"
        if token in _REDIRECTS:
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            if token.startswith((">", "&>")) and token not in (">&",) and target not in ("/dev/null", "/dev/stderr",
                                                                                      "/dev/stdout"):
                found.read_only = False
            if token.startswith("<") and SECRET.search(target):
                found.secrets.append(target)
            # the digit of "2>" was taken as an argument; drop it
            if argv and argv[-1].isdigit() and token.startswith(">"):
                argv.pop()
            i += 2
            continue
        if token in _OPERATORS or (token and set(token) <= set("|&;()")):
            name, runs_stdin = _segment(argv, piped_in, found, depth) if argv else ("", False)
            if piped_in and previous in _NETWORK and runs_stdin:
                found.runs_fetched = True
            piped = token in ("|", "|&")
            previous = name if piped else ""
            piped_in = piped
            argv = []
        else:
            argv.append(token)
        i += 1
    if argv:  # a redirection with no target ended the command
        _segment(argv, piped_in, found, depth)
    # Data in an address: a query or path built from a command's output or from a variable the command does not
    # set itself (a loop variable is not data; "$TOKEN" may be).
    assigned = set(re.findall(r"\bfor\s+(\w+)\s+in\b", command)) | set(re.findall(r"(?:^|[\s;&|(])(\w+)=", command))
    for url in re.findall(r"[a-z][a-z0-9+.-]*://[^\s'\"]+", command, re.I):
        if "$(" in url or "`" in url or set(re.findall(r"\$\{?(\w+)", url)) - assigned:
            found.sends = True
    found.secrets = list(dict.fromkeys(found.secrets))
    return found
