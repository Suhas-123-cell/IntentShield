"""The words of a command line: the operators and quote marks, the program lists and the patterns the reader looks for."""
from __future__ import annotations

import re
import shlex
import threading
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from intentshield.mcp_inspect import _SENSITIVE, _parse

# A template (.env.example) holds names, not values, and is committed on purpose.
SECRET = re.compile(_SENSITIVE + r"|(?:^|[^\w.])\.env(?!\.(?:example|sample|template|dist)$)(?:\.[\w-]+)?$"
                    r"|(?:^|/)\.git-credentials$", re.I)
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
    "uptime", "lsof", "history", "tac", "rev", "fold", "fmt", "expand", "seq", "find", "sed", "awk",
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
                       r"smtplib|ftplib|paramiko|net/http|Net::HTTP|LWP|HTTP::Tiny|file_get_contents|curl_exec|TCPSocket|"
                       r"UDPSocket|"
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
# Only an address that cannot leave this machine. A .local (mDNS) or .internal name, a private address or a cloud
# metadata host is another machine's, and what it serves or receives is not the user's own. The names a container
# runtime gives the host it runs on are the exception: they are this machine seen from inside a container.
_LOOPBACK = re.compile(r"^(?:localhost|[\w.-]+\.localhost|127(?:\.\d+){3}|0\.0\.0\.0|\[?::1\]?|"
                       r"host\.(?:docker|containers)\.internal)$", re.I)


@dataclass
class Command:
    destinations: set[str] = field(default_factory=set)  # canonical URLs, hosts and emails it reaches
    sends: bool = False          # it carries data to a destination (an upload, a POST, stdin into a network tool)
    secrets: list[str] = field(default_factory=list)     # credential stores read, or commands that print secrets
    read_only: bool = True       # every part is a known read-only command or a plain download, and no file is written
    ordinary: bool = True        # nothing but read-only, build, test and local version-control commands (no redirect)
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
