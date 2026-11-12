"""The raw text of a command, searched for what the reader could not parse: an address or a send inside a string."""
from __future__ import annotations

import re
from bisect import bisect_right
from itertools import islice

from .lexical import (
    _ALWAYS_SENDS,
    _DEV_TCP,
    _FILE_READ_CALL,
    _MAX_COMMAND,
    _MAX_PARTS,
    _NET_CALL,
    _SEND_CALL,
    _SOCKET_CALL,
    Command,
    is_loopback,
)
from .network import network_values

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
        found.ordinary = False
    variants = _variants(command)
    read = [w for t in variants for w in _sender_windows(t)]
    windows = [w for w, _ in read]
    static = bool(read) and all(begins and not _DYNAMIC.search(w) for w, begins in read)
    # (a command over the cap was read whole as written by the fallback: not again)
    found.destinations |= _addresses(windows if static else variants, command if len(command) > _MAX_COMMAND else "")
    if not found.read_only:
        found.sends |= _paired(windows)
