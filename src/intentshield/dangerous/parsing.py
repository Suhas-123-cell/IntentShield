"""Reading a command line into stages: here-documents, quotes, comments, substitutions and the shell's own words."""
from __future__ import annotations

import re
import shlex

from .core import _MAX, _MAX_STAGES, _MAX_SUBSTITUTIONS, _MAX_TOKENS, _bin, _Stage
from .paths import _CRON, _PERSIST

# --- parsing ---------------------------------------------------------------------------------------------------

_PUNCT = frozenset("|&;()<>")
_SPLIT_OPS = re.compile(r"<\(|>\(|&&|\|\||\|&|;;|<<<|<<|>>|>&|&>>|&>|<&|<>|>\||[<>|&;()]")
_HEREDOC = re.compile(r"<<-?[ \t]*['\"]?([A-Za-z_][\w-]{0,40})['\"]?")
_SHELL_WORD = re.compile(r"\b(?:ba|z|da|k)?sh\b")
_ASSIGN = re.compile(r"^[A-Za-z_]\w{0,60}=")
_FD = re.compile(r"^\d{1,2}$")
_OPS = frozenset({"|", "&&", "||", ";", "&", "|&", ";;", "(", ")", "<(", ">("})
_REDIRECTS = frozenset({">", ">>", ">|", "&>", "&>>", "<", "<<<", ">&", "<&", "<>"})

# Shell reserved words that start a command on the same line (``if x; then rm -rf /; fi``, ``{ rm -rf /; }``, ``! rm``):
# the command is what follows them.
_KEYWORDS = frozenset({"then", "do", "else", "elif", "if", "while", "until", "!", "{", "}", "coproc"})
_SUDO_LONG = ("--user", "--group", "--host", "--prompt", "--chdir", "--close-from", "--role", "--type", "--other-user",
              "--command-timeout")
_SUDO_VALUED = frozenset({"-u", "-g", "-h", "-p", "-C", "-r", "-t", "-D", "-U", "-T", *_SUDO_LONG})
_ENV_LONG = ("--unset", "--chdir", "--split-string", "--argv0")
_NICE_LONG = ("--adjustment", "--class", "--classdata")
_TIMEOUT_LONG = ("--signal", "--kill-after")
_XARGS_VALUED = frozenset({"-n", "-I", "-L", "-P", "-s", "-d", "-E", "-a", "-J", "--max-args", "--replace", "--max-lines",
                           "--max-procs", "--max-chars", "--delimiter", "--eof", "--arg-file"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "csh", "tcsh"})
_INTERPRETERS = frozenset({"python", "python3", "python2", "perl", "ruby", "node", "php", "deno", "bun", "lua", "pwsh"})
_FETCHERS = frozenset({"curl", "wget", "fetch", "aria2c", "lwp-download", "http", "https", "xh"})


def _substitutions(data: str) -> list[tuple[int, int]]:
    """The spans of the command substitutions ``$(...)`` (with the parentheses inside them matched) and backticks in ``data``.
    An unclosed one runs to the end of the text."""
    spans: list[tuple[int, int]] = []
    n, i = len(data), 0
    while len(spans) <= _MAX_SUBSTITUTIONS and i < n:
        a, b = data.find("$(", i), data.find("`", i)
        if a < 0 and b < 0:
            break
        if b < 0 or 0 <= a < b:
            if data.startswith("$((", a):  # arithmetic: what is inside is read when it holds a substitution of its own
                i = a + 3
                continue
            depth, j = 1, a + 2
            while j < n and depth:
                depth += (data[j] == "(") - (data[j] == ")")
                j += 1
            spans.append((a + 2, j - 1 if depth == 0 else j))
            i = j
        else:
            j = data.find("`", b + 1)
            spans.append((b + 1, n if j < 0 else j))
            i = n if j < 0 else j + 1
    return spans


def _strip_keywords(argv: list[str]) -> list[str]:
    """``argv`` without the reserved words at its front (``then``, ``do``, ``{``, ``!``...) and without ``function NAME``."""
    i = 0
    while i < len(argv):
        if argv[i] in _KEYWORDS:
            i += 1
        elif argv[i] == "function" and i + 1 < len(argv):
            i += 2
        else:
            break
    return argv[i:]


def _strip_heredocs(text: str) -> str:
    """Drops here-document bodies (text for a file or a program's stdin) unless the line starts a shell."""
    out, lines, i = [], text.split("\n"), 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        m = _HEREDOC.search(line)
        if m and "<<<" not in line[m.start():m.start() + 3]:
            end = i
            while end < len(lines) and lines[end].strip() != m[1]:
                end += 1
            if _SHELL_WORD.search(line):
                out.extend(lines[i:end])
            i = end + 1
    return "\n".join(out)


_CODE_WORD = re.compile(r"\b(?:(?:ba|z|da|k)?sh|python[\d.]*|perl|ruby|node|php|deno|bun|lua|pwsh|eval|source|su|ssh|awk|ga"
                        r"wk|mawk|"
                        r"nawk|xargs|watch|parallel|osascript|expect|at|batch)\b")
_CODE_RUNNERS = _SHELLS | _INTERPRETERS | frozenset({"eval", "su", "ssh", "watch", "xargs", "source", ".", "awk", "gawk", "mawk",
                                                     "nawk",
                                                      "parallel", "osascript", "expect", "at", "batch"})
_CMD_END = frozenset(";|&()`\n")


def _blank_heredocs(buf: list[str]) -> None:
    """Blanks the body of a quoted here-document (plain text, the shell expands nothing in it) unless its line starts a
    program. The quotes of an unquoted body are dropped so an apostrophe in it is not read as a quote."""
    text = "".join(buf)
    pos = 0
    lines = text.split("\n")
    starts = []
    for line in lines:
        starts.append(pos)
        pos += len(line) + 1
    i = 0
    unterminated: set[str] = set()
    while i < len(lines):
        line = lines[i]
        i += 1
        m = _HEREDOC.search(line)
        if not m or "<<<" in line[m.start():m.start() + 3]:
            continue
        if m[1] in unterminated or _CODE_WORD.search(line):
            continue
        end = i
        while end < len(lines) and lines[end].strip() != m[1]:
            end += 1
        if end >= len(lines):
            unterminated.add(m[1])  # not searched for again: a line of ``<<X`` repeated must not cost a scan each
            continue
        quoted = bool(re.match(r"<<-?[ \t]*['\"\\]", line[m.start():]))
        for k in range(starts[i], starts[end] - 1):
            if buf[k] != "\n" and (quoted or buf[k] in "'\""):
                buf[k] = " "
        i = end + 1


def _mask_data(text: str) -> str:
    """``text`` with the inside of single-quoted strings and of quoted here-documents blanked, same length. The shell
    reads those as data (a commit message, an ``echo``), so a command or a payload spelled in one is not a command
    here. Left as it is when a program that runs text comes first in the same command (``bash -c '...'``, ``python -c``,
    ``ssh host '...'``) or takes the output (``echo '...' | sh``), and when the text names a startup file or a
    scheduler, where written text runs later."""
    if "'" not in text and "<<" not in text or _PERSIST.search(text) or _CRON.search(text):
        return text
    buf = list(text)
    _blank_heredocs(buf)
    text = "".join(buf)
    cmds: list[tuple[bool, list[tuple[int, int]]]] = []  # (has a code word, spans to blank) per simple command
    spans: list[tuple[int, int]] = []
    runs = [False]
    nxt: list[bool] = []  # the command ends in a pipe
    cur, n, i = "", len(text), 0

    def end_word() -> None:
        nonlocal cur
        if cur and (cur in (".", "-S", "--split-string") or _bin(cur) in _CODE_RUNNERS):
            runs[0] = True
        cur = ""

    def end_cmd(piped: bool) -> None:
        nonlocal spans
        end_word()
        cmds.append((runs[0], spans))
        nxt.append(piped)
        spans, runs[0] = [], False

    while i < n:
        c = text[i]
        if c == "\\":
            cur += text[i:i + 2] if text[i + 1:i + 2] != "\n" else ""
            i += 2
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            cur += text[i + 1:j]
            i = j + 1
        elif c == "'" or c == "$" and text[i + 1:i + 2] == "'":
            a = i + (2 if c == "$" else 1)
            j = a
            while j < n and text[j] != "'":
                j += 2 if c == "$" and text[j] == "\\" else 1
            if j >= n:  # never closed: an apostrophe, not a quote
                cur += c
                i += 1
                continue
            if not runs[0]:
                spans.append((a, j))
            cur += text[a:j]
            i = j + 1
        elif c == "#" and not cur:
            while i < n and text[i] != "\n":
                i += 1
        elif c in " \t":
            end_word()
            i += 1
        elif c in _CMD_END:
            piped = c == "|" and text[i - 1:i] != "|" and text[i + 1:i + 2] != "|"
            end_cmd(piped)
            i += 1
        else:
            cur += c
            i += 1
    end_cmd(False)
    for k, (_, sp) in enumerate(cmds):
        if nxt[k] and k + 1 < len(cmds) and cmds[k + 1][0]:  # its output goes to a program that runs text
            continue
        for a, b in sp:
            for x in range(a, b):
                if buf[x] != "\n":
                    buf[x] = " "
    return "".join(buf)


_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.){0,2000})'")
_ANSI_SIMPLE = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "v": "\v",
                "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _decode_ansi_c(match: re.Match[str]) -> str:
    """``$'\\x72m'`` is the word ``rm`` to bash: the quoted text with its escapes decoded, as a plain single-quoted word."""
    body, out, i = match[1], [], 0
    while i < len(body):
        c = body[i]
        if c != "\\" or i + 1 >= len(body):
            out.append(c)
            i += 1
            continue
        n = body[i + 1]
        if n in _ANSI_SIMPLE:
            out.append(_ANSI_SIMPLE[n])
            i += 2
        elif n in "xuU" or n in "01234567":
            digits, base, width = ("", 16, {"x": 2, "u": 4, "U": 8}[n]) if n in "xuU" else (n, 8, 3)
            j = i + 2
            while j < len(body) and len(digits) < width and body[j] in ("0123456789abcdefABCDEF" if base == 16 else "01234567"):
                digits += body[j]
                j += 1
            try:
                out.append(chr(int(digits, base)) if digits else "\\" + n)
            except (ValueError, OverflowError):
                out.append("?")
            i = j
        else:
            out.append("\\" + n)
            i += 2
    return "'" + "".join(out).replace("'", "'\\''") + "'"


_CONTINUATION = re.compile(r"(?<!\\)((?:\\\\)*)\\\r?\n")
_IFS = re.compile(r"\$\{IFS\}(?:\$\d)?|\$IFS(?![A-Za-z0-9_])(?:\$\d)?")
_WORD_CHAR = re.compile(r"[\w./~$@%+=:,-]")


def _lexical(text: str, comments: bool) -> str:
    """``text`` with the spellings that the shell reads as nothing removed: empty quotes inside a word (``r''m`` is ``rm``), a
    backslash before a letter (``\\rm``) and, with ``comments``, a comment after a command. Left as it is when a quote is never
    closed, so the parser sees what it saw."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            if text[i + 1:i + 2].isalpha() and text[i + 1:i + 2].isascii():  # \rm is rm, r\m is rm
                out.append(text[i + 1])
            else:
                out.append(text[i:i + 2])
            i += 2
        elif c in "'\"" or c == "$" and text[i + 1:i + 2] == "'":
            start = i + 1 if c != "$" else i + 2
            quote = text[start - 1]
            j = start
            while j < n and text[j] != quote:
                j += 2 if text[j] == "\\" and (quote == '"' or c == "$") else 1
            if j >= n:
                return text
            empty = j == start and c != "$"
            before = out[-1][-1:] if out else ""
            if empty and (_WORD_CHAR.match(before) or _WORD_CHAR.match(text[j + 1:j + 2])):
                i = j + 1
                continue
            out.append(text[i:j + 1])
            i = j + 1
        elif comments and c == "#" and (i == 0 or text[i - 1] in " \t\n;&|(<>"):
            while i < n and text[i] not in "\n;&|":
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


# Variables a shell has set, so that a default after ``:-`` does not apply and ``${HOME:-/x}`` is still the home directory.
_SET_VAR = r"(?!(?:HOME|USERPROFILE|PWD|USER|LOGNAME|SHELL|PATH)\b)"
_EMPTY_EXPANSION = re.compile(r"\$[@*]|\$\(\s*(?:(?:true|false|:)\s*)?\)|`\s*(?:true|false|:)\s*`|\$\{" + _SET_VAR
                              + r"[A-Za-z_]\w{0,40}:?[-=]\}")
_DEFAULT_EXPANSION = re.compile(r"\$\{" + _SET_VAR + r"[A-Za-z_]\w{0,40}:?[-=]([^}$`'\"\\\s]{1,60})\}")


def _normalise(text: str) -> str:
    """The text as the shell reads it: NUL bytes dropped (bash ignores them in a script), line continuations joined
    (``rm \\<newline> -rf /``), form feed and vertical tab read as blanks, ``$IFS`` read as a blank, the expansions that are empty
    where they stand (``$@``, ``$()``, ``${X:-}``) dropped, a default that is spelled out (``${RM:-rm}``) read as that word, and
    empty quotes inside words dropped."""
    if "\x00" in text:
        text = text.replace("\x00", "")
    text = _CONTINUATION.sub(r"\1", text)
    if "$" in text or "`" in text:
        text = _EMPTY_EXPANSION.sub("", text)
        text = _DEFAULT_EXPANSION.sub(r"\1", text)
    if "\x0b" in text or "\x0c" in text:
        text = text.replace("\x0b", " ").replace("\x0c", " ")
    if "IFS" in text:
        text = _IFS.sub(" ", text)
    if "''" in text or '""' in text or "\\" in text:
        text = _lexical(text, comments=False)
    return text


_SUBST_SAFE = re.compile(r"[^\w ./~@:=,+-]")


def _wrap_substitutions(text: str) -> str:
    """``text`` with each ``$(...)`` that stands in a word outside quotes put in double quotes, with only plain characters kept
    inside, so that the parentheses do not end the command: ``rm -rf $(echo x) /`` is ``rm -rf`` of two words, not ``rm -rf $``
    and a command ``/``. The code inside is read on its own from the unchanged text."""
    if "$(" not in text:
        return text
    out: list[str] = []
    quote = ""
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "\\" and quote != "'":
            out.append(text[i:i + 2])
            i += 2
        elif quote:
            if c == quote:
                quote = ""
            out.append(c)
            i += 1
        elif c in "'\"":
            quote = c
            out.append(c)
            i += 1
        elif c == "$" and text.startswith("$(", i) and not text.startswith("$((", i):
            depth, j = 1, i + 2
            while j < n and depth:
                depth += (text[j] == "(") - (text[j] == ")")
                j += 1
            if depth:  # never closed: left as it is
                out.append(text[i:])
                break
            out.append('"$(' + _SUBST_SAFE.sub("_", text[i + 2:j - 1]) + ')"')
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _stages(text: str, notes: list[str] | None = None) -> list[_Stage] | None:
    """The simple commands of ``text``, or None when it cannot be tokenized (unbalanced quotes). A reason is added to ``notes``
    when a size limit stopped the reading before the end."""
    notes = [] if notes is None else notes
    text = _strip_heredocs(text[:_MAX])
    if "#" in text:
        text = _lexical(text, comments=True)
    text = text.replace("\r", " ").replace("\n", " ; ")
    if "$'" in text:
        text = _ANSI_C.sub(_decode_ansi_c, text)
    text = _wrap_substitutions(text)
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        raw = list(lexer)
    except ValueError:  # unbalanced quotes: read it again without them, so a stray quote does not hide a command
        lexer = shlex.shlex(text.replace("'", " ").replace('"', " "), posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        try:
            raw = list(lexer)
        except ValueError:
            return None
    if len(raw) > _MAX_TOKENS:
        notes.append(f"more than {_MAX_TOKENS} words")
    pieces: list[str] = []
    for token in raw[:_MAX_TOKENS]:
        if len(token) > 1 and set(token) <= _PUNCT:
            pieces.extend(_SPLIT_OPS.findall(token))
        else:
            pieces.append(token)
    stages: list[_Stage] = []
    argv: list[str] = []
    redirects: list[tuple[str, str]] = []
    piped, pipeline, comment, i = False, 0, False, 0

    def flush() -> None:
        nonlocal argv, redirects, piped
        argv = _strip_keywords(argv)
        if argv or redirects:
            stages.append(_Stage(argv, redirects, piped, pipeline))
        argv, redirects, piped = [], [], False

    while i < len(pieces) and len(stages) < _MAX_STAGES:
        token = pieces[i]
        i += 1
        if token in _OPS:
            flush()
            if token in ("|", "|&"):
                piped = True
            elif token != "(" and token != ")":
                pipeline += 1
            comment = False
            continue
        if comment:
            continue
        if token.startswith("#") and not argv:
            comment = True
            continue
        if token in _REDIRECTS:
            target = pieces[i] if i < len(pieces) else ""
            if target not in _OPS and target not in _REDIRECTS:
                i += 1
                redirects.append((token, target))
            if argv and _FD.match(argv[-1]) and token.startswith(("<", ">")):
                argv.pop()
            continue
        argv.append(token)
    flush()
    if i < len(pieces) and any(p not in _OPS for p in pieces[i:]):
        notes.append(f"more than {_MAX_STAGES} commands")
    # a stage "piped" only when a pipe, not another operator, came right before it
    return stages
