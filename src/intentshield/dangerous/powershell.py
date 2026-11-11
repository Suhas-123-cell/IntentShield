"""The PowerShell cmdlets that correspond to rules, read as the POSIX commands they mean."""
from __future__ import annotations

import base64
import re
import shlex

from .core import _MAX, _MAX_STAGES

# --- PowerShell ------------------------------------------------------------------------------------------------
# The PowerShell tool gets the POSIX reading (native programs such as git, curl.exe or dd are read as they are) and, besides it,
# this reading of the cmdlets and aliases that correspond to rules above: Remove-Item of a root, home or system directory,
# Get-Content (and its aliases) of a credential file, Invoke-WebRequest or Invoke-RestMethod that uploads a file, and a download
# run with Invoke-Expression. Each is rewritten as the equivalent POSIX command and read by the same rules. Other cmdlets
# (Set-Content, Copy-Item to a startup file, Start-Process, .NET calls, scripts) are not read.
_PS_REMOVE = frozenset({"remove-item", "ri", "rm", "rmdir", "rd", "del", "erase"})
_PS_READ = frozenset({"get-content", "gc", "cat", "type"})
_PS_FETCH = frozenset({"invoke-webrequest", "iwr", "invoke-restmethod", "irm", "curl", "wget", "downloadstring", "downloadfile",
                       "start-bitstransfer", "curl.exe", "wget.exe"})
_PS_EXEC = frozenset({"invoke-expression", "iex"})
_PS_KEYWORDS = frozenset({"if", "elseif", "else", "while", "until", "do", "for", "foreach", "in", "switch", "try", "catch",
                          "finally", "begin", "process", "end"})
_PS_PARAMS = {
    "remove": ("path", "literalpath", "filter", "include", "exclude", "recurse", "force", "credential", "whatif", "confirm",
               "stream",
               "usetransaction"),
    "read": ("path", "literalpath", "readcount", "totalcount", "tail", "wait", "delimiter", "encoding", "asbytestream", "raw",
             "stream",
             "filter", "include", "exclude", "force", "credential", "head", "first", "last"),
    "fetch": ("uri", "method", "body", "infile", "outfile", "headers", "contenttype", "useragent", "usebasicparsing",
              "credential",
              "timeoutsec", "maximumredirection", "proxy", "websession"),
}
_PS_VALUED = frozenset({"filter", "include", "exclude", "readcount", "totalcount", "tail", "head", "first", "last", "delimiter",
                        "encoding", "stream", "credential", "erroraction", "ea", "method", "headers", "contenttype", "useragent",
                        "timeoutsec", "maximumredirection", "proxy", "websession", "outfile", "uri", "body", "infile", "path",
                        "literalpath"})
_PS_SPLIT = re.compile(r"\s*(?:\|\||&&|[|;&\n])\s*")
_PS_WORD_BREAK = frozenset("(){}@,")
_PS_URL = re.compile(r"https?://[^\s'\"()<>`]{1,300}", re.I)


def _ps_words(text: str) -> list[tuple[list[str], str]]:
    """``text`` as PowerShell reads it, in statements of words with the separator that ends each (``|``, ``;``, ``&&``): quotes
    and the
    backtick escape are read, and parentheses, braces, ``@`` and commas end a word."""
    out: list[tuple[list[str], str]] = []
    words: list[str] = []
    cur: list[str] = []
    quote = ""
    started = False
    i, n = 0, min(len(text), _MAX)

    def end_word() -> None:
        nonlocal started
        if started:
            words.append("".join(cur))
        cur.clear()
        started = False

    def end_statement(sep: str) -> None:
        nonlocal words
        end_word()
        if words:
            out.append((words, sep))
        words = []

    while i < n and len(out) < _MAX_STAGES:
        c = text[i]
        if quote == "'":
            if c == "'" and text[i + 1:i + 2] == "'":
                cur.append("'")
                i += 1
            elif c == "'":
                quote = ""
            else:
                cur.append(c)
        elif quote == '"':
            if c == "`" and i + 1 < n:
                cur.append(text[i + 1])
                i += 1
            elif c == '"' and text[i + 1:i + 2] == '"':
                cur.append('"')
                i += 1
            elif c == '"':
                quote = ""
            else:
                cur.append(c)
        elif c in "'\"":
            quote, started = c, True
        elif c == "`" and i + 1 < n:
            cur.append(text[i + 1])
            started = True
            i += 1
        elif c in "|;&\n":
            sep = text[i:i + 2] if text[i:i + 2] in ("||", "&&") else c
            end_statement(sep.strip() or ";")
            i += len(sep) - 1
        elif c.isspace() or c in _PS_WORD_BREAK:
            end_word()
        else:
            cur.append(c)
            started = True
        i += 1
    end_statement(";")
    return out


def _ps_path(word: str) -> str:
    """A PowerShell path as the POSIX path the rules read: the home directory variables are ``~``, a drive letter and backslashes
    are read as Windows spells them (``C:\\Users\\me`` is the home directory, ``C:\\Windows`` a system directory, ``C:\\`` the
    root)."""
    w = word.strip()
    w = re.sub(r"(?i)^\$\{?env:(?:userprofile|home)\}?(?=$|[\\/])|^\$home(?=$|[\\/])", "~", w)
    w = re.sub(r"(?i)^\$\{?env:(?:systemroot|windir)\}?(?=$|[\\/])", "/etc", w)
    w = re.sub(r"(?i)^\$\{?env:systemdrive\}?(?=$|[\\/])", "/", w)
    if re.match(r"(?i)^[a-z]:(?:[\\/]|$)", w) or "\\" in w:
        w = w.replace("\\", "/")
        w = re.sub(r"(?i)^[a-z]:/?(?=$)", "/", w)
        w = re.sub(r"(?i)^[a-z]:/(?:windows|program files(?: \(x86\))?|programdata)(?=/|$)", "/etc", w)
        w = re.sub(r"(?i)^[a-z]:/users/[^/]+(?=/|$)", "~", w)
        w = re.sub(r"(?i)^[a-z]:/users$", "/Users", w)
        w = re.sub(r"(?i)^[a-z]:/", "/", w)
    return w


def _ps_params(words: list[str], kind: str) -> tuple[dict[str, str], list[str]]:
    """The named parameters (value ``""`` for a switch) and the positional words of a cmdlet's arguments. A parameter may be cut
    short to
    a name that is its own; one that is not a name of the cmdlet keeps the word after it as its value."""
    names = _PS_PARAMS[kind]
    named: dict[str, str] = {}
    rest: list[str] = []
    i = 0
    while i < len(words):
        w = words[i]
        i += 1
        if not (w.startswith("-") and len(w) > 1 and w[1].isalpha()):
            rest.append(w)
            continue
        head, _, attached = w[1:].partition(":")
        low = head.lower()
        name = low if low in names else next((x for x in names if x.startswith(low)), "force" if low == "f" else low)
        if name in ("recurse", "force", "whatif", "confirm", "raw", "wait", "asbytestream", "usebasicparsing"):
            named[name] = ""
        elif attached:
            named[name] = attached
        elif name in _PS_VALUED and i < len(words):
            named[name] = words[i]
            i += 1
        else:
            named[name] = ""
    return named, rest


def _ps_posix(text: str) -> str:
    """The POSIX command lines that mean what the PowerShell cmdlets of ``text`` mean, one for each statement read, joined with
    ``;`` and the pipes of the original; ``""`` when no statement is one of the cmdlets read here."""
    statements = _ps_words(text)
    out: list[str] = []
    pipeline: list[list[str]] = []
    after_pipe = False
    for words, sep in statements:
        low = [w.lower().lstrip(".\\&").rpartition("\\")[2] for w in words]
        pipeline.append(low)
        start = 0   # past the keyword and the condition of ``if ($ok) { Remove-Item ... }``
        while start < len(words) - 1 and (low[start] in _PS_KEYWORDS or words[start].startswith(("$", "-"))):
            start += 1
        cmd = low[start]
        args = words[start + 1:]
        line = ""
        if cmd in _PS_REMOVE:
            named, rest = _ps_params(args, "remove")
            paths = [p for v in (named.get("path", ""), named.get("literalpath", "")) for p in [v] if p] + rest
            flags = "-" + ("r" if "recurse" in named else "") + ("f" if "force" in named else "")
            pattern = named.get("include") or named.get("filter")
            if pattern and "recurse" in named:
                line = " ".join(["find", *(shlex.quote(_ps_path(p)) for p in paths), "-name", shlex.quote(pattern), "-delete"])
            elif paths:
                shown = [_ps_path(p).rstrip("/") + "/" + pattern if pattern else _ps_path(p) for p in paths]
                line = " ".join(["rm", *([flags] if len(flags) > 1 else []), "--", *(shlex.quote(p) for p in shown)])
        elif cmd in _PS_READ:
            named, rest = _ps_params(args, "read")
            paths = [p for v in (named.get("path", ""), named.get("literalpath", "")) for p in [v] if p] + rest
            if paths:
                line = " ".join(["cat", "--", *(shlex.quote(_ps_path(p)) for p in paths)])
        elif cmd in _PS_FETCH and cmd not in ("downloadstring", "downloadfile"):
            named, rest = _ps_params(args, "fetch")
            url = named.get("uri") or next((r for r in rest if _PS_URL.match(r)), "") or (_PS_URL.search(" ".join(args))
                                                                                          or [""])[0]
            sends = named.get("method", "").lower() in ("post", "put", "patch") or "body" in named or "infile" in named
            infile = named.get("infile") or next((m[1] for m in re.finditer(
                r"(?i)(?:get-content|gc|cat|type|readalltext|readallbytes)\b[\s('\"-]*(?:-(?:path|literalpath)\s+)?['\"]?("
                r"[^\s'\")]+)",
                " ".join(args) if "body" in named else "") if m), "")
            if url and sends and (infile or after_pipe):
                line = "curl " + (f"-T {shlex.quote(_ps_path(infile))} " if infile else "-d @- ") + shlex.quote(url)
        if line:
            out.append(line + (" |" if sep == "|" else ""))
        after_pipe = sep == "|"
        if sep != "|":
            kinds = {w.lstrip(".") for chain in pipeline for w in chain}
            if kinds & _PS_EXEC and kinds & _PS_FETCH:
                found = _PS_URL.search(text)
                out.append(f"curl {shlex.quote(found[0]) if found else 'https://download.invalid/x'} | sh")
            pipeline = []
    joined = " ".join(f"{x}" if x.endswith("|") else f"{x};" for x in out).strip()
    return joined.rstrip(";|").strip()


_POWERSHELLS = frozenset({"pwsh", "powershell", "pwsh-preview"})


def _ps_command_text(argv: list[str]) -> str:
    """The text ``pwsh -Command ...`` or ``-EncodedCommand ...`` runs."""
    for i, a in enumerate(argv[1:], 1):
        low = a.lower()
        if low in ("-c", "-command") or (len(low) > 2 and "-command".startswith(low)):
            return " ".join(argv[i + 1:])
        if len(low) > 2 and low.startswith("-e") and "-encodedcommand".startswith(low) and i + 1 < len(argv):
            try:
                return base64.b64decode(argv[i + 1], validate=False)[:_MAX * 2].decode("utf-16-le", "ignore")
            except ValueError:
                return ""
    return ""
