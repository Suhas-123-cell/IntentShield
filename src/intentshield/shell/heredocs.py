"""Here-documents and the lines that carry them: the text a command is given on its input."""
from __future__ import annotations

import re

from .expand import _program
from .lexical import (
    _ARITHMETIC,
    _DELIMITER_PART,
    _ESCAPED,
    _HEREDOC,
    _INTERPRETERS,
    _MARKED,
    _MAX_PARTS,
    _PARAMETER,
    _PIPED_SHELL,
    _PREP_SPECIAL,
    _QUOTED,
    _SHELLS,
    _STDIN_FILES,
    _binary,
    _step,
)


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
