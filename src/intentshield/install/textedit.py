"""Text-level editing of JSON with comments and of TOML, so a user's file keeps its comments, order and spacing."""
from __future__ import annotations

import json
import re
import tomllib
from typing import Any

_TOML_BEGIN, _TOML_END = "# >>> intentshield hooks >>>", "# <<< intentshield hooks <<<"


def _strip_toml_block(text: str) -> tuple[str, bool]:
    """``text`` without our block. Only a well-formed BEGIN..END pair is cut: a lone marker or one in the
    wrong order is a file somebody edited, and cutting between them would take their lines too."""
    start, end = text.find(_TOML_BEGIN), text.find(_TOML_END)
    if (start < 0) != (end < 0) or end < start:
        raise ValueError(f"the IntentShield block markers are damaged ({_TOML_BEGIN!r} and {_TOML_END!r} must "
                         "both be present, in that order); fix or delete them by hand")
    if start < 0:
        return text, False
    before = text[:start].rstrip("\n")
    after = text[end + len(_TOML_END):].lstrip("\n")
    if before and after:
        return before + "\n\n" + after, True
    return (before + "\n" if before else after), True


def strip_json_comments(text: str) -> str:
    """``text`` without ``//`` and ``/* */`` comments and trailing commas (outside strings), as Gemini CLI reads its settings; a
    comment becomes blanks, so the positions in an error message still point at the right place."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(ch if ch in "\r\n" else " " for ch in text[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return _drop_trailing_commas("".join(out))


def _drop_trailing_commas(text: str) -> str:
    """``text`` with the comma before a closing ``}`` or ``]`` (outside strings) blanked: ``{"a": 1,}`` as JSONC allows it."""
    out, i, n = list(text), 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            i += 1
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                out[i] = " "
            i += 1
        else:
            i += 1
    return "".join(out)


# --- Codex CLI: [mcp_servers.NAME] tables of ~/.codex/config.toml ---------------------------------------------------------
# TOML is edited as text, line by line, so that the rest of the file (comments, order, spacing) stays as it is. Only an entry
# written
# as a table of its own, with ``command`` (and ``args``) on lines of that table, is edited; the result is parsed again and must be
# the
# old file with that command and those args changed, or nothing is written.

_TOML_HEADER = re.compile(r"^[ \t]*\[(?!\[)(.+?)\][ \t]*(?:#.*)?$")
_TOML_ANY_HEADER = re.compile(r"^[ \t]*\[")


def _toml_path(header: str) -> tuple[str, ...]:
    """The key path a table header names (``mcp_servers."my server"`` is ``("mcp_servers", "my server")``)."""
    node: Any = tomllib.loads(f"[{header}]\n")
    path: list[str] = []
    while isinstance(node, dict) and len(node) == 1:
        key, node = next(iter(node.items()))
        path.append(key)
    return tuple(path)


def _toml_value_end(lines: list[str], start: int) -> int:
    """The index after the last line of the TOML value that begins on ``lines[start]`` (an array may run over several lines)."""
    for end in range(start + 1, min(len(lines), start + 200) + 1):
        try:
            tomllib.loads("".join(lines[start:end]))
            return end
        except tomllib.TOMLDecodeError:
            continue
    raise ValueError("a value that does not end")


def _toml_set(text: str, edits: dict[str, tuple[str, list[str] | None]]) -> str:
    """``text`` with ``command`` and ``args`` of each ``[mcp_servers.NAME]`` table of ``edits`` replaced (``args`` of ``None``:
    the
    line removed). Raises ``ValueError`` naming the server that cannot be edited this way."""
    lines = text.splitlines(keepends=True)
    done: set[str] = set()
    i = 0
    while i < len(lines):
        header = _TOML_HEADER.match(lines[i].rstrip("\r\n"))
        try:
            path = _toml_path(header[1]) if header else ()
        except tomllib.TOMLDecodeError:
            path = ()
        if len(path) != 2 or path[0] != "mcp_servers" or path[1] not in edits:
            i += 1
            continue
        name = path[1]
        end = next((k for k in range(i + 1, len(lines)) if _TOML_ANY_HEADER.match(lines[k])), len(lines))
        command, args = edits[name]
        where: dict[str, tuple[int, int]] = {}
        k = i + 1
        while k < end:
            key = re.match(r"^[ \t]*(command|args)[ \t]*=", lines[k])
            stop = _toml_value_end(lines, k) if key else k + 1
            if key:
                where[key[1]] = (k, stop)
            k = stop
        if "command" not in where:
            raise ValueError(f"{name}: the table has no `command` line")
        command_line = lines[where["command"][0]]
        eol = (re.search(r"\r?\n$", command_line) or ["\n"])[0]
        indent = re.match(r"^[ \t]*", command_line)[0]  # type: ignore[index]
        new_command = f"{indent}command = {json.dumps(command, ensure_ascii=False)}{eol}"
        new_args = None if args is None else f"{indent}args = {json.dumps(args, ensure_ascii=False)}{eol}"
        c0, c1 = where["command"]
        a0, a1 = where.get("args", (c1, c1))
        pieces = [(c0, c1, [new_command])]
        pieces.append((a0, a1, [] if new_args is None else [new_args]))
        size = len(lines)
        for start, stop, replacement in sorted(pieces, reverse=True):
            lines[start:stop] = replacement
        done.add(name)
        i = end + len(lines) - size
    if missing := sorted(set(edits) - done):
        raise ValueError(f"{', '.join(missing)}: not written as a [mcp_servers.NAME] table")
    new = "".join(lines)
    before, after = tomllib.loads(text), tomllib.loads(new)
    servers = before.get("mcp_servers", {})
    for name, (command, args) in edits.items():
        entry = servers[name]
        entry["command"] = command
        if args is None:
            entry.pop("args", None)
        else:
            entry["args"] = list(args)
    if before != after:
        raise ValueError("the edit would change more than command and args")
    return new
