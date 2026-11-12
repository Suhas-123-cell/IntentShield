"""What a shell command does, as far as the guard needs to know: where it reaches over the network,
whether it carries data there, which secrets it reads, and whether it only reads.

Best effort: a shell is a programming language, and this reads the common forms (pipelines, ``&&``, newlines,
redirections, here-documents, ``sh -c``, ``$(...)``, ``<(...)``, ``sudo``/``env`` prefixes, variables the command
assigns itself). What it cannot read counts as not read-only, never as harmless, and as sending data when a
network tool or address is in it. Only the standard library and ``mcp_inspect`` are imported, so the hook
starts fast.
"""
from __future__ import annotations

from .heredocs import _prepare
from .lexical import (
    _MAX_CARRIED,
    _MAX_CARRIED_TOTAL,
    _MAX_COMMAND,
    _MAX_EXPANSION,
    _MAX_OPERATORS,
    _MAX_PARTS,
    _READ_ONLY,
    SECRET,
    Command,
    host,
    is_loopback,
)
from .network import network_values
from .reading import _read, parse
from .windows import _MAX_SCANNED, _MAX_WINDOWS, _WINDOW, _plain

__all__ = [
    "Command",
    "SECRET",
    "host",
    "is_loopback",
    "network_values",
    "parse",
    "_MAX_CARRIED",
    "_MAX_CARRIED_TOTAL",
    "_MAX_COMMAND",
    "_MAX_EXPANSION",
    "_MAX_OPERATORS",
    "_MAX_PARTS",
    "_MAX_SCANNED",
    "_MAX_WINDOWS",
    "_READ_ONLY",
    "_WINDOW",
    "_plain",
    "_prepare",
    "_read",
]
