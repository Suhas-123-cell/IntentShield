"""Hosts and mailboxes named in a description or a call, in a canonical form, and the text a tool's schema exposes."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote, urlsplit

from intentshield.mcp_inspect import host_suffixes, leaf_text, readable

from .schema import _TOKEN_KEYWORDS, MAX_PATTERN

_SPLIT_WORDS = re.compile(r"([a-z])([A-Z])")
_NAME_SEPARATORS = re.compile(r"[_\-./#$:~%+]+")


def _exposed_text(schema: Any) -> tuple[str, list[str]]:
    """Free text the schema keywords ``tool_text`` and ``schema_text`` skip can still carry to the
    agent (``pattern``, ``format``, ``$ref``, required names, regex and definition names): joined
    for the description rules, plus ``oversized_schema_pattern`` when a pattern is too long to be a
    pattern."""
    parts: list[str] = []
    flags: list[str] = []

    def words(value: str) -> str:
        return _NAME_SEPARATORS.sub(" ", _SPLIT_WORDS.sub(r"\1 \2", value))

    def visit(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                visit(item)
            return
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str):
                parts.append(value)
                if len(value) > MAX_PATTERN and "oversized_schema_pattern" not in flags:
                    flags.append("oversized_schema_pattern")
            elif key in {"format", "$schema", "$id", *_TOKEN_KEYWORDS} and isinstance(value, str):
                parts.append(words(value))
            elif key == "required" and isinstance(value, list):
                parts.extend(words(str(item)) for item in value)
            elif key in {"dependentRequired", "dependencies"} and isinstance(value, dict):
                for name, needed in value.items():
                    parts.append(words(str(name)))
                    parts.extend(words(str(item)) for item in (needed if isinstance(needed, list) else ()))
                    visit(needed)
            elif key in {"patternProperties", "$defs", "definitions", "dependentSchemas"} and isinstance(value, dict):
                parts.extend(words(str(name)) for name in value)
                visit(list(value.values()))
            elif key == "properties" and isinstance(value, dict):
                visit(list(value.values()))
            elif isinstance(value, (dict, list)) and key not in {"const", "enum", "examples", "default"}:
                visit(value)

    visit(schema)
    return "\n".join(part for part in parts if part), flags


# The scheme and the local part are bounded (RFC 5321 allows 64 characters of local part): unbounded,
# every start inside a long run of word characters rescans the run, so a hostile result with one
# injection marker and 200 KB of "a" would hang the inspection that flagged it.
_URL_TEXT = re.compile(r"[a-z][a-z0-9+.-]{0,31}://[^\s\"'<>\\^`{|}]+", re.I)
_MAILBOX = re.compile(r"([\w.%+-]{1,64})@((?:[\w-]+\.)+[^\W\d_]{2,24})(?![\w-])")
_BARE_HOST = re.compile(r"(?<![\w@./:\\-])((?:[\w-]+\.)+[^\W\d_]{2,24})(?![\w-])")
_AT = re.compile(r"\s*[\[(]\s*at\s*[\])]\s*", re.I)
_DOT = re.compile(r"\s*[\[(]\s*dot\s*[\])]\s*", re.I)
# Every whitespace run is read as one space before the two above: their leading whitespace restarts from each
# character of a long run (200,000 spaces took 212 s, in an argument the agent chooses), and nothing else here
# tells a run of whitespace from a single space.
_SPACES = re.compile(r"\s+")
# Not hosts: file names that end like a domain, and the mail providers every user has.
_FILE_SUFFIXES = frozenset("txt md py js ts json yaml yml csv pdf png jpg jpeg gif html htm css log xml sh rb go rs "
                           "java docx xlsx pptx zip tar gz toml ini cfg conf env sql db lock".split())
_PUBLIC_MAIL = frozenset({"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
                          "icloud.com", "me.com", "proton.me", "protonmail.com", "aol.com"})


def _canonical_host(raw: str) -> str:
    host = unquote(raw).strip().strip(".").lower()
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _network_values(value: Any) -> tuple[set[str], set[str]]:
    """Host names and mailboxes (``local@domain``, +tag dropped) in a value or text, canonicalised:
    the comparison the exact-string taint set cannot make (a bare host, another path or sub-address
    on a tainted host, a case or IDNA spelling of it)."""
    text = _DOT.sub(".", _AT.sub("@", _SPACES.sub(" ", readable(leaf_text(value)))))
    hosts: set[str] = set()
    boxes: set[str] = set()
    for match in _URL_TEXT.finditer(text):
        try:
            host = urlsplit(match.group()).hostname
        except ValueError:
            continue
        if host:
            hosts.add(_canonical_host(host))
    for local, domain in _MAILBOX.findall(text):
        domain = _canonical_host(domain)
        boxes.add(f"{local.split('+', 1)[0].lower()}@{domain}")
        hosts.add(domain)
    hosts.update(_canonical_host(m) for m in _BARE_HOST.findall(text)
                 if m.rsplit(".", 1)[1].lower() not in _FILE_SUFFIXES)
    return hosts - _PUBLIC_MAIL, boxes


def _host_overlap(hosts: set[str], known: set[str]) -> bool:
    """Whether a host is one of ``known`` or a subdomain of one."""
    for host in hosts:
        if any(suffix in known for suffix in host_suffixes(host)):
            return True
    return False
