"""Deterministic checks on untrusted MCP text: tool descriptions and tool outputs.

Descriptions and outputs come from upstream servers and are never trusted. These
rules only produce evidence (rule names); the proxy decides what to do with it.
"""
from __future__ import annotations

from .describe import (
    RULE_MEANINGS,
    _values_text,
    explain_rules,
    scan_description,
    scan_output,
    scan_output_collapsed,
    scan_server,
    schema_text,
    self_disclosure_fields,
)
from .normalize import _normalize, argument_surface, leaf_text, normalized_intent, readable, tool_text
from .rules import _DESCRIPTION_RULES, _OUTPUT_RULES, _PLACEHOLDER_PATH, _PLACEHOLDER_QUERY, _SENSITIVE
from .values import (
    _BRACKETED,
    _DEFANG_HINT,
    _DOT_BEFORE_TLD,
    _TLD,
    _VALUE_PATTERNS,
    _defang,
    _parse,
    _replace_between_blanks,
    authority_values,
    distinctive_values,
    host_suffixes,
    on_tainted_hosts,
    rank_tools,
    sourced_from,
    traced_urls,
)

__all__ = [
    "RULE_MEANINGS",
    "argument_surface",
    "authority_values",
    "distinctive_values",
    "explain_rules",
    "host_suffixes",
    "leaf_text",
    "normalized_intent",
    "on_tainted_hosts",
    "rank_tools",
    "readable",
    "scan_description",
    "scan_output",
    "scan_output_collapsed",
    "scan_server",
    "schema_text",
    "self_disclosure_fields",
    "sourced_from",
    "tool_text",
    "traced_urls",
    "_BRACKETED",
    "_DEFANG_HINT",
    "_DESCRIPTION_RULES",
    "_DOT_BEFORE_TLD",
    "_OUTPUT_RULES",
    "_PLACEHOLDER_PATH",
    "_PLACEHOLDER_QUERY",
    "_SENSITIVE",
    "_TLD",
    "_VALUE_PATTERNS",
    "_defang",
    "_normalize",
    "_parse",
    "_replace_between_blanks",
    "_values_text",
]
