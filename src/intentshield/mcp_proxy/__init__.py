"""Policy-bound bridge from IntentShield to a real upstream MCP server.

Where things are in this package:

* ``config``: ``MCPProxyConfig``, the proxy's settings (upstreams, allow, prohibit, pin and read-only lists, limits), read from a
  JSON file.
* ``schema``: how a tool's input schema is measured, trimmed to its skeleton for the agent, stripped of patterns, and checked
  with a bounded validator, so a hostile schema cannot cost unbounded time or memory.
* ``hosts``: hosts named in a description, compared with those in a call.
* ``taint`` and ``errors``: the bounded sets of values a session holds as tainted, and the errors the proxy raises.
* ``runtime``: ``MCPProxyRuntime``, the one class that does the work. Its methods are spread over these modules, in groups:

  - ``runtime``: the connection (``connect``, ``close``), runs, and the path of a call (``evaluate_and_execute``, ``forward``,
    ``evaluate_only``);
  - ``catalog``: the catalog (``_list_all_tools``, ``_build_registry``: poisoning rules, schema quarantine, name clashes, pins
    against a changed tool) and ``tool_catalog``, ``transparent_tools``, ``hidden_tools``;
  - ``checks``: before a call ``_pre_policy_check`` and ``_rule_check`` (the policy, taint, threat memory) and ``_redact`` (the
    arguments that ask for the agent's own data); after a call ``_inspect_result`` and ``_inspect_error`` (injection rules, the
    classifier, learned rules);
  - ``judging``: the judge's reading of descriptions and outputs;
  - ``approvals``: ``decide_approval``, ``decide_and_learn``, ``learn_example``, ``propose_rules``, ``decide_rule``;
  - ``state``: the attributes all of them share, declared once.

The methods of ``MCPProxyRuntime`` share the registry, the taint of each run and the databases.
"""
from __future__ import annotations

from .config import MCPProxyConfig
from .errors import MCPRemoteToolError, RunLimitError
from .hosts import _network_values
from .judging import _JUDGE_WORKERS
from .log import logger
from .runtime import MCPProxyRuntime
from .schema import (
    _MAX_NAME_SEPARATORS,
    MAX_PATTERN,
    MAX_SCHEMA_DEPTH,
    REF_BASE_ALLOWANCE,
    REF_PER_NODE,
    SchemaTooCostly,
    _public_schema,
    _without_patterns,
    schema_errors,
)
from .taint import MAX_OUTPUT_TAINT, MAX_TAINTED, _newest, _RecentSet

__all__ = [
    "MAX_OUTPUT_TAINT",
    "MAX_PATTERN",
    "MAX_SCHEMA_DEPTH",
    "MAX_TAINTED",
    "MCPProxyConfig",
    "MCPProxyRuntime",
    "MCPRemoteToolError",
    "REF_BASE_ALLOWANCE",
    "REF_PER_NODE",
    "RunLimitError",
    "SchemaTooCostly",
    "logger",
    "schema_errors",
    "_JUDGE_WORKERS",
    "_MAX_NAME_SEPARATORS",
    "_RecentSet",
    "_network_values",
    "_newest",
    "_public_schema",
    "_without_patterns",
]
