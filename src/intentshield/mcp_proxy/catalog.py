"""The catalog: the upstream servers' tools, the registry of those the agent may call, and what the model is shown of each."""
from __future__ import annotations

import asyncio
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import BaseModel

from intentshield.mcp_inspect import (
    distinctive_values,
    scan_description,
    scan_server,
    schema_text,
    self_disclosure_fields,
    tool_text,
)
from intentshield.mcp_upstream import MCPCallResult, MCPTool
from intentshield.models import ReasonCode
from intentshield.tools import MCPArguments, ToolSpec, stable_hash

from .errors import MCPRemoteToolError
from .hosts import _exposed_text
from .log import logger
from .schema import (
    _NESTED_FIELDS,
    MAX_SCHEMA_DEPTH,
    _bounded_errors,
    _BoundedValidator,
    _public_schema,
    _SchemaValidator,
    _too_deep,
    _too_deep_field,
    _withheld_schema,
    _without_patterns,
)
from .state import _State


def _fingerprint(tool: MCPTool) -> str:
    fields = {"title", "description", "input_schema", "output_schema", "annotations"}
    # A field too deep to hash stays out of the fingerprint: the tool is left out and blocked anyway.
    return stable_hash(tool.model_dump(
        mode="json", include={name for name in fields if not _too_deep(getattr(tool, name))}))


_SAFE_TOOL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class _Catalog(_State):
    """Listing the upstream tools and building the registry the agent sees."""

    async def _list_all_tools(self) -> list[MCPTool]:
        """Every upstream's tools. An upstream that cannot list its tools (an error, a catalog over its limits, a
        reply the SDK cannot parse) is left out with a warning and its name in ``_failed_upstreams``: one server
        must not take down every other server behind the same proxy. When none can, the first error is raised."""
        # Each listing gets the upstream's operation timeout, not its 300 s read timeout: the SDK drops a reply it
        # cannot parse (a schema nested past its limit) and the listing then waits the read timeout out.
        results = await asyncio.gather(
            *(asyncio.wait_for(upstream.list_tools(), getattr(getattr(upstream, "config", None), "timeout_seconds", None))
              for upstream in self.upstreams.values()), return_exceptions=True
        )
        pages: list[list[MCPTool]] = []
        self._failed_upstreams = {}
        for server_id, result in zip(self.upstreams, results):
            if not isinstance(result, Exception):
                if isinstance(result, BaseException):  # a cancellation is not an upstream's failure
                    raise result
                pages.append(result)
                continue
            logger.warning("Upstream MCP server %r left out: it could not list its tools (%s: %s)",
                           server_id, type(result).__name__, str(result)[:200])
            self._failed_upstreams[server_id] = f"{type(result).__name__}: {str(result)[:200]}"
        if not pages and results:
            raise next(result for result in results if isinstance(result, Exception))
        tools = [tool for page in pages for tool in page]
        if len(tools) > self.config.max_total_tools:
            raise ValueError("Combined MCP catalog exceeds max_total_tools")
        total_schema_bytes = sum(
            len(json.dumps(tool.input_schema, separators=(",", ":")).encode())
            for tool in tools if _too_deep_field(tool) is None
        )
        if total_schema_bytes > self.config.max_total_schema_bytes:
            raise ValueError("Combined MCP catalog exceeds max_total_schema_bytes")
        return tools

    def _catalog_names(self) -> set[str]:
        """Tool names the other proxies on this machine wrote to ``tool_catalog_dir``: with one proxy
        per wrapped server, a description naming another server's tool is still shadowing."""
        if not self.config.tool_catalog_dir:
            return set()
        own = "-".join(sorted(u.server_id for u in self.config.upstream_configs))
        names: set[str] = set()
        for path in Path(self.config.tool_catalog_dir).expanduser().glob("*.json"):
            if path.stem == own:
                continue
            try:
                names |= {str(t["name"]).rpartition("__")[2] for t in json.loads(path.read_text())}
            except (OSError, ValueError, TypeError, KeyError):
                continue
        return names

    def _build_registry(self, tools: list[MCPTool]) -> dict[str, ToolSpec]:
        registry: dict[str, ToolSpec] = {}
        self._quarantined, self._description_values, self._redacted, self._left_out = {}, {}, {}, {}
        self._unjudged, self._unjudged_text = [], {}
        tools = self._without_deep(tools)
        pending: dict[str, str] = {}  # descriptions the rules, memory and detectors passed: the judge reads them
        self._quarantine_split(tools)
        names_by_server: dict[str, set[str]] = {}
        for tool in tools:
            names_by_server.setdefault(tool.server_id, set()).add(tool.name)
        catalog_names = self._catalog_names()  # one directory scan, not one per tool
        for tool in tools:
            self._read_tool(tool, names_by_server, catalog_names, pending)
        self._judge_descriptions(pending)
        self._say_hidden()
        counts = Counter(tool.qualified_name for tool in tools)
        for tool in tools:
            spec = self._serve(tool, counts)
            if spec is None:
                continue
            qualified = tool.qualified_name
            registry[qualified] = spec
            if self.config.is_allowed(qualified) and not spec.grounding_terms:
                raise ValueError(
                    f"Allowed MCP tool requires grounding_terms_by_tool: {qualified}"
                )
        return registry

    def _without_deep(self, tools: list[MCPTool]) -> list[MCPTool]:
        """The tools, less those whose schema nests too deep to read: they are left out, with the reason kept."""
        # Before anything reads a schema: every reader of one recurses.
        for tool in tools:
            if deep := _too_deep_field(tool):
                what = _NESTED_FIELDS[deep]
                logger.warning("Upstream MCP tool %r left out: %s nested over %d levels",
                               tool.qualified_name, what, MAX_SCHEMA_DEPTH)
                self._left_out[tool.qualified_name] = f"{what} nested over {MAX_SCHEMA_DEPTH} levels"
        return [tool for tool in tools if tool.qualified_name not in self._left_out]

    def _quarantine_split(self, tools: list[MCPTool]) -> None:
        """An instruction split across one server's tools quarantines all of them."""
        for server_id in dict.fromkeys(tool.server_id for tool in tools):
            own = [tool for tool in tools if tool.server_id == server_id]
            split = scan_server(tool_text(t.description, t.input_schema, t.title) for t in own)
            if split and self.config.quarantine_poisoned_tools:
                self._quarantined.update({tool.qualified_name: list(split) for tool in own})

    def _read_tool(self, tool: MCPTool, names_by_server: dict[str, set[str]], catalog_names: set[str],
                   pending: dict[str, str]) -> None:
        """Reads one tool's description and schema text for poisoning, and keeps what the agent may be shown of its schema."""
        qualified = tool.qualified_name
        # Untrusted text: scanned for poisoning; a reference to another
        # server's tool name is shadowing.
        text = tool_text(tool.description, tool.input_schema, tool.title)
        if extra := schema_text(tool.input_schema):
            text = f"{text}\n{extra}"
        # Keywords those two skip still reach the agent in the schema (pattern, format, $ref, required
        # names, regex and definition names): scanned as well, and a pattern too long to be one is poison.
        exposed, schema_flags = _exposed_text(tool.input_schema)
        if exposed:
            text = f"{text}\n{exposed}"
        if schema_flags and self.config.quarantine_poisoned_tools:
            self._quarantined[qualified] = [*self._quarantined.get(qualified, []), *schema_flags]
        own_names = names_by_server[tool.server_id]
        foreign = set().union(*(names for sid, names in names_by_server.items() if sid != tool.server_id),
                              catalog_names)
        findings = scan_description(text, foreign - own_names)
        if qualified in self.config.trusted_tools:  # the operator vouches for a description that names a secret file
            findings = [rule for rule in findings if rule != "sensitive_target"]
        if findings and self.config.quarantine_poisoned_tools:
            self._quarantined[qualified] = [*self._quarantined.get(qualified, []), *findings]
        if any(rule != "sensitive_target" for rule in findings):
            # One listing is one "run": several poisoned tools must not count as many. A description that only names a
            # secret file is a weak signal (a tool may say it reads the .env): it hides the tool but is not learned
            # as an attack by its server.
            self._recall.record_attack(text, findings, source=tool.server_id, run_key=f"catalog:{tool.server_id}")
        if not findings and qualified not in self._quarantined:
            if self._recall.check_text(text, target="description"):
                self._suspect_tools[qualified] = ReasonCode.REVIEW_KNOWN_THREAT
            elif self._semantic_flag(text, "description"):
                self._suspect_tools[qualified] = ReasonCode.REVIEW_CLASSIFIER_FLAGGED
            elif self._judge:
                pending[qualified] = text
        self._description_values[qualified] = distinctive_values(text)
        hidden = self_disclosure_fields(tool.input_schema)
        if hidden:
            self._redacted[qualified] = hidden
        visible = tool.input_schema if not hidden else {
            **tool.input_schema,
            "properties": {k: v for k, v in tool.input_schema["properties"].items() if k not in hidden},
            **({"required": [k for k in tool.input_schema["required"] if k not in hidden]}
               if isinstance(tool.input_schema.get("required"), list) else {}),
        }
        self._visible_schemas[qualified] = visible

    def _say_hidden(self) -> None:
        """The client just sees fewer tools: say why, once per tool."""
        for qualified, matched in self._quarantined.items():
            if (qualified, tuple(matched)) not in self._said_hidden:
                self._said_hidden.add((qualified, tuple(matched)))
                logger.warning("IntentShield hid the tool %r: its description matched %s. Run `intentshield scan` on the server "
                               "to see why.", qualified, ", ".join(dict.fromkeys(matched)))

    def _serve(self, tool: MCPTool, counts: Counter[str]) -> ToolSpec | None:
        """The registry entry for ``tool``, or None when the proxy cannot serve it safely."""
        qualified = tool.qualified_name
        visible = self._visible_schemas[qualified]
        # A tool the proxy cannot serve safely is left out, not the whole connect: one server must not be
        # able to take down every other server behind the same proxy. Both copies of a duplicate go.
        problem = "an invalid name" if not _SAFE_TOOL_NAME.fullmatch(tool.name) \
            else "a duplicate name" if counts[qualified] > 1 else None
        if problem is None:
            try:
                Draft202012Validator.check_schema(tool.input_schema)
            except SchemaError as exc:
                problem = f"an invalid input schema ({str(exc.message)[:120]})"
        if problem:
            logger.warning("Upstream MCP tool %r left out: %s", qualified, problem)
            self._left_out[qualified] = problem
            return None
        validator = _BoundedValidator(_without_patterns(tool.input_schema))

        def validate(arguments: dict[str, Any], *, current: _SchemaValidator = validator) -> None:
            errors = sorted(_bounded_errors(current, arguments), key=lambda item: list(item.path))
            if errors:
                path = ".".join(str(part) for part in errors[0].path) or "arguments"
                raise ValueError(f"{path}: {errors[0].message}")

        def execute(parsed: BaseModel, *, current: MCPTool = tool) -> dict[str, Any]:
            if self._loop is None:
                raise RuntimeError("MCP proxy is not connected")
            upstream = self.upstreams[current.server_id]
            timeout = upstream.config.read_timeout_seconds
            future = asyncio.run_coroutine_threadsafe(
                asyncio.wait_for(upstream.call_tool(current.name, parsed.model_dump(mode="json")), timeout),
                self._loop,
            )
            try:
                # ``wait_for`` cancels the upstream call on the loop; the grace period only covers
                # the hop back to this thread, so a hung tool never leaves a task behind.
                result: MCPCallResult = future.result(timeout=timeout + 5)
            except TimeoutError:
                future.cancel()
                raise
            if result.is_error:  # inspected like an output by ``_inspect_error``, which the service calls
                raise MCPRemoteToolError(result.error.message if result.error else "Upstream MCP tool failed",
                                         upstream=True)
            return {"trust": "UNTRUSTED_MCP_OUTPUT", "upstream": self._bounded(result)}

        return ToolSpec(
            name=qualified,
            description=(
                f"Quarantined MCP tool {qualified}; upstream description matched poisoning rules."
                if qualified in self._quarantined
                else tool.description
                if self.config.expose_upstream_descriptions and tool.description
                and qualified not in self._suspect_tools and qualified not in self._unjudged
                else f"Guarded MCP tool {qualified}; upstream description withheld as untrusted."
            ),
            args_model=MCPArguments,
            mutation=not self.config.is_read_only(qualified),
            destination_field=self.config.destination_fields.get(qualified),
            executor=execute,
            schema_override=tool.input_schema,
            public_schema_override=_withheld_schema(visible, flagged=qualified in self._suspect_tools)
            if qualified in self._suspect_tools or qualified in self._unjudged else _public_schema(visible),
            argument_validator=validate,
            upstream_id=tool.server_id,
            upstream_tool_name=tool.name,
            resource_field=self.config.resource_fields.get(qualified),
            allowed_resources_override=self.config.allowed_resources_by_tool.get(qualified),
            allowed_destinations_override=self.config.allowed_destinations_by_tool.get(qualified),
            grounding_terms=tuple(sorted(self.config.grounding_terms_by_tool.get(qualified, ()))),
        )

    async def tool_catalog(self, *, refresh: bool = True) -> list[dict[str, Any]]:
        if refresh:
            await self._refresh_catalog()
        catalog = self._service().tool_catalog()
        for item in catalog:
            item["available"] = not (
                item["name"] in self._drifted_tools or item["name"] in self._quarantined
            )
            item["schema_drift"] = item["name"] in self._drifted_tools
            item["quarantined"] = item["name"] in self._quarantined
            if item["quarantined"]:  # the schema is where the poison was found: it goes no further
                item["schema"] = {"type": "object"}
            elif item["name"] in self._suspect_tools or item["name"] in self._unjudged:  # as its description is
                item["schema"] = _withheld_schema(self._visible_schemas[item["name"]],
                                                  flagged=item["name"] in self._suspect_tools)
            item["poisoning_findings"] = self._quarantined.get(item["name"], [])
            item["redacted_fields"] = sorted(self._redacted.get(item["name"], ()))
            item["classifier_flagged"] = self._suspect_tools.get(item["name"]) == ReasonCode.REVIEW_CLASSIFIER_FLAGGED
            item["judge_flagged"] = self._suspect_tools.get(item["name"]) == ReasonCode.REVIEW_JUDGE_FLAGGED
            item["judge_status"] = "unreviewed" if item["name"] in self._unjudged else \
                "off" if self._judge is None else "reviewed"
            if item["name"] in self._unjudged:  # not read by the judge yet: no free text until it is
                item["description"] = f"Guarded MCP tool {item['name']}; upstream description not yet reviewed."
            elif item["name"] in self._suspect_tools:  # flagged after the spec was built
                item["description"] = f"Guarded MCP tool {item['name']}; upstream description withheld as untrusted."
        return catalog

    async def _refresh_catalog(self) -> None:
        discovered = await self._list_all_tools()
        # Rug pull: any change to schema, description, title or annotations
        # after connect fails closed, not only schema changes.
        current = {tool.qualified_name: _fingerprint(tool) for tool in discovered}
        # An upstream that could not list this time says nothing about its tools: they are neither drifted nor
        # cleared (a blip must not retire them for the session; the next listing that works is compared).
        silent = {tool.qualified_name for tool in self._tools if tool.server_id in self._failed_upstreams}
        changed = {
            name for name in set(current) | set(self._bound_fingerprints)
            if name not in silent and current.get(name) != self._bound_fingerprints.get(name)
        }
        with self._lock:
            newly_drifted = changed - self._drifted_tools
            self._drifted_tools.update(changed)
        if newly_drifted:
            self._service().storage.add_event(
                self._ensure_system_run(),
                "MCP_CATALOG_DRIFT",
                {"tools": sorted(newly_drifted)},
            )
        if self._judge_retry_due():
            await asyncio.to_thread(self._judge_pending)

    async def transparent_tools(self) -> list[tuple[MCPTool, dict[str, Any]]]:
        """Upstream tools an MCP client may see directly: not quarantined, not drifted, with
        self-disclosure parameters removed from the schema."""
        await self._refresh_catalog()
        withheld = "Description withheld by IntentShield: it may try to instruct the agent."
        shown = []
        for tool in self._tools:
            name = tool.qualified_name
            if self._blocked_reason(name):
                continue
            visible = self._visible_schemas[name]
            if name in self._suspect_tools or name in self._unjudged:  # a flagged or unread tool keeps no free text
                shown.append((tool.model_copy(update={"description": withheld, "title": None}),
                              _withheld_schema(visible, flagged=name in self._suspect_tools)))
            else:
                shown.append((tool, _public_schema(visible, annotations=True)))
        return shown

    def _blocked_reason(self, name: str) -> str | None:
        # Transparent mode runs no call policy, but the operator's tool lists still bind it. Without an
        # allow-list every tool of a wrapped server stays callable, as it always has.
        if self.config.is_prohibited(name):
            return f"{name} is prohibited by the operator's policy"
        if self.config.allowed_tools and not self.config.is_allowed(name):
            return f"{name} is not on the operator's allowed_tools list"
        if name in self._left_out:
            return f"{name} was left out: the upstream gave it {self._left_out[name]}"
        if name in self._quarantined:
            return f"{name} is quarantined: its description matched poisoning rules"
        if name in self._drifted_tools:
            return f"{name} changed after connect (possible rug pull) and is blocked"
        return None

    async def hidden_tools(self, *, refresh: bool = True) -> list[tuple[MCPTool, str]]:
        """Tools ``transparent_tools`` leaves out, with the reason a call to one is refused.
        A drifted tool stays blocked for the rest of the session, even if the upstream
        later restores it: the fingerprint is bound once at connect and never re-bound.
        ``refresh=False`` for a caller that listed an instant ago, in the same call."""
        if refresh:
            await self._refresh_catalog()
        return [(tool, reason) for tool in self._tools if (reason := self._blocked_reason(tool.qualified_name))]
