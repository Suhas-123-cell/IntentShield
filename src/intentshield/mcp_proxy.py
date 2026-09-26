"""Policy-bound bridge from IntentShield to a real upstream MCP server."""

from __future__ import annotations

import asyncio
import fnmatch
import json
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .mcp_upstream import MCPCallResult, MCPTool, MCPUpstream, MCPUpstreamConfig
from .models import GatewayResult, ToolCall
from .policy import PolicyConfig
from .service import IntentShieldService
from .storage import Storage
from .tools import MCPArguments, ToolSpec


class MCPProxyConfig(BaseModel):
    """Local trust policy plus connection details for one upstream server."""

    model_config = ConfigDict(extra="forbid")

    # ``upstream`` remains accepted for existing single-server configs.
    upstream: MCPUpstreamConfig | None = None
    upstreams: list[MCPUpstreamConfig] = Field(default_factory=list)
    database_path: str = "intentshield-mcp.db"
    allowed_tools: list[str] = Field(default_factory=list)
    prohibited_tools: list[str] = Field(default_factory=list)
    read_only_tools: list[str] = Field(default_factory=list)
    resource_fields: dict[str, str] = Field(default_factory=dict)
    destination_fields: dict[str, str] = Field(default_factory=dict)
    allowed_resources_by_tool: dict[str, set[str]] = Field(default_factory=dict)
    allowed_destinations_by_tool: dict[str, list[str]] = Field(default_factory=dict)
    expose_upstream_descriptions: bool = False
    allowed_resources: set[str] = Field(default_factory=set)
    allowed_destinations: list[str] = Field(default_factory=list)
    call_budget: int = Field(default=8, ge=1)
    injection_block_threshold: float = Field(default=0.75, ge=0, le=1)
    minimum_intent_alignment: float = Field(default=0.60, ge=0, le=1)
    approval_ttl_seconds: int = Field(default=600, ge=1)
    max_upstreams: int = Field(default=8, ge=1, le=64)
    max_total_tools: int = Field(default=2_000, ge=1, le=100_000)
    max_total_schema_bytes: int = Field(default=16_000_000, ge=1, le=128_000_000)
    max_result_bytes: int = Field(default=4_000_000, ge=1, le=64_000_000)
    max_result_content_blocks: int = Field(default=1_000, ge=1, le=100_000)

    @model_validator(mode="after")
    def validate_upstreams(self) -> "MCPProxyConfig":
        if self.upstream is not None and self.upstreams:
            raise ValueError("Configure either upstream or upstreams, not both")
        configured = self.upstream_configs
        if not configured:
            raise ValueError("At least one upstream MCP server is required")
        if len(configured) > self.max_upstreams:
            raise ValueError("Configured upstream count exceeds max_upstreams")
        server_ids = [item.server_id for item in configured]
        if len(server_ids) != len(set(server_ids)):
            raise ValueError("Every upstream MCP server_id must be unique")
        scoped_keys = (
            set(self.resource_fields)
            | set(self.destination_fields)
            | set(self.allowed_resources_by_tool)
            | set(self.allowed_destinations_by_tool)
        )
        if any(":" not in key for key in scoped_keys):
            raise ValueError("Resource and destination policies require qualified server:tool keys")
        if self.allowed_resources or self.allowed_destinations:
            raise ValueError(
                "MCP scope policy must use allowed_resources_by_tool and "
                "allowed_destinations_by_tool, not global allowlists"
            )
        if set(self.resource_fields) != set(self.allowed_resources_by_tool):
            raise ValueError(
                "Every resource_fields entry needs one allowed_resources_by_tool entry"
            )
        if set(self.destination_fields) != set(self.allowed_destinations_by_tool):
            raise ValueError(
                "Every destination_fields entry needs one allowed_destinations_by_tool entry"
            )
        if any(not values for values in self.allowed_resources_by_tool.values()):
            raise ValueError("Per-tool allowed resource sets cannot be empty")
        if any(not values for values in self.allowed_destinations_by_tool.values()):
            raise ValueError("Per-tool allowed destination lists cannot be empty")
        return self

    @property
    def upstream_configs(self) -> list[MCPUpstreamConfig]:
        return self.upstreams or ([self.upstream] if self.upstream is not None else [])

    @classmethod
    def from_file(cls, path: str | Path) -> "MCPProxyConfig":
        return cls.model_validate(json.loads(Path(path).read_text()))

    @staticmethod
    def _matches(name: str, patterns: list[str]) -> bool:
        # Patterns are intentionally matched against qualified names only.
        # An unqualified ``read`` rule must not accidentally authorize the same
        # raw tool name on every connected server.
        return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)

    def is_allowed(self, name: str) -> bool:
        return self._matches(name, self.allowed_tools)

    def is_prohibited(self, name: str) -> bool:
        return self._matches(name, self.prohibited_tools)

    def is_read_only(self, name: str) -> bool:
        # MCP annotations are untrusted hints. Read-only status must come from
        # this operator-owned configuration.
        return self._matches(name, self.read_only_tools)


class MCPRemoteToolError(RuntimeError):
    """An upstream tool returned an MCP-level error result."""


_SCHEMA_ANNOTATIONS = {
    "title", "description", "$comment", "examples", "default",
    "deprecated", "readOnly", "writeOnly",
}
_SAFE_TOOL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _public_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Remove untrusted annotation text while preserving validation structure."""
    result: dict[str, Any] = {}
    schema_maps = {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}
    schema_values = {
        "items", "additionalProperties", "contains", "not", "if", "then", "else",
        "propertyNames", "unevaluatedItems", "unevaluatedProperties",
    }
    schema_lists = {"allOf", "anyOf", "oneOf", "prefixItems"}
    for key, value in schema.items():
        if key in _SCHEMA_ANNOTATIONS or key.startswith("x-"):
            continue
        if key in schema_maps and isinstance(value, dict):
            result[key] = {
                name: _public_schema(child) if isinstance(child, dict) else child
                for name, child in value.items()
            }
        elif key in schema_values and isinstance(value, dict):
            result[key] = _public_schema(value)
        elif key in schema_lists and isinstance(value, list):
            result[key] = [
                _public_schema(child) if isinstance(child, dict) else child for child in value
            ]
        else:
            result[key] = value
    return result


class MCPProxyRuntime:
    """Own an upstream connection and a policy service bound to its schemas."""

    def __init__(
        self,
        config: MCPProxyConfig,
        upstream: MCPUpstream | None = None,
        upstreams: dict[str, MCPUpstream] | None = None,
    ) -> None:
        self.config = config
        if upstream is not None and upstreams is not None:
            raise ValueError("Pass upstream or upstreams, not both")
        if upstream is not None:
            server_id = config.upstream_configs[0].server_id
            self.upstreams = {server_id: upstream}
        elif upstreams is not None:
            expected = {item.server_id for item in config.upstream_configs}
            if set(upstreams) != expected:
                raise ValueError("Injected upstreams must exactly match configured server_ids")
            self.upstreams = dict(upstreams)
        else:
            self.upstreams = {
                item.server_id: MCPUpstream(item) for item in config.upstream_configs
            }
        self.service: IntentShieldService | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._tools: list[MCPTool] = []
        self._bound_schemas: dict[str, dict[str, Any]] = {}
        self._drifted_tools: set[str] = set()

    async def __aenter__(self) -> "MCPProxyRuntime":
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        await self.close()

    async def connect(self) -> None:
        if self.service is not None:
            return
        self._loop = asyncio.get_running_loop()
        try:
            for upstream in self.upstreams.values():
                await upstream.connect()
            tools = await self._list_all_tools()
            registry = self._build_registry(tools)
        except Exception:
            self._loop = None
            await self._close_upstreams()
            raise
        policy = PolicyConfig(
            allowed_tools={name for name in registry if self.config.is_allowed(name)},
            prohibited_tools={name for name in registry if self.config.is_prohibited(name)},
            allowed_resources=set(),
            allowed_destinations=[],
            call_budget=self.config.call_budget,
            injection_block_threshold=self.config.injection_block_threshold,
            minimum_intent_alignment=self.config.minimum_intent_alignment,
            approval_ttl_seconds=self.config.approval_ttl_seconds,
        )
        self._tools = tools
        self._bound_schemas = {tool.qualified_name: tool.input_schema for tool in tools}
        self.service = IntentShieldService(
            Storage(self.config.database_path), policy, registry=registry
        )

    async def close(self) -> None:
        self.service = None
        self._loop = None
        await self._close_upstreams()

    async def _close_upstreams(self) -> None:
        # MCP transport context managers are task-affine. Close them in the
        # same lifespan task that opened them rather than child gather tasks.
        errors: list[BaseException] = []
        for upstream in reversed(tuple(self.upstreams.values())):
            try:
                await upstream.close()
            except BaseException as exc:
                errors.append(exc)
        if errors:
            raise RuntimeError(f"Failed to close {len(errors)} upstream MCP connection(s)") from errors[0]

    async def _list_all_tools(self) -> list[MCPTool]:
        pages = await asyncio.gather(
            *(upstream.list_tools() for upstream in self.upstreams.values())
        )
        tools = [tool for page in pages for tool in page]
        if len(tools) > self.config.max_total_tools:
            raise ValueError("Combined MCP catalog exceeds max_total_tools")
        total_schema_bytes = sum(
            len(json.dumps(tool.input_schema, separators=(",", ":")).encode())
            for tool in tools
        )
        if total_schema_bytes > self.config.max_total_schema_bytes:
            raise ValueError("Combined MCP catalog exceeds max_total_schema_bytes")
        return tools

    def _build_registry(self, tools: list[MCPTool]) -> dict[str, ToolSpec]:
        registry: dict[str, ToolSpec] = {}
        for tool in tools:
            qualified = tool.qualified_name
            if not _SAFE_TOOL_NAME.fullmatch(tool.name) or qualified in registry:
                raise ValueError(f"Invalid or duplicate upstream MCP tool: {qualified!r}")
            Draft202012Validator.check_schema(tool.input_schema)
            validator = Draft202012Validator(tool.input_schema)

            def validate(arguments: dict[str, Any], *, current=validator) -> None:
                errors = sorted(current.iter_errors(arguments), key=lambda item: list(item.path))
                if errors:
                    path = ".".join(str(part) for part in errors[0].path) or "arguments"
                    raise ValueError(f"{path}: {errors[0].message}")

            def execute(parsed: BaseModel, *, current=tool) -> dict[str, Any]:
                if self._loop is None:
                    raise RuntimeError("MCP proxy is not connected")
                upstream = self.upstreams[current.server_id]
                future = asyncio.run_coroutine_threadsafe(
                    upstream.call_tool(current.name, parsed.model_dump(mode="json")),
                    self._loop,
                )
                result: MCPCallResult = future.result(
                    timeout=upstream.config.read_timeout_seconds
                )
                if result.is_error:
                    message = result.error.message if result.error else "Upstream MCP tool failed"
                    raise MCPRemoteToolError(message)
                normalized_result = result.model_dump(mode="json")
                if len(result.content) > self.config.max_result_content_blocks:
                    raise MCPRemoteToolError("Upstream MCP result exceeded the content-block limit")
                if len(json.dumps(normalized_result, separators=(",", ":")).encode()) > self.config.max_result_bytes:
                    raise MCPRemoteToolError("Upstream MCP result exceeded the byte limit")
                return {
                    "trust": "UNTRUSTED_MCP_OUTPUT",
                    "upstream": normalized_result,
                }

            registry[qualified] = ToolSpec(
                name=qualified,
                description=(
                    tool.description
                    if self.config.expose_upstream_descriptions and tool.description
                    else f"Guarded MCP tool {qualified}; upstream description withheld as untrusted."
                ),
                args_model=MCPArguments,
                mutation=not self.config.is_read_only(qualified),
                destination_field=(
                    self.config.destination_fields.get(qualified)
                ),
                executor=execute,
                schema_override=tool.input_schema,
                public_schema_override=_public_schema(tool.input_schema),
                argument_validator=validate,
                upstream_id=tool.server_id,
                upstream_tool_name=tool.name,
                resource_field=self.config.resource_fields.get(qualified),
                allowed_resources_override=self.config.allowed_resources_by_tool.get(qualified),
                allowed_destinations_override=self.config.allowed_destinations_by_tool.get(qualified),
            )
        return registry

    def _service(self) -> IntentShieldService:
        if self.service is None:
            raise RuntimeError("MCP proxy is not connected")
        return self.service

    async def create_run(self, user_intent: str) -> str:
        return await asyncio.to_thread(self._service().create_run, user_intent)

    async def tool_catalog(self, *, refresh: bool = True) -> list[dict[str, Any]]:
        if refresh:
            await self._refresh_catalog()
        catalog = self._service().tool_catalog()
        for item in catalog:
            item["available"] = item["name"] not in self._drifted_tools
            item["schema_drift"] = item["name"] in self._drifted_tools
        return catalog

    async def _refresh_catalog(self) -> None:
        discovered = await self._list_all_tools()
        current = {tool.qualified_name: tool.input_schema for tool in discovered}
        changed = {
            name for name in set(current) | set(self._bound_schemas)
            if current.get(name) != self._bound_schemas.get(name)
        }
        newly_drifted = changed - self._drifted_tools
        self._drifted_tools.update(changed)
        if newly_drifted:
            self._service().storage.add_event(
                self._ensure_system_run(),
                "MCP_CATALOG_DRIFT",
                {"tools": sorted(newly_drifted)},
            )

    def _ensure_system_run(self) -> str:
        return self._service().create_run("Monitor upstream MCP tool catalog", "mcp-catalog")

    async def evaluate_and_execute(self, run_id: str, call: ToolCall) -> GatewayResult:
        service = self._service()
        await self._refresh_catalog()
        if call.tool_name in self._drifted_tools:
            # Force the existing pure policy engine down its schema-drift path.
            # The upstream executor remains unreachable.
            call = call.model_copy(update={"schema_hash": "mcp-catalog-drift"})
        # Execution must run off the event loop because the synchronous policy
        # engine may wait for an upstream coroutine scheduled onto this loop.
        return await asyncio.to_thread(service.evaluate_and_execute, run_id, "", call)

    async def evaluate_only(self, run_id: str, call: ToolCall) -> GatewayResult:
        """Evaluate a proposed call without execution or approval persistence."""
        await self._refresh_catalog()
        if call.tool_name in self._drifted_tools:
            call = call.model_copy(update={"schema_hash": "mcp-catalog-drift"})
        return await asyncio.to_thread(self._service().evaluate_only, run_id, call)

    async def decide_approval(self, approval_id: str, approve: bool) -> GatewayResult:
        service = self._service()
        approval = await asyncio.to_thread(service.storage.get_approval, approval_id)
        if not approval:
            raise KeyError(approval_id)
        await self._refresh_catalog()
        if approve and approval["tool_name"] in self._drifted_tools:
            # A human approved the previously displayed operation, not a
            # replacement schema supplied later by the upstream server.
            return await asyncio.to_thread(service.decide_approval, approval_id, False)
        return await asyncio.to_thread(service.decide_approval, approval_id, approve)

    async def get_run(self, run_id: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self._service().storage.get_run, run_id)

    async def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        storage = self._service().storage
        approval = await asyncio.to_thread(storage.get_approval, approval_id)
        if approval is None:
            return None
        completion = await asyncio.to_thread(storage.get_approval_result, approval_id)
        return {**approval, "ready": completion is not None, "completion": completion}
