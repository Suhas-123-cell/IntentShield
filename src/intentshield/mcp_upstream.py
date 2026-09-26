"""Transport-neutral client adapter for real upstream MCP servers.

The rest of IntentShield should depend on the small, normalized surface in this
module rather than on SDK response models.  That keeps policy/audit code stable
when MCP adds fields while still using the official SDK for the wire protocol.
"""

from __future__ import annotations

from contextlib import AsyncExitStack
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import json
import os
import re
from typing import Any, Callable, Literal, Mapping
from urllib.parse import parse_qsl, urlparse

from pydantic import BaseModel, ConfigDict, Field, model_validator


_CREDENTIAL_NAME_PARTS = {
    "auth", "authorization", "bearer", "cookie", "credential", "credentials",
    "key", "password", "passwd", "secret", "session", "token",
}


def _credential_shaped_name(name: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", name.casefold()).strip("_")
    parts = set(normalized.split("_")) if normalized else set()
    return bool(parts & _CREDENTIAL_NAME_PARTS or "apikey" in normalized)


class MCPUpstreamConfig(BaseModel):
    """Connection settings for one upstream MCP server."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    server_id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    transport: Literal["stdio", "streamable_http"]
    url: str | None = None
    command: str | None = None
    args: tuple[str, ...] = ()
    env: dict[str, str] | None = None
    env_from_env: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    headers_from_env: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: float = Field(default=30.0, gt=0)
    read_timeout_seconds: float = Field(default=300.0, gt=0)
    max_catalog_pages: int = Field(default=100, ge=1, le=10_000)
    max_catalog_tools: int = Field(default=1_000, ge=1, le=100_000)
    max_tool_schema_bytes: int = Field(default=1_000_000, ge=1, le=16_000_000)

    @model_validator(mode="after")
    def validate_transport_fields(self) -> "MCPUpstreamConfig":
        if self.transport == "stdio":
            if not self.command:
                raise ValueError("stdio transport requires command")
            if self.url is not None:
                raise ValueError("stdio transport does not accept url")
            if self.headers or self.headers_from_env:
                raise ValueError("stdio transport does not accept HTTP headers")
            duplicate_env = set(self.env or {}).intersection(self.env_from_env)
            if duplicate_env:
                raise ValueError(
                    "stdio environment keys cannot be configured in both env and env_from_env: "
                    + ", ".join(sorted(duplicate_env))
                )
        else:
            if not self.url or not self.url.startswith(("http://", "https://")):
                raise ValueError("streamable_http transport requires an http(s) URL")
            parsed = urlparse(self.url)
            if parsed.username is not None or parsed.password is not None:
                raise ValueError("MCP URLs must not contain userinfo credentials")
            credential_query_names = sorted({
                name for name, _value in parse_qsl(parsed.query, keep_blank_values=True)
                if _credential_shaped_name(name)
            })
            if credential_query_names:
                raise ValueError(
                    "MCP URLs must not contain credential query parameters: "
                    + ", ".join(credential_query_names)
                )
            if parsed.scheme == "http" and parsed.hostname not in {
                "127.0.0.1", "localhost", "::1"
            }:
                raise ValueError(
                    "plain HTTP is allowed only for loopback MCP servers; use HTTPS remotely"
                )
            if (
                self.command is not None
                or self.args
                or self.env is not None
                or self.env_from_env
            ):
                raise ValueError("streamable_http transport does not accept stdio settings")
            literal_headers = {name.casefold() for name in self.headers}
            duplicate_headers = [
                name for name in self.headers_from_env if name.casefold() in literal_headers
            ]
            if duplicate_headers:
                raise ValueError(
                    "HTTP header names cannot be configured in both headers and "
                    "headers_from_env: " + ", ".join(sorted(duplicate_headers))
                )
            literal_credential_headers = sorted(
                name for name in self.headers if _credential_shaped_name(name)
            )
            if literal_credential_headers:
                raise ValueError(
                    "Credential headers must use headers_from_env: "
                    + ", ".join(literal_credential_headers)
                )

        literal_credential_env = sorted(
            name for name in (self.env or {}) if _credential_shaped_name(name)
        )
        if literal_credential_env:
            raise ValueError(
                "Credential environment values must use env_from_env: "
                + ", ".join(literal_credential_env)
            )

        invalid_references = sorted({
            reference
            for reference in (*self.env_from_env.values(), *self.headers_from_env.values())
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", reference)
        })
        if invalid_references:
            raise ValueError(
                "credential environment-variable references must be valid names: "
                + ", ".join(invalid_references)
            )
        return self


class MCPErrorInfo(BaseModel):
    """Stable, JSON-serializable error envelope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    message: str
    details: Any | None = None


class MCPTool(BaseModel):
    """SDK-independent representation of a discovered MCP tool."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    server_id: str
    name: str
    title: str | None = None
    description: str | None = None
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] | None = None
    meta: dict[str, Any] | None = None

    @property
    def qualified_name(self) -> str:
        return f"{self.server_id}:{self.name}"


class MCPCallResult(BaseModel):
    """Normalized result of an MCP ``tools/call`` operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    server_id: str
    tool_name: str
    ok: bool
    is_error: bool
    content: list[dict[str, Any]] = Field(default_factory=list)
    structured_content: Any | None = None
    meta: dict[str, Any] | None = None
    error: MCPErrorInfo | None = None


class MCPUpstreamError(RuntimeError):
    """A transport/protocol failure with a stable external representation."""

    def __init__(self, code: str, message: str, *, details: Any | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": False,
            "error": MCPErrorInfo(
                code=self.code, message=self.message, details=_normalize(self.details)
            ).model_dump(mode="json"),
        }


@dataclass(frozen=True)
class _SDKBindings:
    Client: type[Any]
    StdioServerParameters: type[Any]
    streamable_http_client: Callable[..., Any]
    AsyncClient: type[Any]
    Timeout: type[Any]


def _load_sdk() -> _SDKBindings:
    """Import optional MCP runtime dependencies only when a connection opens."""

    try:
        from httpx2 import AsyncClient, Timeout
        from mcp import Client, StdioServerParameters
        from mcp.client.streamable_http import streamable_http_client
    except ImportError as exc:  # pragma: no cover - exercised without the optional SDK
        raise MCPUpstreamError(
            "MCP_SDK_UNAVAILABLE",
            "The official MCP Python SDK is not installed",
            details={"exception_type": type(exc).__name__},
        ) from exc
    return _SDKBindings(Client, StdioServerParameters, streamable_http_client, AsyncClient, Timeout)


def _attribute(value: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if hasattr(value, name):
            return getattr(value, name)
        if isinstance(value, Mapping) and name in value:
            return value[name]
    return default


def _normalize(value: Any) -> Any:
    """Convert SDK/Pydantic values into deterministic JSON-compatible values."""

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return _normalize(value.value)
    if isinstance(value, BaseModel):
        return _normalize(value.model_dump(mode="json", by_alias=False, exclude_none=True))
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _normalize(model_dump(mode="json", by_alias=False, exclude_none=True))
    if is_dataclass(value) and not isinstance(value, type):
        return _normalize(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _normalize(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [_normalize(item) for item in value]
        return sorted(items, key=repr) if isinstance(value, (set, frozenset)) else items
    # MCP SDK response types are Pydantic models.  This is a conservative final
    # fallback for extension-provided scalar types such as URL implementations.
    return str(value)


def _mapping_or_none(value: Any) -> dict[str, Any] | None:
    normalized = _normalize(value)
    return normalized if isinstance(normalized, dict) else None


def _content_blocks(value: Any) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    for block in value or []:
        normalized = _normalize(block)
        if isinstance(normalized, dict):
            blocks.append(normalized)
        else:
            blocks.append({"type": "unknown", "value": normalized})
    return blocks


def _tool_error_message(content: list[dict[str, Any]]) -> str:
    text = [block.get("text") for block in content if block.get("type") == "text"]
    messages = [item.strip() for item in text if isinstance(item, str) and item.strip()]
    return "\n".join(messages) if messages else "The MCP tool reported an error"


def _redact(value: Any, secrets: tuple[str, ...]) -> Any:
    """Remove known credential values from externally visible data."""

    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, "[REDACTED]")
        return value
    if isinstance(value, Mapping):
        return {key: _redact(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, secrets) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact(item, secrets) for item in value)
    return value


def _resolve_environment_references(
    references: Mapping[str, str],
    *,
    server_id: str,
) -> dict[str, str]:
    """Resolve destination names to values without persisting values in config."""

    missing = sorted({
        source
        for source in references.values()
        if source not in os.environ or not os.environ[source].strip()
    })
    if missing:
        raise MCPUpstreamError(
            "MCP_CREDENTIALS_MISSING",
            f"Required credential environment variables are missing or empty for MCP server {server_id!r}",
            details={"server_id": server_id, "environment_variables": missing},
        )
    return {destination: os.environ[source] for destination, source in references.items()}


def _credential_values(*mappings: Mapping[str, str]) -> tuple[str, ...]:
    """Return non-empty values, longest first, for deterministic redaction."""

    return tuple(sorted(
        {value for mapping in mappings for value in mapping.values() if value},
        key=len,
        reverse=True,
    ))


class MCPUpstream:
    """One-use-lifecycle adapter around the official high-level MCP client.

    Constructing this class performs no I/O. Use it with ``async with`` or call
    :meth:`connect` and :meth:`close` explicitly. An instance may reconnect only
    by creating a fresh official SDK Client internally after it has been closed.
    """

    def __init__(
        self,
        config: MCPUpstreamConfig,
        *,
        _sdk_loader: Callable[[], _SDKBindings] = _load_sdk,
    ) -> None:
        self.config = config
        self._sdk_loader = _sdk_loader
        self._stack: AsyncExitStack | None = None
        self._client: Any | None = None
        self._credential_values: tuple[str, ...] = ()

    @property
    def connected(self) -> bool:
        return self._client is not None

    @property
    def connection_info(self) -> dict[str, Any]:
        client = self._require_client()
        return _redact({
            "server_id": self.config.server_id,
            "transport": self.config.transport,
            "protocol_version": _normalize(getattr(client, "protocol_version", None)),
            "server_info": _normalize(getattr(client, "server_info", None)),
            "server_capabilities": _normalize(getattr(client, "server_capabilities", None)),
            "instructions": _normalize(getattr(client, "instructions", None)),
        }, self._credential_values)

    async def __aenter__(self) -> "MCPUpstream":
        return await self.connect()

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        await self.close()

    async def connect(self) -> "MCPUpstream":
        if self.connected:
            return self

        stack = AsyncExitStack()
        try:
            sdk = self._sdk_loader()
            if self.config.transport == "stdio":
                referenced_env = _resolve_environment_references(
                    self.config.env_from_env,
                    server_id=self.config.server_id,
                )
                child_env = {**(self.config.env or {}), **referenced_env}
                self._credential_values = _credential_values(
                    self.config.env or {}, referenced_env
                )
                target = sdk.StdioServerParameters(
                    command=self.config.command,
                    args=list(self.config.args),
                    env=child_env if self.config.env is not None or referenced_env else None,
                )
            else:
                referenced_headers = _resolve_environment_references(
                    self.config.headers_from_env,
                    server_id=self.config.server_id,
                )
                headers = {**self.config.headers, **referenced_headers}
                self._credential_values = _credential_values(
                    self.config.headers, referenced_headers
                )
                timeout = sdk.Timeout(
                    connect=self.config.timeout_seconds,
                    write=self.config.timeout_seconds,
                    pool=self.config.timeout_seconds,
                    read=self.config.read_timeout_seconds,
                )
                http_client = sdk.AsyncClient(headers=headers, timeout=timeout)
                await stack.enter_async_context(http_client)
                target = sdk.streamable_http_client(self.config.url, http_client=http_client)

            client = sdk.Client(target, read_timeout_seconds=self.config.read_timeout_seconds)
            connected_client = await stack.enter_async_context(client)
        except MCPUpstreamError:
            await stack.aclose()
            self._credential_values = ()
            raise
        except Exception as exc:
            await stack.aclose()
            self._credential_values = ()
            raise MCPUpstreamError(
                "MCP_CONNECTION_FAILED",
                f"Could not connect to MCP server {self.config.server_id!r}",
                details={"server_id": self.config.server_id, "exception_type": type(exc).__name__},
            ) from exc

        self._stack = stack
        self._client = connected_client
        return self

    async def close(self) -> None:
        stack, self._stack = self._stack, None
        self._client = None
        self._credential_values = ()
        if stack is None:
            return
        try:
            await stack.aclose()
        except Exception as exc:
            raise MCPUpstreamError(
                "MCP_CLOSE_FAILED",
                f"Could not close MCP server {self.config.server_id!r}",
                details={"server_id": self.config.server_id, "exception_type": type(exc).__name__},
            ) from exc

    async def list_tools(self) -> list[MCPTool]:
        client = self._require_client()
        tools: list[MCPTool] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        page_count = 0
        try:
            while True:
                page_count += 1
                if page_count > self.config.max_catalog_pages:
                    raise MCPUpstreamError(
                        "MCP_CATALOG_LIMIT_EXCEEDED",
                        "The MCP tool catalog exceeded the configured page limit",
                        details={"server_id": self.config.server_id},
                    )
                response = await client.list_tools(cursor=cursor)
                for tool in _attribute(response, "tools", default=[]) or []:
                    input_schema = _mapping_or_none(_attribute(tool, "input_schema", "inputSchema"))
                    if input_schema is None:
                        raise MCPUpstreamError(
                            "MCP_INVALID_TOOL_SCHEMA",
                            f"Tool {_attribute(tool, 'name', default='<unknown>')!r} has no object input schema",
                            details={"server_id": self.config.server_id},
                        )
                    schema_bytes = len(json.dumps(input_schema, separators=(",", ":")).encode())
                    if schema_bytes > self.config.max_tool_schema_bytes:
                        raise MCPUpstreamError(
                            "MCP_CATALOG_LIMIT_EXCEEDED",
                            "An MCP tool schema exceeded the configured size limit",
                            details={
                                "server_id": self.config.server_id,
                                "tool_name": _attribute(tool, "name", default="<unknown>"),
                                "schema_bytes": schema_bytes,
                            },
                        )
                    tools.append(MCPTool(
                        server_id=self.config.server_id,
                        name=str(_attribute(tool, "name", default="")),
                        title=_attribute(tool, "title"),
                        description=_attribute(tool, "description"),
                        input_schema=input_schema,
                        output_schema=_mapping_or_none(_attribute(tool, "output_schema", "outputSchema")),
                        annotations=_mapping_or_none(_attribute(tool, "annotations")),
                        meta=_mapping_or_none(_attribute(tool, "meta", "_meta")),
                    ))
                    if len(tools) > self.config.max_catalog_tools:
                        raise MCPUpstreamError(
                            "MCP_CATALOG_LIMIT_EXCEEDED",
                            "The MCP tool catalog exceeded the configured tool limit",
                            details={"server_id": self.config.server_id},
                        )
                next_cursor = _attribute(response, "next_cursor", "nextCursor")
                if not next_cursor:
                    return tools
                if next_cursor in seen_cursors:
                    raise MCPUpstreamError(
                        "MCP_PAGINATION_LOOP",
                        "The MCP server repeated a tools/list cursor",
                        details={"server_id": self.config.server_id, "cursor": next_cursor},
                    )
                seen_cursors.add(str(next_cursor))
                cursor = str(next_cursor)
        except MCPUpstreamError:
            raise
        except Exception as exc:
            raise MCPUpstreamError(
                "MCP_LIST_TOOLS_FAILED",
                f"Could not list tools from MCP server {self.config.server_id!r}",
                details={"server_id": self.config.server_id, "exception_type": type(exc).__name__},
            ) from exc

    async def call_tool(self, name: str, arguments: Mapping[str, Any] | None = None) -> MCPCallResult:
        client = self._require_client()
        try:
            response = await client.call_tool(name, dict(arguments or {}))
        except Exception as exc:
            raise MCPUpstreamError(
                "MCP_CALL_TOOL_FAILED",
                f"Could not call MCP tool {name!r} on {self.config.server_id!r}",
                details={
                    "server_id": self.config.server_id,
                    "tool_name": name,
                    "exception_type": type(exc).__name__,
                },
            ) from exc

        content = _redact(
            _content_blocks(_attribute(response, "content", default=[])),
            self._credential_values,
        )
        structured = _redact(
            _normalize(_attribute(response, "structured_content", "structuredContent")),
            self._credential_values,
        )
        is_error = bool(_attribute(response, "is_error", "isError", default=False))
        error = None
        if is_error:
            error = MCPErrorInfo(
                code="MCP_TOOL_ERROR",
                message=_tool_error_message(content),
                details=structured,
            )
        return MCPCallResult(
            server_id=self.config.server_id,
            tool_name=name,
            ok=not is_error,
            is_error=is_error,
            content=content,
            structured_content=structured,
            meta=_redact(
                _mapping_or_none(_attribute(response, "meta", "_meta")),
                self._credential_values,
            ),
            error=error,
        )

    def _require_client(self) -> Any:
        if self._client is None:
            raise MCPUpstreamError(
                "MCP_NOT_CONNECTED",
                f"MCP server {self.config.server_id!r} is not connected",
                details={"server_id": self.config.server_id},
            )
        return self._client
