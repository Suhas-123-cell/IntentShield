from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from intentshield.mcp_upstream import (
    MCPUpstream,
    MCPUpstreamConfig,
    MCPUpstreamError,
    _SDKBindings,
)


class FakeContext:
    def __init__(self, value):
        self.value = value
        self.entered = False
        self.exited = False

    async def __aenter__(self):
        self.entered = True
        return self.value

    async def __aexit__(self, exc_type, exc, traceback):
        self.exited = True


class FakeHTTPClient(FakeContext):
    created: list["FakeHTTPClient"] = []

    def __init__(self, **kwargs):
        super().__init__(self)
        self.kwargs = kwargs
        self.created.append(self)


class FakeTimeout:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class FakeClient(FakeContext):
    created: list["FakeClient"] = []

    def __init__(self, target, **kwargs):
        super().__init__(self)
        self.target = target
        self.kwargs = kwargs
        self.tool_calls = []
        self.list_cursors = []
        self.protocol_version = "2026-07-28"
        self.server_info = SimpleNamespace(name="fixture", version="1")
        self.server_capabilities = {"tools": {}}
        self.instructions = None
        self.created.append(self)

    async def list_tools(self, *, cursor=None):
        self.list_cursors.append(cursor)
        if cursor is None:
            return SimpleNamespace(
                tools=[SimpleNamespace(
                    name="read",
                    title="Read",
                    description="Read a value",
                    input_schema={"type": "object"},
                    output_schema={"type": "object"},
                    annotations=None,
                    meta={"risk": "low"},
                )],
                next_cursor="page-2",
            )
        return SimpleNamespace(
            tools=[SimpleNamespace(
                name="write",
                title=None,
                description="Write a value",
                input_schema={"type": "object", "required": ["value"]},
                output_schema=None,
                annotations={"destructiveHint": True},
                meta=None,
            )],
            next_cursor=None,
        )

    async def call_tool(self, name, arguments):
        self.tool_calls.append((name, arguments))
        if name == "fail":
            return SimpleNamespace(
                content=[SimpleNamespace(model_dump=lambda **_: {"type": "text", "text": "denied"})],
                structured_content={"reason": "policy"},
                is_error=True,
                meta={"request": "2"},
            )
        return SimpleNamespace(
            content=[{"type": "text", "text": "ok"}],
            structured_content={"value": arguments.get("value")},
            is_error=False,
            meta={"request": "1"},
        )


def fake_bindings() -> _SDKBindings:
    FakeClient.created.clear()
    FakeHTTPClient.created.clear()

    class Params:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    return _SDKBindings(
        Client=FakeClient,
        StdioServerParameters=Params,
        streamable_http_client=lambda url, http_client: ("http", url, http_client),
        AsyncClient=FakeHTTPClient,
        Timeout=FakeTimeout,
    )


def test_config_rejects_mixed_transport_settings():
    with pytest.raises(ValidationError):
        MCPUpstreamConfig(
            server_id="mail",
            transport="stdio",
            command="python",
            url="https://example.test/mcp",
        )

    with pytest.raises(ValidationError, match="stdio settings"):
        MCPUpstreamConfig(
            server_id="mail",
            transport="streamable_http",
            url="https://example.test/mcp",
            env_from_env={"TOKEN": "MCP_TOKEN"},
        )

    with pytest.raises(ValidationError, match="HTTP headers"):
        MCPUpstreamConfig(
            server_id="mail",
            transport="stdio",
            command="python",
            headers_from_env={"Authorization": "MCP_AUTHORIZATION"},
        )


def test_config_rejects_ambiguous_and_invalid_environment_references():
    with pytest.raises(ValidationError, match="both env and env_from_env"):
        MCPUpstreamConfig(
            server_id="local",
            transport="stdio",
            command="python",
            env={"TOKEN": "literal"},
            env_from_env={"TOKEN": "MCP_TOKEN"},
        )

    with pytest.raises(ValidationError, match="both headers and headers_from_env"):
        MCPUpstreamConfig(
            server_id="remote",
            transport="streamable_http",
            url="https://example.test/mcp",
            headers={"authorization": "literal"},
            headers_from_env={"Authorization": "MCP_AUTHORIZATION"},
        )

    with pytest.raises(ValidationError, match="valid names"):
        MCPUpstreamConfig(
            server_id="remote",
            transport="streamable_http",
            url="https://example.test/mcp",
            headers_from_env={"Authorization": "NOT-A-VALID-NAME"},
        )


def test_config_rejects_cleartext_remote_http():
    with pytest.raises(ValidationError, match="plain HTTP"):
        MCPUpstreamConfig(
            server_id="remote",
            transport="streamable_http",
            url="http://mcp.example.test/mcp",
        )

    local = MCPUpstreamConfig(
        server_id="local",
        transport="streamable_http",
        url="http://127.0.0.1:9000/mcp",
    )
    assert local.url.startswith("http://127.0.0.1")


def test_streamable_http_lifecycle_listing_and_calls(monkeypatch):
    monkeypatch.setenv("MCP_TEST_AUTH", "Bearer test")

    async def exercise():
        config = MCPUpstreamConfig(
            server_id="mail",
            transport="streamable_http",
            url="https://example.test/mcp",
            headers_from_env={"Authorization": "MCP_TEST_AUTH"},
        )
        upstream = MCPUpstream(config, _sdk_loader=fake_bindings)
        assert not upstream.connected
        async with upstream:
            assert upstream.connected
            assert upstream.connection_info["protocol_version"] == "2026-07-28"
            tools = await upstream.list_tools()
            assert [tool.qualified_name for tool in tools] == ["mail:read", "mail:write"]
            assert FakeClient.created[0].list_cursors == [None, "page-2"]

            success = await upstream.call_tool("write", {"value": 7})
            assert success.ok is True
            assert success.structured_content == {"value": 7}

            failure = await upstream.call_tool("fail")
            assert failure.ok is False
            assert failure.error is not None
            assert failure.error.model_dump() == {
                "code": "MCP_TOOL_ERROR",
                "message": "denied",
                "details": {"reason": "policy"},
            }
        assert not upstream.connected
        assert FakeHTTPClient.created[0].exited
        assert FakeClient.created[0].exited

    asyncio.run(exercise())


def test_streamable_http_resolves_headers_at_connect_time(monkeypatch):
    monkeypatch.setenv("MCP_REMOTE_AUTH", "Bearer environment-secret")
    config = MCPUpstreamConfig(
        server_id="mail",
        transport="streamable_http",
        url="https://example.test/mcp",
        headers={"X-Client": "IntentShield"},
        headers_from_env={"Authorization": "MCP_REMOTE_AUTH"},
    )

    # Serialized configuration contains only the environment-variable name.
    serialized = config.model_dump(mode="json")
    assert serialized["headers_from_env"] == {"Authorization": "MCP_REMOTE_AUTH"}
    assert "environment-secret" not in str(serialized)

    async def exercise():
        async with MCPUpstream(config, _sdk_loader=fake_bindings) as upstream:
            assert FakeHTTPClient.created[0].kwargs["headers"] == {
                "X-Client": "IntentShield",
                "Authorization": "Bearer environment-secret",
            }

            # A malicious server cannot reflect a credential through metadata.
            FakeClient.created[0].instructions = "token=Bearer environment-secret"
            assert "environment-secret" not in str(upstream.connection_info)
            assert upstream.connection_info["instructions"] == "token=[REDACTED]"

    asyncio.run(exercise())


def test_stdio_builds_official_parameter_shape():
    async def exercise():
        config = MCPUpstreamConfig(
            server_id="local",
            transport="stdio",
            command="python3",
            args=("server.py",),
            env={"MODE": "fixture"},
        )
        async with MCPUpstream(config, _sdk_loader=fake_bindings):
            target = FakeClient.created[0].target
            assert target.command == "python3"
            assert target.args == ["server.py"]
            assert target.env == {"MODE": "fixture"}

    asyncio.run(exercise())


def test_stdio_resolves_child_environment_at_connect_time(monkeypatch):
    monkeypatch.setenv("LOCAL_GITHUB_TOKEN", "github-secret")
    config = MCPUpstreamConfig(
        server_id="local",
        transport="stdio",
        command="python3",
        env={"MODE": "test"},
        env_from_env={"GITHUB_TOKEN": "LOCAL_GITHUB_TOKEN"},
    )

    assert "github-secret" not in config.model_dump_json()

    async def exercise():
        async with MCPUpstream(config, _sdk_loader=fake_bindings):
            target = FakeClient.created[0].target
            assert target.env == {"MODE": "test", "GITHUB_TOKEN": "github-secret"}

    asyncio.run(exercise())


@pytest.mark.parametrize("value", [None, "", "   "])
def test_missing_or_empty_environment_credential_fails_clearly_without_secret(
    monkeypatch,
    value,
):
    monkeypatch.delenv("MISSING_MCP_TOKEN", raising=False)
    if value is not None:
        monkeypatch.setenv("MISSING_MCP_TOKEN", value)
    config = MCPUpstreamConfig(
        server_id="mail",
        transport="streamable_http",
        url="https://example.test/mcp",
        headers_from_env={"Authorization": "MISSING_MCP_TOKEN"},
    )

    async def exercise():
        upstream = MCPUpstream(config, _sdk_loader=fake_bindings)
        with pytest.raises(MCPUpstreamError) as caught:
            await upstream.connect()
        error = caught.value.as_dict()["error"]
        assert error == {
            "code": "MCP_CREDENTIALS_MISSING",
            "message": "Required credential environment variables are missing or empty for MCP server 'mail'",
            "details": {
                "server_id": "mail",
                "environment_variables": ["MISSING_MCP_TOKEN"],
            },
        }
        assert not upstream.connected
        assert FakeHTTPClient.created == []

    asyncio.run(exercise())


def test_credentials_are_redacted_from_metadata_and_connection_failures(monkeypatch):
    literal_secret = "Bearer environment-super-secret"
    monkeypatch.setenv("MCP_REDACTION_AUTH", literal_secret)
    config = MCPUpstreamConfig(
        server_id="mail",
        transport="streamable_http",
        url="https://example.test/mcp",
        headers_from_env={"Authorization": "MCP_REDACTION_AUTH"},
    )

    async def metadata_exercise():
        async with MCPUpstream(config, _sdk_loader=fake_bindings) as upstream:
            FakeClient.created[0].server_info = {
                "name": "fixture",
                "debug": f"received {literal_secret}",
            }
            info = upstream.connection_info
            assert "literal-super-secret" not in str(info)
            assert info["server_info"]["debug"] == "received [REDACTED]"

    asyncio.run(metadata_exercise())

    class ExplodingClient(FakeClient):
        async def __aenter__(self):
            raise RuntimeError(f"request failed with {literal_secret}")

    bindings = fake_bindings()
    failing_bindings = _SDKBindings(
        Client=ExplodingClient,
        StdioServerParameters=bindings.StdioServerParameters,
        streamable_http_client=bindings.streamable_http_client,
        AsyncClient=bindings.AsyncClient,
        Timeout=bindings.Timeout,
    )

    async def failure_exercise():
        upstream = MCPUpstream(config, _sdk_loader=lambda: failing_bindings)
        with pytest.raises(MCPUpstreamError) as caught:
            await upstream.connect()
        rendered = str(caught.value.as_dict())
        assert "literal-super-secret" not in rendered
        assert caught.value.code == "MCP_CONNECTION_FAILED"

    asyncio.run(failure_exercise())


@pytest.mark.parametrize(
    ("url", "headers"),
    [
        ("https://user:secret@example.test/mcp", {}),
        ("https://example.test/mcp?api_key=secret", {}),
        ("https://example.test/mcp", {"X-Auth-Token": "secret"}),
    ],
)
def test_config_rejects_credentials_embedded_in_url_or_headers(url, headers):
    with pytest.raises(ValidationError, match="credential|Credential"):
        MCPUpstreamConfig(
            server_id="mail",
            transport="streamable_http",
            url=url,
            headers=headers,
        )


def test_credentials_are_redacted_from_upstream_tool_errors(monkeypatch):
    monkeypatch.setenv("MCP_REMOTE_AUTH", "Bearer policy-secret")
    config = MCPUpstreamConfig(
        server_id="mail",
        transport="streamable_http",
        url="https://example.test/mcp",
        headers_from_env={"Authorization": "MCP_REMOTE_AUTH"},
    )

    async def exercise():
        async with MCPUpstream(config, _sdk_loader=fake_bindings) as upstream:
            client = FakeClient.created[0]

            async def secret_error(name, arguments):
                return SimpleNamespace(
                    content=[{
                        "type": "text",
                        "text": "remote echoed Bearer policy-secret",
                    }],
                    structured_content={"credential": "Bearer policy-secret"},
                    is_error=True,
                    meta={"debug": "Bearer policy-secret"},
                )

            client.call_tool = secret_error
            result = await upstream.call_tool("fail")
            dumped = result.model_dump_json()
            assert "policy-secret" not in dumped
            assert "[REDACTED]" in dumped

    asyncio.run(exercise())


def test_operations_fail_closed_when_disconnected():
    async def exercise():
        upstream = MCPUpstream(MCPUpstreamConfig(
            server_id="mail",
            transport="streamable_http",
            url="https://example.test/mcp",
        ), _sdk_loader=fake_bindings)
        with pytest.raises(MCPUpstreamError) as caught:
            await upstream.call_tool("read")
        assert caught.value.as_dict()["error"]["code"] == "MCP_NOT_CONNECTED"

    asyncio.run(exercise())
