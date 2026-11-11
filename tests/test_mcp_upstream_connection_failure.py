"""A server that cannot be started says why: the command is not found, it ended, or it did not answer.

These start real child processes (a missing path, a shell that exits, a sleep) through the official SDK."""
from __future__ import annotations

import asyncio
import sys

import pytest

from intentshield.mcp_upstream import MCPUpstream, MCPUpstreamConfig, MCPUpstreamError, _connection_failure


def failure(**config) -> MCPUpstreamError:
    async def attempt() -> None:
        async with MCPUpstream(MCPUpstreamConfig(server_id="demo", transport="stdio", **config)):
            pass

    with pytest.raises(MCPUpstreamError) as caught:
        asyncio.run(attempt())
    assert caught.value.code == "MCP_CONNECTION_FAILED"
    return caught.value


def test_a_command_that_does_not_exist_is_named():
    assert "'/no/such/binary' does not exist" in failure(command="/no/such/binary").message


def test_a_bare_command_that_is_not_on_path_says_so():
    assert "'no-such-program-xyz' was not found on PATH" in failure(command="no-such-program-xyz").message


def test_a_server_that_exits_at_once_says_it_ended_before_it_answered():
    message = failure(command=sys.executable, args=["-c", "import sys; sys.exit(3)"]).message
    assert message.startswith("Could not connect to MCP server 'demo': the server ended before it answered")


def test_a_server_that_never_answers_says_it_timed_out():
    message = failure(command=sys.executable, args=["-c", "import time; time.sleep(60)"], timeout_seconds=1,
                      read_timeout_seconds=1).message
    assert "did not answer the start-up message in time" in message


def test_the_cause_of_a_failure_is_the_error_at_the_bottom_of_a_task_group():
    config = MCPUpstreamConfig(server_id="demo", transport="stdio", command="x")
    group = ExceptionGroup("tg", [ExceptionGroup("tg", [PermissionError(13, "denied")])])
    assert _connection_failure(group, config) == "the command 'x' cannot be run (permission denied)"


def test_a_url_in_the_error_never_reaches_the_message():
    config = MCPUpstreamConfig(server_id="web", transport="streamable_http", url="https://example.test/mcp")
    text = _connection_failure(RuntimeError("Client error '401' for url 'https://example.test/mcp/session/SECRET'"), config)
    assert "SECRET" not in text and "<url>" in text
