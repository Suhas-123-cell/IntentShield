from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from mcp import Client
import pytest

from intentshield.mcp_verify import verify_mcp


pytestmark = pytest.mark.skipif(
    os.getenv("INTENTSHIELD_RUN_HTTP_E2E") != "1",
    reason="set INTENTSHIELD_RUN_HTTP_E2E=1 to bind real localhost MCP servers",
)


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for_port(port: int, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"server exited during startup with {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"server did not bind 127.0.0.1:{port}")


def _stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        raise AssertionError("MCP server did not shut down after SIGINT")


def test_real_streamable_http_upstream_gateway_control_and_shutdown(
    tmp_path: Path,
) -> None:
    upstream_port = _free_port()
    gateway_port = _free_port()
    control_token = "local-e2e-control-token"
    config_path = tmp_path / "http-e2e.json"
    config_path.write_text(json.dumps({
        "upstreams": [
            {
                "server_id": "notes_stdio",
                "transport": "stdio",
                "command": sys.executable,
                "args": ["-m", "intentshield.demo_mcp_server"],
            },
            {
                "server_id": "notes_http",
                "transport": "streamable_http",
                "url": f"http://127.0.0.1:{upstream_port}/mcp",
            },
        ],
        "database_path": str(tmp_path / "http-e2e.db"),
        "allowed_tools": ["notes_stdio:*", "notes_http:*"],
        "prohibited_tools": [],
        "read_only_tools": [
            "notes_stdio:read_note",
            "notes_stdio:execution_stats",
            "notes_http:read_note",
            "notes_http:execution_stats",
        ],
    }))
    quiet = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    upstream = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "intentshield.demo_mcp_server",
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(upstream_port),
        ],
        **quiet,
    )
    gateway: subprocess.Popen[bytes] | None = None
    try:
        _wait_for_port(upstream_port, upstream)
        environment = os.environ.copy()
        environment["INTENTSHIELD_CONTROL_TOKEN"] = control_token
        gateway = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "intentshield.mcp_server",
                "--transport",
                "streamable-http",
                "--config",
                str(config_path),
                "--host",
                "127.0.0.1",
                "--port",
                str(gateway_port),
            ],
            env=environment,
            **quiet,
        )
        _wait_for_port(gateway_port, gateway)
        endpoint = f"http://127.0.0.1:{gateway_port}/mcp"
        report = asyncio.run(
            verify_mcp(
                config_path,
                verification_mode="streamable_http_wire",
                url=endpoint,
            )
        )
        assert report["status"] == "PASS"
        assert report["summary"]["guarded_tools_discovered"] == 6

        async def create_review() -> str:
            async with Client(endpoint) as client:
                catalog = (
                    await client.call_tool("intentshield_list_tools", {})
                ).structured_content["tools"]
                append = next(
                    tool for tool in catalog if tool["name"] == "notes_http:append_note"
                )
                run = await client.call_tool(
                    "intentshield_create_run",
                    {"user_intent": "Append a line to the welcome note"},
                )
                review = await client.call_tool("intentshield_call", {
                    "run_id": run.structured_content["run_id"],
                    "tool_name": append["name"],
                    "arguments": {"note_id": "welcome", "text": "E2E review"},
                    "schema_hash": append["schema_hash"],
                    "idempotency_key": "http-control-e2e",
                })
                assert review.structured_content["decision"] == "REVIEW"
                assert review.structured_content["executed"] is False
                return str(review.structured_content["approval_id"])

        approval_id = asyncio.run(create_review())
        control_url = (
            f"http://127.0.0.1:{gateway_port}/control/approvals/{approval_id}"
        )
        body = json.dumps({"decision": "reject"}).encode()
        with pytest.raises(HTTPError) as unauthorized:
            urlopen(Request(control_url, data=body, method="POST"), timeout=5)
        assert unauthorized.value.code == 401

        response = urlopen(Request(
            control_url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {control_token}",
                "Content-Type": "application/json",
            },
        ), timeout=5)
        rejected = json.loads(response.read())
        assert rejected["decision"] == "BLOCK"
        assert rejected["executed"] is False
    finally:
        if gateway is not None:
            _stop(gateway)
        _stop(upstream)
