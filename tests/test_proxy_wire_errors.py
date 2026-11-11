"""The transparent proxy answers a request it cannot read with a JSON-RPC error, and keeps serving.

A request whose ``params`` is not an object used to be dropped without a reply, so a client waited for ever. Run in a process of
its own, over the real stdio transport, with the demo MCP server behind it."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from intentshield.mcp_server import _refused_line

SRC = str(Path(__file__).resolve().parents[1] / "src")


def converse(tmp_path: Path, lines: list[str], answers: int, timeout: float = 60) -> list[dict]:
    config = tmp_path / "proxy.json"
    demo = json.loads((Path(SRC).parent / "configs" / "mcp-proxy.demo.json").read_text())
    demo["upstreams"][0].update(command=sys.executable, args=["-m", "intentshield.demo_mcp_server"])
    config.write_text(json.dumps({**demo, "database_path": str(tmp_path / "proxy.db")}))
    env = {**os.environ, "PYTHONPATH": SRC, "HOME": str(tmp_path), "INTENTSHIELD_INTENT_MODEL_DIR": "/nonexistent",
           "INTENTSHIELD_PROXY_CONFIG": "", "INTENTSHIELD_CONTROL_TOKEN": ""}
    command = [sys.executable, "-c", "from intentshield.mcp_server import main; main()", "--transparent", "--config", str(config)]
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                            env=env, cwd=tmp_path)
    replies: list[dict] = []
    watchdog = threading.Timer(timeout, proc.kill)  # a proxy that never answers must fail the test, not hang it
    watchdog.start()
    try:
        assert proc.stdin and proc.stdout
        proc.stdin.write("\n".join(lines) + "\n")
        proc.stdin.flush()
        for _ in range(answers):
            line = proc.stdout.readline()
            if not line:
                break
            replies.append(json.loads(line))
    finally:
        watchdog.cancel()
        proc.kill()
        proc.wait(timeout=10)
    return replies


INIT = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}})
READY = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})


def request(request_id: int, method: str, params) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})


@pytest.mark.parametrize("params", [[1], "text", 7, True])
def test_a_tools_call_whose_params_is_not_an_object_gets_an_invalid_params_error(tmp_path, params):
    replies = converse(tmp_path, [INIT, READY, request(2, "tools/call", params), request(3, "tools/list", {})], answers=3)
    by_id = {r.get("id"): r for r in replies}
    assert by_id[2]["error"]["code"] == -32602
    assert "result" in by_id[3] and by_id[3]["result"]["tools"], "later calls are still served"


def test_text_that_is_not_json_gets_a_parse_error_and_the_proxy_keeps_serving(tmp_path):
    replies = converse(tmp_path, [INIT, READY, "this is not json", request(3, "tools/list", {})], answers=3)
    errors = [r for r in replies if "error" in r]
    assert errors and errors[0]["error"]["code"] == -32700 and errors[0]["id"] is None
    assert any(r.get("id") == 3 and "result" in r for r in replies)


def test_refused_line_leaves_every_readable_message_to_the_protocol_layer():
    assert _refused_line(request(2, "tools/call", {"name": "x", "arguments": {}})) is None
    assert _refused_line(request(2, "tools/list", None)) is None
    assert _refused_line(json.dumps({"jsonrpc": "2.0", "method": "tools/list"})) is None
    assert _refused_line(json.dumps({"jsonrpc": "2.0", "id": 4, "result": {}})) is None


def test_refused_line_answers_a_request_with_the_id_it_came_with_and_never_a_notification():
    assert _refused_line(request(9, "tools/call", [1])) == (9, -32602, "Invalid params: params must be an object")
    assert _refused_line(request(0, "tools/call", "x"))[0] == 0  # type: ignore[index]
    assert _refused_line(json.dumps({"jsonrpc": "2.0", "id": "abc", "method": "m", "params": 3}))[0] == "abc"  # type: ignore[index]
    assert _refused_line(json.dumps({"jsonrpc": "2.0", "method": "notifications/x", "params": [1]})) is None
    assert _refused_line(json.dumps({"jsonrpc": "2.0", "id": True, "method": "m", "params": [1]})) is None
