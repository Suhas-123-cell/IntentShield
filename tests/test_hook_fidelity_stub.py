"""Offline tests of the model-free stub endpoint (benchmarks/hook_fidelity/stub_model.py): it is driven with
request shapes written from vendor source and documentation for the three wire formats (Anthropic Messages, OpenAI
Responses as Codex sends it, Gemini generateContent; none was recorded from a live client), and no harness is
launched. The only process started is the stub itself, from the command line."""
from __future__ import annotations

import ast
import gzip
import http.client
import json
import subprocess
import sys
from pathlib import Path

import pytest

BENCH = Path(__file__).resolve().parents[1] / "benchmarks"
sys.path.insert(0, str(BENCH))
from hook_fidelity import stub_model  # noqa: E402
from hook_fidelity.stub_model import Script, ScriptError, StubServer  # noqa: E402

STUB_FILE = BENCH / "hook_fidelity" / "stub_model.py"
NONCE = "n0nce42"
FAKE_KEY = "sk-ant-FAKEKEY0123456789abcdef"
FAKE_GOOGLE_KEY = "AIzaFAKEFAKEFAKEFAKEFAKE0123456"

SCRIPT = {
    "nonce": NONCE,
    "call": {"name": "Bash", "args": {"command": "touch ran-{nonce}.txt"}},
    "by_api": {
        "openai": {"name": "exec_command", "args": {"cmd": "touch ran-{nonce}.txt"}},
        "gemini": {"name": "run_shell_command", "args": {"command": "touch ran-{nonce}.txt"}},
    },
    "final_text": "all done {nonce}",
}
MCP_SCRIPT = {
    "nonce": NONCE,
    "call": {"name": "mcp__notes__search_notes", "args": {"query": NONCE}},
    "by_api": {"openai": {"namespace": "mcp__notes__", "name": "search_notes", "args": {"query": NONCE}}},
}


@pytest.fixture
def stub(tmp_path):
    with StubServer(Script.from_obj(SCRIPT), tmp_path / "log" / "requests.jsonl") as server:
        yield server


def post(server, path, body, headers=None, raw=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    data = raw if raw is not None else json.dumps(body).encode()
    conn.request("POST", path, body=data, headers={"Content-Type": "application/json", **(headers or {})})
    response = conn.getresponse()
    payload = response.read()
    conn.close()
    return response.status, response.getheader("Content-Type"), payload


def sse_events(payload: bytes) -> list[tuple[str | None, dict]]:
    events = []
    for block in payload.decode().replace("\r\n", "\n").split("\n\n"):
        if not block.strip():
            continue
        name, data = None, None
        for line in block.split("\n"):
            if line.startswith("event: "):
                name = line[len("event: "):]
            elif line.startswith("data: "):
                data = json.loads(line[len("data: "):])
        events.append((name, data))
    return events


def log_records(server) -> list[dict]:
    return [json.loads(line) for line in server.log_path.read_text().splitlines()]


# ---------------------------------------------------------------- Anthropic Messages
ANTHROPIC_TURN1 = {
    "model": "claude-haiku-5-5", "max_tokens": 1024, "stream": True,
    "system": [{"type": "text", "text": "You are Claude Code."}],
    "tools": [{"name": "Bash", "description": "run", "input_schema": {"type": "object"}},
              {"name": "mcp__notes__search_notes", "description": "s", "input_schema": {"type": "object"}}],
    "messages": [{"role": "user", "content": [{"type": "text", "text": "run touch"}]}],
}


def anthropic_followup(is_error: bool, text: str) -> dict:
    return {**ANTHROPIC_TURN1, "messages": [
        *ANTHROPIC_TURN1["messages"],
        {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_x", "name": "Bash", "input": {}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_x", "is_error": is_error,
                                      "content": [{"type": "text", "text": text}]}]}]}


def test_anthropic_streaming_tool_call(stub):
    status, ctype, payload = post(stub, "/v1/messages?beta=true", ANTHROPIC_TURN1, {"x-api-key": FAKE_KEY})
    assert status == 200 and ctype == "text/event-stream"
    events = sse_events(payload)
    assert [n for n, _ in events] == ["message_start", "ping", "content_block_start", "content_block_delta",
                                      "content_block_stop", "message_delta", "message_stop"]
    start = events[2][1]["content_block"]
    assert start["type"] == "tool_use" and start["name"] == "Bash" and start["input"] == {}
    assert start["id"].startswith("toolu_")
    delta = events[3][1]["delta"]
    assert delta["type"] == "input_json_delta"
    assert json.loads(delta["partial_json"]) == {"command": f"touch ran-{NONCE}.txt"}
    assert events[5][1]["delta"]["stop_reason"] == "tool_use"
    assert all(data["type"] == name for name, data in events)


def test_anthropic_non_streaming_tool_call(stub):
    status, ctype, payload = post(stub, "/v1/messages", {**ANTHROPIC_TURN1, "stream": False})
    message = json.loads(payload)
    assert status == 200 and ctype == "application/json"
    assert message["type"] == "message" and message["role"] == "assistant" and message["stop_reason"] == "tool_use"
    assert message["content"][0]["type"] == "tool_use"
    assert message["content"][0]["input"] == {"command": f"touch ran-{NONCE}.txt"}
    assert message["usage"]["input_tokens"] >= 0


def test_anthropic_after_tool_result_gives_final_text_and_logs_the_result(stub):
    reason = "blocked by guard: needs approval"
    _, _, payload = post(stub, "/v1/messages", anthropic_followup(True, reason))
    events = sse_events(payload)
    deltas = [d for n, d in events if n == "content_block_delta"]
    assert deltas[0]["delta"] == {"type": "text_delta", "text": f"all done {NONCE}"}
    assert [d for n, d in events if n == "message_delta"][0]["delta"]["stop_reason"] == "end_turn"
    record = log_records(stub)[-1]
    assert record["decision"] == "text:after-tool-result" and record["has_tool_result"] is True
    assert record["tool_results"] == [{"is_error": True, "text": reason}]


def test_anthropic_request_without_tools_gets_text_not_a_call(stub):
    side = {"model": "claude-haiku-5-5", "max_tokens": 32, "stream": False,
            "messages": [{"role": "user", "content": "write a title"}]}
    _, _, payload = post(stub, "/v1/messages", side)
    message = json.loads(payload)
    assert message["content"] == [{"type": "text", "text": "stub ok"}] and message["stop_reason"] == "end_turn"
    assert log_records(stub)[-1]["decision"] == "text:no-tools-offered"


def test_anthropic_count_tokens(stub):
    status, _, payload = post(stub, "/v1/messages/count_tokens", ANTHROPIC_TURN1)
    assert status == 200 and "input_tokens" in json.loads(payload)


def test_log_proves_offered_tool_names_and_whether_the_scripted_tool_was_among_them(stub):
    post(stub, "/v1/messages", ANTHROPIC_TURN1)
    only_mcp = {**ANTHROPIC_TURN1, "tools": [ANTHROPIC_TURN1["tools"][1]]}
    post(stub, "/v1/messages", only_mcp)
    first, second = log_records(stub)
    assert first["offered_tools"] == ["Bash", "mcp__notes__search_notes"] and first["scripted_tool_offered"] is True
    assert second["offered_tools"] == ["mcp__notes__search_notes"] and second["scripted_tool_offered"] is False
    assert second["decision"] == "tool_call", "the call is still issued; the log says it was not offered"


# ---------------------------------------------------------------- OpenAI Responses (Codex 0.165)
def codex_turn1(tools=None) -> dict:
    return {"model": "stub-model", "stream": True, "tool_choice": "auto", "parallel_tool_calls": False,
            "reasoning": None, "store": False, "include": [], "instructions": "x",
            "tools": tools if tools is not None else [
                {"type": "function", "name": "exec_command", "description": "Runs a command", "strict": False,
                 "parameters": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]}},
                {"type": "custom", "name": "apply_patch", "description": "patch",
                 "format": {"type": "grammar", "syntax": "lark", "definition": ""}},
                {"type": "namespace", "name": "mcp__notes__", "description": "Tools in the notes namespace.",
                 "tools": [{"type": "function", "name": "search_notes", "description": "s", "strict": False,
                            "parameters": {"type": "object"}}]}],
            "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "go"}]}]}


def test_openai_streaming_function_call(stub):
    status, ctype, payload = post(stub, "/v1/responses", codex_turn1(), {"authorization": f"Bearer {FAKE_KEY}"})
    assert status == 200 and ctype == "text/event-stream"
    events = sse_events(payload)
    assert [n for n, _ in events] == ["response.created", "response.output_item.added", "response.output_item.done",
                                      "response.completed"]
    assert all(data["type"] == name for name, data in events)
    assert [d["sequence_number"] for _, d in events] == [0, 1, 2, 3]
    item = events[2][1]["item"]
    assert item["type"] == "function_call" and item["name"] == "exec_command"
    assert isinstance(item["arguments"], str), "Responses API arguments are a JSON string, not an object"
    assert json.loads(item["arguments"]) == {"cmd": f"touch ran-{NONCE}.txt"}
    assert item["call_id"] and "_" in item["id"]
    completed = events[3][1]["response"]
    assert completed["id"] and "end_turn" not in completed, "an end_turn flag would make Codex re-sample after a block"
    assert set(completed["usage"]) >= {"input_tokens", "output_tokens", "total_tokens"}


def test_openai_namespaced_mcp_call_matches_the_offered_namespace_tool(tmp_path):
    with StubServer(Script.from_obj(MCP_SCRIPT), tmp_path / "r.jsonl") as server:
        _, _, payload = post(server, "/v1/responses", codex_turn1())
        item = sse_events(payload)[2][1]["item"]
        assert item["namespace"] == "mcp__notes__" and item["name"] == "search_notes"
        record = log_records(server)[0]
        assert "mcp__notes__search_notes" in record["offered_tools"] and record["scripted_tool_offered"] is True
        assert record["offered_tools"][:2] == ["exec_command", "apply_patch"]


def test_openai_freeform_tool_call_is_a_custom_tool_call(tmp_path):
    patch = "*** Begin Patch\n*** Add File: ran-{nonce}.txt\n+x\n*** End Patch"
    script = {"nonce": NONCE, "by_api": {"openai": {"name": "apply_patch", "input": patch}}}
    with StubServer(Script.from_obj(script), tmp_path / "r.jsonl") as server:
        _, _, payload = post(server, "/v1/responses", codex_turn1())
        item = sse_events(payload)[2][1]["item"]
        assert item["type"] == "custom_tool_call" and item["name"] == "apply_patch"
        assert item["input"] == patch.replace("{nonce}", NONCE) and "arguments" not in item
        body = codex_turn1()
        body["input"] += [item, {"type": "custom_tool_call_output", "call_id": item["call_id"], "output": "denied"}]
        _, _, payload = post(server, "/v1/responses", body)
        assert sse_events(payload)[3][1]["item"]["type"] == "message"
        assert log_records(server)[0]["scripted_tool_offered"] is True


def test_openai_after_function_call_output_gives_final_message(stub):
    body = codex_turn1()
    body["input"] += [
        {"type": "function_call", "name": "exec_command", "arguments": "{}", "call_id": "call_stub_1"},
        {"type": "function_call_output", "call_id": "call_stub_1", "output": "hook said no"}]
    _, _, payload = post(stub, "/v1/responses", body)
    events = sse_events(payload)
    assert [n for n, _ in events] == ["response.created", "response.output_item.added", "response.output_text.delta",
                                      "response.output_item.done", "response.completed"]
    assert events[2][1]["delta"] == f"all done {NONCE}"
    item = events[3][1]["item"]
    assert item["type"] == "message" and item["role"] == "assistant"
    assert item["content"] == [{"type": "output_text", "text": f"all done {NONCE}", "annotations": []}]
    assert "end_turn" not in events[4][1]["response"]
    record = log_records(stub)[-1]
    assert record["has_tool_result"] and record["tool_results"][0]["text"] == "hook said no"


def test_openai_non_streaming(stub):
    _, ctype, payload = post(stub, "/v1/responses", {**codex_turn1(), "stream": False})
    body = json.loads(payload)
    assert ctype == "application/json" and body["output"][0]["type"] == "function_call"


# ---------------------------------------------------------------- Gemini
GEMINI_TURN1 = {
    "contents": [{"role": "user", "parts": [{"text": "run touch"}]}],
    "tools": [{"functionDeclarations": [{"name": "run_shell_command", "description": "x"},
                                        {"name": "mcp_notes_search_notes", "description": "y"}]}],
    "generationConfig": {"temperature": 1},
}


def test_gemini_stream_generate_content_sse(stub):
    path = "/v1beta/models/gemini-stub:streamGenerateContent?alt=sse"
    status, ctype, payload = post(stub, path, GEMINI_TURN1, {"x-goog-api-key": FAKE_GOOGLE_KEY})
    assert status == 200 and ctype == "text/event-stream"
    assert payload.endswith(b"\r\n\r\n"), "the SDK splits chunks on a blank line; CRLF is what the API sends"
    chunks = [d for _, d in sse_events(payload)]
    assert len(chunks) == 1
    part = chunks[0]["candidates"][0]["content"]["parts"][0]
    assert part == {"functionCall": {"name": "run_shell_command", "args": {"command": f"touch ran-{NONCE}.txt"}}}
    assert chunks[0]["candidates"][0]["finishReason"] == "STOP" and chunks[0]["usageMetadata"]["totalTokenCount"] >= 0
    record = log_records(stub)[0]
    assert record["api"] == "gemini" and record["model"] == "gemini-stub"
    assert record["offered_tools"] == ["run_shell_command", "mcp_notes_search_notes"]


def test_gemini_generate_content_json_and_after_function_response(stub):
    _, ctype, payload = post(stub, "/v1beta/models/gemini-stub:generateContent", GEMINI_TURN1)
    assert ctype == "application/json"
    assert json.loads(payload)["candidates"][0]["content"]["parts"][0]["functionCall"]["name"] == "run_shell_command"
    followup = {**GEMINI_TURN1, "contents": [
        *GEMINI_TURN1["contents"],
        {"role": "model", "parts": [{"functionCall": {"name": "run_shell_command", "args": {}}}]},
        {"role": "user", "parts": [{"functionResponse": {"name": "run_shell_command",
                                                          "response": {"error": "blocked by hook"}}}]}]}
    _, _, payload = post(stub, "/v1beta/models/gemini-stub:generateContent", followup)
    assert json.loads(payload)["candidates"][0]["content"]["parts"] == [{"text": f"all done {NONCE}"}]
    record = log_records(stub)[-1]
    assert record["decision"] == "text:after-tool-result" and record["tool_results"][0]["is_error"] is True


def test_gemini_stream_without_alt_sse_is_a_json_array_and_count_tokens(stub):
    _, ctype, payload = post(stub, "/v1beta/models/m:streamGenerateContent", GEMINI_TURN1)
    assert ctype == "application/json" and isinstance(json.loads(payload), list)
    status, _, payload = post(stub, "/v1beta/models/m:countTokens", {"contents": []})
    assert status == 200 and "totalTokens" in json.loads(payload)


def test_gemini_request_without_tools_gets_text(stub):
    _, _, payload = post(stub, "/v1beta/models/m:generateContent", {"contents": [{"role": "user", "parts": []}]})
    assert json.loads(payload)["candidates"][0]["content"]["parts"] == [{"text": "stub ok"}]


# ---------------------------------------------------------------- behaviour, redaction, robustness
def test_retry_of_turn_one_gets_the_call_again_because_behaviour_is_a_function_of_the_request(stub):
    for _ in range(2):
        _, _, payload = post(stub, "/v1/messages", {**ANTHROPIC_TURN1, "stream": False})
        assert json.loads(payload)["stop_reason"] == "tool_use"
    assert [r["call_index"] for r in log_records(stub)] == [1, 2]


def test_max_calls_caps_tool_calls(tmp_path):
    with StubServer(Script.from_obj(SCRIPT), tmp_path / "r.jsonl", max_calls=1) as server:
        post(server, "/v1/messages", {**ANTHROPIC_TURN1, "stream": False})
        _, _, payload = post(server, "/v1/messages", {**ANTHROPIC_TURN1, "stream": False})
        assert json.loads(payload)["stop_reason"] == "end_turn"
        assert log_records(server)[-1]["decision"] == "text:call-budget-exhausted"


def test_log_redacts_credentials_in_headers_query_and_dumps(tmp_path):
    dump = tmp_path / "dump"
    with StubServer(Script.from_obj(SCRIPT), tmp_path / "r.jsonl", dump_dir=dump) as server:
        headers = {"x-api-key": FAKE_KEY, "Authorization": f"Bearer {FAKE_KEY}", "x-goog-api-key": FAKE_GOOGLE_KEY,
                   "Cookie": "session=abc", "User-Agent": "claude-cli/9.9.9 (external, cli)",
                   "anthropic-beta": "claude-code-20250219", "X-Odd": f"prefix {FAKE_GOOGLE_KEY}"}
        body = {**ANTHROPIC_TURN1, "stream": False,
                "messages": [{"role": "user", "content": f"my key is {FAKE_KEY}"}]}
        post(server, f"/v1/messages?key={FAKE_GOOGLE_KEY}&alt=sse", body, headers)
        text = server.log_path.read_text() + "".join(p.read_text() for p in dump.iterdir())
    for secret in (FAKE_KEY, FAKE_GOOGLE_KEY, "session=abc"):
        assert secret not in text
    record = json.loads(text.splitlines()[0])
    assert record["headers"]["x-api-key"].startswith("<redacted len=")
    assert record["headers"]["authorization"].startswith("<redacted")
    assert record["headers"]["x-odd"].startswith("<redacted"), "key-shaped values are redacted whatever the name"
    assert record["headers"]["user-agent"] == "claude-cli/9.9.9 (external, cli)", "version banners are kept"
    assert record["headers"]["anthropic-beta"] == "claude-code-20250219"
    assert record["query"] == "key=<redacted>&alt=sse"
    assert len(list(dump.iterdir())) == 1


def test_gzip_request_body_is_decoded(stub):
    raw = gzip.compress(json.dumps({**ANTHROPIC_TURN1, "stream": False}).encode())
    _, _, payload = post(stub, "/v1/messages", None, {"Content-Encoding": "gzip"}, raw=raw)
    assert json.loads(payload)["stop_reason"] == "tool_use"


def test_unreadable_and_unrouted_requests_are_logged_and_never_return_a_tool_call(stub):
    status, _, _ = post(stub, "/v1/messages", None, raw=b"not json")
    assert status == 400
    status, _, _ = post(stub, "/v1/messages", None, {"Content-Encoding": "br"}, raw=b"x")
    assert status == 400
    status, _, payload = post(stub, "/api/event_logging/batch", {"events": []})
    assert status == 404 and b"call" not in payload
    decisions = [r["decision"] for r in log_records(stub)]
    assert decisions == ["error", "error", "unrouted"]
    assert [r["status"] for r in log_records(stub)] == [400, 400, 404]


def test_get_models_and_head_are_answered(stub):
    conn = http.client.HTTPConnection("127.0.0.1", stub.port, timeout=10)
    conn.request("GET", "/v1/models")
    response = conn.getresponse()
    assert response.status == 200 and json.loads(response.read())["object"] == "list"
    conn.request("HEAD", "/")
    response = conn.getresponse()
    response.read()
    assert response.status == 404
    conn.close()


def test_server_binds_loopback_on_distinct_random_ports(tmp_path):
    with StubServer(Script.from_obj(SCRIPT), tmp_path / "a.jsonl") as one, \
            StubServer(Script.from_obj(SCRIPT), tmp_path / "b.jsonl") as two:
        assert one.httpd.server_address[0] == "127.0.0.1" == two.httpd.server_address[0]
        assert one.port != two.port and one.port > 0


# ---------------------------------------------------------------- script
def test_script_validation():
    with pytest.raises(ScriptError):
        Script.from_obj([])
    with pytest.raises(ScriptError):
        Script.from_obj({"nonce": "x", "unexpected": 1})
    with pytest.raises(ScriptError):
        Script.from_obj({"by_api": {"cursor": {"name": "x"}}})
    with pytest.raises(ScriptError):
        Script.from_obj({"call": {"name": "Bash", "args": "touch x"}})
    with pytest.raises(ScriptError):
        Script.from_obj({"call": {"name": ""}})
    with pytest.raises(ScriptError):
        Script.from_obj({"call": {"name": "Bash", "input": "freeform text is OpenAI-only"}})


def test_script_substitutes_nonce_everywhere_and_leaves_json_braces_alone():
    script = Script.from_obj({"nonce": "Z9", "call": {"name": "Bash", "args": {"command": "echo '{\"a\": 1}' > f-{nonce}",
                                                                              "list": ["{nonce}", 3]}}})
    call = script.call_for("anthropic")
    assert call.args == {"command": "echo '{\"a\": 1}' > f-Z9", "list": ["Z9", 3]}


def test_text_only_script_never_calls_a_tool(tmp_path):
    with StubServer(Script.from_obj({"nonce": NONCE}), tmp_path / "r.jsonl") as server:
        _, _, payload = post(server, "/v1/messages", {**ANTHROPIC_TURN1, "stream": False})
        assert json.loads(payload)["stop_reason"] == "end_turn"
        assert log_records(server)[0]["decision"] == "text:no-scripted-call"


# ---------------------------------------------------------------- module properties and the command line
def test_stub_imports_only_the_standard_library():
    tree = ast.parse(STUB_FILE.read_text())
    names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert names <= set(sys.stdlib_module_names) | {"compression"}, names - set(sys.stdlib_module_names)
    assert "intentshield" not in names


def test_stub_has_no_way_to_reach_out_or_run_code():
    tree = ast.parse(STUB_FILE.read_text())
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not imported & {"subprocess", "socket", "urllib.request", "http.client", "os", "shutil"}
    assert stub_model.HOST == "127.0.0.1"


def test_command_line_serves_and_writes_the_port_file(tmp_path):
    script = tmp_path / "script.json"
    script.write_text(json.dumps(SCRIPT))
    port_file, log = tmp_path / "port", tmp_path / "requests.jsonl"
    proc = subprocess.Popen([sys.executable, "-I", str(STUB_FILE), "--script", str(script), "--log", str(log),
                             "--port-file", str(port_file)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        banner = json.loads(proc.stdout.readline())
        assert banner["host"] == "127.0.0.1" and banner["url"] == f"http://127.0.0.1:{banner['port']}"
        assert int(port_file.read_text()) == banner["port"]
        conn = http.client.HTTPConnection("127.0.0.1", banner["port"], timeout=10)
        conn.request("POST", "/v1/messages", body=json.dumps({**ANTHROPIC_TURN1, "stream": False}),
                     headers={"Content-Type": "application/json"})
        assert json.loads(conn.getresponse().read())["stop_reason"] == "tool_use"
        conn.close()
        assert json.loads(log.read_text().splitlines()[0])["decision"] == "tool_call"
    finally:
        proc.terminate()
        proc.communicate(timeout=10)


def test_command_line_rejects_a_bad_script(tmp_path):
    script = tmp_path / "script.json"
    script.write_text(json.dumps({"call": {"name": "Bash", "args": []}}))
    done = subprocess.run([sys.executable, "-I", str(STUB_FILE), "--script", str(script),
                           "--log", str(tmp_path / "r.jsonl")], capture_output=True, text=True, timeout=30)
    assert done.returncode == 2 and "bad script" in done.stderr


# ---------------------------------------------------------------- build-critique fixes
def test_no_openai_body_carries_end_turn(stub):
    _, _, payload = post(stub, "/v1/responses", {**codex_turn1(), "stream": False})
    assert "end_turn" not in json.loads(payload)


def test_anthropic_stream_has_ping_after_message_start_and_cache_usage_fields(stub):
    _, _, payload = post(stub, "/v1/messages", ANTHROPIC_TURN1)
    events = sse_events(payload)
    assert [n for n, _ in events][:2] == ["message_start", "ping"]
    usage = events[0][1]["message"]["usage"]
    assert usage["cache_creation_input_tokens"] == 0 and usage["cache_read_input_tokens"] == 0


def test_chunked_request_body_is_decoded_not_treated_as_empty(stub):
    body = json.dumps({**ANTHROPIC_TURN1, "stream": False}).encode()
    conn = http.client.HTTPConnection("127.0.0.1", stub.port, timeout=10)
    conn.putrequest("POST", "/v1/messages")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Transfer-Encoding", "chunked")
    conn.endheaders()
    half = len(body) // 2
    for chunk in (body[:half], body[half:]):
        conn.send(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
    conn.send(b"0\r\n\r\n")
    response = conn.getresponse()
    payload = response.read()
    conn.close()
    assert response.status == 200 and json.loads(payload)["stop_reason"] == "tool_use"
    record = log_records(stub)[-1]
    assert record["body_bytes"] == len(body) and record["offered_tools"] == ["Bash", "mcp__notes__search_notes"]


def test_call_index_is_assigned_under_the_lock_and_distinct_under_concurrency(tmp_path):
    import threading
    with StubServer(Script.from_obj(SCRIPT), tmp_path / "r.jsonl") as server:
        threads = [threading.Thread(target=post, args=(server, "/v1/messages", {**ANTHROPIC_TURN1, "stream": False}))
                   for _ in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        indexes = sorted(r["call_index"] for r in log_records(server) if r.get("decision") == "tool_call")
    assert indexes == list(range(1, 9))


def test_command_line_default_issues_one_tool_call_only(tmp_path):
    script = tmp_path / "script.json"
    script.write_text(json.dumps(SCRIPT))
    log = tmp_path / "requests.jsonl"
    proc = subprocess.Popen([sys.executable, "-I", str(STUB_FILE), "--script", str(script), "--log", str(log)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        port = json.loads(proc.stdout.readline())["port"]
        answers = []
        for _ in range(2):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("POST", "/v1/messages", body=json.dumps({**ANTHROPIC_TURN1, "stream": False}),
                         headers={"Content-Type": "application/json"})
            answers.append(json.loads(conn.getresponse().read())["stop_reason"])
            conn.close()
        assert answers == ["tool_use", "end_turn"]
    finally:
        proc.terminate()
        proc.communicate(timeout=10)


def test_scrub_text_removes_email_and_home_path_and_dump_dir_is_restricted(tmp_path):
    text = stub_model.scrub_text("mail me at someone@example.com from /Users/somebody/project key sk-abcdefghijkl1234")
    assert "someone@example.com" not in text and "somebody" not in text and "sk-abcdefghijkl1234" not in text
    assert stub_model.dump_dir_allowed(tmp_path / "d")
    assert stub_model.dump_dir_allowed(Path("/work/repo/artifacts/dumps"))
    assert not stub_model.dump_dir_allowed(Path("/work/repo/results/dumps"))
    script = tmp_path / "script.json"
    script.write_text(json.dumps(SCRIPT))
    done = subprocess.run([sys.executable, "-I", str(STUB_FILE), "--script", str(script), "--log",
                           str(tmp_path / "r.jsonl"), "--dump-dir", "/work/repo/results/dumps"],
                          capture_output=True, text=True, timeout=30)
    assert done.returncode == 2 and "--dump-dir" in done.stderr


def test_tool_less_side_calls_log_what_they_were_about(stub):
    body = {"model": "m", "max_tokens": 5, "system": "Generate a title for mail to a@b.co",
            "messages": [{"role": "user", "content": "hi"}]}
    post(stub, "/v1/messages", body)
    record = log_records(stub)[-1]
    assert record["decision"] == "text:no-tools-offered" and record["side_call_head"].startswith("Generate a title")
    assert "a@b.co" not in record["side_call_head"]


# Plain-data contract: the fields the real clients' deserialisers require (written from the sources read in the task:
# Codex rust-v0.165.0 codex-api/src/sse/responses.rs and protocol ResponseItem; Gemini CLI v0.66.0 geminiChat.ts and
# turn.ts; the public Anthropic Messages streaming format). The pilot's pass criterion is the real client accepting the
# stream, not this test.
CONTRACT = {
    "codex_function_call_item": {"type", "id", "call_id", "name", "arguments"},
    "codex_custom_tool_call_item": {"type", "id", "call_id", "name", "input"},
    "codex_completed_response": {"id", "usage"},
    "codex_usage": {"input_tokens", "output_tokens", "total_tokens"},
    "anthropic_message_start": {"id", "type", "role", "model", "content", "usage"},
    "anthropic_tool_use_start": {"type", "id", "name", "input"},
}


def test_wire_shapes_carry_the_fields_the_clients_require(stub, tmp_path):
    events = sse_events(post(stub, "/v1/responses", codex_turn1())[2])
    item, completed = events[2][1]["item"], events[3][1]["response"]
    assert CONTRACT["codex_function_call_item"] <= set(item)
    assert CONTRACT["codex_completed_response"] <= set(completed) and CONTRACT["codex_usage"] <= set(completed["usage"])
    with StubServer(Script.from_obj({**SCRIPT, "by_api": {"openai": {"name": "apply_patch", "input": "*** Begin Patch"}}}),
                    tmp_path / "r2.jsonl") as server:
        custom = sse_events(post(server, "/v1/responses", codex_turn1())[2])[2][1]["item"]
    assert CONTRACT["codex_custom_tool_call_item"] <= set(custom)
    anth = sse_events(post(stub, "/v1/messages", ANTHROPIC_TURN1)[2])
    assert CONTRACT["anthropic_message_start"] <= set(anth[0][1]["message"])
    assert CONTRACT["anthropic_tool_use_start"] <= set(anth[2][1]["content_block"])  # after the ping
