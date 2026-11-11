"""A model-free stub model endpoint for the hook-fidelity study (arm S).

    stub_model.py --script script.json --log /abs/requests.jsonl [--port-file /abs/port] [--dump-dir /abs/dir]

Standard library only, bound to 127.0.0.1 on a random port (the chosen port is printed as one JSON line and written
to ``--port-file``). It speaks the minimum of three wire formats so that a coding-agent harness can be pointed at it
with a fake key and no network:

* Anthropic Messages, ``POST .../v1/messages`` (JSON or SSE), plus ``count_tokens``;
* OpenAI Responses, ``POST .../responses`` (SSE, as Codex CLI 0.165 sends it; Codex removed ``wire_api = "chat"``,
  so there is no Chat Completions route);
* Gemini ``models/<m>:generateContent`` and ``:streamGenerateContent`` (SSE with ``alt=sse``), plus ``:countTokens``.

Behaviour is a pure function of the request, so it holds across retries and extra side requests:

* a request that offers no tools gets a short text answer (title, summary and classifier calls);
* a request that carries a tool result gets a final text answer and the turn ends;
* any other request that offers tools gets exactly the one scripted tool call.

Every request is appended to the JSONL log with its headers redacted, the tool names the harness offered, whether the
scripted tool was among them, and the text of any tool result the harness sent back (which shows a hook's block
reason, or the command output). Nothing is sent anywhere and nothing is executed: the stub only returns JSON.

The script file::

    {"nonce": "abc123",
     "call": {"name": "Bash", "args": {"command": "touch ran-{nonce}.txt"}},
     "by_api": {"openai": {"name": "exec_command", "args": {"cmd": "touch ran-{nonce}.txt"}},
                "gemini": {"name": "run_shell_command", "args": {"command": "touch ran-{nonce}.txt"}}},
     "final_text": "stub done {nonce}"}

``by_api`` keys are ``anthropic``, ``openai`` and ``gemini``; an entry overrides fields of ``call``. For the OpenAI
API a call may carry ``namespace`` (Codex exposes MCP tools as the namespace ``mcp__<server>__`` plus the bare tool
name). ``{nonce}`` is replaced in every string. ``call`` may be omitted for a text-only stub.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
import threading
import time
import zlib
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

try:  # Python 3.14+; Codex only compresses for its own backend, so this is a convenience
    from compression import zstd as _zstd  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - depends on the interpreter
    _zstd = None

HOST = "127.0.0.1"
APIS = ("anthropic", "openai", "gemini")
DEFAULT_FINAL_TEXT = "stub done {nonce}"
NO_TOOLS_TEXT = "stub ok"
MAX_BODY = 64 * 1024 * 1024
RESULT_TEXT_CHARS = 300

_SECRET_NAME = re.compile(r"auth|key|token|secret|cookie|session-token|account|user-id|signature", re.I)
_SECRET_VALUE = re.compile(r"sk-[A-Za-z0-9_-]{10,}|AIza[0-9A-Za-z_-]{20,}|Bearer\s+\S+", re.I)
_SECRET_QUERY = re.compile(r"key|token|secret|auth", re.I)


# --- script ---------------------------------------------------------------------------------------------------

class ScriptError(ValueError):
    pass


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: dict
    namespace: str | None = None
    freeform: str | None = None  # OpenAI only: the raw input of a freeform ("custom") tool such as Codex's apply_patch

    def offered_name(self) -> str:
        """The name as it appears in the harness's offered-tool list."""
        return f"{self.namespace}{self.name}" if self.namespace else self.name


@dataclass(frozen=True)
class Script:
    nonce: str = ""
    call: dict | None = None
    by_api: dict = field(default_factory=dict)
    final_text: str = DEFAULT_FINAL_TEXT

    @classmethod
    def from_obj(cls, obj: object) -> "Script":
        if not isinstance(obj, dict):
            raise ScriptError("script must be a JSON object")
        unknown = set(obj) - {"nonce", "call", "by_api", "final_text"}
        if unknown:
            raise ScriptError(f"unknown script keys: {sorted(unknown)}")
        nonce = obj.get("nonce", "")
        if not isinstance(nonce, str):
            raise ScriptError("nonce must be a string")
        call = obj.get("call")
        by_api = obj.get("by_api", {})
        if not isinstance(by_api, dict) or set(by_api) - set(APIS):
            raise ScriptError(f"by_api keys must be among {APIS}")
        final_text = obj.get("final_text", DEFAULT_FINAL_TEXT)
        if not isinstance(final_text, str):
            raise ScriptError("final_text must be a string")
        script = cls(nonce=nonce, call=call, by_api=by_api, final_text=final_text)
        for api in APIS:  # fail at startup, not on the first request
            script.call_for(api)
        return script

    @classmethod
    def load(cls, path: Path) -> "Script":
        return cls.from_obj(json.loads(path.read_text()))

    def text(self) -> str:
        return _subst(self.final_text, self.nonce)

    def call_for(self, api: str) -> ToolCall | None:
        if self.call is None and api not in self.by_api:
            return None
        merged = {**(self.call or {}), **self.by_api.get(api, {})}
        if merged.get("name") is None:
            return None
        if not isinstance(merged["name"], str) or not merged["name"]:
            raise ScriptError(f"{api}: call name must be a non-empty string")
        args = merged.get("args", {})
        if not isinstance(args, dict):
            raise ScriptError(f"{api}: call args must be an object")
        namespace = merged.get("namespace")
        if namespace is not None and not isinstance(namespace, str):
            raise ScriptError(f"{api}: namespace must be a string")
        freeform = merged.get("input")
        if freeform is not None and (not isinstance(freeform, str) or api != "openai"):
            raise ScriptError(f"{api}: input is a string and only valid for the openai API")
        return ToolCall(_subst(merged["name"], self.nonce), _subst(args, self.nonce),
                        _subst(namespace, self.nonce) if namespace else None,
                        _subst(freeform, self.nonce) if freeform is not None else None)


def _subst(value, nonce: str):
    """Replace ``{nonce}`` in every string, without ``str.format`` (JSON braces stay as they are)."""
    if isinstance(value, str):
        return value.replace("{nonce}", nonce)
    if isinstance(value, dict):
        return {k: _subst(v, nonce) for k, v in value.items()}
    if isinstance(value, list):
        return [_subst(v, nonce) for v in value]
    return value


# --- redaction ------------------------------------------------------------------------------------------------

def redact_headers(headers) -> dict[str, str]:
    """Header map for the log: values of anything credential-shaped become ``<redacted len=N>``."""
    out: dict[str, str] = {}
    for name, value in headers.items():
        lowered = name.lower()
        if _SECRET_NAME.search(lowered) or _SECRET_VALUE.search(value):
            out[lowered] = f"<redacted len={len(value)}>"
        else:
            out[lowered] = value
    return out


def redact_query(query: str) -> str:
    pairs = [(k, "<redacted>" if _SECRET_QUERY.search(k) else v) for k, v in parse_qsl(query, keep_blank_values=True)]
    return "&".join(f"{k}={v}" for k, v in pairs)


_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_HOME_PATH = re.compile(r"/(?:Users|home)/[^/\s\"']+")


def scrub_text(text: str) -> str:
    """Key-shaped strings, e-mail addresses and home-directory paths removed (a request body carries the system prompt
    and any memory or settings text the harness loaded)."""
    return _HOME_PATH.sub("/<user>", _EMAIL.sub("<email>", _SECRET_VALUE.sub("<redacted>", text)))


def _texts(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [t for v in value for t in _texts(v)]
    if isinstance(value, dict):
        return [t for k in ("text", "content", "parts", "input_text") if k in value for t in _texts(value[k])]
    return []


def head_text(body: dict, limit: int = 160) -> str:
    """First characters of the system text, else of the last message: what a tool-less side call was about."""
    for key in ("system", "instructions", "systemInstruction", "system_instruction"):
        text = " ".join(_texts(body.get(key))).strip()
        if text:
            return scrub_text(text)[:limit]
    for key in ("messages", "input", "contents"):
        items = body.get(key)
        if isinstance(items, list) and items:
            text = " ".join(_texts(items[-1])).strip()
            if text:
                return scrub_text(text)[:limit]
    return ""


def locate_markers(body: dict, markers: list[str]) -> dict[str, list[str]]:
    """Where each marker string occurs in a request body: the top-level key, and for the list-valued conversation keys
    (``messages``, ``input``, ``contents``) the role and block type of the item, for example ``messages[user:tool_result]``
    or ``contents[user:functionResponse]``. Used by the coverage study to show what the model was sent: a marker under
    ``tools`` was in a tool declaration, one under a tool-result block came back from a tool, one under ``system`` was
    in the system prompt. A marker that is absent from the body is absent from the result."""
    hits: dict[str, set[str]] = {}

    def note(label: str, value) -> None:
        text = json.dumps(value, ensure_ascii=False)
        for marker in markers:
            if marker in text:
                hits.setdefault(marker, set()).add(label)

    for key, value in body.items():
        if key not in ("messages", "input", "contents") or not isinstance(value, list):
            note(key, value)
            continue
        for item in value:
            if not isinstance(item, dict):
                note(f"{key}[str]", item)
                continue
            role = str(item.get("role") or item.get("type") or "")
            pieces = item.get("content", item.get("parts"))
            if not isinstance(pieces, list):
                note(f"{key}[{role}:{item.get('type', 'text')}]", item)
                continue
            for piece in pieces:
                if isinstance(piece, dict):
                    kind = str(piece["type"]) if "type" in piece else next(
                        (k for k in ("functionResponse", "functionCall", "text") if k in piece), "?")
                else:
                    kind = "str"
                note(f"{key}[{role}:{kind}]", piece)
    return {m: sorted(v) for m, v in hits.items()}


# --- request analysis -----------------------------------------------------------------------------------------

@dataclass
class Analysis:
    api: str
    model: str = ""
    stream: bool = False
    offered: list[str] = field(default_factory=list)
    has_result: bool = False
    results: list[dict] = field(default_factory=list)
    n_messages: int = 0
    call_index: int = 0       # the index decide() assigned to the scripted call, taken under the lock
    head: str = ""            # first characters of the system or last user text (for tool-less side calls)


def _clip(text: str) -> str:
    return text if len(text) <= RESULT_TEXT_CHARS else text[:RESULT_TEXT_CHARS] + "..."


def _stringify(value) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def analyse_anthropic(body: dict) -> Analysis:
    a = Analysis("anthropic", model=str(body.get("model", "")), stream=bool(body.get("stream")))
    a.offered = [t["name"] for t in body.get("tools") or [] if isinstance(t, dict) and isinstance(t.get("name"), str)]
    messages = body.get("messages") or []
    a.n_messages = len(messages)
    for message in messages:
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_result":
                inner = block.get("content", "")
                if isinstance(inner, list):
                    inner = " ".join(b.get("text", "") for b in inner if isinstance(b, dict))
                a.results.append({"is_error": bool(block.get("is_error")), "text": _clip(_stringify(inner))})
    a.has_result = bool(a.results)
    return a


def _openai_offered(tools) -> list[str]:
    out: list[str] = []
    for tool in tools or []:
        if not isinstance(tool, dict):
            continue
        if tool.get("type") == "namespace":
            ns = str(tool.get("name", ""))
            out.extend(f"{ns}{inner.get('name', '')}" for inner in tool.get("tools") or [] if isinstance(inner, dict))
        else:
            out.append(str(tool.get("name") or tool.get("type") or "?"))
    return out


def analyse_openai(body: dict) -> Analysis:
    a = Analysis("openai", model=str(body.get("model", "")), stream=bool(body.get("stream")))
    a.offered = _openai_offered(body.get("tools"))
    items = body.get("input") or []
    if isinstance(items, str):
        items = []
    a.n_messages = len(items)
    for item in items:
        if isinstance(item, dict) and str(item.get("type", "")).endswith("_output"):
            a.results.append({"is_error": None, "text": _clip(_stringify(item.get("output", "")))})
    a.has_result = bool(a.results)
    return a


def analyse_gemini(body: dict, model: str, stream: bool) -> Analysis:
    a = Analysis("gemini", model=model, stream=stream)
    for tool in body.get("tools") or []:
        if isinstance(tool, dict):
            a.offered.extend(d["name"] for d in tool.get("functionDeclarations") or []
                             if isinstance(d, dict) and isinstance(d.get("name"), str))
    contents = body.get("contents") or []
    a.n_messages = len(contents)
    for content in contents:
        for part in (content.get("parts") or []) if isinstance(content, dict) else []:
            response = part.get("functionResponse") if isinstance(part, dict) else None
            if isinstance(response, dict):
                payload = response.get("response", {})
                a.results.append({"is_error": isinstance(payload, dict) and "error" in payload,
                                  "text": _clip(_stringify(payload))})
    a.has_result = bool(a.results)
    return a


# --- response bodies ------------------------------------------------------------------------------------------

def _sse(events: list[tuple[str | None, dict]], crlf: bool = False) -> bytes:
    sep = "\r\n" if crlf else "\n"
    chunks = []
    for name, data in events:
        head = f"event: {name}{sep}" if name else ""
        chunks.append(f"{head}data: {json.dumps(data, separators=(',', ':'))}{sep}{sep}")
    return "".join(chunks).encode()


def anthropic_response(a: Analysis, call: ToolCall | None, text: str, seq: int) -> tuple[bytes, str]:
    mid = f"msg_stub_{seq}"
    usage_in = {"input_tokens": 1, "output_tokens": 1, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
    if call:
        block = {"type": "tool_use", "id": f"toolu_stub_{seq}", "name": call.name, "input": call.args}
        stop = "tool_use"
    else:
        block = {"type": "text", "text": text}
        stop = "end_turn"
    if not a.stream:
        message = {"id": mid, "type": "message", "role": "assistant", "model": a.model, "content": [block],
                   "stop_reason": stop, "stop_sequence": None, "usage": usage_in}
        return json.dumps(message).encode(), "application/json"
    start_block = {**block, "input": {}} if call else {"type": "text", "text": ""}
    delta = ({"type": "input_json_delta", "partial_json": json.dumps(call.args)} if call
             else {"type": "text_delta", "text": text})
    events: list[tuple[str | None, dict]] = [
        ("message_start", {"type": "message_start", "message": {
            "id": mid, "type": "message", "role": "assistant", "model": a.model, "content": [],
            "stop_reason": None, "stop_sequence": None, "usage": usage_in}}),
        ("ping", {"type": "ping"}),
        ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": start_block}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": delta}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                           "usage": {"output_tokens": 1}}),
        ("message_stop", {"type": "message_stop"}),
    ]
    return _sse(events), "text/event-stream"


def openai_response(a: Analysis, call: ToolCall | None, text: str, seq: int) -> tuple[bytes, str]:
    rid = f"resp_stub_{seq}"
    usage = {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}
    if call:
        item_id = f"fc_stub_{seq}"
        if call.freeform is not None:
            item: dict = {"type": "custom_tool_call", "id": item_id, "call_id": f"call_stub_{seq}", "name": call.name,
                          "input": call.freeform, "status": "completed"}
            added = {**item, "input": "", "status": "in_progress"}
        else:
            item = {"type": "function_call", "id": item_id, "call_id": f"call_stub_{seq}", "name": call.name,
                    "arguments": json.dumps(call.args), "status": "completed"}
            added = {**item, "arguments": "", "status": "in_progress"}
        if call.namespace:
            item["namespace"] = call.namespace
            added["namespace"] = call.namespace
    else:
        item_id = f"msg_stub_{seq}"
        item = {"type": "message", "id": item_id, "role": "assistant", "status": "completed",
                "content": [{"type": "output_text", "text": text, "annotations": []}]}
        added = {**item, "status": "in_progress", "content": []}
    output = [item]
    if not a.stream:
        body = {"id": rid, "object": "response", "status": "completed", "model": a.model, "output": output,
                "usage": usage}
        return json.dumps(body).encode(), "application/json"
    events: list[tuple[str | None, dict]] = [
        ("response.created", {"type": "response.created", "response": {"id": rid, "status": "in_progress"}}),
        ("response.output_item.added", {"type": "response.output_item.added", "output_index": 0, "item": added}),
    ]
    if not call:
        events.append(("response.output_text.delta", {"type": "response.output_text.delta", "item_id": item_id,
                                                      "output_index": 0, "content_index": 0, "delta": text}))
    events += [
        ("response.output_item.done", {"type": "response.output_item.done", "output_index": 0, "item": item}),
        ("response.completed", {"type": "response.completed", "response": {
            "id": rid, "object": "response", "status": "completed", "model": a.model, "output": output,
            "usage": usage}}),
    ]
    for number, (_, data) in enumerate(events):
        data["sequence_number"] = number
    return _sse(events), "text/event-stream"


def gemini_response(a: Analysis, call: ToolCall | None, text: str, seq: int, sse: bool) -> tuple[bytes, str]:
    part = {"functionCall": {"name": call.name, "args": call.args}} if call else {"text": text}
    chunk = {"candidates": [{"content": {"role": "model", "parts": [part]}, "finishReason": "STOP", "index": 0}],
             "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2},
             "modelVersion": a.model, "responseId": f"resp_stub_{seq}"}
    if a.stream and sse:
        return _sse([(None, chunk)], crlf=True), "text/event-stream"
    if a.stream:  # streamGenerateContent without alt=sse is a JSON array of chunks
        return json.dumps([chunk]).encode(), "application/json"
    return json.dumps(chunk).encode(), "application/json"


# --- routing --------------------------------------------------------------------------------------------------

_GEMINI_PATH = re.compile(r"/models/([^/:]+):([A-Za-z]+)$")


def route(method: str, path: str) -> tuple[str, str, str]:
    """(api, kind, model) for a request path; api is ``""`` when nothing matches."""
    p = urlsplit(path).path.rstrip("/")
    if method == "POST":
        if p.endswith("/messages/count_tokens"):
            return "anthropic", "count", ""
        if p.endswith("/messages"):
            return "anthropic", "generate", ""
        if p.endswith("/responses"):
            return "openai", "generate", ""
        match = _GEMINI_PATH.search(p)
        if match:
            verb = match.group(2)
            if verb in ("generateContent", "streamGenerateContent"):
                return "gemini", verb, match.group(1)
            if verb == "countTokens":
                return "gemini", "count", match.group(1)
    elif method == "GET" and p.endswith("/models"):
        return "any", "models", ""
    return "", "", ""


# --- server ---------------------------------------------------------------------------------------------------

class _Server(ThreadingHTTPServer):
    request_queue_size = 128  # a burst of side requests must not be reset by the default backlog of 5
    daemon_threads = True


class StubServer:
    """The stub. ``start()`` serves on a background thread (tests); ``serve_forever()`` blocks (the CLI)."""

    def __init__(self, script: Script, log_path: Path, dump_dir: Path | None = None, port: int = 0,
                 max_calls: int = 0, markers: list[str] | None = None) -> None:
        self.script = script
        self.markers = list(markers or [])
        self.log_path = Path(log_path)
        self.dump_dir = Path(dump_dir) if dump_dir else None
        self.max_calls = max_calls
        self.calls_issued = 0
        self.requests = 0
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if self.dump_dir:
            self.dump_dir.mkdir(parents=True, exist_ok=True)
        self.httpd = _Server((HOST, port), _make_handler(self))
        self.httpd.daemon_threads = True

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    @property
    def url(self) -> str:
        return f"http://{HOST}:{self.port}"

    def start(self) -> "StubServer":
        self._thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        self.httpd.serve_forever()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)

    def __enter__(self) -> "StubServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- behaviour --

    def decide(self, a: Analysis) -> tuple[ToolCall | None, str]:
        """The one scripted call, or None with the reason a text answer is given instead."""
        call = self.script.call_for(a.api)
        if not a.offered:
            return None, "text:no-tools-offered"
        if a.has_result:
            return None, "text:after-tool-result"
        if call is None:
            return None, "text:no-scripted-call"
        with self._lock:
            if self.max_calls and self.calls_issued >= self.max_calls:
                return None, "text:call-budget-exhausted"
            self.calls_issued += 1
            a.call_index = self.calls_issued
        return call, "tool_call"

    def next_seq(self) -> int:
        with self._lock:
            self.requests += 1
            return self.requests

    def log(self, record: dict) -> None:
        line = json.dumps(record, ensure_ascii=False)
        with self._lock:
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()


def _read_chunked(handler: BaseHTTPRequestHandler) -> tuple[bytes, str | None]:
    """A Transfer-Encoding: chunked body, decoded (a client that streams its request body is not treated as empty)."""
    out = bytearray()
    while True:
        size_line = handler.rfile.readline(1024).split(b";", 1)[0].strip()
        try:
            size = int(size_line or b"0", 16)
        except ValueError:
            return b"", "bad chunk size"
        if size == 0:
            while handler.rfile.readline(1024).strip():  # trailers
                pass
            return bytes(out), None
        if len(out) + size > MAX_BODY:
            return b"", "body too large"
        out += handler.rfile.read(size)
        handler.rfile.readline(4)  # the CRLF after the chunk


def _read_body(handler: BaseHTTPRequestHandler) -> tuple[bytes, str | None]:
    """The decoded request body, or (b"", reason) when it cannot be read."""
    if "chunked" in (handler.headers.get("Transfer-Encoding") or "").lower():
        raw, problem = _read_chunked(handler)
        if problem:
            return b"", problem
    else:
        try:
            length = int(handler.headers.get("Content-Length") or 0)
        except ValueError:
            return b"", "bad Content-Length"
        if length > MAX_BODY:
            return b"", "body too large"
        raw = handler.rfile.read(length) if length else b""
    encoding = (handler.headers.get("Content-Encoding") or "identity").lower()
    try:
        if encoding in ("", "identity"):
            return raw, None
        if encoding in ("gzip", "x-gzip"):
            return zlib.decompress(raw, 16 + zlib.MAX_WBITS), None
        if encoding == "deflate":
            return zlib.decompress(raw), None
        if encoding == "zstd" and _zstd is not None:
            return _zstd.decompress(raw), None
    except Exception as exc:
        return b"", f"cannot decode {encoding} body: {type(exc).__name__}"
    return b"", f"unsupported Content-Encoding {encoding}"


def _make_handler(server: StubServer):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args) -> None:  # silence the default stderr line per request
            pass

        def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _error(self, status: int, message: str) -> None:
            self._send(status, json.dumps({"error": {"type": "stub_error", "message": message}}).encode())

        def do_HEAD(self) -> None:
            self._handle()

        def do_GET(self) -> None:
            self._handle()

        def do_POST(self) -> None:
            self._handle()

        def do_OPTIONS(self) -> None:
            self._handle()

        def _handle(self) -> None:
            seq = server.next_seq()
            split = urlsplit(self.path)
            record: dict = {"seq": seq, "ts_ns": time.time_ns(), "method": self.command, "path": split.path,
                            "query": redact_query(split.query), "headers": redact_headers(self.headers),
                            "script_nonce": server.script.nonce}
            raw, problem = _read_body(self) if self.command == "POST" else (b"", None)
            record["body_bytes"] = len(raw)
            record["body_sha256"] = hashlib.sha256(raw).hexdigest()
            api, kind, model = route(self.command, self.path)
            record["api"] = api or None
            record["kind"] = kind or None
            try:
                status, body, ctype = self._respond(record, api, kind, model, raw, problem, split.query, seq)
            except Exception as exc:
                record["decision"] = "error"
                record["error"] = f"{type(exc).__name__}: {exc}"
                status, body, ctype = 500, json.dumps({"error": {"type": "stub_error", "message": str(exc)}}).encode(), \
                    "application/json"
            record["status"] = status
            server.log(record)
            if server.dump_dir and raw:
                text = scrub_text(raw.decode("utf-8", "replace"))
                (server.dump_dir / f"req-{seq:04d}.json").write_text(
                    json.dumps({"record": record, "body": text}, ensure_ascii=False))
            self._send(status, body, ctype)

        def _respond(self, record, api, kind, model, raw, problem, query, seq):
            if kind == "models":
                return 200, json.dumps({"object": "list", "data": [], "models": []}).encode(), "application/json"
            if not api:
                record["decision"] = "unrouted"
                return 404, json.dumps({"error": {"type": "not_found", "message": "stub: unrouted"}}).encode(), \
                    "application/json"
            if problem:
                record["decision"] = "error"
                record["error"] = problem
                return 400, json.dumps({"error": {"type": "stub_error", "message": problem}}).encode(), \
                    "application/json"
            try:
                body = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                record["decision"] = "error"
                record["error"] = "request body is not JSON"
                return 400, json.dumps({"error": {"type": "stub_error", "message": "not JSON"}}).encode(), \
                    "application/json"
            if not isinstance(body, dict):
                body = {}
            if kind == "count":
                record["decision"] = "count"
                payload = {"input_tokens": 1} if api == "anthropic" else {"totalTokens": 1}
                return 200, json.dumps(payload).encode(), "application/json"
            if api == "anthropic":
                a = analyse_anthropic(body)
            elif api == "openai":
                a = analyse_openai(body)
            else:
                a = analyse_gemini(body, model, stream=(kind == "streamGenerateContent"))
            if server.markers:
                record["marker_hits"] = locate_markers(body, server.markers)
            call, reason = server.decide(a)
            record.update({"model": a.model, "stream": a.stream, "offered_tools": a.offered,
                           "n_messages": a.n_messages, "has_tool_result": a.has_result,
                           "tool_results": a.results, "decision": reason})
            if reason == "text:no-tools-offered":
                record["side_call_head"] = head_text(body)
            if call:
                record["scripted_tool"] = {"name": call.name, "namespace": call.namespace, "args": call.args,
                                           "freeform": call.freeform}
                record["scripted_tool_offered"] = call.offered_name() in a.offered
                record["call_index"] = a.call_index
            text = NO_TOOLS_TEXT if reason == "text:no-tools-offered" else server.script.text()
            if api == "anthropic":
                payload, ctype = anthropic_response(a, call, text, seq)
            elif api == "openai":
                payload, ctype = openai_response(a, call, text, seq)
            else:
                payload, ctype = gemini_response(a, call, text, seq, sse="alt=sse" in query)
            return 200, payload, ctype

    return Handler


def dump_dir_allowed(path: Path) -> bool:
    """Request dumps may hold personal text, so they go only where nothing is committed: an ``artifacts`` directory
    (gitignored in this repo) or a temp directory."""
    resolved = Path(path).resolve()
    temps = {Path(t).resolve() for t in ("/tmp", "/private/tmp", tempfile.gettempdir())}
    return "artifacts" in resolved.parts or any(t == resolved or t in resolved.parents for t in temps)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--script", required=True, type=Path, help="JSON script: the one tool call and the final text")
    parser.add_argument("--log", required=True, type=Path, help="absolute path of the JSONL request log")
    parser.add_argument("--port", type=int, default=0, help="0 picks a random free port (default)")
    parser.add_argument("--port-file", type=Path, help="write the chosen port here once the socket is bound")
    parser.add_argument("--dump-dir", type=Path, help="also write each request body (keys, e-mail addresses and home paths "
                        "scrubbed); off by default, and only under an `artifacts` directory or a temp directory")
    parser.add_argument("--max-calls", type=int, default=1,
                        help="stop issuing tool calls after N; 1 by default so that a re-sample after a block or a side "
                             "request cannot run the scripted call twice (0 = unlimited)")
    parser.add_argument("--markers", default="",
                        help="comma-separated strings to look for in every request body; the log gets `marker_hits`")
    args = parser.parse_args(argv)
    try:
        script = Script.load(args.script)
    except (OSError, ValueError) as exc:
        print(f"stub_model: bad script: {exc}", file=sys.stderr)
        return 2
    if args.dump_dir and not dump_dir_allowed(args.dump_dir):
        print("stub_model: --dump-dir must be under a directory named `artifacts` (gitignored) or a temp directory",
              file=sys.stderr)
        return 2
    stub = StubServer(script, args.log, args.dump_dir, args.port, args.max_calls,
                      [m for m in args.markers.split(",") if m])
    if args.port_file:
        args.port_file.write_text(str(stub.port))
    print(json.dumps({"host": HOST, "port": stub.port, "url": stub.url}), flush=True)
    try:
        stub.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stub.httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
