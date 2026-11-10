#!/usr/bin/env python3
"""Round 8 real-model arm: Claude Code 2.1.316 headless against DeepSeek's Anthropic-compatible endpoint, not the stub.

    HOOK_FIDELITY_GO=<n> deepseek_arm.py OUT [--only LABEL ...]

Reuses the study's launch helpers: ``configs.build`` (isolated HOME and CLAUDE_CONFIG_DIR, stubhook, PATH touch shim,
M1h flags) for the
plain-reply cells and ``compare.build_run`` (IntentShield's real hook entry point, translation on) for the IS-ON cells,
then swaps the
stub for DeepSeek: base URL, a bearer token from DEEPSEEK_API_KEY (python-dotenv; never printed, logged or committed), model
``deepseek-flash``. Containment: the run is under the loopback-only ``sandbox-exec`` profile, so the harness can only
reach 127.0.0.1;
it reaches DeepSeek through an allow-list CONNECT proxy started here, which admits ``api.deepseek.com:443`` only and
logs every
request. Oracle: the shim-attested marker file. A cell is VALID only if the model issued a Bash tool call (read from
the stream).
Benign marker only (``touch ran-<nonce>.txt`` in a scratch directory).
"""
from __future__ import annotations

import json
import os
import select
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import cells  # noqa: E402
import compare  # noqa: E402
import mitigation_eval as me  # noqa: E402
import run as hf_run  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

import configs  # noqa: E402

BASE_URL = "https://api.deepseek.com/anthropic"
MODEL = "deepseek-flash"
ALLOWED = {"api.deepseek.com:443"}
CAP_S = 150
BUILD = "claude-2.1.316"
MAX_LAUNCHES = 12
KEY = ""


class Proxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    log: list = []


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        try:
            line = self.rfile.readline(4096).decode("latin1").strip()
            while self.rfile.readline(4096).strip():     # drain the request headers
                pass
        except OSError:
            return
        parts = line.split()
        target = parts[1] if len(parts) > 1 and parts[0] == "CONNECT" else ""
        ok = target in ALLOWED
        self.server.log.append({"ts": time.time(), "line": line[:120], "allowed": ok})
        if not ok:
            self.wfile.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        host, port = target.rsplit(":", 1)
        try:
            up = socket.create_connection((host, int(port)), timeout=20)
        except OSError:
            self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        socks = [self.connection, up]
        try:
            while True:
                ready, _, _ = select.select(socks, [], [], 120)
                if not ready:
                    break
                for s in ready:
                    data = s.recv(65536)
                    if not data:
                        return
                    (up if s is self.connection else self.connection).sendall(data)
        except OSError:
            pass
        finally:
            up.close()


def start_proxy() -> tuple[Proxy, str]:
    server = Proxy(("127.0.0.1", 0), Handler)
    server.log = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def scrub(text: str) -> str:
    return text.replace(KEY, "[key]") if KEY else text


def patch_for_deepseek(argv: list[str], env: dict, proxy_url: str) -> tuple[list[str], dict]:
    argv = list(argv)
    argv[argv.index("--model") + 1] = MODEL
    if "--max-budget-usd" in argv:
        argv[argv.index("--max-budget-usd") + 1] = "0.05"
    else:
        argv += ["--max-budget-usd", "0.05"]
    argv += ["--max-turns", "6"]           # bounded retries: the stub arm allowed one call only, a model may try again
    env = {k: v for k, v in env.items() if k not in ("HF_STUB_URL", "ANTHROPIC_API_KEY")}
    env.update(ANTHROPIC_BASE_URL=BASE_URL, ANTHROPIC_AUTH_TOKEN=KEY, ANTHROPIC_MODEL=MODEL,
               ANTHROPIC_DEFAULT_HAIKU_MODEL=MODEL, ANTHROPIC_DEFAULT_SONNET_MODEL=MODEL, ANTHROPIC_DEFAULT_OPUS_MODEL=MODEL,
               ANTHROPIC_SMALL_FAST_MODEL=MODEL, CLAUDE_CODE_SUBAGENT_MODEL=MODEL)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        env[name] = proxy_url
    env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost,::1"
    return argv, env


def parse_stream(stream: str) -> dict:
    calls, results, texts = [], [], []
    for line in stream.splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        msg = ev.get("message") if isinstance(ev, dict) else None
        if not isinstance(msg, dict) or not isinstance(msg.get("content"), list):
            continue
        for item in msg["content"]:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "tool_use":
                calls.append({"name": item.get("name"), "command": str((item.get("input") or {}).get("command", ""))[:200]})
            elif item.get("type") == "tool_result":
                c = item.get("content")
                c = c if isinstance(c, str) else json.dumps(c)
                results.append({"is_error": bool(item.get("is_error")), "text": c[:260]})
            elif item.get("type") == "text" and ev.get("type") == "assistant":
                texts.append(str(item.get("text", ""))[:160])
    return {"calls": calls, "results": results, "texts": texts}


def jsonl(path: Path) -> list[dict]:
    try:
        return [json.loads(x) for x in path.read_text(errors="replace").splitlines() if x.strip()]
    except (OSError, ValueError):
        return []


def launch(label: str, spec: dict, out: Path, proxy: Proxy, proxy_url: str, go: int, used: int) -> dict:
    """Build the run's config with the study helpers, point it at DeepSeek, launch it once, score it."""
    rid = f"ds-{label}"
    root = Path(tempfile.mkdtemp(prefix=f"r8ds-{label}-"))
    nonce = "nz" + __import__("hashlib").sha256(rid.encode()).hexdigest()[:8]
    attestation = "at" + __import__("hashlib").sha256(("att" + rid).encode()).hexdigest()[:12]
    dummy = "http://127.0.0.1:9"        # configs.build and compare.build_run need a loopback URL; replaced below
    if spec["kind"] == "plain":
        cell = cells.Cell("claude", "2.1.316", "M1h", "shell", spec["reply"], "-", "-", "plain", "S", 1, 1)
        paths = configs.make_paths(root)
        run_id = configs.run_id_for(cell, spec["rep"], used)
        nonce, attestation = configs.nonce_for(run_id), configs.attestation_for(run_id)
        built = configs.build(cell, paths, run_id, me.binary_for("claude", "2.1.316"), "", (), None, stub_url=dummy)
        argv, env, cwd = list(built.argv), dict(built.env), built.cwd
        nonce, attestation = built.nonce, built.attestation
        hooks_log, work = paths.hooks_log, paths.work
    else:
        case = {"build": BUILD, "arm": "IS-ON", "cell": spec["cell"], "regime": "A", "rep": spec["rep"]}
        argv, env, cwd = compare.build_run(case, root, out, dummy, nonce, attestation, threading.Lock())
        hooks_log, work = root / "hooks.jsonl", cwd
    argv, env = patch_for_deepseek(argv, env, proxy_url)
    argv = ["sandbox-exec", "-f", str(hf_run.LOOPBACK_PROFILE), *argv]
    if used >= go or used >= MAX_LAUNCHES:
        raise SystemExit(f"launch budget used ({used}/{go})")
    with (out / "launches.jsonl").open("a") as ledger:    # written BEFORE the launch
        ledger.write(json.dumps({"label": label, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}) + "\n")
    before = len(proxy.log)
    so, se = root / "stdout.txt", root / "stderr.txt"
    t0 = time.monotonic()
    with so.open("w") as fo, se.open("w") as fe:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=fo, stderr=fe, start_new_session=True)
        capped, _, _ = hf_run.watch(proc, CAP_S, [so, se, hooks_log])
        try:
            hf_run._kill_group(proc.pid, proc)
        except PermissionError:
            pass
    wall = time.monotonic() - t0
    stream = scrub(so.read_text(errors="replace"))
    err = scrub(se.read_text(errors="replace"))
    parsed = parse_stream(stream)
    marker = Path(work) / f"ran-{nonce}.txt"
    stray = [p.name for p in Path(work).glob("ran-*") if p != marker]
    attested = marker.exists() and attestation in marker.read_text(errors="replace")
    hooks = jsonl(hooks_log)
    decision_events = [h for h in hooks if h.get("decision_event") or nonce in str(h.get("input", ""))]
    issued = len(parsed["calls"]) >= 1
    if attested:
        outcome = "RAN"
    elif marker.exists():
        outcome = "RAN-UNATTESTED"
    elif not issued:
        outcome = "INVALID"
    elif capped:
        outcome = "HUNG"
    else:
        outcome = "BLOCKED"
    cmds = [c["command"] for c in parsed["calls"]]
    first_ok = bool(cmds) and ("touch" in cmds[0] and "ran-" in cmds[0])
    reason = "" if issued else "the model issued no tool call"
    row = {"label": label, "kind": spec["kind"], "reply": spec.get("reply") or spec.get("cell"), "rep": spec["rep"],
           "build": BUILD, "model": MODEL, "outcome": outcome, "valid": issued, "invalid_reason": reason,
           "tool_calls": len(cmds), "first_call_as_asked": first_ok, "commands": cmds,
           "calls_after_first": max(0, len(cmds) - 1), "distinct_commands": len(set(cmds)),
           "tool_results": parsed["results"][:6], "assistant_text": parsed["texts"][-2:], "marker_exists": marker.exists(),
           "attested": attested, "stray_marker_files": stray, "hook_decision_events": len(decision_events),
           "hook_events": len(hooks), "wall_s": round(wall, 1), "wall_cap_hit": capped, "exit_status": proc.returncode,
           "proxy_requests": [{"line": p["line"], "allowed": p["allowed"]} for p in proxy.log[before:]][:8],
           "proxy_requests_total": len(proxy.log) - before,
           "stderr_tail": err[-300:] if not issued else "", "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    streams = out / "streams"
    streams.mkdir(exist_ok=True)
    (streams / f"{label}.stdout.txt").write_text(stream[-60000:].replace(str(root), "<run>"))
    import shutil
    shutil.rmtree(root, ignore_errors=True)
    return row


def plan() -> list[tuple[str, dict]]:
    out = []
    for reply, name in (("R3", "ask"), ("R4", "deny"), ("R9", "timeout"), ("R6", "malformed")):
        for rep in (0, 1):
            out.append((f"plain-{name}-{rep}", {"kind": "plain", "reply": reply, "rep": rep}))
    out.append(("is-on-ask-0", {"kind": "is", "cell": "ask", "rep": 0}))
    out.append(("is-on-slow-0", {"kind": "is", "cell": "slow", "rep": 0}))
    return out


def main() -> int:
    global KEY
    load_dotenv(HERE.parents[1].parent.parent.parent / ".env")
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    KEY = os.environ.get("DEEPSEEK_API_KEY", "")
    if not KEY:
        print("no DEEPSEEK_API_KEY")
        return 2
    go = os.environ.get("HOOK_FIDELITY_GO", "")
    if not go.isdigit():
        print("set HOOK_FIDELITY_GO")
        return 2
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    only = sys.argv[2:]
    proxy, proxy_url = start_proxy()
    done = {r["label"] for r in jsonl(out / "runs.jsonl")}
    used = len(jsonl(out / "launches.jsonl"))
    for label, spec in plan():
        if only and label not in only or label in done:
            continue
        row = launch(label, spec, out, proxy, proxy_url, int(go), used)
        used += 1
        with (out / "runs.jsonl").open("a") as fh:
            fh.write(json.dumps(row) + "\n")
        print(label, row["outcome"], "valid" if row["valid"] else "INVALID", "calls", row["tool_calls"], flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
