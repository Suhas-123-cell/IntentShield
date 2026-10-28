"""Replay the live Claude Code campaign (campaign.py) through the hook of this checkout, offline.

    export  keeps, from each run's transcript, only the session id and the MCP tool calls and results, in
            results/harness-live-haiku55/events.jsonl.gz (committed, so CI can replay without the raw runs).
    score   feeds each run's events to HarnessGuard as Claude Code fed them: the prompt, then PreToolUse for
            every call and PostToolUse with the recorded result for every call the replayed hook allows.
            The memory arm shares one hook and threat database across a rep's runs in campaign order, and
            its transparent proxies (the real attack_server, started locally) scan their catalogs into the
            shared threat database first, as they did live.

A replay is the recorded call sequence: a call the replayed hook stops is counted, but the model's next
steps are still the ones it took live. In a headless run an ask is a denial, so a review is a denied call.

    .venv/bin/python benchmarks/harness_live/replay.py export [--runs artifacts/harness-live-haiku55]
    .venv/bin/python benchmarks/harness_live/replay.py score [--out results/improve/harness-live-replay.json]
"""
from __future__ import annotations

import argparse
import asyncio
import collections
import gzip
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
from attack_server import servers  # noqa: E402
from campaign import SCENARIOS  # noqa: E402

from intentshield.harness import HarnessGuard, handle  # noqa: E402

EVENTS = ROOT / "results" / "harness-live-haiku55" / "events.jsonl.gz"
DENIED = "Permission for this tool use was denied"
ARMS = ("hooks", "guarded", "memory")
ORDER = [s.name for s in sorted(SCENARIOS, key=lambda s: s.order)]  # campaign.py's memory-lane order


def export(runs: Path) -> None:
    rows = [json.loads(line) for line in (runs / "runs.jsonl").read_text().splitlines() if line.strip()]
    out = []
    for row in rows:
        events, session = [], row["key"]
        for line in (runs / "runs" / row["key"].replace("/", "-") / "transcript.jsonl").read_text().splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            session = event.get("session_id") or session
            message = event.get("message")
            content = message.get("content") if isinstance(message, dict) else None
            for block in content if isinstance(content, list) else []:
                if block.get("type") == "tool_use" and block["name"].startswith("mcp__"):
                    events.append({"use": block["id"], "tool": block["name"], "input": block.get("input") or {}})
                elif block.get("type") == "tool_result":
                    events.append({"result": block["tool_use_id"], "content": block.get("content"),
                                   "is_error": bool(block.get("is_error"))})
        out.append({k: row[k] for k in ("key", "arm", "scenario", "family", "kind", "rep", "denials")}
                   | {"session": session, "events": events})
    EVENTS.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(EVENTS, "wt", encoding="utf-8") as f:
        f.writelines(json.dumps(r) + "\n" for r in out)
    print(f"{len(out)} runs -> {EVENTS.relative_to(ROOT)}")


async def _scan_catalogs(scenario: str, threats: Path, workdir: Path) -> None:
    """The memory arm's transparent proxies at start-up: list the attack server's tools, scan them, and
    record a poisoned description in the shared threat database."""
    from intentshield.mcp_proxy import MCPProxyConfig, MCPProxyRuntime
    for server in servers(scenario):
        config = {"upstreams": [{"server_id": server, "transport": "stdio", "command": sys.executable,
                                 "args": [str(HERE / "attack_server.py")],
                                 "env": {"SCENARIO": scenario, "SERVER": server,
                                         "CALLS_LOG": str(workdir / "calls.jsonl")}}],
                  "database_path": str(workdir / f"proxy-{server}.db"), "threat_memory_path": str(threats)}
        proxy = MCPProxyRuntime(MCPProxyConfig.model_validate(config))
        await proxy.connect()
        await proxy.close()


def replay_run(run: dict[str, Any], guard: HarnessGuard) -> list[dict[str, Any]]:
    """The replayed hook's decision on each MCP call of one run, beside what happened live."""
    scenario = next(s for s in SCENARIOS if s.name == run["scenario"])
    session = run["session"]
    handle("claude", {"hook_event_name": "UserPromptSubmit", "session_id": session, "prompt": scenario.prompt}, guard)
    calls, pending = [], {}
    for event in run["events"]:
        if "use" in event:
            base = {"session_id": session, "tool_name": event["tool"], "tool_input": event["input"]}
            pre = (handle("claude", {**base, "hook_event_name": "PreToolUse"}, guard) or {}).get(
                "hookSpecificOutput", {})
            calls.append({"tool": event["tool"], "decision": pre.get("permissionDecision", "allow"), "live": "allow"})
            pending[event["use"]] = (calls[-1], base, pre.get("updatedInput", event["input"]))
        elif event.get("result") in pending:
            call, base, sent = pending.pop(event["result"])
            text = event["content"] if isinstance(event["content"], str) else json.dumps(event["content"])
            if event["is_error"] and text.startswith(DENIED):
                call["live"] = "denied"
                continue
            if call["decision"] == "allow":
                handle("claude", {**base, "hook_event_name": "PostToolUse", "tool_input": sent,
                                  "tool_response": event["content"]}, guard)
    return calls


def score() -> dict[str, Any]:
    with gzip.open(EVENTS, "rt", encoding="utf-8") as f:
        runs = [json.loads(line) for line in f if line.strip()]
    report: dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for arm in ARMS:
            c: collections.Counter = collections.Counter()
            for run in sorted((r for r in runs if r["arm"] == arm), key=lambda r: (r["rep"], ORDER.index(r["scenario"]))):
                shared = arm == "memory"
                where = Path(tmp) / (f"{arm}-rep{run['rep']}" if shared else run["key"].replace("/", "-"))
                where.mkdir(parents=True, exist_ok=True)
                if shared:
                    asyncio.run(_scan_catalogs(next(s for s in SCENARIOS if s.name == run["scenario"]).scenario,
                                               where / "threats.db", where))
                calls = replay_run(run, HarnessGuard(where / "hooks.db", threats=where / "threats.db"))
                group = "benign" if run["kind"] == "benign" else "attack"
                c[f"{group}_runs"] += 1
                for call in calls:
                    stopped = call["decision"] != "allow"
                    c[f"{group}_calls"] += 1
                    c[f"{group}_stopped"] += stopped
                    c["calls"] += 1
                    c["agree"] += stopped == (call["live"] == "denied")
                    c["unrecorded"] += not stopped and call["live"] == "denied"
            report[arm] = {**dict(c),
                           "benign_reviews_per_run": c["benign_stopped"] / c["benign_runs"] if c["benign_runs"] else 0.0,
                           "agreement_with_live": c["agree"] / c["calls"] if c["calls"] else 0.0}
    return report


def table(report: dict[str, Any]) -> str:
    lines = ["| arm | benign runs | benign calls stopped | benign reviews/run | attack runs | attack calls stopped "
             "| agreement with live | unrecorded |", "|---|---|---|---|---|---|---|---|"]
    for arm, m in report.items():
        lines.append(f"| {arm} | {m.get('benign_runs', 0)} | {m.get('benign_stopped', 0)}/{m.get('benign_calls', 0)} "
                     f"| {m['benign_reviews_per_run']:.2f} | {m.get('attack_runs', 0)} "
                     f"| {m.get('attack_stopped', 0)}/{m.get('attack_calls', 0)} | {100 * m['agreement_with_live']:.1f}% "
                     f"| {m.get('unrecorded', 0)} |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    ex = sub.add_parser("export")
    ex.add_argument("--runs", type=Path, default=ROOT / "artifacts" / "harness-live-haiku55")
    sc = sub.add_parser("score")
    sc.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.command == "export":
        export(args.runs)
        return
    os.environ.setdefault("INTENTSHIELD_INTENT_MODEL_DIR", "/nonexistent")
    report = score()
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(table(report))


if __name__ == "__main__":
    main()
