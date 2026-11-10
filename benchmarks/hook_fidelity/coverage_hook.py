#!/usr/bin/env python3
"""The passive hook of the coverage re-run: it logs which probe markers each hook event carries, and always replies with
nothing (empty stdout, exit 0), so it never changes a decision.

    coverage_hook.py <harness> <log.jsonl> [--raw-dir DIR]        # the event JSON on stdin

One line per invocation: nanosecond time (the same clock the stub model's request log uses, so a hook event can be ordered
against the first model request that carried a marker), event name, tool name, MCP server field, the markers found in the
event's input and, per marker, the field path it was found under (``tool_input``, ``tool_response``, ``prompt``,
``llm_request.messages`` ...), and whether the marker is inside ``tool_input`` (written by the model, so not a delivery).
Markers are ``ISC-<SURFACE>-<tag>`` with letters and digits in the tag. Standard library only; it imports nothing from
IntentShield.
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

MARKER = re.compile(r"ISC-[A-Z0-9]+-[A-Za-z0-9]+")


def paths_of(value, marker: str, prefix: str = "", depth: int = 0) -> list[str]:
    """Field paths (two levels deep) of an event under which the marker's text occurs."""
    if isinstance(value, dict) and depth < 2:
        out: list[str] = []
        for key, inner in value.items():
            out += paths_of(inner, marker, f"{prefix}{key}" if not prefix else f"{prefix}.{key}", depth + 1)
        return out
    return [prefix or "<root>"] if marker in json.dumps(value, ensure_ascii=False) else []


def main(argv: list[str]) -> int:
    harness, log = argv[0], Path(argv[1])
    raw_dir = Path(argv[argv.index("--raw-dir") + 1]) if "--raw-dir" in argv else None
    raw = sys.stdin.read(4_000_000)
    try:
        event = json.loads(raw)
    except ValueError:
        event = {}
    if not isinstance(event, dict):
        event = {}
    context = event.get("mcp_context") if isinstance(event.get("mcp_context"), dict) else {}
    markers = sorted(set(MARKER.findall(raw)))
    tool_input = json.dumps(event.get("tool_input", event.get("toolInput", "")), ensure_ascii=False)
    now = time.time_ns()
    line = {"ts_ns": now, "harness": harness,
            "event": event.get("hook_event_name") or event.get("hookEventName") or event.get("event") or "",
            "tool": event.get("tool_name") or event.get("toolName") or "",
            "server": event.get("mcp_server") or context.get("server_name") or "",
            "keys": sorted(event), "markers": markers,
            "marker_paths": {m: paths_of(event, m) for m in markers},
            "in_tool_input": [m for m in markers if m in tool_input], "raw_bytes": len(raw)}
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a") as handle:
        handle.write(json.dumps(line) + "\n")
    if raw_dir is not None:  # the full event, for a reader who wants to see exactly what a hook was given
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / f"{now}-{line['event'] or 'event'}.json").write_text(raw)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
