"""Coverage-study hook: records each event a harness sends and which probe markers it carries.
Prints nothing, so it never changes a decision.

    python log_hook.py <harness> <hook-log.jsonl>        # event JSON on stdin
"""
import json
import sys
import time
from pathlib import Path

MARKERS = ("ISC-DESC-41", "ISC-RESULT-42", "ISC-RES-43", "ISC-PROMPT-44", "ISC-DESC2-45", "ISC-ELICIT-46")

raw = sys.stdin.read()
try:
    event = json.loads(raw)
except ValueError:
    event = {}
context = event.get("mcp_context") or {}
with Path(sys.argv[2]).open("a") as handle:
    handle.write(json.dumps({
        "t": time.time(), "harness": sys.argv[1], "event": event.get("hook_event_name"),
        "tool": event.get("tool_name"), "server": event.get("mcp_server") or context.get("server_name"),
        "transcript": event.get("transcript_path"), "markers": [m for m in MARKERS if m in raw],
        # What a guard would record as the user's own words on this event.
        "prompt": str(event.get("prompt", ""))[:300],
    }) + "\n")
