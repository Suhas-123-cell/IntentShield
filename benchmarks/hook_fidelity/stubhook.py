#!/usr/bin/env python3
"""The stub hook of the hook-fidelity study: it answers every decision event with one fixed reply.

    stubhook.py --harness claude --reply R4 --run-id X --log /abs/hooks.jsonl [--witness /abs/in-workspace/file]
                [--delay SECONDS] [--latency SECONDS] [--stderr-noise BYTES]

The reply id is fixed on the command line, not read from the environment, because a harness may scrub the
environment. The invocation is logged BEFORE the reply is produced (run id, nanosecond time, pid, event, tool,
tool input, planned reply and exit code), to ``--log`` and, as a second channel that a sandbox that cannot write
outside the workspace does not remove, to ``--witness``. A failed log write is reported on stderr and never
changes the reply. A reply that sleeps (R9, the latency variant) appends a second "reply-completed" line after the
sleep: if the harness killed the hook at its timeout that line never appears, which is how a run shows whether the
timeout was honoured.

Independence: this file imports nothing from IntentShield (not harness.py). The byte tables below are written
from the vendors' public hook documentation, not from IntentShield's adapters, so a shared reading of the
code cannot confirm itself. Each table row names the documentation it comes from; none of the rows has had a
second reader yet (section 6 of docs/research-notes/hook-fidelity/hook-fidelity-study.md), and they are what a hook
emitting these exact bytes does, not what every guard emits. Replies that are a property of the hook FILE rather than its
bytes (R10a a file that is not executable, R10b a shebang to a missing interpreter, R13 a missing script) are built by
configs.py, not here.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

# Events whose reply the harness reads as a verdict. Any other event gets a neutral reply.
DECISION_EVENTS = {"claude": {"PreToolUse"}, "codex": {"PreToolUse"}, "gemini": {"BeforeTool"},
                   "cursor": {"beforeShellExecution", "beforeMCPExecution"}}
REASON = "stubhook fixed reply"
MALFORMED = '{"decision": "deny", "reason": '  # truncated JSON, so not parseable under any harness
# Replies the stub cannot produce itself (a property of the hook file, see configs.py).
FILE_LEVEL = {"R10a", "R10b", "R13"}
# RP = replay: the exact stdout bytes, stderr bytes and exit code a third-party guard produced (guard_capture.py), read
# from --replay-file (JSON: stdout_b64, stderr_b64, exit_code). The guard's own code is not run here, only its bytes.
REPLAY = "RP"


# Row source (vendor documentation, no URL pinned yet): the decision-control section of each hook reference.
#   claude  hooks reference, PreToolUse: hookSpecificOutput.permissionDecision allow|ask|deny; exit 2 + stderr blocks
#   codex   hooks documentation, PreToolUse: same hookSpecificOutput shape; exit 2 + stderr blocks
#   gemini  hooks reference, BeforeTool: {"decision": "allow"|"deny"|"ask", "reason"}; exit 2 blocks, stderr is the reason
#   cursor  hooks documentation, beforeShellExecution / beforeMCPExecution: {"permission": "allow"|"deny"|"ask", ...}
def verdict(harness: str, decision: str, reason: str = REASON) -> str:
    if harness in ("claude", "codex"):
        return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                                  "permissionDecisionReason": reason}})
    if harness == "gemini":
        return json.dumps({"decision": decision, "reason": reason})
    if harness == "cursor":
        return json.dumps({"permission": decision, "user_message": reason, "agent_message": reason})
    raise ValueError(f"unknown harness {harness!r}")


def replay_reply(path: str) -> tuple[str, str, int, float]:
    """(stdout, stderr, exit code, 0.0) of a captured guard reply. Bytes are decoded as UTF-8 with replacement (the captured
    guards write text); a capture that timed out or has no exit code is refused rather than guessed."""
    import base64
    record = json.loads(open(path).read())
    code = record.get("exit_code")
    if not isinstance(code, int):
        raise ValueError(f"replay file {path} has no integer exit code (a timed-out capture cannot be replayed)")
    return (base64.b64decode(record.get("stdout_b64", "")).decode("utf-8", "replace"),
            base64.b64decode(record.get("stderr_b64", "")).decode("utf-8", "replace"), code, 0.0)


def planned(harness: str, reply: str, delay: float = 30.0, replay_file: str = "") -> tuple[str, str, int, float]:
    """(stdout, stderr, exit code, seconds to sleep before replying) for a decision event."""
    if reply == REPLAY:
        if not replay_file:
            raise ValueError("reply RP needs --replay-file")
        return replay_reply(replay_file)
    if reply in FILE_LEVEL:
        raise ValueError(f"{reply} is a hook-file property, built by configs.py")
    table = {
        "R1": ("{}", "", 0, 0.0),                                     # no opinion
        "R2": (verdict(harness, "allow"), "", 0, 0.0),
        "R3": (verdict(harness, "ask"), "", 0, 0.0),
        "R4": (verdict(harness, "deny"), "", 0, 0.0),
        "R5": ("", "", 0, 0.0),                                       # empty stdout, exit 0
        "R6": (MALFORMED, "", 0, 0.0),                                # malformed JSON, exit 0
        "R7": ("", "stubhook: blocked (R7)\n", 2, 0.0),              # exit 2 with a stderr reason
        "R8": ("", "stubhook: exit 1 (R8)\n", 1, 0.0),
        "R9": ("{}", "", 0, delay),                                   # sleeps past the configured timeout
        "R11": ("", "", 2, 0.0),                                      # exit 2, empty stderr
        "R12": (verdict(harness, "deny", ""), "", 0, 0.0),            # deny with an empty reason
        "R14": ("", "stubhook: exit 3 (R14)\n", 3, 0.0),             # an exit code the docs do not name
        "R15": ("", "stubhook: exit 126 (R15)\n", 126, 0.0),         # what a shell reports for a non-executable hook
        "R16": ("", "stubhook: exit 127 (R16)\n", 127, 0.0),         # what a shell reports for a missing command
    }
    if reply not in table:
        raise ValueError(f"unknown reply {reply!r}")
    return table[reply]


def _append(path: str, line: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a") as handle:
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harness", required=True, choices=sorted(DECISION_EVENTS))
    parser.add_argument("--reply", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--witness", default="")
    parser.add_argument("--delay", type=float, default=30.0)
    parser.add_argument("--stderr-noise", type=int, default=0)
    parser.add_argument("--latency", type=float, default=0.0, help="sleep this long before ANY reply")
    parser.add_argument("--replay-file", default="", help="with --reply RP: JSON of a captured guard reply (guard_capture.py)")
    args = parser.parse_args(argv)
    raw = sys.stdin.read(1_000_000)
    try:
        event = json.loads(raw) if raw.strip() else {}
    except ValueError:
        event = {}
    if not isinstance(event, dict):
        event = {}
    name = str(event.get("hook_event_name") or event.get("hookEventName") or "")
    decision = name in DECISION_EVENTS[args.harness]
    out, err, code, sleep = ("{}", "", 0, 0.0)
    if decision:
        out, err, code, sleep = planned(args.harness, args.reply, args.delay, args.replay_file)
    if decision and not sleep:
        sleep = args.latency
    tool_input = event.get("tool_input", event.get("command", ""))
    line = json.dumps({"run_id": args.run_id, "ts_ns": time.time_ns(), "pid": os.getpid(), "harness": args.harness,
                       "event": name, "tool": str(event.get("tool_name") or event.get("toolName") or ""),
                       "tool_input": json.dumps(tool_input)[:500], "decision_event": decision, "reply": args.reply,
                       "exit_code": code, "sleep": sleep})
    for path in (args.log, args.witness):
        if path:
            try:
                _append(path, line)
            except OSError as exc:
                sys.stderr.write(f"stubhook: could not write {path}: {exc}\n")
    if decision and args.stderr_noise:
        sys.stderr.write("n" * args.stderr_noise + "\n")
    if sleep:
        time.sleep(sleep)
        # Reached only if the harness did not kill this process: whether a timeout was honoured is read from the absence
        # of this line (R9, latency variant), not guessed from the verdict.
        done = json.dumps({"run_id": args.run_id, "ts_ns": time.time_ns(), "pid": os.getpid(), "harness": args.harness,
                           "event": "reply-completed", "phase": "completed", "tool": "", "tool_input": "",
                           "decision_event": False, "reply": args.reply, "exit_code": code, "sleep": sleep})
        for path in (args.log, args.witness):
            if path:
                try:
                    _append(path, done)
                except OSError:
                    pass
    sys.stdout.write(out)
    sys.stdout.flush()
    sys.stderr.write(err)
    return code


if __name__ == "__main__":
    sys.exit(main())
