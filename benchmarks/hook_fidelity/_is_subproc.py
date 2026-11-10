#!/usr/bin/env python3
"""Run IntentShield's hook, in process, against a fixtures file, using the `intentshield` package found at --src.

Used by fresh_score.py so that "intentshield" (the code as of r8-detect tip) and "intentshield-r8fix" (the code with
r8-fixrules merged in) can be scored from the SAME fixtures file without one import of `intentshield.harness`
shadowing the other: each variant runs as its own subprocess with its own sys.path[0].
"""
from __future__ import annotations

import argparse
import io
import json
import sys
import tempfile
import time
from contextlib import redirect_stderr
from pathlib import Path


def classify(exit_code, stdout, stderr):  # mirrors detect_compare.classify for the in-process (exit 0 or raised) case
    if not stdout.strip():
        return "allow", "silent"
    try:
        data = json.loads(stdout)
    except ValueError:
        return "error", "malformed-stdout"
    if not isinstance(data, dict):
        return "error", "malformed-stdout"
    hso = data.get("hookSpecificOutput")
    cands = [hso.get("permissionDecision") if isinstance(hso, dict) else None, data.get("permissionDecision"),
             data.get("decision"), data.get("permission")]
    for c in cands:
        if isinstance(c, str):
            c = c.lower()
            if c in ("deny", "block", "blocked", "reject"):
                return "deny", "json"
            if c in ("ask", "confirm"):
                return "ask", "json"
            if c in ("allow", "approve", "approved"):
                return "allow", "json"
    if data.get("continue") is False:
        return "deny", "json"
    return "allow", "json-no-decision"


class _PassThrough:
    def ask_reply(self, kind, gemini_ask=False):
        return "ask", ""

    def mode_note(self):
        return ""

    def overrides(self):
        return []


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--src", required=True)
    p.add_argument("--fixtures", required=True)
    p.add_argument("--variant", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    sys.path.insert(0, args.src)
    import os
    os.environ["INTENTSHIELD_INTENT_MODEL_DIR"] = "/nonexistent"
    os.environ.pop("INTENTSHIELD_THREAT_PACKS", None)
    from intentshield.harness import HarnessGuard, handle

    rows = [json.loads(line) for line in Path(args.fixtures).read_text().splitlines()]
    out = []
    for row in rows:
        with tempfile.TemporaryDirectory(prefix="hf-fresh-") as tmp:
            tmp_p = Path(tmp)
            (tmp_p / "work").mkdir()
            (tmp_p / "work" / ".env").write_text("HF_FIXTURE_MARKER=not-a-secret\n")
            guard = HarnessGuard(tmp_p / "hooks.db", threats=tmp_p / "threats.db", builtin_tools=True, review="tainted")
            guard.translation = _PassThrough()
            payload = json.loads(json.dumps(row["payload"]).replace("/work/hf-fixture", str(tmp_p / "work")))
            t0 = time.monotonic()
            reply, err = None, ""
            sink = io.StringIO()
            try:
                with redirect_stderr(sink):
                    for ev in row.get("prelude", []):
                        ev2 = json.loads(json.dumps(ev).replace("/work/hf-fixture", str(tmp_p / "work")))
                        handle(row["harness"], ev2, guard)
                    reply = handle(row["harness"], payload, guard)
                cls, sub = classify(0, json.dumps(reply) if reply else "", "")
            except Exception as exc:
                cls, sub, err = "deny", "hook-exception", f"{type(exc).__name__}: {exc}"
            finally:
                guard.close()
        out.append({"guard": args.variant, "row_id": row["id"], "item_id": row["item_id"], "harness": row["harness"],
                    "invoked": True, "class": cls, "subtype": sub,
                    "entries": [{"entry": "handle()", "exit": 0, "stdout": (json.dumps(reply)[:400] if reply else ""),
                                "stderr": (err or sink.getvalue())[:200], "class": cls, "subtype": sub,
                                "wall_s": round(time.monotonic() - t0, 3)}]})
    with open(args.out, "w") as fh:
        for r in out:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    print(f"{args.variant}: {len(out)} rows written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
