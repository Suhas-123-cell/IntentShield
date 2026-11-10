"""Round 4 launcher for one-off argv and env variants of a cell, through the normal runner (all its containment applies).

    R4_DROP_ARGS="--json" R4_SET_ENV="RUST_LOG=debug" HOOK_FIDELITY_GO=<n> \\
        r4_variant.py run OUT --execute --cells-json F ...

It wraps ``configs.build`` so the built RunSpec loses the argv words of R4_DROP_ARGS, gains the words of R4_ADD_ARGS at the end
(unit-separator joined) and gains the variables of R4_SET_ENV, then hands over to ``run.main`` unchanged: same stub, isolated
HOME, egress proxy, sign-off gate and launch ledger. R4_PERMREQ_DIR=<dir> (Claude) also registers a passive PermissionRequest
hook whose events go to <dir>. The variant is recorded in no row field, so state it in the results README. Used for: Codex
without ``--json`` and with RUST_LOG (does a human-readable or log line mention a skipped hook), Gemini with
``--allowed-tools=run_shell_command``, Claude with a PermissionRequest hook and no bypass.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from hook_fidelity import configs, run  # noqa: E402

_build = configs.build


def build(*args, **kwargs):
    spec = _build(*args, **kwargs)
    drop = set(filter(None, os.environ.get("R4_DROP_ARGS", "").split(",")))
    spec.argv[:] = [a for a in spec.argv if a not in drop]
    spec.argv.extend(a for a in os.environ.get("R4_ADD_ARGS", "").split("\x1f") if a)   # unit separator between words
    for item in filter(None, os.environ.get("R4_SET_ENV", "").split(",")):
        name, _, value = item.partition("=")
        spec.env[name] = value
    log_dir = os.environ.get("R4_PERMREQ_DIR", "")
    if log_dir and "--settings" in spec.argv:   # Claude: add a passive PermissionRequest hook (coverage_hook.py logs the event)
        settings_file = Path(spec.argv[spec.argv.index("--settings") + 1])
        settings = json.loads(settings_file.read_text())
        command = " ".join([sys.executable, str(HERE / "coverage_hook.py"), "claude",
                            f"{log_dir}/events-{spec.nonce}.jsonl", "--raw-dir", f"{log_dir}/raw-{spec.nonce}"])
        settings.setdefault("hooks", {})["PermissionRequest"] = [
            {"matcher": "", "hooks": [{"type": "command", "command": command, "timeout": 3}]}]
        settings_file.write_text(json.dumps(settings))
    return spec


configs.build = build

if __name__ == "__main__":
    sys.exit(run.main(sys.argv[1:]))
