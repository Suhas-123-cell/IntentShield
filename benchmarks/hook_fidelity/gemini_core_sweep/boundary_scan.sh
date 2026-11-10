#!/bin/bash
# Hash the hook-runner files of every non-nightly @google/gemini-cli-core release in a version range (npm pack, no install, no
# scripts run, nothing executed). Shows whether the unsampled releases between two sampled ones carry the same hook runner.
# usage: boundary_scan.sh OUT.jsonl SCRATCH_DIR VERSION...
set -u
OUT="$1"; SCRATCH="$2"; shift 2
mkdir -p "$SCRATCH"; : > "$OUT"
for v in "$@"; do
  d="$SCRATCH/$v"; mkdir -p "$d"
  ( cd "$d" && npm pack --silent "@google/gemini-cli-core@$v" > pack.log 2>&1 )
  tgz=$(ls "$d"/*.tgz 2>/dev/null | head -1)
  [ -z "$tgz" ] && { echo "{\"version\":\"$v\",\"error\":\"pack failed\"}" >> "$OUT"; continue; }
  tar -xzf "$tgz" -C "$d" package/dist/src/hooks package/dist/src/tools/shell.js package/package.json 2>/dev/null
  python3 - "$v" "$d" "$tgz" >> "$OUT" <<'PY'
import hashlib, json, sys
from pathlib import Path
v, d, tgz = sys.argv[1:]
hooks = Path(d) / "package" / "dist" / "src" / "hooks"
shell = Path(d) / "package" / "dist" / "src" / "tools" / "shell.js"
def sha(p): 
    p = hooks / p
    return hashlib.sha256(p.read_bytes()).hexdigest()[:16] if p.is_file() else None
print(json.dumps({"version": v, "tarball_sha256": hashlib.sha256(Path(tgz).read_bytes()).hexdigest(),
                  **{f: sha(f) for f in ("hookRunner.js", "hookAggregator.js", "hookEventHandler.js", "hookPlanner.js", "hookRegistry.js", "types.js")},
                  # how many times the shell tool's source mentions forcedDecision (0 = its shouldConfirmExecute drops a hook ask)
                  "shell_forcedDecision_mentions": (shell.read_text().count("forcedDecision") if shell.is_file() else None)}))
PY
done
