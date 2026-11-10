#!/bin/bash
# The registry's own `dist.integrity` of each @google/gemini-cli-core release, as JSON {version: sha512-...}, for table.py to
# compare with the integrity npm recorded in the scratch install's package-lock.json.
# usage: registry_integrity.sh OUT.json VERSION...
set -u
OUT="$1"; shift
python3 - "$OUT" "$@" <<'PY'
import json, subprocess, sys
out, versions = sys.argv[1], sys.argv[2:]
result = {}
for v in versions:
    done = subprocess.run(["npm", "view", f"@google/gemini-cli-core@{v}", "dist.integrity"], capture_output=True, text=True)
    result[v] = done.stdout.strip() or None
json.dump(result, open(out, "w"), indent=1, sort_keys=True)
print(f"{sum(1 for x in result.values() if x)}/{len(result)} integrity hashes from the registry")
PY
