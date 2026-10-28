"""Phase 2: which held-out outputs lost (or gained) provenance coverage, and what value they had.
Compares authority_values at 2d24327 (phase 2 start) with this checkout on the injection_eval rows."""
import collections, subprocess, sys, types
from pathlib import Path
sys.path.insert(0, "benchmarks")
import injection_eval as ie
from intentshield import mcp_inspect as new

old = types.ModuleType("intentshield.old_inspect")
old.__package__ = "intentshield"
exec(subprocess.run(["git", "show", "2d24327:src/intentshield/mcp_inspect.py"], capture_output=True, text=True,
                    check=True).stdout, old.__dict__)
rows = ie.load_corpus(Path("artifacts/injection/dataset.jsonl"), Path("artifacts/data/InjecAgent/data"),
                      Path("artifacts/data/agentdojo-strings.jsonl"), Path("artifacts/injection/hard_negatives.jsonl"))
c, kinds = collections.Counter(), collections.Counter()
for r in rows:
    if r["split"] not in ("test", "external") or r["kind"] != "output":
        continue
    o, n = old.authority_values(r["text"]), new.authority_values(r["text"])
    if bool(o) != bool(n):
        c[("lost" if o else "gained", r["label"], r["family"])] += 1
        for v in o - n:
            kinds[("timestamp (date + hour read as one number)" if v.isdigit() and v[:2] in ("19", "20")
                   else "digits" if v.isdigit() else "other", r["label"])] += 1
for k, v in sorted(c.items()):
    print(*k, v)
print("lost values by kind:", dict(kinds))
