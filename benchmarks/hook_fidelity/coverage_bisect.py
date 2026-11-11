#!/usr/bin/env python3
"""Find, among the installed releases, the first build where a surface became (or stopped being) hook-visible.

    HOOK_FIDELITY_GO=<launches> coverage_bisect.py --harness codex --manifest releases/codex/manifest.json \
        --lo 0.131.0 --hi 0.166.0 --surface resource --marker RES --work W --out O [--codex-persist-trust]

``lo`` and ``hi`` are builds already measured with opposite outcomes ("any hook event carried the marker"). Each step
launches the build halfway between them once through coverage_run.py (so every step is an ordinary row in O/rows.jsonl)
and moves the matching end. The search assumes one change between the ends; it does not prove monotonicity, and the
answer is the adjacent pair of installed builds where the outcome flips, not a changelog claim. A step whose launch is
invalid stops the search.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hook_fidelity import coverage_run


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split("-")[0].split(".") if p.isdigit())


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--harness", required=True)
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--lo", required=True)
    p.add_argument("--hi", required=True)
    p.add_argument("--surface", required=True, help="the launch kind: tools, resource or prompt")
    p.add_argument("--marker", required=True, help="DESC, INSTR, RES ...")
    p.add_argument("--work", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--lo-visible", action="store_true", help="the lo build had a hook carry the marker (hi did not)")
    p.add_argument("--codex-persist-trust", action="store_true")
    p.add_argument("--codex-namespace", default="mcp__probe__")
    a = p.parse_args(argv)
    manifest = json.loads(a.manifest.read_text())
    usable = [v for v in manifest["versions"] if v.get("version_ok", v.get("version_works"))]
    builds = sorted(((v["version"], v["binary_path"]) for v in usable), key=lambda t: version_key(t[0]))
    names = [v for v, _ in builds]
    lo, hi = names.index(a.lo), names.index(a.hi)
    go_each = 2 if a.codex_persist_trust else 1
    trail = []
    while hi - lo > 1:
        mid = (lo + hi) // 2
        version, binary = builds[mid]
        os.environ["HOOK_FIDELITY_GO"] = str(go_each)
        args = ["--harness", a.harness, "--version", version, "--binary", binary, "--surfaces", a.surface, "--reps", "1",
                "--work", str(a.work), "--out", str(a.out)]
        if a.harness == "codex":
            args += ["--codex-namespace", a.codex_namespace]
            if a.codex_persist_trust:
                args += ["--codex-persist-trust"]
        coverage_run.main(args)
        row = json.loads((a.out / "rows.jsonl").read_text().splitlines()[-1])
        if not row["valid"]:
            print(f"step {version}: INVALID {row['problems']}; search stopped", flush=True)
            return 1
        visible = bool(row["surfaces"][a.marker]["seen_by_any_hook"])
        trail.append({"version": version, "visible": visible})
        print(f"step {version}: hook-visible={visible}", flush=True)
        if visible == a.lo_visible:  # same outcome as the lo end, so the flip is above mid
            lo = mid
        else:
            hi = mid
    print(json.dumps({"adjacent_pair": [names[lo], names[hi]], "trail": trail}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
