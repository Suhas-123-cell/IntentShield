#!/usr/bin/env python3
"""Clone the 26 corpus guards at the commits pinned in results/hook-fidelity/corpus.json, into $HF_SCRATCH/corpus/<dir>/repo.

    fetch_corpus.py --dry-run                 # print the plan; no network, nothing written
    fetch_corpus.py                           # clone (network) every guard that is not already at its pinned commit
    fetch_corpus.py --only knox --only safety-net
    fetch_corpus.py --scratch DIR             # default: $HF_SCRATCH, else <tmp>/intentshield-hook-fidelity

What this gives: the directory layout that ``detect_compare.py decide`` and ``guard_replay.py`` read (the other guards' hook
entry points), and that ``tests/test_hook_fidelity_detect.py`` needs to run its 5 skipped tests. The clones contain other
people's code. Nothing here runs it: a clone is ``git init`` + ``git fetch --depth 1 <commit>`` + ``git checkout``, with the
clone's hooks disabled, no submodules and no checkout filters. Running a guard happens only inside the sandbox of
``guard_capture.py``.

What this does not give: the harness release installs under ``$HF_SCRATCH/releases/`` (``release-manifests/README.md``), the
build of ``block-no-verify`` that ``detect_compare.py`` reads under ``$HF_SCRATCH/guard-replay/block-no-verify/build``, the Node
toolchain, or the four guards that were never run (the corpus lists them; they are cloned too, so the inventory is complete).
A pinned commit that a repository owner has since removed cannot be fetched; the plan then fails for that guard and says so.
After a clone the script checks ``git rev-parse HEAD`` against the pinned commit and refuses a mismatch.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CORPUS = ROOT / "results" / "hook-fidelity" / "corpus.json"
SHA = re.compile(r"[0-9a-f]{40}")
GIT = ("git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "-c", "core.fsmonitor=false")


def default_scratch() -> Path:
    """The same default as ``guard_capture.SCRATCH_ROOT``."""
    return Path(os.environ.get("HF_SCRATCH") or os.path.join(tempfile.gettempdir(), "intentshield-hook-fidelity"))


def plan(corpus: Path = CORPUS, scratch: Path | None = None, only: list[str] | None = None) -> list[dict]:
    """One entry per guard: where it goes, which repository and commit. No network and no writes (it only checks whether the
    destination already has a ``.git`` directory)."""
    scratch = scratch if scratch is not None else default_scratch()
    guards = json.loads(Path(corpus).read_text())["guards"]
    wanted = set(only or [])
    unknown = wanted - {g["id"] for g in guards} - {g["dir"] for g in guards}
    if unknown:
        raise SystemExit(f"unknown guard(s): {', '.join(sorted(unknown))}")
    out: list[dict] = []
    for g in guards:
        if wanted and g["id"] not in wanted and g["dir"] not in wanted:
            continue
        if not SHA.fullmatch(g["commit"]):
            raise SystemExit(f"{g['id']}: the pinned commit {g['commit']!r} is not a 40-hex sha")
        dest = scratch / "corpus" / g["dir"] / "repo"
        out.append({"id": g["id"], "dir": g["dir"], "repo": g["repo"], "commit": g["commit"], "dest": str(dest),
                    "present": (dest / ".git").exists()})
    return out


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([*GIT, *args], cwd=cwd, capture_output=True, text=True, timeout=600)


def head_of(dest: Path) -> str:
    res = _git(["rev-parse", "HEAD"], dest)
    return res.stdout.strip() if res.returncode == 0 else ""


def fetch_one(item: dict) -> tuple[bool, str]:
    dest = Path(item["dest"])
    if item["present"] and head_of(dest) == item["commit"]:
        return True, "already at the pinned commit"
    dest.mkdir(parents=True, exist_ok=True)
    steps = ([["init", "-q"], ["remote", "add", "origin", item["repo"]]] if not (dest / ".git").exists() else [])
    steps += [["fetch", "-q", "--depth", "1", "--no-tags", "--no-recurse-submodules", "origin", item["commit"]],
              ["-c", "advice.detachedHead=false", "checkout", "-q", "--detach", "FETCH_HEAD"]]
    for step in steps:
        res = _git(step, dest)
        if res.returncode != 0:
            return False, f"git {step[0] if step[0] != '-c' else step[2]} failed: {res.stderr.strip()[:200]}"
    got = head_of(dest)
    if got != item["commit"]:
        return False, f"HEAD is {got or 'unreadable'}, expected {item['commit']}"
    return True, "cloned and verified"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="print the plan and exit; no network, no writes")
    parser.add_argument("--scratch", help="default: $HF_SCRATCH, else <tmp>/intentshield-hook-fidelity")
    parser.add_argument("--only", action="append", default=[], help="a guard id or directory (repeatable)")
    args = parser.parse_args(argv)
    items = plan(scratch=Path(args.scratch).resolve() if args.scratch else None, only=args.only)
    if args.dry_run:
        root = Path(items[0]["dest"]).parents[2] if items else "-"
        print(f"{len(items)} guard(s); a real run needs network and writes under {root}")
        for it in items:
            state = "present" if it["present"] else "missing"
            print(f"{it['id']:<24} {state:<8} git fetch --depth 1 {it['repo']} {it['commit']} -> {it['dest']}")
        return 0
    failed = 0
    for it in items:
        ok, note = fetch_one(it)
        failed += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {it['id']}: {note}", flush=True)
    print(f"{len(items) - failed} of {len(items)} guards at their pinned commits")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
