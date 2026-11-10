#!/usr/bin/env python3
"""Regenerates every number of docs/hook-fidelity-corpus.md from the data files, and checks the document against them.

    python3 benchmarks/hook_fidelity/corpus_counts.py            # prints the derived numbers as JSON
    python3 benchmarks/hook_fidelity/corpus_counts.py --check    # exit 1 unless the stored summary and measured blocks and the
                                                                 # committed document equal what the data files derive

Inputs: results/hook-fidelity/corpus.json (guard records), results/hook-fidelity/guards/summary.json (replay cells),
results/hook-fidelity/guards/captures.jsonl (byte captures) and corpus_build/github_meta.json (stars). No number in the document
is typed by hand: corpus_build/build.py formats the dicts this script derives.
"""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE / "corpus_build"))
from counts import derive, derive_measured  # noqa: E402

CORPUS = ROOT / "results" / "hook-fidelity" / "corpus.json"
GUARDS = ROOT / "results" / "hook-fidelity" / "guards"
GITHUB = HERE / "corpus_build" / "github_meta.json"
DOC = ROOT / "docs" / "hook-fidelity-corpus.md"


def derive_all() -> dict:
    data = json.loads(CORPUS.read_text())
    out = {"summary": derive(data)}
    if (GUARDS / "summary.json").is_file():
        captures = [json.loads(line) for line in (GUARDS / "captures.jsonl").read_text().splitlines() if line.strip()]
        github = json.loads(GITHUB.read_text()) if GITHUB.is_file() else {}
        out["measured"] = derive_measured(json.loads((GUARDS / "summary.json").read_text()), captures, github)
    return out


def check() -> list[str]:
    problems: list[str] = []
    data = json.loads(CORPUS.read_text())
    derived = derive_all()
    if derived["summary"] != data.get("summary"):
        problems.append("corpus.json summary differs from the derived summary")
    if derived.get("measured", {}) != data.get("measured", {}):
        problems.append("corpus.json measured block differs from the derived measured block")
    import build  # type: ignore[import-not-found]  # corpus_build/build.py (on sys.path above)

    rebuilt = build.markdown(data)
    if rebuilt.strip() != DOC.read_text().strip():
        diff = list(
            difflib.unified_diff(DOC.read_text().splitlines(), rebuilt.splitlines(), "committed", "rebuilt", lineterm="", n=0)
        )
        problems.append(
            "the committed document differs from the document rebuilt from corpus.json (first lines: "
            + " | ".join(diff[:6])
            + ")"
        )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if args.check:
        problems = check()
        for problem in problems:
            print("FAIL:", problem)
        print("ok" if not problems else f"{len(problems)} problem(s)")
        return 1 if problems else 0
    print(json.dumps(derive_all(), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
