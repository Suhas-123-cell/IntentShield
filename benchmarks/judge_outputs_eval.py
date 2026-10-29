"""The LLM judge on tool results: plain-language injections the rules miss, against hard benign texts.

    .venv/bin/python benchmarks/judge_outputs_eval.py --judge gemini --split test --per-source 25
    .venv/bin/python benchmarks/judge_outputs_eval.py --judge ollama:qwen2.5:7b --split test

Rows: the corpus's LLM-written outputs (as the user, polite, false error, new task, their translations, and
benign outputs; ``artifacts/injection/dataset.jsonl``) and the hard benign texts (agent hints, requests
between people, quoted attacks; ``artifacts/injection/hard_negatives.jsonl``) of one split. Tool descriptions
are left out. ``--per-source`` samples that many rows of each source (seed 7) to fit a free-tier quota.

The rows carry no user request, so the judge gets none: harder than in use, where the hook passes the
user's prompt. The judge's prompt was written on the train split and frozen before the one test run.
Answers are cached (``--cache``), so a rerun after a quota error spends nothing twice.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections import defaultdict
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from intentshield.evaluation import wilson  # noqa: E402
from intentshield.judge import Judge  # noqa: E402
from intentshield.mcp_inspect import scan_output  # noqa: E402


def rows(split: str, per_source: int) -> list[dict]:
    found = []
    for path in ("artifacts/injection/dataset.jsonl", "artifacts/injection/hard_negatives.jsonl"):
        for line in open(path):
            row = json.loads(line)
            source = row["source"]
            if row.get("split") == split and source.startswith(("generated_output", "hard_")) \
                    and not source.startswith("hard_description"):
                found.append(row)
    random.seed(7)
    by_source: dict[str, list[dict]] = defaultdict(list)
    for row in found:
        by_source[row["source"]].append(row)
    return [row for _, group in sorted(by_source.items())
            for row in (random.sample(group, min(per_source, len(group))) if per_source else group)]


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--judge", required=True, help="groq, gemini or ollama[:model]")
    parser.add_argument("--split", default="test")
    parser.add_argument("--per-source", type=int, default=0, help="rows per source (0: all)")
    parser.add_argument("--cache", type=Path, default=None, help="judge answers on disk")
    parser.add_argument("--pace", type=float, default=0.0, help="seconds between calls (free-tier rate limits)")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    load_dotenv(".env")
    judge = Judge.from_spec(args.judge, cache=args.cache, timeout=120, retries=6)
    sample = rows(args.split, args.per_source)
    tally: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    families: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in sample:
        cached = len(judge._answers)
        flagged = {"judge": judge.output("", "tool", row["text"]) is not None, "rules": bool(scan_output(row["text"]))}
        flagged["rules+judge"] = flagged["judge"] or flagged["rules"]
        if args.pace and len(judge._answers) > cached:
            time.sleep(args.pace)
        family = f"{row['label']}:{row['source'].split('_translated')[0]}"
        for name, value in flagged.items():
            tally[row["label"]][name] += value
            families[family][name] += value
        tally[row["label"]]["n"] += 1
        families[family]["n"] += 1
    report = {"judge": f"{judge.provider}:{judge.model}", "split": args.split, "rows": len(sample),
              "judge_errors": judge.errors, "user_request": "not given",
              "detectors": {label: {name: {"flagged": counts[name], "n": counts["n"],
                                           "rate": counts[name] / counts["n"], "ci95": wilson(counts[name], counts["n"])}
                                    for name in ("rules", "judge", "rules+judge")}
                            for label, counts in tally.items()},
              "families": {family: dict(counts) for family, counts in sorted(families.items())}}
    print(f"{report['judge']} on {args.split}: {len(sample)} rows, {judge.errors} judge errors (no opinion)")
    for label, name in (("instruction", "attacks caught"), ("data", "benign flagged")):
        for detector, cell in report["detectors"].get(label, {}).items():
            low, high = cell["ci95"]
            print(f"  {name:15} {detector:12} {cell['flagged']}/{cell['n']} {100 * cell['rate']:5.1f}% "
                  f"[{100 * low:.1f}, {100 * high:.1f}]")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
