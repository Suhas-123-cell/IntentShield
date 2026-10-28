"""CI gate on review load: fail if benign reviews per task rise more than 0.05 over the baseline.

Reruns the offline replays of this checkout (msb_replay.py over the recorded MSB traces, harness_live/replay.py
over the live Claude Code campaign) and compares, for every recorded trace/guard pair and every live arm,
benign reviews per case (per run) with results/improve/baseline. A pair missing from either side fails too.

    .venv/bin/python benchmarks/review_gate.py [--slack 0.05]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASELINE = HERE.parent / "results" / "improve" / "baseline"
SLACK = 0.05


def load_rates(msb: dict, live: dict) -> dict[str, float]:
    return {**{f"msb {k}": v["benign_reviews_per_case"] for k, v in msb.items()},
            **{f"live {k}": v["benign_reviews_per_run"] for k, v in live.items()}}


def compare(baseline: dict[str, float], current: dict[str, float], slack: float = SLACK) -> list[str]:
    """One line per pair whose rate rose more than ``slack``, or that only one side has."""
    failures = [f"{key}: missing from {'the current run' if key in baseline else 'the baseline'}"
                for key in sorted(baseline.keys() ^ current.keys())]
    failures += [f"{key}: {baseline[key]:.3f} -> {current[key]:.3f}" for key in sorted(baseline.keys() & current.keys())
                 if current[key] - baseline[key] > slack + 1e-9]
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--slack", type=float, default=SLACK)
    args = parser.parse_args(argv)
    os.environ.setdefault("INTENTSHIELD_INTENT_MODEL_DIR", "/nonexistent")
    sys.path[:0] = [str(HERE), str(HERE / "harness_live")]
    import msb_replay
    import replay

    msb = msb_replay.score(argparse.Namespace(results=msb_replay.ROOT / "results" / "msb", decisions=None))
    current = load_rates(msb, replay.score())
    baseline = load_rates(json.loads((BASELINE / "msb-replay.json").read_text()),
                          json.loads((BASELINE / "harness-live-replay.json").read_text()))
    failures = compare(baseline, current, args.slack)
    for key in sorted(current):
        print(f"{key}: {baseline.get(key, float('nan')):.3f} -> {current[key]:.3f}")
    if failures:
        print(f"\nBenign reviews per task rose more than {args.slack} over {BASELINE}:", *failures, sep="\n  ")
        return 1
    print(f"\nreview load within {args.slack} of the baseline on all {len(current)} pairs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
