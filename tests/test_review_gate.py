"""The CI gate on review load (benchmarks/review_gate.py): its comparison, without running the replays."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "benchmarks"))
import review_gate  # noqa: E402


def test_the_gate_fails_on_a_rise_over_the_slack_and_on_a_missing_pair():
    baseline = review_gate.load_rates({"qwen/none/gateway": {"benign_reviews_per_case": 0.20}},
                                      {"memory": {"benign_reviews_per_run": 0.20}})
    assert review_gate.compare(baseline, {"msb qwen/none/gateway": 0.25, "live memory": 0.0}) == []
    assert review_gate.compare(baseline, {"msb qwen/none/gateway": 0.26, "live memory": 0.0}) == [
        "msb qwen/none/gateway: 0.200 -> 0.260"]
    assert review_gate.compare(baseline, {"msb qwen/none/gateway": 0.2}) == ["live memory: missing from the current run"]


@pytest.mark.skipif(not (review_gate.BASELINE / "msb-replay.json").exists(),
                    reason="needs results/improve/baseline (not in the sdist)")
def test_the_committed_baseline_has_every_replayed_pair():
    msb = json.loads((review_gate.BASELINE / "msb-replay.json").read_text())
    live = json.loads((review_gate.BASELINE / "harness-live-replay.json").read_text())
    rates = review_gate.load_rates(msb, live)
    assert len(rates) == 25 and {"live hooks", "live guarded", "live memory"} <= rates.keys()
