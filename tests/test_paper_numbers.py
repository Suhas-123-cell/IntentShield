"""The headline MSB cells, replayed from the committed traces in results/msb by benchmarks/paper_numbers.py,
so a rescoring drift (metric code or result files) fails the suite instead of silently moving the README."""
from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmarks"))

import paper_numbers  # noqa: E402

RESULTS = ROOT / "results" / "msb"
DATA = ROOT / "artifacts" / "data" / "MSB"

pytestmark = pytest.mark.skipif(not (DATA.exists() and RESULTS.exists()),
                                reason="needs the MSB checkout (artifacts/data/MSB) for the case grid")


@pytest.fixture(scope="module")
def models() -> dict:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):  # no bootstrap: the point estimates are exact without it
        models = paper_numbers.main(["--results", str(RESULTS), "--data", str(DATA), "--bootstrap", "0"])
    assert out.getvalue().startswith("manifest: ok\n")
    return models


def test_paired_n_per_model(models):
    assert {m: h["paired_n"] for m, h in models.items()} == {
        "gemini-3.5-flash-lite": 99, "llama3.1_8b": 220, "ornith_9b": 216, "qwen2.5_7b": 218}


def test_no_guarded_arm_executes_harm(models):
    for model, h in models.items():
        for arm, s in h["arms"].items():
            if arm != "none":
                assert s["harm_executed"]["k"] == 0, (model, arm)
                assert s["harm_executed"]["n"] == h["paired_n"], (model, arm)
    assert models["qwen2.5_7b"]["arms"]["none"]["harm_executed"]["k"] == 128  # 58.7% of 218


def test_qwen_gateway_task_tool_executed_is_86_of_218(models):
    m = models["qwen2.5_7b"]["arms"]["gateway"]["task_tool_executed"]
    assert (m["k"], m["n"]) == (86, 218)
    assert paper_numbers.kn(m) == "86/218 39.4%"  # not 39.5: formatted from k/n, never pre-rounded


def test_user_task_gateway_minus_baseline(models):
    points = {m: f"{100 * h['user_task_gateway_minus_baseline']:+.1f}" for m, h in models.items()}
    assert points == {"gemini-3.5-flash-lite": "-7.9", "llama3.1_8b": "-14.3", "ornith_9b": "-8.6", "qwen2.5_7b": "-8.6"}
    lines = paper_numbers.headline(models)
    assert lines[0] == ("paired cases per model (main arms): gemini-3.5-flash-lite 99, llama3.1_8b 220, "
                        "ornith_9b 216, qwen2.5_7b 218")
    assert lines[1].endswith("range 8–14 points across 4 agents")
