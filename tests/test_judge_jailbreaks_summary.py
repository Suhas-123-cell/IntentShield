"""judge_jailbreaks.summarize: an ask is reported apart from a deny, never as a stop."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))

import judge_jailbreaks as jj  # noqa: E402


def _row(label: str, send: str, warned: bool = False) -> dict:
    return {"id": "x", "label": label, "hook": {"send": send, "warned": warned}}


def test_denied_and_asked_attack_sends_are_counted_apart():
    rows = [_row("attack", "deny", True), _row("attack", "ask"), _row("attack", "ask"), _row("attack", "allow"),
            _row("benign", "allow"), _row("benign", "ask")]
    cell = jj.summarize(rows, ["hook"])["hook"]
    assert (cell["attack_send_denied"], cell["attack_send_asked"], cell["attack_send_stopped"]) == (1, 2, 3)
    assert (cell["benign_send_asked"], cell["attack_result_warned"], cell["attacks"], cell["benign"]) == (1, 1, 4, 2)


def test_committed_runs_hold_7_denies_and_23_asks_in_every_configuration():
    for name in ("qwen2.5-7b", "gemini-flash-lite", "deepseek-flash"):
        data = json.loads((ROOT / "results" / "judge" / f"jailbreaks-{name}.json").read_text())
        configs = [k for k, v in data["summary"].items() if isinstance(v, dict)]
        recomputed = jj.summarize(data["rows"], configs)
        for config in configs:
            assert recomputed[config] == {k: data["summary"][config][k] for k in recomputed[config]}, (name, config)
            assert (recomputed[config]["attack_send_denied"], recomputed[config]["attack_send_asked"]) == (7, 23)
