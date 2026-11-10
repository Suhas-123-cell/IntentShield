"""The real-model arms' counts, recomputed from the committed rows (nothing here launches a harness or calls a model)."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HF = ROOT / "results/hook-fidelity"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def _valid(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r["action_attempted"] and r["outcome"] != "INVALID"]


def test_ledger_and_row_counts_of_the_three_ollama_ledgers():
    committed, supp, critic = (_load(HF / d / "launches.jsonl") for d in ("real-model", "real-model-supp", "real-model-critic"))
    assert (len(committed), len(supp), len(critic)) == (34, 27, 10)
    rows = [_load(HF / d / "runs.jsonl") for d in ("real-model", "real-model-supp", "real-model-critic")]
    assert [len(r) for r in rows] == [34, 26, 10]
    assert [len(_valid(r)) for r in rows] == [29, 23, 9]
    assert sum(len(_valid(r)) for r in rows) == 61


def test_the_ollama_ledgers_overlap_in_plan_keys_but_not_in_run_rows():
    keys = [{x["key"] for x in _load(HF / d / "launches.jsonl")} for d in ("real-model", "real-model-supp", "real-model-critic")]
    assert len(keys[0] & keys[1]) == 16          # replicates: merging by plan key would collide
    started = [{(r["run_id"], r["started_at"]) for r in _load(HF / d / "runs.jsonl") if "started_at" in r}
               for d in ("real-model", "real-model-supp")]
    assert not started[0] & started[1]           # distinct launches, nothing double counted


def test_tool_call_rate_across_the_ollama_ledgers_by_harness():
    rows = sum((_load(HF / d / "runs.jsonl") for d in ("real-model", "real-model-supp", "real-model-critic")), [])
    claude = [r for r in rows if r["harness"] == "claude"]
    codex = [r for r in rows if r["harness"] == "codex"]
    assert (sum(r["action_attempted"] for r in claude), len(claude)) == (29, 38)
    assert (sum(r["action_attempted"] for r in codex), len(codex)) == (32, 32)
    scored = [r for r in rows if "egress_attempts" in r and r["action_attempted"]]
    assert scored and all(not r["egress_attempts"] and not r["unattested_hits"] for r in scored)


def test_deepseek_arm_is_ten_valid_single_call_launches():
    rows = _load(HF / "real-model-deepseek/runs.jsonl")
    ledger = _load(HF / "real-model-deepseek/launches.jsonl")
    assert len(rows) == len(ledger) == 10 and all(r["valid"] for r in rows)
    assert all(len(r["commands"]) == 1 and r["calls_after_first"] == 0 for r in rows)
    assert sum(r["outcome"] == "BLOCKED" for r in rows) == 6 and sum(r["outcome"] == "RAN" for r in rows) == 4
