"""The launch counts the data README states for Gemini CLI are what its ledger holds."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LANE = ROOT / "results" / "hook-fidelity" / "gemini"


def test_the_gemini_ledger_adds_up_and_the_readme_states_its_totals():
    ledger = json.loads((LANE / "ledger.json").read_text(encoding="utf-8"))
    rows = sum(ledger["rows_in_results"].values())
    without_row = sum(x["launches"] for x in ledger["launches_not_in_rows"])
    assert (rows, without_row, ledger["launches_total"]) == (382, 4, 386)
    for name, count in ledger["rows_in_results"].items():
        committed = LANE / name / "runs.jsonl"
        if committed.exists():
            assert len([line for line in committed.read_text(encoding="utf-8").splitlines() if line.strip()]) == count, name
    readme = " ".join((ROOT / "results/hook-fidelity/README.md").read_text(encoding="utf-8").split())
    assert "386 launches in all against 382 committed rows" in readme
