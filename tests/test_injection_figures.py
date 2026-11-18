"""The prompt-injection figures the README and docs/benchmarks.md cite, recomputed from the committed per-row verdicts."""
# ruff: noqa: E501
from __future__ import annotations

import hashlib
import io
import json
import re
import sys
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmarks"))

import injection_eval as ie  # noqa: E402

RESULTS = ROOT / "results" / "injection"
ROWS = [json.loads(line) for line in (RESULTS / "rows.jsonl").read_text(encoding="utf-8").splitlines()]
GENERATED = ("generated_output_as_user", "generated_output_false_error", "generated_output_new_task", "generated_output_polite")
# the injections no rule was written from: InjecAgent base, AgentDojo direct and the LLM-written outputs, translations included
INDEPENDENT = {"injecagent_dh_base", "injecagent_ds_base", "agentdojo_direct", *GENERATED, *(f"{g}_translated" for g in GENERATED)}


def count(detector: str, label: str, families: set[str] | None = None) -> tuple[int, int]:
    rows = [r for r in ROWS if r["label"] == label and (families is None or r["family"] in families)]
    return sum(1 for r in rows if r["verdicts"][detector]), len(rows)


def pct(k: int, n: int) -> str:
    return f"{100 * k / n:.1f}%"


def flat(name: str) -> str:
    return re.sub(r"\s+", " ", (ROOT / name).read_text(encoding="utf-8"))


def test_the_rows_hold_no_text_and_cover_every_scored_row():
    assert len(ROWS) == 3717
    assert set(ROWS[0]) == {"sha256", "source", "family", "label", "split", "kind", "verdicts"}
    assert {"rules", "exemplars", "rules+exemplars"} <= set(ROWS[0]["verdicts"])


def test_the_committed_corpus_files_are_all_in_the_rows_by_hash():
    hashes = {r["sha256"] for r in ROWS}
    for name, splits in (("dataset.jsonl", {"test"}), ("hard_negatives.jsonl", {"test"}), ("agentdojo-strings.jsonl", {"external"})):
        scored = [json.loads(line) for line in (RESULTS / name).read_text(encoding="utf-8").splitlines() if line.strip()]
        scored = [r for r in scored if r.get("split", "external") in splits]
        assert scored, name
        assert all(hashlib.sha256(r["text"].encode()).hexdigest()[:16] in hashes for r in scored), name


def test_the_table_is_what_the_committed_rows_give():
    out = io.StringIO()
    with redirect_stdout(out):
        count_, splits, report = ie.report_from_rows(RESULTS / "rows.jsonl")
        print(f"{count_} rows, splits {splits}")
        ie.print_report(report)
    assert out.getvalue() == (RESULTS / "table.txt").read_text(encoding="utf-8")


def test_the_committed_report_json_agrees_with_the_rows():
    report = json.loads((RESULTS / "report-rules-pg-exemplars.json").read_text(encoding="utf-8"))
    assert report["rows"] == len(ROWS)
    for detector in ("rules", "exemplars", "rules+exemplars"):
        k, n = count(detector, "instruction")
        assert (report["detectors"][detector]["recall"]["flagged"], report["detectors"][detector]["recall"]["n"]) == (k, n)


def test_the_readme_figures_are_the_ones_the_rows_give():
    assert count("rules", "instruction", INDEPENDENT) == (28, 1427)
    assert count("rules+exemplars", "instruction", INDEPENDENT) == (252, 1427)
    assert count("rules", "instruction") == (1503, 2959)
    assert count("rules+exemplars", "instruction") == (1727, 2959)
    assert count("rules", "data") == (16, 758) and count("rules+exemplars", "data") == (18, 758)
    readme = flat("README.md")
    assert "28 of 1,427 (2.0%)" in readme and "252 (17.7%)" in readme and "50.8% of all 2,959 injections" in readme
    assert pct(28, 1427) == "2.0%" and pct(252, 1427) == "17.7%" and pct(1503, 2959) == "50.8%"


def test_the_benchmarks_table_is_the_one_the_rows_give():
    doc = flat("docs/benchmarks.md")
    assert "| 1,427 | 28 (2.0%) | 252 (17.7%) |" in doc
    assert "| 2,959 | 1,503 (50.8%) | 1,727 (58.4%) |" in doc
    assert "| benign texts flagged | 758 | 16 (2.1%) | 18 (2.4%) |" in doc
