"""docs/hook-fidelity-report.md and docs/contribution.md against the data and themselves. No harness is launched."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmarks" / "hook_fidelity"
sys.path.insert(0, str(BENCH))

import report_numbers as rn  # noqa: E402

REPORT = (ROOT / "docs" / "hook-fidelity-report.md").read_text()
STUDY = (ROOT / "docs" / "hook-fidelity-study.md").read_text()
CONTRIBUTION = (ROOT / "docs" / "contribution.md").read_text()


def _script_output() -> str:
    cmd = [sys.executable, str(BENCH / "report_numbers.py")]
    done = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, timeout=120)
    assert done.returncode == 0, done.stderr[-500:]
    return done.stdout.rstrip("\n")


# ------------------------------------------------------------------------------------------------------------ the report
def test_report_numbers_block_is_what_the_script_prints_from_the_committed_rows():
    printed = _script_output()
    assert printed == _script_output()  # deterministic
    block = REPORT.split("```\n")[-2]
    assert block.rstrip("\n") == printed


def test_report_matrix_and_findings_are_the_recomputed_ones():
    rows = rn.stub_rows()
    assert len(rows) == 1342
    assert rn.matrix_md(rn.matrix(rows)) in REPORT
    for text in {**rn.findings(rows), **rn.guards()}.values():
        assert text in REPORT, text


def test_report_headline_figures():
    rows = rn.stub_rows()
    f = rn.findings(rows)
    assert f["deny"].startswith("deny enforced where the hook ran: 220/220 ")
    assert "47 of 273" in f["deny"]
    assert f["ask_claude"].endswith("last RAN 2.1.84, first BLOCKED 2.1.85")
    assert f["ask_gemini"].endswith("last RAN 0.37.2, first HUNG 0.38.0")
    assert "Gemini CLI BLOCKED on 22 of 26, RAN on 4 of 26" in f["fail_dead"]
    assert "hook did not run on 5 builds (0.131.0 to 0.140.0), ran on 14 builds (0.141.0 to 0.166.0)" in f["codex_bypass"]
    g = rn.guards()
    assert "28/104" in g["fresh_is_after"] and "96/104" in g["fresh_is_before"]
    assert "44/85" in g["fresh_vs_safety_net"] and "25/85" in g["fresh_vs_safety_net"]
    assert "137/166" in g["detect_is"] and "31/130" in g["detect_sn"]


def test_report_states_both_sides_and_every_limit():
    low = REPORT.lower()
    for needle in (
        "where intentshield is behind",
        "where intentshield is ahead",
        "stub model",
        "macos",
        "cursor",
        "no inter-rater",
        "not in `main`",
        "cannot verify",
        "nothing has been sent",
        "outside those categories",
        "fetch_corpus.py",
        "same model family",
        "one to two builds",
        "determinism run",
    ):
        assert needle in low, needle


def test_report_has_no_process_vocabulary():
    for word in ("round", "lane", "critic", "worktree", "branch"):
        assert not re.search(rf"\b{word}s?\b", REPORT, re.I), word


# ------------------------------------------------------------------------------------------------------------- the study
def test_study_points_to_the_report_and_has_no_stale_status():
    head = STUDY.split("\n", 6)
    assert "hook-fidelity-report.md" in "\n".join(head) and "full record" in "\n".join(head)
    assert "round 8 integrated" not in STUDY and "rounds 1 to 9 documented" in STUDY


def test_study_never_calls_the_registration_pre_registered_without_a_qualifier():
    hits = [line for line in STUDY.splitlines() if re.search(r"pre-?registered|pre-?registration", line, re.I)]
    # the one remaining use describes another group's probes, not this study's predictions
    assert len(hits) == 1 and "violation predicates" in hits[0]
    assert "not verifiable from this repository" in STUDY or "cannot verify them" in STUDY


def test_study_section_14_does_not_overstate_what_regenerates():
    section = STUDY.split("## 14. Companion documents and how to reproduce")[1].split("## 15.")[0]
    assert "fetch_corpus.py" in section and "no clone present" in section
    assert "the guard decisions themselves" in section


# --------------------------------------------------------------------------------------------------------- contribution.md
def test_contribution_sections_are_in_reading_order_and_references_resolve():
    top = [int(m.group(1)) for m in re.finditer(r"^## (\d+)\. ", CONTRIBUTION, re.M)]
    assert top == list(range(1, len(top) + 1)), top
    subs = {m.group(1) for m in re.finditer(r"^#{3} (\d+\.\d+) ", CONTRIBUTION, re.M)}
    assert {"6.1", "9.1", "9.5", "12.1", "12.2"} <= subs
    for ref in re.findall(r"§(\d+(?:\.\d+)?)", CONTRIBUTION):
        top_level = int(ref.split(".")[0])
        assert top_level in top and ("." not in ref or ref in subs), ref
    assert "6b" not in "".join(re.findall(r"§\S+", CONTRIBUTION))


def test_contribution_has_one_current_verdict_box_before_section_1():
    before = CONTRIBUTION.split("## 1. ")[0]
    assert before.count("**Verdict (current") == 1
    assert "**Claimed, each with its limit**" in before and "**Not claimed**" in before and "**Route that remains.**" in before
    assert "Verdict (2026-10-12" not in CONTRIBUTION and "Update 2026-10-13" not in CONTRIBUTION


def test_contribution_marks_each_superseded_msb_table():
    section6 = CONTRIBUTION.split("## 6. The numbers that hold up")[1].split("### 6.1")[0]
    assert section6.count("SUPERSEDED") >= 5  # the lead paragraph and four items
    for needle in ("MSB held-out, live servers, neutral ids", "Earlier MSB rows", "Paired on 218 cases", "Tests:**"):
        line = next(line for line in section6.splitlines() if needle in line)
        assert "SUPERSEDED" in line, needle
    assert "**SUPERSEDED table" in CONTRIBUTION.split("## 9. Route 3")[1].split("### 9.1")[0]
    assert not re.search(r"pre-?regist", CONTRIBUTION, re.I)
