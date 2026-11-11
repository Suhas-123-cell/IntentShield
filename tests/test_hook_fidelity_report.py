"""The hook study report and its appendix, the study and docs/contribution.md against the data and themselves. No harness runs."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from decimal import ROUND_HALF_EVEN, ROUND_HALF_UP, Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmarks" / "hook_fidelity"
sys.path.insert(0, str(BENCH))

import report_numbers as rn  # noqa: E402

REPORT = (ROOT / "docs" / "hook-fidelity-report.md").read_text()
APPENDIX = (ROOT / "docs" / "hook-fidelity-report-appendix.md").read_text()
BOTH = REPORT + "\n" + APPENDIX


def _flat(text: str) -> str:
    """The text with every run of whitespace, line breaks and list indents included, as one space."""
    return re.sub(r"\s+", " ", text)


FLAT = _flat(REPORT)
STUDY = (ROOT / "docs" / "research-notes" / "hook-fidelity" / "hook-fidelity-study.md").read_text()
CONTRIBUTION = (ROOT / "docs" / "contribution.md").read_text()
HISTORY = (ROOT / "docs" / "research-notes" / "contribution-history.md").read_text()


def _script_output() -> str:
    cmd = [sys.executable, str(BENCH / "report_numbers.py")]
    done = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, timeout=120)
    assert done.returncode == 0, done.stderr[-500:]
    return done.stdout.rstrip("\n")


# ------------------------------------------------------------------------------------------------------------ the report
def test_report_numbers_block_is_what_the_script_prints_from_the_committed_rows():
    printed = _script_output()
    assert printed == _script_output()  # deterministic
    block = APPENDIX.split("```\n")[-2]
    assert block.rstrip("\n") == printed


def test_report_matrix_and_findings_are_the_recomputed_ones():
    rows = rn.stub_rows()
    assert len(rows) == 1342
    assert rn.matrix_md(rn.matrix(rows)) in REPORT
    assert rn.build_counts_md(rn.build_counts(rows)) in REPORT
    assert rn.build_counts_md(rn.build_counts(rows)) in APPENDIX
    for text in {**rn.findings(rows), **rn.guards()}.values():
        assert text in BOTH, text


def test_one_build_count_per_harness_in_every_document_that_states_it():
    counts = rn.build_counts(rn.stub_rows())
    c, x, g = counts["claude"], counts["codex"], counts["gemini"]
    assert (c["installed"], c["scored"], c["excluded"]) == (28, 27, 1)
    assert (x["installed"], x["scored"], x["excluded"]) == (19, 14, 5)
    assert (g["installed"], g["scored"], g["excluded"]) == (28, 28, 0)
    sentence = f"Claude Code ({c['scored']} scored builds), Codex CLI ({x['scored']}) and Gemini CLI ({g['scored']})"
    readme = (ROOT / "README.md").read_text()
    results = (ROOT / "results" / "hook-fidelity" / "README.md").read_text()
    for name, text in (("README.md", readme), ("contribution.md", CONTRIBUTION), ("results/hook-fidelity/README.md", results)):
        assert sentence in text.replace("\n", " "), name
    for name, text in (("README.md", readme), ("contribution.md", CONTRIBUTION), ("report", REPORT), ("appendix", APPENDIX)):
        flat = text.replace("\n", " ")
        assert "Claude Code (23 builds)" not in flat and "Codex CLI (17)" not in flat, name


def test_report_headline_figures():
    rows = rn.stub_rows()
    f = rn.findings(rows)
    assert f["deny"].startswith("deny enforced where the hook ran: 65 of 65 builds, 218/218 ")
    assert "83 deterministic cells on 65 builds" in f["deny"] and "bounds repeatability, not a population rate" in f["deny"]
    assert "47 of 271" in f["deny"]
    assert f["ask_claude"].endswith("last RAN 2.1.84, first BLOCKED 2.1.85")
    assert f["ask_gemini"].endswith("last RAN 0.37.2, first HUNG 0.38.0")
    assert "Gemini CLI BLOCKED on 22 of 26, RAN on 4 of 26" in f["fail_dead"]
    assert "hook did not run on 5 builds (0.131.0 to 0.140.0), ran on 14 builds (0.141.0 to 0.166.0)" in f["codex_bypass"]
    g = rn.guards()
    assert "28/104" in g["fresh_is_after"] and "96/104" in g["fresh_is_before"]
    assert "44/85" in g["fresh_vs_safety_net"] and "25/85" in g["fresh_vs_safety_net"]
    assert "137/166" in g["detect_is"] and "31/130" in g["detect_sn"]
    for needle in ("65 of 65 builds", "47 of 271", "0 of 70", "22 of 22 Claude Code", "12 of 12 Codex CLI", "15 of 28"):
        assert needle in FLAT, needle
    for key in ("fresh_is_before", "fresh_is_after", "fresh_vs_safety_net", "fresh_vs_knox", "detect_is", "detect_sn"):
        for figure in re.findall(r"\d+/\d+ \[[\d.]+, [\d.]+\]%", g[key]):
            assert figure in FLAT, (key, figure)
    assert "41/85, IntentShield 24/85" in FLAT


def test_report_states_both_sides_and_every_limit():
    low = FLAT.lower()
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
        "same model family",
        "one to two builds",
        "determinism run",
        "tooling",
        "ai coding agents",
        "no human second coder",
        "do not settle the order",
        "only on its own rule categories, and post hoc",
        "a tie with safety-net and a loss to knox",
    ):
        assert needle in low, needle
    assert "fetch_corpus.py" in APPENDIX


def test_the_benign_line_is_not_listed_as_a_place_where_intentshield_is_ahead():
    ahead = REPORT.split("**Where IntentShield is ahead")[1].split("**Benign calls")[0]
    assert "benign" not in ahead.lower().replace("benign calls", "")
    benign = REPORT.split("**Benign calls: a tie with safety-net and a loss to knox.**")[1].split("\n\n")[0]
    assert "knox flags 0" in benign and "safety-net denies 4" in benign


def test_the_467_set_is_also_rescored_without_the_items_now_in_the_rules_tests():
    line = rn.guards()["rules_without_overlap"]
    for needle in (
        "without the 33 items",
        "133 items that stayed held out, 104/133 ",
        " before, 6/133 ",
        "123 built-in tool calls, 104/123 ",
    ):
        assert needle in line, needle
    for figure in ("104/133 [70.4, 84.4]%", "6/133 [2.1, 9.5]%"):
        assert figure in FLAT and figure in _flat(APPENDIX), figure
    import overlap_check

    pinned = json.loads((BENCH / "overlap_items.json").read_text())
    live = overlap_check.overlapping_items(
        [json.loads(x) for x in (ROOT / "results/hook-fidelity/detect/fixtures.jsonl").read_text().splitlines()],
        overlap_check.repository_text(["tests", "src"]),
    )
    assert len(pinned["fixtures_467_set"]) == 33 and set(pinned["fixtures_467_set"]) <= set(live)


def test_report_has_no_process_vocabulary():
    for word in ("round", "lane", "critic", "worktree", "branch"):
        assert not re.search(rf"\b{word}s?\b", BOTH, re.I), word


def test_the_main_text_stays_short_and_links_to_its_appendix():
    words = [w for w in REPORT.split() if not set(w) <= set("|-")]
    assert len(words) <= 2000, len(words)
    assert "(hook-fidelity-report-appendix.md)" in REPORT and "(hook-fidelity-report.md)" in APPENDIX
    assert "#reproduce-in-full" in REPORT


# ------------------------------------------------------------------------------------------------------------- the study
def test_study_points_to_the_report_and_opens_with_a_five_line_status():
    head = STUDY.split("## Full record (working notes)")[0]
    assert "hook-fidelity-report.md" in head and "full record" in head
    status = head.split("Status (2026-11-11):\n")[1].strip().splitlines()
    assert len(status) == 5 and [line[:2] for line in status] == ["1.", "2.", "3.", "4.", "5."]
    assert "round 8 integrated" not in STUDY and "rounds 1 to 9" in head
    glossary = STUDY.split("## Full record (working notes)")[1].split("## 0. Verdict first")[0]
    for term in ("*round*", "*lane*", "*critic*"):
        assert term in glossary, term


def test_the_order_of_writing_is_stated_as_the_authors_word_everywhere():
    pattern = re.compile(r"registered in advance|before any matrix run|author-registered|advance registration", re.I)
    files = [ROOT / "docs" / name for name in ("hook-fidelity-report.md", "hook-fidelity-report-appendix.md", "contribution.md")]
    files += sorted((ROOT / "docs" / "research-notes").rglob("*.md")) + [ROOT / "results" / "hook-fidelity" / "README.md"]
    files += sorted(BENCH.glob("*.py"))
    for path in files:
        for line in path.read_text().splitlines():
            if path.name == "test_hook_fidelity_report.py":
                continue
            if "Read \"registered in advance\" as" in line:
                continue
            assert not pattern.search(line), (path.name, line[:120])
    for text in (REPORT, STUDY):
        assert "the available timestamps do not settle the order" in _flat(text)


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
def test_contribution_is_a_short_current_page_with_each_part_the_verdict_needs():
    assert len(CONTRIBUTION.splitlines()) <= 140
    assert CONTRIBUTION.count("**Verdict.**") == 1
    for heading in (
        "## What is claimed, and the limit of each claim",
        "## What is not claimed",
        "## The route that remains",
        "## Pointers",
    ):
        assert heading in CONTRIBUTION, heading
    assert "SUPERSEDED" not in CONTRIBUTION
    assert "contribution-history.md" in CONTRIBUTION
    assert not re.search(r"pre-?regist|registered in advance", CONTRIBUTION, re.I)


def test_contribution_keeps_the_anchor_that_other_documents_link_to():
    assert '<a id="121-where-it-stands-among-open-source-mcp-guards"></a>' in CONTRIBUTION
    assert "### 12.1 Where it stands among open-source MCP guards" in HISTORY


def test_contribution_history_keeps_the_old_sections_and_their_superseded_marks():
    top = [int(m.group(1)) for m in re.finditer(r"^## (\d+)\. ", HISTORY, re.M)]
    assert top == list(range(1, len(top) + 1)), top
    subs = {m.group(1) for m in re.finditer(r"^#{3} (\d+\.\d+) ", HISTORY, re.M)}
    assert {"6.1", "9.1", "9.5", "12.1", "12.2"} <= subs
    for ref in re.findall(r"§(\d+(?:\.\d+)?)", HISTORY):
        top_level = int(ref.split(".")[0])
        assert top_level in top and ("." not in ref or ref in subs), ref
    section6 = HISTORY.split("## 6. The numbers that hold up")[1].split("### 6.1")[0]
    assert section6.count("SUPERSEDED") >= 5  # the lead paragraph and four items
    for needle in ("MSB held-out, live servers, neutral ids", "Earlier MSB rows", "Paired on 218 cases", "Tests:**"):
        line = next(line for line in section6.splitlines() if needle in line)
        assert "SUPERSEDED" in line, needle
    assert "**SUPERSEDED table" in HISTORY.split("## 9. Route 3")[1].split("### 9.1")[0]
    assert "Verdict (current" not in HISTORY.split("## The contribution, in detail")[0] + HISTORY.split("## 1. ")[0]


# ---------------------------------------------------------------------------------------------- one denominator, no slips
def test_the_rules_are_compared_before_and_after_on_one_denominator():
    g = rn.guards()
    line = g["rules_same_items"]
    for needle in (
        "166 items that stayed held out, 137/166 ",
        " before, 6/166 ",
        "178 items declared held out, 137/178 ",
        " before, 6/178 ",
        "156 built-in tool calls",
        "137/156 ",
        " before, 6/156 ",
    ):
        assert needle in line, needle
    assert "22 of 22" in g["rules_mcp_items"]
    assert "6 of 178" not in REPORT and "137/166 [76.0, 87.6]%, asks on 29" in REPORT
    fixtures = [json.loads(x) for x in (ROOT / "results/hook-fidelity/detect/fixtures.jsonl").read_text().splitlines()]
    declared = [f for f in fixtures if f["primary"] and f["label"] == "harmful" and f["heldout"]]
    decisions = json.loads((ROOT / "results/hook-fidelity/detect/summary.json").read_text())["decisions"]
    summary = decisions["intentshield"]["claimed"]["heldout"]
    assert len(declared) == 178 and summary["n_harmful"] == 166 and summary["false_allow"] == 137


def test_the_fresh_set_split_without_discovery_only_items_is_from_the_committed_rows():
    line = rn.guards()["fresh_discovery"]
    for needle in ("19/95", "(28/104 with them)", "safety-net 36/77", "IntentShield 17/77", "knox 39/68", "IntentShield 13/68"):
        assert needle in line, needle
    assert len(rn.DISCOVERY_ONLY) == 9 and "FH098" in rn.DISCOVERY_ONLY


# A k/n written beside a percentage must be that percentage, formatted from k and n at the digits shown (CLAUDE.md, "Rates").
# A tie at the last digit may go either way, because the generated tables round half to even.
_FORWARD = re.compile(
    r"(?<![\d.,/])(\d[\d,]*)\s*(?:/|of)\s*(\d[\d,]*)(?![\d/])\)?"
    r"(?:\s*(?:\(|is |=|,|:|-)\s*|\s+)(\d+(?:\.\d+)?)\s*(?:%|percent)(?!\s*(?:CI|conf))"
)
_BACKWARD = re.compile(r"(?<![\d.])(\d+(?:\.\d+)?)\s*(?:%|percent)\s*\(\s*(\d[\d,]*)\s*(?:/|of)\s*(\d[\d,]*)\s*\)")


def _matches(k: int, n: int, shown: str) -> bool:
    decimals = len(shown.split(".")[1]) if "." in shown else 0
    step = Decimal(1).scaleb(-decimals)
    exact = Decimal(k) * 100 / Decimal(n)
    return Decimal(shown) in {exact.quantize(step, rounding=ROUND_HALF_UP), exact.quantize(step, rounding=ROUND_HALF_EVEN)}


def percentage_mismatches(text: str) -> list[tuple[int, str]]:
    bad = []
    for number, line in enumerate(text.splitlines(), 1):
        found = [(m.group(1), m.group(2), m.group(3), m.group(0)) for m in _FORWARD.finditer(line)]
        found += [(m.group(2), m.group(3), m.group(1), m.group(0)) for m in _BACKWARD.finditer(line)]
        for k, n, shown, whole in found:
            k, n = int(k.replace(",", "")), int(n.replace(",", ""))
            if 0 < n and k <= n and not _matches(k, n, shown):
                bad.append((number, whole))
    return bad


def test_the_checker_catches_the_slip_it_was_written_for():
    assert percentage_mismatches("the per-build 263 of 277 is 95.0 percent") == [(1, "263 of 277 is 95.0 percent")]
    assert percentage_mismatches("the per-build 263 of 277 is 94.9 percent, 91.7 to 97.0") == []
    assert percentage_mismatches("5/8 62% and 5/8 63%") == []  # a tie at the last digit
    assert percentage_mismatches("27% (28/104)") == [] and percentage_mismatches("28% (28/104)") == [(1, "28% (28/104)")]


def test_no_percentage_in_the_study_documents_disagrees_with_its_k_over_n():
    docs = ROOT / "docs"
    files = sorted(docs.glob("hook-fidelity-*.md")) + [docs / "contribution.md", docs / "coverage-study.md"]
    files += sorted((docs / "research-notes").rglob("*.md")) + [ROOT / "results" / "README.md"]
    files += [p for p in sorted((ROOT / "results" / "hook-fidelity").rglob("README.md")) if "vendor-archive" not in p.parts]
    bad = {path.name: percentage_mismatches(path.read_text()) for path in files}
    assert not {name: found for name, found in bad.items() if found}
