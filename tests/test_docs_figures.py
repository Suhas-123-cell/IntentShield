"""Figures that the front-door documents state, checked against the committed data or the scripts that print them.

The README line budget, the reading path's word counts, the injection table, the upper bounds printed beside 0.0% cells and the
baseline outputs in CONTRIBUTING.md.
"""
from __future__ import annotations

import math
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
READ = lambda name: (ROOT / name).read_text(encoding="utf-8")


def _wilson_upper(k: int, n: int, z: float = 1.959964) -> float:
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return 100 * (centre + half)


def test_the_readme_stays_a_front_page_of_at_most_140_lines():
    assert len(READ("README.md").splitlines()) <= 140


def test_the_reading_path_word_counts_are_wc_counts():
    """docs/README.md gives a word count and a time per step; each count is within 5% of `wc -w` on the file."""
    text = READ("docs/README.md")
    table = text.split("**A reading path**")[1].split("\n\n")[1]
    rows = [[c.strip() for c in line.strip("|").split("|")] for line in table.splitlines()[2:]]
    actual = {
        "README": len(READ("README.md").split("## Results")[0].split()),
        "contribution.md": len(READ("docs/contribution.md").split()),
        "hook-fidelity-report.md": len(READ("docs/hook-fidelity-report.md").split()),
    }
    stated = {}
    for step, _what, words, minutes in rows:
        count = int(words.replace(",", ""))
        stated[step] = (count, int(minutes))
        key = next((k for k in actual if k in step), None)
        if key:
            assert abs(count - actual[key]) <= 0.05 * actual[key], (key, count, actual[key])
    total_words, total_minutes = stated["all three"]
    parts = [v for k, v in stated.items() if k != "all three"]
    assert abs(total_words - sum(w for w, _ in parts)) <= 10
    assert abs(total_minutes - total_words / 250) <= 1 and abs(total_minutes - sum(m for _, m in parts)) <= 1


def _words(paths) -> int:
    return sum(len(path.read_text(encoding="utf-8", errors="replace").split()) for path in paths)


def test_the_stated_size_of_each_group_of_documents_is_a_wc_count():
    """docs/README.md says how many words the product documentation and the research write-ups hold."""
    text = " ".join(READ("docs/README.md").split())
    product = [ROOT / name for name in ("README.md", "docs/guide.md", "docs/layers.md", "docs/gateway.md", "docs/detectors.md",
                                         "docs/benchmarks.md", "docs/security-review.md", "docs/architecture-and-testing.md",
                                         "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md")]
    research = [ROOT / "docs" / name for name in ("contribution.md", "hook-fidelity-report.md",
                                                   "hook-fidelity-report-appendix.md", "related-work.md", "coverage-study.md")]
    user = [ROOT / "README.md", ROOT / "docs" / "guide.md"]
    stated = {
        "product": (r"\*\*Product documentation\*\*[^.]*?about ([\d,]+) words in all", product),
        "user": (r"needs only the README and the guide, about ([\d,]+) words", user),
        "research": (r"\*\*Research write-ups\*\*[^:]*?about ([\d,]+) words", research),
    }
    for name, (pattern, files) in stated.items():
        match = re.search(pattern, text)
        assert match, name
        count = int(match.group(1).replace(",", ""))
        assert abs(count - _words(files)) <= 0.03 * _words(files), (name, count, _words(files))


def _injection_rows() -> dict[str, list[tuple[int, int]]]:
    """family -> [(k, n) per column] from results/injection/table.txt (rules, prompt_guard, exemplars, rules+exemplars, ...)."""
    rows = {}
    for line in READ("results/injection/table.txt").splitlines():
        match = re.match(r"^(instruction|data):(\S+)\s+(.*)$", line)
        if match:
            rows[f"{match.group(1)}:{match.group(2)}"] = [(int(k), int(n)) for k, n in re.findall(r"(\d+)/(\d+)", match.group(3))]
    return rows


def _rules_column() -> dict[str, tuple[int, int]]:
    """The rules' hits per group of rows, from the committed corpus, with the rules in this checkout.

    InjecAgent is not committed, so its rows are not here."""
    import injection_eval

    res = ROOT / "results" / "injection"
    rows = [r for r in injection_eval.load_corpus(res / "dataset.jsonl", Path("/nonexistent"), res / "agentdojo-strings.jsonl",
                                                   res / "hard_negatives.jsonl") if r["split"] in ("test", "external")]
    groups: dict[str, list[int]] = {}
    for r in rows:
        family = r["family"]
        if r["label"] == "data":
            key = "benign"
        elif family.startswith("generated_output_"):
            key = "generated"
        elif family.startswith("mcptox_poisoned_description"):
            key = "mcptox"
        elif family in ("agentdojo_important_instructions", "agentdojo_system_message", "agentdojo_tool_knowledge"):
            key = "agentdojo_tuned"
        else:
            key = family
        hit = injection_eval.rules(r["text"], r["kind"])
        groups.setdefault(key, [0, 0])
        groups[key][0] += bool(hit)
        groups[key][1] += 1
    return {k: (v[0], v[1]) for k, v in groups.items()}


def test_the_injection_table_in_benchmarks_matches_the_rules_and_the_committed_table():
    """The table of docs/benchmarks.md was measured on 2026-11-12 with the exemplar index, which is not committed.

    The rules' column for every family that does not need InjecAgent is recomputed here, the sums are checked, and the exemplar
    column is checked against the committed table of 2026-10-21 for the families whose figure did not change."""
    mine = _rules_column()
    assert mine["generated"] == (11, 346) and mine["agentdojo_direct"] == (0, 27)
    assert mine["agentdojo_ignore_previous"] == (27, 27) and mine["agentdojo_tuned"] == (81, 81) and mine["mcptox"] == (313, 370)
    assert mine["benign"][0] == 16 - 0 and mine["benign"][1] == 758 - 17      # the 17 InjecAgent benign rows are not committed
    old = _injection_rows()
    rules, rules_exemplars = 0, 3     # column positions in the committed table
    generated = [f for f in old if f.startswith("instruction:generated_output_")]
    assert sum(old[f][rules_exemplars][0] for f in generated) == 228 and sum(old[f][rules][0] for f in generated) == 13
    assert old["instruction:agentdojo_direct"][rules_exemplars][0] == 1
    ignore_previous = old["instruction:agentdojo_ignore_previous"]
    assert ignore_previous[rules] == (0, 27) and ignore_previous[rules_exemplars] == (11, 27)
    dh_base, ds_base = old["instruction:injecagent_dh_base"], old["instruction:injecagent_ds_base"]
    assert dh_base[rules][0] + ds_base[rules][0] == 17
    assert dh_base[rules_exemplars][0] + ds_base[rules_exemplars][0] == 23
    # the sums in the document's table
    assert 17 + 0 + 27 + 11 == 55 and 23 + 1 + 27 + 228 == 279 and 55 - 27 == 28 and 279 - 27 == 252
    assert 55 + 1054 + 81 + 313 == 1503 and 279 + 1054 + 81 + 313 == 1727 and 1454 + 1054 + 81 + 370 == 2959
    flat = re.sub(r"\s+", " ", READ("docs/benchmarks.md"))
    for row in ("| InjecAgent base, two settings | 1,054 | 17 (1.6%) | 23 (2.2%) |",
                "| AgentDojo `ignore_previous` (a 0.3.5 rule was written from these) | 27 | 27 | 27 |",
                "| generated outputs, four styles (the exemplar index's own styles) | 346 | 11 (3.2%) | 228 (65.9%) |",
                "| **these four, 1,454 injections not tuned on** | 1,454 | 55 (3.8%) | 279 (19.2%) |",
                "| **without `ignore_previous`, 1,427 no rule was written from** | 1,427 | 28 (2.0%) | 252 (17.7%) |",
                "| **all injections** | 2,959 | 1,503 (50.8%) | 1,727 (58.4%) |",
                "| benign texts flagged | 758 | 16 (2.1%) | 18 (2.4%) |"):
        assert row in flat, row
    assert "30 of the 1,454 (2.1%) and rules + exemplars 263 (18.1%)" in flat
    readme = re.sub(r"\s+", " ", READ("README.md"))
    assert "28 of 1,427 (2.0%)" in readme and "252 (17.7%)" in readme and "50.8% of all 2,959 injections" in readme


def test_the_upper_bounds_printed_beside_zero_counts_are_wilson_bounds():
    for n in (216, 218, 220):
        assert f"{_wilson_upper(0, n):.1f}" == "1.7", n
    assert f"{_wilson_upper(0, 99):.1f}" == "3.7"
    assert f"{_wilson_upper(0, 194):.1f}" == "1.9"
    benchmarks = re.sub(r"\s+", " ", READ("docs/benchmarks.md"))
    assert "0 of 216 to 220 cases (95% upper bound 1.7%) or 0 of 99 (3.7%)" in benchmarks
    assert "95% upper bound 1.9%" in re.sub(r"\s+", " ", READ("docs/contribution.md"))
    assert "0 of 194" in READ("docs/benchmarks.md") and "1.9%" in READ("docs/benchmarks.md")


def _run(args: list[str], extra_env: dict[str, str] | None = None) -> str:
    env = {k: v for k, v in os.environ.items() if not k.startswith("INTENTSHIELD_")}
    env.update(extra_env or {})
    done = subprocess.run([sys.executable, *args], capture_output=True, text=True, cwd=ROOT, env=env, timeout=300)
    assert done.returncode == 0, done.stderr[-500:]
    return done.stdout


def test_contributings_baseline_outputs_are_what_the_scripts_print(tmp_path):
    text = READ("CONTRIBUTING.md")
    printed = _run(
        ["benchmarks/injection_eval.py", "--dataset", "results/injection/dataset.jsonl", "--hard",
         "results/injection/hard_negatives.jsonl", "--agentdojo", "results/injection/agentdojo-strings.jsonl",
         "--injecagent", "/nonexistent", "--out", str(tmp_path / "eval.json")],
        {"INTENTSHIELD_INTENT_MODEL_DIR": "/nonexistent"},
    )
    recall = re.search(r"^ALL instruction \(recall\)\s+(\d+/\d+)", printed, re.M)
    benign = re.search(r"^ALL data \(benign flagged\)\s+(\d+/\d+)", printed, re.M)
    assert recall and f"`ALL instruction (recall) {recall.group(1)}`" in text, recall and recall.group(1)
    assert benign and f"`ALL data (benign flagged) {benign.group(1)}`" in text, benign and benign.group(1)
    replay = _run(["benchmarks/shell_replay.py"])
    shell = re.search(r"^\s*shell: (\d+/\d+) asked or denied", replay, re.M)
    write = re.search(r"^\s*write: (\d+/\d+) asked or denied", replay, re.M)
    assert shell and f"`shell: {shell.group(1)} asked or denied`" in text, shell and shell.group(1)
    assert write and f"`write: {write.group(1)}`" in text, write and write.group(1)


def test_the_readme_puts_what_it_stops_the_install_and_local_storage_before_the_results():
    headings = re.findall(r"^## (.+)$", READ("README.md"), re.M)
    results, study = headings.index("Results"), headings.index("The hook study")
    for early in ("Install", "What it stops and does not stop", "What is stored locally", "Upgrading and removing"):
        assert headings.index(early) < results < study, early


def test_the_readme_results_summary_is_short_and_leads_with_the_weak_numbers():
    section = READ("README.md").split("\n## Results\n")[1].split("\n## ")[0]
    lines = [line for line in section.splitlines() if line.strip()]
    assert len(lines) <= 9, len(lines)      # the lead-in line and at most eight lines of summary
    assert lines[1].startswith("- **Injection text the rules were not written for")


def test_the_msb_tables_say_how_a_held_call_is_counted():
    """Every table of 'harmful executed' carries the footnote that a call held for a human counts as not executed."""
    text = re.sub(r"\s+", " ", READ("docs/benchmarks.md"))
    assert text.count("*Harmful executed* counts a call held for a human as not executed") == 2
    assert "*Harm executed* counts a call held for a human" in text


def test_the_hook_overhead_in_the_guide_matches_the_benchmark_row_and_the_readme():
    row = next(line for line in READ("docs/benchmarks.md").splitlines() if line.startswith("| Overhead"))
    low, high = (float(x) for x in re.search(r"hook (\d+) to (\d+) ms per event", row).groups())
    tag = re.search(r"73\.5 to 74\.1 ms per\s+event", READ("docs/benchmarks.md"))
    assert tag
    guide = re.sub(r"\s+", " ", READ("docs/guide.md"))
    stated = re.search(r"Each hook is a process of about (\d+) to (\d+) ms", guide)
    assert stated and float(stated.group(1)) <= low and float(stated.group(2)) >= 74.1
    assert "about 60 ms" not in guide
    readme = re.search(r"about (\d+) ms per hook event", re.sub(r"\s+", " ", READ("README.md")))
    assert readme and float(stated.group(1)) <= float(readme.group(1)) <= float(stated.group(2))

