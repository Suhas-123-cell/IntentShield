"""Figures that the front-door documents state, checked against the committed data or the scripts that print them.

The README line budget, the reading path's word counts, the split of the exemplar detector's 18.1%, the upper bounds printed
beside 0.0% cells and the baseline outputs in CONTRIBUTING.md.
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


def test_the_readme_stays_under_230_lines():
    assert len(READ("README.md").splitlines()) < 230


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


def _injection_rows() -> dict[str, list[tuple[int, int]]]:
    """family -> [(k, n) per column] from results/injection/table.txt (rules, prompt_guard, exemplars, rules+exemplars, ...)."""
    rows = {}
    for line in READ("results/injection/table.txt").splitlines():
        match = re.match(r"^(instruction|data):(\S+)\s+(.*)$", line)
        if match:
            rows[f"{match.group(1)}:{match.group(2)}"] = [(int(k), int(n)) for k, n in re.findall(r"(\d+)/(\d+)", match.group(3))]
    return rows


def test_the_exemplar_detectors_18_percent_is_split_into_seen_and_unseen_sources():
    rows = _injection_rows()
    generated = [f for f in rows if f.startswith("instruction:generated_output_")]
    unseen = ["instruction:agentdojo_direct", "instruction:agentdojo_ignore_previous", "instruction:injecagent_dh_base",
              "instruction:injecagent_ds_base"]
    rules, rules_exemplars = 0, 3   # column positions in the table
    in_distribution = (sum(rows[f][rules_exemplars][0] for f in generated), sum(rows[f][0][1] for f in generated))
    never_seen = (sum(rows[f][rules_exemplars][0] for f in unseen), sum(rows[f][0][1] for f in unseen))
    rules_unseen = sum(rows[f][rules][0] for f in unseen)
    assert in_distribution == (228, 346) and never_seen == (35, 1108) and rules_unseen == 17
    assert in_distribution[0] + never_seen[0] == 263 and in_distribution[1] + never_seen[1] == 1454
    assert sum(rows[f][rules][0] for f in generated + unseen) == 30
    flat = {name: re.sub(r"\s+", " ", READ(name)) for name in ("README.md", "docs/benchmarks.md", "docs/detectors.md")}
    assert "228 of its 263 hits" in flat["README.md"] and "35, or 3.2%" in flat["README.md"]
    for name in ("docs/benchmarks.md", "docs/detectors.md"):
        assert "228 of the 263 hits" in flat[name] and "35 (3.2%)" in flat[name] and "17 (1.5%)" in flat[name], name


def test_the_upper_bounds_printed_beside_zero_counts_are_wilson_bounds():
    for n in (216, 218, 220):
        assert f"{_wilson_upper(0, n):.1f}" == "1.7", n
    assert f"{_wilson_upper(0, 99):.1f}" == "3.7"
    assert f"{_wilson_upper(0, 194):.1f}" == "1.9"
    readme = re.sub(r"\s+", " ", READ("README.md"))
    assert "0 of 216 to 220 cases (95% upper bound 1.7%) or 0 of 99 (3.7%)" in readme
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


def test_the_readme_puts_what_it_stops_the_demo_and_local_storage_before_the_results():
    headings = re.findall(r"^## (.+)$", READ("README.md"), re.M)
    results, study = headings.index("Results"), headings.index("The hook study")
    for early in ("See it work", "What it stops and does not stop", "What is stored locally"):
        assert headings.index(early) < results < study, early


def test_the_injection_headline_says_which_rules_it_was_measured_with():
    """The committed table was made before the 0.3.5 rule that reads "Ignore your previous iunstructions". The rules now flag
    all 27 AgentDojo `ignore_previous` rows that the table counts as missed, so those rows are no longer independent of the
    rules."""
    import json

    sys.path.insert(0, str(ROOT / "benchmarks"))
    import injection_eval

    assert _injection_rows()["instruction:agentdojo_ignore_previous"][0] == (0, 27)    # the rules column of the committed table
    rows = [json.loads(line) for line in READ("results/injection/agentdojo-strings.jsonl").splitlines()]
    mine = [r for r in rows if r["source"] == "agentdojo_ignore_previous"]
    assert len(mine) == 27 and all(injection_eval.rules(r["text"], "output") for r in mine)
    flat = re.sub(r"\s+", " ", READ("README.md"))
    assert "before 0.3.5" in flat and "27 are AgentDojo `ignore_previous` rows" in flat
    assert "28 of 1,427 (2.0%)" in flat and "not re-measured with the 0.4.3 rules" in flat


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

