"""Counts and ranges in the committed hook-fidelity rows, recomputed from the rows themselves (no harness is launched). They pin the
figures the study's working notes quoted. The notes are on the research-notes branch; their wording is not checked here."""
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "results" / "hook-fidelity"
if not RES.is_dir():
    pytest.skip("needs the repository's docs/ and results/ (a full clone, not an installed package)", allow_module_level=True)


def rows(*parts: str) -> list[dict]:
    path = RES.joinpath(*parts)
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_untrusted_codex_rows_are_70_not_40():
    codex = rows("codex", "runs.jsonl")
    untrusted = [r for r in codex if r["state"] == "untrusted"]
    assert len(codex) == 428 and len(untrusted) == 70
    assert sum(r["version"] in ("0.165.0", "0.166.0") for r in untrusted) == 40


def test_claude_r9_rows_and_wall_times():
    claude = rows("claude", "all-runs.jsonl")
    r9 = [r for r in claude if r["reply"] == "R9"]
    assert len(claude) == 540 and len(r9) == 53 and {r["timeout_observation"] for r in r9} == {"killed-or-abandoned"}
    ran = [r for r in r9 if r["outcome"] == "RAN"]
    assert len(ran) == 48 and (min(r["wall_s"] for r in ran), max(r["wall_s"] for r in ran)) == (3.53, 4.33)
    assert sum(r["version"] == "2.1.0" for r in r9) == 2


def test_codex_r9_wall_times():
    r9 = [r for r in rows("codex", "runs.jsonl") if r["reply"] == "R9"]
    assert len(r9) == 24 and (min(r["wall_s"] for r in r9), max(r["wall_s"] for r in r9)) == (3.9, 4.13)


def test_committed_stub_rows_are_1350_and_the_kill_criterion_is_three_of_five():
    from hook_fidelity import summarize

    gemini = [r for d in ("main", "sweep", "enable-default", "smoke") for r in rows("gemini", d, "runs.jsonl")]
    allrows = rows("claude", "all-runs.jsonl") + rows("codex", "runs.jsonl") + gemini
    assert len(allrows) == 1350
    kept = [r for r in allrows if r not in rows("gemini", "smoke", "runs.jsonl")]
    assert len(kept) == 1342
    kill = summarize.summarize(kept)["kill"]
    assert kill["met"] is False
    assert sum(v["undocumented"] for v in kill["harness"].values()) == 20
    assert sum(v["replicated_on_3"] for v in kill["harness"].values()) == 3


def test_the_claude_ask_flip_is_between_2_1_84_and_2_1_85():
    flip = rows("claude", "r4-gaps", "bisect", "runs.jsonl")
    ask = {v: {r["outcome"] for r in flip if r["version"] == v and r["reply"] == "R3"} for v in {r["version"] for r in flip}}
    assert ask == {"2.1.78": {"RAN"}, "2.1.83": {"RAN"}, "2.1.84": {"RAN"}, "2.1.85": {"BLOCKED"}, "2.1.86": {"BLOCKED"}}


def test_codex_persisted_trust_failure_replies_all_ran():
    gaps = [r for r in rows("codex", "r4-gaps", "runs.jsonl") if r["state"] == "trusted-persisted"
            and r["reply"] in ("R3", "R5", "R9", "R11", "R16")]
    more = rows("codex", "r4-integration", "runs.jsonl")
    assert len(gaps) == 20 and all(r["outcome"] == "RAN" and r["hook_invoked"] is True for r in gaps)
    assert len(more) == 6 and {r["reply"] for r in more} == {"R6", "R8", "R15"}
    assert all(r["outcome"] == "RAN" and r["hook_invoked"] is True and r["version"] == "0.166.0" for r in more)


def test_codex_bypass_boundary_is_0_140_to_0_141():
    bisect = rows("codex", "r4-integration", "bisect", "runs.jsonl")
    seen = {(r["version"], r["outcome"], r["hook_invoked"]) for r in bisect}
    assert seen == {("0.141.0", "RAN", True), ("0.142.0", "RAN", True)}
    assert len(bisect) == 4
    sweep = [r for r in rows("codex", "runs.jsonl")
             if r["version"] == "0.140.0" and r["reply"] == "R1" and r["state"] == "trusted-bypass"]
    assert sweep and not any(r["hook_invoked"] for r in sweep)


def test_round4_mitigation_controls():
    import hook_fidelity.mitigation_r4_summary as summary

    eval_rows = summary.load(RES / "mitigation" / "eval-r4")
    t = summary.tally(eval_rows)
    assert len(eval_rows) == 36 and t["allow_evaluable"] == 11 and t["allow_cells"] == 12
    assert t["allow_ran_off"] == t["allow_ran_on"] == 11 and t["allow_native_gate"] == ["claude 2.1.296"]
    assert len(t["deny_all"]) == 6 and all(x[2] == "BLOCKED" for x in t["deny_all"])
    assert sum(x[3] == "RAN" for x in t["deny_all"]) == 5
    assert [x[2] for x in t["slow"]] == ["BLOCKED"] * 3 and all(30 <= x[3] < 33 for x in t["slow"])
    assert [x[2] for x in t["norecord"]] == ["BLOCKED"] * 3


def test_round3_mitigation_counts():
    m = rows("mitigation", "eval", "runs.jsonl")
    assert len(m) == 192 and sum(bool(r.get("user_agent")) and r["version"] in r["user_agent"] for r in m) == 148


def test_guard_headline_is_restated_per_run():
    headline = json.loads((RES / "guards" / "summary.json").read_text())["headline"]
    assert headline["live_cells_tested"] == 38 and headline["live_cells_guarded_call_ran"] == 5
    per_run = headline["per_run"]
    assert per_run["codex untrusted"] == {"runs": 12, "call_ran": 12, "hook_invoked": 0}
    assert per_run["codex trusted"]["call_ran"] == 0 and per_run["codex trusted"]["runs"] == 18
    assert per_run["claude"]["call_ran"] == 0 and per_run["claude"]["runs"] == 66


# ----------------------------------------------------------------------------------------------------------------- round 8
# ruff: noqa: E501
def test_round_8_launch_ledgers_sum_to_the_200_the_study_cites():
    def lines(*parts):
        return len((RES.joinpath(*parts)).read_text().splitlines())

    lane = [lines("detect", "validation", "launches.jsonl"), lines("compare", "launches-r8.jsonl"), lines("real-model", "launches.jsonl"),
            lines("real-model-supp", "launches.jsonl"), lines("real-model-deepseek", "launches.jsonl")]
    assert lane == [59, 51, 34, 27, 10] and sum(lane) == 181
    critics = [9, lines("real-model-critic", "launches.jsonl")]   # the close-out critic's 9 are reported, not ledgered in the repo
    assert critics[1] == 10 and sum(lane) + sum(critics) == 200


def test_round_8_closeout_figures():
    summary = json.loads((RES / "compare" / "summary-r8.json").read_text())
    assert (summary["rows"], summary["invalid"], summary["launches"]) == (51, 0, 51)
    p1 = summary["part1"]
    assert (p1["rows"], p1["pairs"]["n"], p1["pairs"]["r8_survived"], p1["groups_same"], p1["rows_same_outcome_as_r7"], p1["changes"]) == (36, 12, 12, 20, 36, [])
    assert (p1["ask"]["r8_blocked"], p1["ask"]["r8_n"]) == (12, 12)
    det = summary["detector"]
    how = det["how"]
    assert sum(v for k, v in how.items() if "command line has its" in k) == 41     # real flag reads
    assert (how["headless: the harness has no terminal"], how["headless: the harness process was not found among the ancestors: assumed headless"]) == (6, 4)
    assert (det["source"], det["complete"], det["errors"]) == ({"libproc": 51}, 51, 0)
    p2 = summary["part2"]
    assert (p2["rows"], p2["ran"], p2["by_cell"]["emptyexit0"]) == (15, 3, {"ran": 3, "n": 3})
    assert sum(c["ran"] for k, c in p2["by_cell"].items() if k != "emptyexit0") == 0
    allow = summary["allow_fraction"]["all_shapes"]
    assert (allow["allows"], allow["allows_blocked_by_default"], allow["allows_blocked_by_on_empty_allow"]) == (17, 12, 0)
    pairs = summary["allow_fraction"]["by_pair_claude_codex_gemini"]
    assert (pairs["silent_allow_pairs"], pairs["allow_pairs"], pairs["silent_allow_pairs_excluding_fail_open"], pairs["allow_pairs_excluding_fail_open"]) == (6, 9, 5, 8)


def test_round_8_linux_figures():
    rows_ = rows("linux", "rows.jsonl")
    assert len(rows_) == 37
    summary = json.loads((RES / "linux" / "summary.json").read_text())
    g = summary["by_group"]
    assert (g["matrix"]["agree"], g["matrix"]["n"], g["hidepid"]["agree"], g["pid1"]["agree"], g["pid1"]["n"], g["pid1"]["mode_equal"]) == (28, 28, 1, 0, 8, 6)


def test_round_8_detection_fixture_sizes():
    summary = json.loads((RES / "detect" / "summary.json").read_text())
    assert summary["fixtures"]["heldout"] == {"harmful": 166, "benign": 234}


def test_codex_round4_rows_are_51_not_47():
    parts = (("r4-gaps", "runs.jsonl"), ("r4-gaps", "nojson-debug", "runs.jsonl"), ("r4-integration", "runs.jsonl"),
             ("r4-integration", "bisect", "runs.jsonl"))
    counts = [len(rows("codex", *p)) for p in parts]
    assert counts == [39, 2, 6, 4]
    ids = {r["run_id"] for p in parts for r in rows("codex", *p)}
    assert len(ids) == sum(counts) == 51


def _committed_stub_rows() -> list[dict]:
    gemini = [r for d in ("main", "sweep", "enable-default") for r in rows("gemini", d, "runs.jsonl")]
    return rows("claude", "all-runs.jsonl") + rows("codex", "runs.jsonl") + gemini


def test_the_coding_is_deterministic_over_the_committed_rows():
    """Re-running the coder (cell grouping, liveness, prediction hit or miss, deviation class, kill criterion) over the committed raw
    rows gives the same codes: twice in the same order, and under seeded shuffles. This checks the coder; it does not re-run any
    launch (the 6 cells x 20 repeats determinism run on the stub was not done) and does not re-score a launch from its evidence."""
    import random

    from hook_fidelity import summarize

    allrows = _committed_stub_rows()
    assert len(allrows) == 1342
    first = summarize.summarize(allrows)
    again = summarize.summarize(allrows)
    assert summarize.format_report(first) == summarize.format_report(again)
    assert len(first["table"]) == 507 and first["informative"] == 245
    assert first["hits"][("docs", True)] == 263 and first["hits"][("docs", False)] == 14

    def same(a: dict, b: dict) -> bool:
        # only the order of the flip lines (and of dict keys) depends on the order of the input rows
        def flips(summary: dict) -> list:
            return sorted((repr(key), sorted(by_build.items())) for key, by_build in summary["flips"])

        return all(a[k] == b[k] for k in a if k != "flips") and flips(a) == flips(b)

    assert same(first, again)
    for seed in (0, 1, 2):
        shuffled = allrows[:]
        random.Random(seed).shuffle(shuffled)
        other = summarize.summarize(shuffled)
        assert same(first, other), seed
        assert sorted(summarize.format_report(other).splitlines()) == sorted(summarize.format_report(first).splitlines())

