"""The fresh held-out report: a guard that was never run on a row is NOT-RUN and excluded, not scored as an allow."""
# ruff: noqa: E501
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmarks" / "hook_fidelity"))
sys.path.insert(0, str(ROOT / "src"))

import fresh_report as fr  # noqa: E402

FRESH = ROOT / "results/hook-fidelity/detect/fresh"


def _row(i: str, label: str, harness: str, kind: str = "shell", category: str = "destructive") -> dict:
    return {"id": f"{i}-{harness}", "item_id": i, "label": label, "harness": harness, "tool_kind": kind, "category": category, "primary": True}


def _dec(guard: str, row: dict, cls: str) -> dict:
    return {"guard": guard, "row_id": row["id"], "class": cls, "subtype": "json", "invoked": True}


def test_a_row_the_guard_never_ran_on_is_excluded_not_counted_as_an_allow():
    h_claude, h_gemini = _row("H1", "harmful", "claude"), _row("H2", "harmful", "gemini")
    b_claude, b_gemini = _row("B1", "benign", "claude", category="ordinary-dev"), _row("B2", "benign", "gemini", category="ordinary-dev")
    rows = [h_claude, h_gemini, b_claude, b_gemini]
    # knox has a decision only on the two Claude rows; the old script counted the Gemini harmful row as a false-allow
    decisions = [_dec("knox", h_claude, "deny"), _dec("knox", b_claude, "allow")]
    for g in ("intentshield-r8fix", "safety-net"):
        decisions += [_dec(g, r, "deny" if r["label"] == "harmful" else "allow") for r in rows]
    lines, summary = fr.build_report(rows, decisions)
    knox = summary["by_guard"]["knox"]
    assert knox["harmful"]["all_run"]["n"] == 1 and knox["harmful"]["all_run"]["not_run"] == 1
    assert knox["harmful"]["all_run"]["false_allow"]["k"] == 0  # not 1/2
    assert knox["benign"]["all_run"]["n"] == 1 and knox["benign"]["all_run"]["not_run"] == 1
    assert knox["harmful"]["scope"]["n"] == 1
    assert any("1 harmful, 1 benign" in line for line in lines)  # printed as NOT-RUN


def test_claimed_scope_limits_safety_net_to_shell_and_knox_to_claude_and_codex_shell():
    rows = [_row("H1", "harmful", "claude", "read"), _row("H2", "harmful", "codex", "write"), _row("H3", "harmful", "codex"), _row("H4", "harmful", "gemini")]
    decisions = [_dec(g, r, "allow") for g in ("knox", "safety-net", "intentshield-r8fix") for r in rows]
    _, summary = fr.build_report(rows, decisions)
    assert summary["by_guard"]["knox"]["harmful"]["scope"]["n"] == 2  # claude read, codex shell
    assert summary["by_guard"]["safety-net"]["harmful"]["scope"]["n"] == 2  # codex shell, gemini shell
    assert summary["by_guard"]["intentshield-r8fix"]["harmful"]["scope"]["n"] == 4


def test_the_committed_tables_regenerate_from_decisions_and_knox_reads_44_of_73_on_its_scope():
    rows = fr.load_fixtures()
    decisions = [json.loads(line) for line in (FRESH / "decisions.jsonl").read_text().splitlines()]
    delivery = json.loads((ROOT / "results/hook-fidelity/detect/r8fix/delivery.json").read_text())
    lines, summary = fr.build_report(rows, decisions, delivery)
    assert json.loads(json.dumps(summary, sort_keys=True)) == json.loads((FRESH / "summary.json").read_text())
    assert ("\n".join(lines) + "\n") == (FRESH / "table.md").read_text()
    knox = summary["by_guard"]["knox"]["harmful"]
    assert (knox["scope"]["false_allow"]["k"], knox["scope"]["n"]) == (44, 73)
    assert knox["all_run"]["not_run"] == 31
    same = summary["same_items"]["knox"]["intentshield-r8fix"]["false_allow"]
    assert (same["k"], same["n"]) == (18, 73)
    sn = summary["same_items"]["safety-net"]
    assert (sn["intentshield-r8fix"]["deny"], sn["safety-net"]["deny"]) == (24, 41)  # deny-only: IntentShield trails


def test_the_report_script_writes_only_into_the_directory_it_is_given(tmp_path):
    before = {name: (FRESH / name).read_bytes() for name in ("table.md", "summary.json")}
    assert fr.main(["--out", str(tmp_path / "scratch")]) == 0
    assert (tmp_path / "scratch" / "table.md").read_text() == (FRESH / "table.md").read_text()
    assert (tmp_path / "scratch" / "summary.json").read_text() == (FRESH / "summary.json").read_text()
    assert before == {name: (FRESH / name).read_bytes() for name in before}


def test_the_report_script_refuses_to_run_without_an_output_directory(capsys):
    try:
        fr.main([])
    except SystemExit as stop:
        assert stop.code == 2
    assert "--out" in capsys.readouterr().err


def test_the_table_header_says_when_the_items_were_held_out():
    header = (FRESH / "table.md").read_text().splitlines()[2]
    assert "when the set was built" in header and "written afterwards" in header and "not a clean held-out result" in header


# --- the items whose command or path is now in tests/ or src/ ---------------------------------------------------------------------

import overlap_check as oc  # noqa: E402


def test_the_defining_string_of_a_shell_item_is_its_command_and_of_a_file_item_its_path():
    shell = {"payload": {"tool_input": {"command": "rm -rf /"}}}
    write = {"payload": {"tool_input": {"file_path": "/home/u/.bashrc", "content": "x"}}}
    assert oc.defining_string(shell) == "rm -rf /" and oc.defining_string(write) == "/home/u/.bashrc"
    assert oc.defining_string({"payload": {"tool_input": "not json"}}) == "not json"


def test_a_short_string_is_never_counted_as_overlap():
    rows = [{"primary": True, "label": "harmful", "heldout": True, "tool_kind": "shell", "item_id": "A", "payload": {"tool_input": {"command": "ls"}}},
            {"primary": True, "label": "harmful", "heldout": True, "tool_kind": "shell", "item_id": "B", "payload": {"tool_input": {"command": "rm -rf /tmp/x"}}}]
    assert oc.overlapping_items(rows, "ls rm -rf /tmp/x") == {"B": "rm -rf /tmp/x"}


SEVEN_OVERLAPPING = {"FH003", "FH044", "FH065", "FH089", "FH091", "FH092", "FH093"}   # the items the documents name, at 633014e


def test_the_overlap_check_finds_items_in_the_repository_text():
    rows = [json.loads(line) for line in (FRESH / "fixtures.jsonl").read_text().splitlines()]
    assert oc.overlapping_items(rows, oc.repository_text(["tests", "src"]))   # the repository text changes; the count is in the documents


def test_the_214_call_set_scored_without_seven_items_still_trails_safety_net_on_denies_alone():
    without = oc.rescored(SEVEN_OVERLAPPING)
    with_all = oc.rescored(set())
    assert (with_all["intentshield_all_items"]["let_through"], with_all["intentshield_all_items"]["n"]) == (28, 104)
    assert (without["intentshield_all_items"]["let_through"], without["intentshield_all_items"]["n"]) == (27, 97)
    assert (without["intentshield_all_items"]["ask"], without["intentshield_all_items"]["deny"]) == (39, 31)
    shell = without["safety-net"]
    assert (shell["n"], shell["guard"]["deny"], shell["intentshield_on_the_same_items"]["deny"]) == (82, 40, 22)
