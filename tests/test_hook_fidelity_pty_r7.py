"""Offline tests of the round 7 additions to the interactive pty lane: the plan and its launch count, the per-round ledger cap,
the cells' traits (no ps relay, wrapper, no tty, replay), the replay hook configuration, the no-tty driver against a real
process, the observer's ground-truth facts and the table. No harness CLI is launched and nothing touches the network."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1] / "benchmarks" / "hook_fidelity"
sys.path.insert(0, str(BENCH.parent))
sys.path.insert(0, str(BENCH))
import pty_lane as pl  # noqa: E402


def test_the_round_7_plan_is_twenty_one_launches_under_the_cap_of_forty():
    cases = pl.plan_r7()
    assert len(cases) == 21 and len(cases) <= pl.LEDGER_CAP
    assert len({pl.case_id(c) for c in cases}) == 21 and all(c["round"] == 7 for c in cases)
    count = {}
    for c in cases:
        count[(c["harness"], c["cell"])] = count.get((c["harness"], c["cell"]), 0) + 1
    assert count[("claude", "ask-on-nops")] == count[("gemini", "ask-on-nops")] == 2
    assert count[("claude", "ask-on-dark")] == count[("gemini", "ask-on-dark")] == 2
    assert all(count[(h, c)] == 1 for h in pl.VERSIONS for c in ("ask-on-wrapped", "headless-notty"))
    assert count[("claude", "headless-notty-dark")] == 1 and pl.cell_traits("headless-notty-dark")["sources"] == "none"
    assert count[("codex", "ask-raw")] == count[("claude", "replay-ccsafe")] == count[("claude", "replay-railway")] == 2


def test_no_round_7_cell_uses_the_ps_relay_and_the_round_6_cells_keep_theirs():
    assert all(not pl.cell_traits(c)["relay"] for c in pl.CELLS_R7)
    assert pl.cell_traits("ask-on")["relay"] is pl.PS_RELAY
    assert pl.cell_traits("ask-on-dark")["sources"] == "none" and pl.cell_traits("ask-on-nops")["sources"] == ""
    assert pl.cell_traits("headless-notty")["interactive"] is False and pl.cell_traits("headless-notty")["launch"] == "notty"
    assert pl.cell_traits("ask-on-wrapped")["launch"] == "wrapped"


def test_the_ledger_cap_is_per_round(tmp_path):
    for _ in range(40):
        pl.write_ledger(tmp_path, {"run_id": "x", "case": {}})              # round 6 entries have no field
    assert pl.ledger_count(tmp_path, 6) == 40 and pl.ledger_count(tmp_path, 7) == 0
    pl.write_ledger(tmp_path, {"run_id": "y", "round": 7, "case": {}})
    assert pl.ledger_count(tmp_path, 7) == 1 and pl.ledger_count(tmp_path, 6) == 40


def test_the_shipped_ledger_still_counts_forty_for_round_6():
    out = BENCH.parents[1] / "results" / "hook-fidelity" / "interactive"
    assert pl.ledger_count(out, 6) == 40


def test_replays_use_the_captured_bytes_and_the_guards_shipped_matcher(tmp_path):
    for cell, guard in (("replay-ccsafe", "cc-safe-setup"), ("replay-railway", "railway-guard")):
        case = {"harness": "claude", "version": "2.1.316", "cell": cell, "rep": 0, "round": 7}
        assert pl.replay_file(case).exists()
        record = json.loads(pl.replay_file(case).read_text())
        sent = json.loads(base64.b64decode(record["stdout_b64"]))["hookSpecificOutput"]
        assert sent["permissionDecision"] == "ask" and record["exit_code"] == 0
        entries = pl.hook_entries(case, tmp_path)
        group = entries["PreToolUse"][0]
        assert group["matcher"] == "Bash" and "timeout" not in group["hooks"][0]
        command = group["hooks"][0]["command"]
        assert "stubhook.py" in command and "--reply RP" in command
        assert "pty_hook" not in command and "mitigation_hook" not in command         # no IntentShield code runs in a replay
        assert "onFailure" not in group["hooks"][0] and "||" not in command          # the shipped config: no launcher
        assert pl.GUARD_REPLAYS[cell][0] == guard


def test_the_ask_replays_are_the_ones_the_study_indexed_as_ask():
    index = json.loads((pl.GUARDS_REPLAY_DIR / "index.json").read_text())
    for guard, rid in pl.GUARD_REPLAYS.values():
        entry = next(e for e in index if e["id"] == rid)
        assert entry["intent"] == "ASK" and any(c["guard"] == guard and c["shape"] == "claude" for c in entry["captures"])


def test_the_raw_ask_arm_is_the_installed_entries_with_the_bytes_replayed_and_no_launcher(tmp_path):
    case = {"harness": "codex", "version": "0.166.0", "cell": "ask-raw", "rep": 0, "round": 7}
    entries = pl.hook_entries(case, tmp_path)
    commands = [h["command"] for g in entries["PreToolUse"] for h in g["hooks"]]
    assert commands and all("stubhook.py" in c and "||" not in c for c in commands)
    raw = json.loads(pl.RAW_ASK.read_text())
    sent = json.loads(base64.b64decode(raw["stdout_b64"]))["hookSpecificOutput"]
    assert sent["permissionDecision"] == "ask" and raw["exit_code"] == 0


def test_a_translated_dark_cell_passes_ancestry_sources_none_to_the_hook(tmp_path):
    case = {"harness": "claude", "version": "2.1.316", "cell": "ask-on-dark", "rep": 0, "round": 7}
    command = pl.hook_entries(case, tmp_path)["PreToolUse"][0]["hooks"][0]["command"]
    assert "--ancestry-sources none" in command and "--eval-translate on" in command


def test_the_wrapper_runs_the_harness_as_a_child_not_an_exec(tmp_path):
    wrapper = pl.wrapper_program(tmp_path)
    probe = "import os; print(os.getppid() != 1, os.environ['LAUNCHED_BY_WRAPPER'])"
    done = subprocess.run(["/bin/sh", str(wrapper), sys.executable, "-c", probe], capture_output=True, text=True, timeout=20)
    assert done.stdout.strip() == "True 1" and "wrapper: harness exited 0" in done.stderr


def test_the_no_tty_driver_gives_a_process_no_terminal_and_no_session_leader_tty(tmp_path):
    code = ("import os,sys; ok=True\n"
            "try:\n    os.close(os.open('/dev/tty', os.O_RDWR))\nexcept OSError:\n    ok=False\n"
            "print('ctty', ok, 'stdin_tty', os.isatty(0), 'stdout_tty', os.isatty(1))\n")
    proc, obs, clean, raw = pl.drive_notty([sys.executable, "-c", code], dict(os.environ), tmp_path, tmp_path / "out.txt")
    assert proc.returncode == 0 and obs.exited and "ctty False stdin_tty False stdout_tty False" in clean.text


def test_the_observer_records_ground_truth_facts_that_do_not_come_from_the_detector(tmp_path):
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "s", "tool_input": {"command": "touch x"},
             "cwd": str(tmp_path)}
    log = tmp_path / "l.jsonl"
    env = {**os.environ, "INTENTSHIELD_HARNESS_VERSION": "2.1.316", "INTENTSHIELD_HOOK_DB": str(tmp_path / "h.db"),
           "INTENTSHIELD_THREAT_MEMORY": "0"}
    env.pop("INTENTSHIELD_HARNESS_MODE", None)
    argv = [sys.executable, str(BENCH / "pty_hook.py"), "claude", "--builtin-tools", "--eval-verdict", "ask",
            "--eval-translate", "on", "--pty-log", str(log), "--ancestry-sources", "none"]
    done = subprocess.run(argv, input=json.dumps(event), capture_output=True, text=True, env=env, timeout=60)
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    start = next(r for r in rows if r["phase"] == "start")
    assert start["has_ctty"] in (True, False) and start["stdout_isatty"] is False and start["ps_check"]
    assert start["ancestry_sources_env"] == "none" and start["probe_mode"] == "unknown"
    assert start["probe_ancestry"] == {"source": "none", "complete": False, "why": start["probe_ancestry"]["why"]}
    end = next(r for r in rows if r["phase"] == "end")
    assert end["ask_decisions"][0]["mode"] == "unknown" and end["ask_decisions"][0]["sent"] == "ask"
    assert "read this session as unknown" in done.stdout


def _row(**kw):
    base = {"harness": "claude", "version": "2.1.316", "cell": "ask-on-nops", "rep": 0, "round": 7, "ps_relay": False,
            "session": "interactive-pty", "hook": "ask", "translation": "on", "native_policy": "p", "outcome": "PROMPT-DENIED",
            "prompt_appeared": True, "call_ran": False,
            "detector": [{"probe_mode": "interactive", "ancestry": {"source": "libproc", "complete": True}, "has_ctty": True,
                          "ps_check": "PermissionError: [Errno 1] Operation not permitted"}],
            "hook_replies": [{"stdout": "x", "ask_decisions": [{"sent": "ask", "mode": "interactive"}]}]}
    base.update(kw)
    return base


def test_the_table_separates_rounds_and_shows_the_source_and_the_ground_truth():
    old_blind = _row(round=None, cell="ask-on", detector=[{"probe_mode": "headless"}])
    del old_blind["round"]
    text = pl.table([old_blind, _row(), _row(rep=1)])
    assert "[ps blocked in the sandbox: detector blind]" in text                      # only the round 6 row
    assert "interactive 2 (ancestry via libproc 2)" in text and "own tty 2/2; ps blocked 2/2" in text
    assert text.count("ask-on-nops [ps blocked") == 0 and "| 7 |" in text and "| 6 |" in text
