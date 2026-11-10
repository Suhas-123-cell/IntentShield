"""Offline tests of the guard byte-capture and replay tooling (benchmarks/hook_fidelity/guard_capture.py, guard_replay.py,
stubhook.py replay mode, corpus_counts.py) and of the committed results under results/hook-fidelity/guards. No harness is
launched and no guard code is executed: the sandbox is exercised only with /bin/sh probes."""

from __future__ import annotations

import base64
import json
import os
import pwd
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmarks"
sys.path.insert(0, str(BENCH))
sys.path.insert(0, str(BENCH / "hook_fidelity" / "corpus_build"))
from hook_fidelity import corpus_counts, guard_capture, guard_replay, stubhook  # noqa: E402

GUARDS = ROOT / "results" / "hook-fidelity" / "guards"


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


# ---------------------------------------------------------------- intent: what a captured reply asks for
@pytest.mark.parametrize(
    "stdout,stderr,code,expected",
    [
        ("", "", 0, "ALLOW"),
        ("{}", "", 0, "ALLOW"),
        ('{"decision":"allow"}', "", 0, "ALLOW"),
        ("", "BLOCKED: x\n", 2, "BLOCK"),
        ("", "", 2, "BLOCK"),
        ('{"hookSpecificOutput":{"permissionDecision":"deny"}}', "", 0, "BLOCK"),
        ('{"hookSpecificOutput":{"permissionDecision":"ask"}}', "", 0, "ASK"),
        ('{"decision":"block","reason":"r"}', "r", 2, "BLOCK"),
        ('{"permission":"deny"}', "", 0, "BLOCK"),
        ("", "boom", 1, "ERROR"),
    ],
)
def test_intent_reads_the_guards_own_contract(stdout, stderr, code, expected):
    assert guard_replay.intent(stdout, stderr, code)[0] == expected


def test_a_timed_out_capture_is_an_error_not_a_verdict():
    assert guard_replay.intent("", "", None)[0] == "ERROR"


# ---------------------------------------------------------------- Wilson interval and the cause of a run
def test_wilson_bounds_are_computed_from_k_and_n_unrounded():
    lo, hi = guard_replay.wilson(0, 3)
    assert lo == 0.0 and 0.55 < hi < 0.57  # 0 of 3 -> upper bound about 56 percent
    lo, hi = guard_replay.wilson(3, 3)
    assert hi == 1.0 and 0.43 < lo < 0.45
    assert guard_replay.wilson(0, 0) == (0.0, 1.0)
    assert guard_replay.fmt_rate(0, 3) == "0/3 [0, 56]"


def _row(**kw):
    base = {"intent": "BLOCK", "hook_invoked": True, "state": "-", "control": "", "outcome": "RAN"}
    base.update(kw)
    return base


def test_cause_of_a_guarded_call_that_ran():
    assert guard_replay.cause_of([_row(intent="ASK")]) == "ask with no human"
    assert guard_replay.cause_of([_row(hook_invoked=False, state="untrusted")]) == "untrusted skip"
    assert "matcher gap" in guard_replay.cause_of([_row(hook_invoked=False)])
    assert "fail-open" in guard_replay.cause_of([_row()])


def test_summarize_requires_the_no_hook_control_and_excludes_invalid_runs():
    def run(outcome, control="", cell="k", **kw):
        r = {
            "harness": "claude",
            "build": "1",
            "mode": "M1",
            "mode_desc": "d",
            "state": "-",
            "guard": "g",
            "entry": "e",
            "scenario": "s",
            "matcher": "",
            "intent": "BLOCK",
            "reply_id": "rp1",
            "run_id": f"r{outcome}{control}{kw.get('i', 0)}",
            "kind": "shell",
            "control": control,
            "cell_key": cell,
            "outcome": outcome,
            "hook_invoked": True,
            "matcher_source": "",
        }
        r.update(kw)
        return r

    rows = [
        run("BLOCKED", i=0),
        run("BLOCKED", i=1),
        run("INVALID", i=2),
        run("RAN", control="no-hook", cell="c0", intent="NONE"),
    ]
    summary = guard_replay.summarize_stub(rows)
    cell = summary["cells"][0]
    assert (cell["n_runs"], cell["n_valid"], cell["ran"], cell["blocked"]) == (3, 2, 0, 2)
    assert cell["control_ran"] is True and cell["tested"] and not cell["guarded_call_ran"]
    rows.append(run("BLOCKED", control="no-hook", cell="c1", intent="NONE", i=9))
    assert guard_replay.summarize_stub(rows)["cells"][0]["control_ran"] is False


# ---------------------------------------------------------------- stubhook replay mode
def test_stubhook_replay_emits_exactly_the_captured_bytes_and_exit_code(tmp_path):
    reply = tmp_path / "rp.json"
    reply.write_text(
        json.dumps({"stdout_b64": _b64('{"decision":"block","reason":"r"}'), "stderr_b64": _b64("why\n"), "exit_code": 2})
    )
    proc = subprocess.run(
        [
            sys.executable,
            str(BENCH / "hook_fidelity" / "stubhook.py"),
            "--harness",
            "gemini",
            "--reply",
            "RP",
            "--replay-file",
            str(reply),
            "--run-id",
            "t",
            "--log",
            str(tmp_path / "log.jsonl"),
        ],
        input=json.dumps({"hook_event_name": "BeforeTool", "tool_name": "x", "tool_input": {}}),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2 and proc.stdout == '{"decision":"block","reason":"r"}' and proc.stderr == "why\n"
    assert json.loads((tmp_path / "log.jsonl").read_text().splitlines()[0])["reply"] == "RP"


def test_stubhook_replay_answers_a_non_decision_event_neutrally_and_refuses_a_missing_or_timed_out_capture(tmp_path):
    reply = tmp_path / "rp.json"
    reply.write_text(json.dumps({"stdout_b64": _b64("x"), "stderr_b64": "", "exit_code": 2}))
    proc = subprocess.run(
        [
            sys.executable,
            str(BENCH / "hook_fidelity" / "stubhook.py"),
            "--harness",
            "claude",
            "--reply",
            "RP",
            "--replay-file",
            str(reply),
            "--run-id",
            "t",
            "--log",
            str(tmp_path / "l.jsonl"),
        ],
        input=json.dumps({"hook_event_name": "SessionStart"}),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0 and proc.stdout == "{}"
    with pytest.raises(ValueError):
        stubhook.planned("claude", "RP")  # no --replay-file
    reply.write_text(json.dumps({"stdout_b64": "", "stderr_b64": "", "exit_code": None}))
    with pytest.raises(ValueError):
        stubhook.replay_reply(str(reply))


# ---------------------------------------------------------------- the capture sandbox
def test_sandbox_profile_is_deny_default_with_no_network_and_writes_only_under_scratch(tmp_path):
    profile = guard_capture.profile_for(tmp_path / "scratch", [Path("/opt/clone")])
    assert "(deny default)" in profile and "(deny network*)" in profile
    writes = [line for line in profile.splitlines() if line.startswith("(allow file-write*")]
    assert len(writes) == 1 and str(tmp_path / "scratch") in writes[0] and "/Users" not in writes[0]
    reads = [line for line in profile.splitlines() if line.startswith("(allow file-read*")][0]
    assert "/opt/clone" in reads and str(Path.home()) not in reads


def test_capture_payloads_are_text_fixtures_and_the_cwd_placeholder_is_replaced_at_capture_time():
    shapes = {
        h: guard_capture.payload(h, guard_capture.SHELL_TOOL[h], {"command": "echo x"})
        for h in ("claude", "codex", "gemini", "cursor", "cursor-pre")
    }
    assert shapes["claude"]["hook_event_name"] == "PreToolUse" and shapes["gemini"]["hook_event_name"] == "BeforeTool"
    assert shapes["cursor"]["command"] == "echo x" and shapes["cursor-pre"]["tool_name"] == "Shell"
    for items in (guard_capture.shell_scenarios("claude"),):
        names = [n for n, _ in items]
        assert names[:3] == ["flagged-rm", "flagged-env-read", "benign"]
        assert all(guard_capture.CWD in json.dumps(p) for _, p in items)


def test_scrub_bytes_removes_scratch_and_home_paths():
    raw = f"{guard_capture.SCRATCH_ROOT}/x and {Path.home()}/y".encode()
    out = guard_capture.scrub_bytes(raw)
    assert b"<scratch>/x" in out and b"<home>/y" in out and str(Path.home()).encode() not in out


@pytest.mark.skipif(sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").exists(), reason="macOS sandbox-exec only")
def test_the_sandbox_refuses_a_write_outside_scratch_and_the_network(tmp_path):
    scratch = tmp_path / "s"
    env = guard_capture.clean_env(scratch)
    outside = tmp_path / "outside.txt"
    r = guard_capture.run_sandboxed(["/bin/sh", "-c", f"echo x > {outside}"], b"", scratch, [], env)
    if r["exit_code"] == 134 or (r["exit_code"] and r["exit_code"] < 0):
        pytest.skip("sandbox-exec cannot be applied from this process (nested sandbox)")
    assert r["exit_code"] != 0 and not outside.exists()
    ok = guard_capture.run_sandboxed(["/bin/sh", "-c", f"echo x > {scratch}/work/in.txt"], b"", scratch, [], env)
    assert ok["exit_code"] == 0 and (scratch / "work" / "in.txt").exists()
    net = guard_capture.run_sandboxed(["/usr/bin/nc", "-z", "-w", "2", "127.0.0.1", "9"], b"", scratch, [], env)
    assert net["exit_code"] != 0


def test_harness_containment_allows_loopback_only_and_hides_the_real_home(tmp_path):
    text = guard_replay.harness_profile(tmp_path / "run")
    assert "(deny network*)" in text and 'remote ip "localhost:*"' in text
    assert f'(deny file-read* (subpath "{Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()}"))' in text
    assert text.count("(allow file-write*") == 1 and str(tmp_path / "run") in text


# ---------------------------------------------------------------- the plan and its launch gate
def test_plan_has_controls_for_every_mode_and_never_runs_a_cell_without_a_matcher_source():
    plan = guard_replay.plan_cells()
    modes = {(c.harness, c.mode, c.kind) for c in plan if c.control == "no-hook"}
    for c in plan:
        if c.control != "no-hook":
            assert (c.harness, c.mode, c.kind) in modes or c.harness == "codex" and (c.harness, c.mode, "shell") in modes, c
            assert c.note, c
    assert (
        sum(c.reps for c in plan)
        + sum(c.reps for c in guard_replay.extra_build_cells())
        + sum(c.reps for c in guard_replay.matcher_probe_cells())
        < guard_replay.MAX_LAUNCHES
    )


def test_stub_run_refuses_without_a_matching_go_ahead(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("HOOK_FIDELITY_GO", raising=False)
    index = GUARDS / "replay"
    assert guard_replay.cmd_stub_run(index, tmp_path, 3, "claude|2.1.316|M1|-|railway-guard", "", 1) == 2
    monkeypatch.setenv("HOOK_FIDELITY_GO", "7")
    assert guard_replay.cmd_stub_run(index, tmp_path, 3, "claude|2.1.316|M1|-|railway-guard", "", 1) == 2
    assert "refused" in capsys.readouterr().err


# ---------------------------------------------------------------- committed results
def _jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_committed_captures_carry_exact_bytes_and_no_local_paths():
    rows = _jsonl(GUARDS / "captures.jsonl")
    done = [r for r in rows if not r.get("status")]
    not_done = [r for r in rows if r.get("status") == "NOT-CAPTURED"]
    assert (
        len(done) >= 80
        and {r["guard"] for r in not_done} == {"dcg", "tool-gate-hook", "ggshield", "hol-guard"}
        and all(r["reason"] for r in not_done)
    )
    for r in done:
        assert (
            base64.b64decode(r["stdout_b64"]).decode() == r["stdout"]
            and base64.b64decode(r["stderr_b64"]).decode() == r["stderr"]
        )
        assert len(r["guard_commit"]) == 40 and r["sandbox"].startswith("sandbox-exec deny-default")
    text = (GUARDS / "captures.jsonl").read_text() + (GUARDS / "stub-rows.jsonl").read_text()
    assert "/Users/" not in text and "claude-501" not in text
    meta = json.loads((GUARDS / "captures-meta.json").read_text())
    assert all(v["held"] for v in meta["sandbox_selftest"].values())


def test_replay_index_matches_the_captures_and_every_replay_file_exists():
    index = json.loads((GUARDS / "replay" / "index.json").read_text())
    captures = [r for r in _jsonl(GUARDS / "captures.jsonl") if not r.get("status")]
    assert sum(len(i["captures"]) for i in index) == len(captures)
    for item in index:
        assert (GUARDS / "replay" / f"{item['id']}.json").is_file() and item["intent"] in ("BLOCK", "ASK", "ALLOW", "ERROR")
        assert (
            guard_replay.triple_id(
                {
                    "stdout_b64": json.loads((GUARDS / "replay" / f"{item['id']}.json").read_text())["stdout_b64"],
                    "stderr_b64": json.loads((GUARDS / "replay" / f"{item['id']}.json").read_text())["stderr_b64"],
                    "exit_code": item["exit_code"],
                }
            )
            == item["id"]
        )


def test_launch_ledger_stays_under_the_cap_and_every_final_row_has_a_ledger_entry():
    ledger = _jsonl(GUARDS / "launches-final.jsonl")
    rows = _jsonl(GUARDS / "stub-rows.jsonl")
    assert {r["run_id"] for r in rows} == {e["run_id"] for e in ledger} and len(rows) == len(ledger)
    invalid_pass = _jsonl(GUARDS / "stub-rows-attempt1-invalid.jsonl")
    assert len(ledger) + len(invalid_pass) + 3 <= guard_replay.MAX_LAUNCHES  # 3 = wiring pilots, kept as a count


def test_summary_and_the_headline_are_what_the_rows_derive_and_controls_ran():
    rows = _jsonl(GUARDS / "stub-rows.jsonl")
    summary = json.loads((GUARDS / "summary.json").read_text())
    again = guard_replay.summarize_stub(rows)
    assert again["cells"] == summary["cells"] and again["controls"] == summary["controls"]
    live = [c for c in summary["cells"] if c["tested"] and not c["probe"]]
    assert summary["headline"]["live_cells_tested"] == len(live) and summary["headline"]["live_cells_guarded_call_ran"] == sum(
        c["guarded_call_ran"] for c in live
    )
    for c in live:
        # a cell counts only if the harness+build+mode+tool control ran, and every cell that ran is attributed to a cause
        assert c["control_ran"] is True, c
        assert bool(c["cause"]) == c["guarded_call_ran"]
        assert c["n_valid"] >= 1 and c["ran"] + c["blocked"] + c["hung"] == c["n_valid"]
    # no run of the final data is an invalid pass
    assert all(r["outcome"] != "INVALID" for r in rows), "an INVALID row in the final set"


def test_headline_causes_are_all_untrusted_skips_with_no_hook_invocation():
    summary = json.loads((GUARDS / "summary.json").read_text())
    ran = [c for c in summary["cells"] if c["tested"] and not c["probe"] and c["guarded_call_ran"]]
    assert ran and all(
        c["harness"] == "codex" and c["state"] == "untrusted" and c["hook_invoked"] == 0 and c["cause"] == "untrusted skip"
        for c in ran
    )
    asks = [c for c in summary["cells"] if c["intent"] == "ASK"]
    assert asks and all(c["ran"] == 0 for c in asks)


def test_gemini_replay_has_22_releases_and_every_native_block_reply_denied():
    files = sorted((GUARDS / "gemini-replay").glob("*.jsonl"))
    assert len(files) == 22
    index = {i["id"]: i for i in json.loads((GUARDS / "replay" / "index.json").read_text())}
    for f in files:
        by = {r["scenario"].removeprefix("replay:"): r for r in _jsonl(f)}
        assert set(by) == set(index) and not any("driverError" in r for r in by.values())
        for rid, item in index.items():
            native = any(c["shape"] == "gemini" for c in item["captures"])
            if native and item["intent"] == "BLOCK":
                assert by[rid]["layerA"]["decision"] == "deny" and by[rid]["layerA"]["proceeds"] == "no", (f.name, rid)


# ---------------------------------------------------------------- corpus: derived numbers
def test_corpus_counts_check_passes_on_the_committed_data():
    assert corpus_counts.check() == []


def test_corpus_has_stars_and_age_per_guard_and_the_measured_block():
    data = json.loads((ROOT / "results" / "hook-fidelity" / "corpus.json").read_text())
    for g in data["guards"]:
        assert isinstance(g["stars"], int) and g["repo_pushed_at"] and "commit_age_days_at_2026-11-01" in g, g["id"]
    m = data["measured"]
    assert m["live_cells_tested"] == 38 or m["live_cells_tested"] > 0
    doc = (ROOT / "docs" / "hook-fidelity-corpus.md").read_text()
    assert f"{m['live_cells_ran']} of {m['live_cells_tested']} let the guarded call run" in doc
    assert "ask with no human ran in 0 of" in doc


def test_star_median_is_the_median_of_an_even_count_not_the_upper_middle_element():
    import counts  # corpus_build/counts.py
    assert counts._median([9, 17]) == 13 and counts._median([1, 2, 3]) == 2 and counts._median([]) is None
    assert counts._median([0, 1, 2, 3]) == 1.5
