"""Offline tests of the interactive pty lane (round 6): the terminal-text cleaner, the terminal-query answers, the plan and ledger
cap, the outcome classifier, the per-harness configuration, the table, the pty driver against a fake TUI, and the mode detector
read
from a real pty by a fake harness process. No harness CLI is launched and nothing touches the network."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

BENCH = Path(__file__).resolve().parents[1] / "benchmarks" / "hook_fidelity"
sys.path.insert(0, str(BENCH.parent))
sys.path.insert(0, str(BENCH))
import pty_lane as pl  # noqa: E402


# ------------------------------------------------------------------------------------------------ text
def test_cleaner_strips_escapes_and_turns_cursor_forward_into_spaces():
    c = pl.Cleaner()
    c.feed(b"\x1b[1mDo\x1b[0m\x1b[1Cyou\x1b[3Cwant\x1b]0;title\x07 to proceed?\r\n")
    assert pl.squash(c.text).strip() == "Do you want to proceed?"


def test_cleaner_holds_back_a_split_escape_sequence():
    c = pl.Cleaner()
    c.feed(b"ab\x1b[3")
    c.feed(b"1mcd\x1b")
    c.feed(b"[0mef")
    assert c.text == "abcdef"


def test_cleaner_cursor_jump_is_a_line_break():
    c = pl.Cleaner()
    c.feed(b"first\x1b[5;1Hsecond")
    assert pl.squash(c.text) == "first second"


def test_query_answers():
    reply, seen = pl.answer_queries(b"x\x1b[6nabc\x1b[c\x1b[?u")
    assert reply == b"\x1b[24;1R\x1b[?62;c\x1b[?0u"
    assert seen["cursor-position"] == 1 and seen["device-attributes"] == 1 and seen["kitty-keyboard"] == 1
    assert pl.answer_queries(b"plain text")[0] == b""


def test_rules_regexes_match_the_known_screens():
    import re

    assert re.search(pl.RULES["claude"].ready, "  ? for shortcuts")
    assert re.search(pl.RULES["gemini"].ready, "> Type your message or @path/to/file")
    assert re.search(pl.RULES["claude"].permission, "Do you want to proceed? 1. Yes 2. No")
    assert re.search(pl.RULES["gemini"].permission, "Allow once")


# ------------------------------------------------------------------------------------------------ plan, ledger, outcome
def test_plan_has_the_cells_n2_and_one_headless_per_harness():
    cases = pl.plan()
    assert len(cases) == 3 * (4 * 2 + 1)
    assert len({pl.case_id(c) for c in cases}) == len(cases)
    for harness, version in pl.VERSIONS.items():
        mine = [c for c in cases if c["harness"] == harness]
        assert {c["version"] for c in mine} == {version}
        assert sum(c["cell"] == "headless-on" for c in mine) == 1
        for cell in ("ask-on", "ask-off", "deny-on", "r0"):
            assert sum(c["cell"] == cell for c in mine) == 2


def test_builds_are_the_pinned_ones():
    assert pl.VERSIONS == {"claude": "2.1.316", "gemini": "0.66.0", "codex": "0.166.0"}


@pytest.mark.parametrize(
    "args,expected",
    [
        ((True, False, True, True, True), "PROMPT-DENIED"),
        ((True, True, True, True, True), "PROMPT-RAN"),
        ((False, True, False, True, True), "RAN-NO-PROMPT"),
        ((False, False, True, True, True), "BLOCKED-NO-PROMPT"),
        ((False, False, False, True, True), "TIMEOUT-NO-PROMPT"),
        ((False, False, False, False, True), "INVALID"),
        ((False, False, False, True, False), "INVALID"),
    ],
)
def test_classify(args, expected):
    assert pl.classify(*args)[0] == expected


def test_run_refuses_a_wrong_go_count_and_the_cap(tmp_path, monkeypatch, capsys):
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(pl.plan(("claude",))))
    args = pl.argparse.Namespace(plan=plan_path, out=tmp_path / "out", where="", unplanned=False, attempt=0, round=6)
    monkeypatch.delenv("HOOK_FIDELITY_GO", raising=False)
    assert pl.cmd_run(args) == 2
    monkeypatch.setenv("HOOK_FIDELITY_GO", "3")
    assert pl.cmd_run(args) == 2
    assert "must equal the 9 launches" in capsys.readouterr().err
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "ledger.jsonl").write_text("".join(json.dumps({"i": i}) + "\n" for i in range(35)))
    monkeypatch.setenv("HOOK_FIDELITY_GO", "9")
    assert pl.cmd_run(args) == 2
    assert "pass the cap of 40" in capsys.readouterr().err


# ------------------------------------------------------------------------------------------------ configuration
def _build(harness, cell, tmp_path):
    case = {"harness": harness, "version": pl.VERSIONS[harness], "cell": cell, "rep": 0}
    return pl.build(case, tmp_path, "http://127.0.0.1:1", "nzabc", "att") if _has_release(harness) else None


def _has_release(harness):
    try:
        pl.me.binary_for(harness, pl.VERSIONS[harness])
        return True
    except (FileNotFoundError, OSError):
        return False


@pytest.fixture
def fake_release(monkeypatch, tmp_path):
    """A release tree with empty executables where binary_for looks, so the argv shapes can be tested without the installs."""
    rel = tmp_path / "releases"
    base = rel / "claude-code" / "2.1.316" / "node_modules" / "@anthropic-ai" / "claude-code-darwin-arm64"
    base.mkdir(parents=True)
    (base / "claude").write_text("#!/bin/sh\n")
    codex = rel / "codex" / "0.166.0" / "node_modules" / "@openai" / "codex-darwin-arm64" / "bin"
    codex.mkdir(parents=True)
    (codex / "codex").write_text("#!/bin/sh\n")
    gem = rel / "gemini-cli" / "0.66.0" / "node_modules" / ".bin"
    gem.mkdir(parents=True)
    (gem / "gemini").write_text("#!/bin/sh\n")
    monkeypatch.setattr(pl.me, "RELEASES", rel)
    return rel


def test_interactive_argv_has_no_prompt_and_no_headless_flag(fake_release, tmp_path):
    for harness in ("claude", "gemini", "codex"):
        for cell in ("ask-on", "ask-off", "deny-on", "r0"):
            root = tmp_path / f"{harness}-{cell}"
            argv, env, work, facts = _build(harness, cell, root)
            flags = set(argv)
            assert not flags & {"-p", "--print", "exec", "--prompt"}, (harness, cell, argv)
            assert facts["prompt"] not in argv
            assert env["TERM"] == "xterm-256color" and env["HOME"].startswith(str(root))
            assert "ANTHROPIC_API_KEY" not in env or env["ANTHROPIC_API_KEY"] == pl.configs.STUB_KEY


def test_headless_argv_has_the_flag(fake_release, tmp_path):
    claude = _build("claude", "headless-on", tmp_path / "c")[0]
    assert "-p" in claude
    gemini = _build("gemini", "headless-on", tmp_path / "g")[0]
    assert "-p" in gemini and "yolo" not in gemini
    codex = _build("codex", "headless-on", tmp_path / "x")[0]
    assert "exec" in codex and "--dangerously-bypass-hook-trust" in codex


def test_native_policy_is_preapproved_only_where_a_hook_is_installed(fake_release, tmp_path):
    a = _build("claude", "ask-on", tmp_path / "a")
    r = _build("claude", "r0", tmp_path / "r")
    assert "--allowedTools" in a[0] and "--allowedTools" not in r[0]
    assert "pre-approved" in a[3]["native_policy"] and "prompts" in r[3]["native_policy"]
    settings = json.loads((tmp_path / "r" / "settings.json").read_text())
    assert settings["hooks"] == {}
    g = (
        json.loads((tmp_path / "a" / "home" / ".gemini" / "settings.json").read_text())
        if (tmp_path / "a" / "home" / ".gemini").exists()
        else None
    )
    assert g is None  # the claude build wrote no gemini settings
    ga = _build("gemini", "ask-on", tmp_path / "ga")
    gr = _build("gemini", "r0", tmp_path / "gr")
    assert json.loads((tmp_path / "ga" / "home" / ".gemini" / "settings.json").read_text())["tools"]["allowed"] == [
        "run_shell_command"
    ]
    assert "tools" not in json.loads((tmp_path / "gr" / "home" / ".gemini" / "settings.json").read_text())
    assert ga[3]["native_policy"] != gr[3]["native_policy"]
    cx = _build("codex", "ask-on", tmp_path / "cx")
    cr = _build("codex", "r0", tmp_path / "cr")
    assert 'approval_policy = "never"' in (tmp_path / "cx" / "home" / "codex-home" / "config.toml").read_text()
    assert 'approval_policy = "on-request"' in (tmp_path / "cr" / "home" / "codex-home" / "config.toml").read_text()
    assert "--dangerously-bypass-hook-trust" in cx[0] and "--dangerously-bypass-hook-trust" not in cr[0]


def test_hook_commands_per_arm(fake_release, tmp_path):
    on = _build("claude", "ask-on", tmp_path / "on")
    off = _build("claude", "ask-off", tmp_path / "off")
    on_cmd = json.loads((tmp_path / "on" / "settings.json").read_text())["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    off_cmd = json.loads((tmp_path / "off" / "settings.json").read_text())["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert "--deadline 30" in on_cmd and "|| {" in on_cmd and "--eval-translate on" in on_cmd and "--eval-verdict ask" in on_cmd
    assert "--deadline" not in off_cmd and "|| {" not in off_cmd and "--eval-translate off" in off_cmd
    assert "--pty-log" in on_cmd and "--pty-log" in off_cmd
    deny = _build("claude", "deny-on", tmp_path / "deny")
    assert (
        "--eval-verdict deny"
        in json.loads((tmp_path / "deny" / "settings.json").read_text())["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    )
    assert on and off and deny


def test_gemini_ask_flag_is_set_for_ask_cells_only(fake_release, tmp_path):
    _build("gemini", "ask-on", tmp_path / "a")
    _build("gemini", "deny-on", tmp_path / "d")
    a = json.loads((tmp_path / "a" / "home" / ".gemini" / "settings.json").read_text())["hooks"]["BeforeTool"][0]["hooks"][0][
        "command"
    ]
    d = json.loads((tmp_path / "d" / "home" / ".gemini" / "settings.json").read_text())["hooks"]["BeforeTool"][0]["hooks"][0][
        "command"
    ]
    assert "--gemini-ask" in a and "--gemini-ask" not in d


def test_version_record_uses_the_real_path(fake_release, tmp_path):
    _build("claude", "ask-on", tmp_path / "v")
    record = json.loads((tmp_path / "v" / "home" / ".intentshield" / "harness-versions.json").read_text())["claude"]
    assert record["version"] == "2.1.316" and record["binary"] == os.path.realpath(record["path"])


# ------------------------------------------------------------------------------------------------ table
def _row(**kw):
    base = {
        "harness": "claude",
        "version": "2.1.316",
        "cell": "ask-on",
        "rep": 0,
        "session": "interactive-pty",
        "hook": "ask",
        "translation": "on",
        "native_policy": "p",
        "outcome": "PROMPT-DENIED",
        "prompt_appeared": True,
        "call_ran": False,
        "detector": [{"probe_mode": "interactive"}],
        "hook_replies": [{"ask_decisions": [{"sent": "ask", "mode": "interactive"}]}],
    }
    base.update(kw)
    return base


def test_table_counts_k_over_n_and_keeps_invalid_apart():
    rows = [_row(ps_relay=True), _row(rep=1, ps_relay=True), _row(rep=2, outcome="INVALID", prompt_appeared=False, ps_relay=True)]
    text = pl.table(rows)
    assert (
        "| 2 (1) | 2/2 | n/a | 0/2 | PROMPT-DENIED 2/2 | interactive 2 | ask (mode interactive) 2 | none (empty reply) 2 |"
        in text
    )


def test_detector_summary():
    assert pl.detector_summary(_row(detector=[{"probe_mode": "headless"}, {"probe_error": "x"}])) == "error x1, headless x1"
    assert pl.detector_summary({"detector": []}) == "no hook call"


# ------------------------------------------------------------------------------------------------ the driver on a fake TUI
FAKE_TUI = textwrap.dedent("""
    import os, sys, termios, tty, time
    tty.setraw(0)
    def out(s): os.write(1, s.encode())
    out("\\x1b[6n")                      # a cursor position query: the driver must answer
    data = b""
    while b"R" not in data:
        data += os.read(0, 64)
    out("Welcome. Choose the text style\\r\\n")
    while b"\\r" not in os.read(0, 64): pass
    out("\\x1b[2J  ? for shortcuts\\r\\n")
    buf = b""
    while b"\\r" not in buf: buf += os.read(0, 4096)
    if os.environ.get("FAKE_MODE") == "prompt":
        out("\\x1b[1mDo\\x1b[0m you want to proceed?\\r\\n 1. Yes\\r\\n 2. No\\r\\n")
        key = os.read(0, 64)
        out("denied" if key == b"\\x1b" else "other")
        open(os.environ["MARKER_DIR"] + "/answer", "wb").write(key)
        time.sleep(30)
    elif os.environ.get("FAKE_MODE") == "run":
        open(os.environ["MARKER"], "w").write("att")
        time.sleep(30)
    else:
        time.sleep(30)
""")


def _drive_fake(tmp_path, mode, prompt_wait=2.0):
    script = tmp_path / "fake_tui.py"
    script.write_text(FAKE_TUI)
    marker = tmp_path / "ran.txt"
    log = tmp_path / "requests.jsonl"
    env = {**os.environ, "FAKE_MODE": mode, "MARKER": str(marker), "MARKER_DIR": str(tmp_path)}
    proc, master = pl.spawn([sys.executable, str(script)], env, tmp_path)
    try:
        obs, clean, raw = pl.drive(
            proc, master, pl.RULES["claude"], "touch it", marker, log, True, prompt_wait=prompt_wait, startup_wait=15
        )
    finally:
        pl.kill_group(proc)
        os.close(master)
    return obs, clean, tmp_path


@pytest.fixture(autouse=True)
def _short_waits(monkeypatch):
    monkeypatch.setattr(pl, "AFTER_ANSWER_S", 2.0)


def test_driver_dismisses_onboarding_answers_queries_and_denies_a_prompt(tmp_path):
    obs, clean, root = _drive_fake(tmp_path, "prompt")
    assert obs.queries["cursor-position"] == 1
    assert [o["name"] for o in obs.onboarding] == ["theme"]
    assert obs.ready_by == "pattern"
    assert obs.permission_at is not None and "Do you want to proceed?" in obs.permission_excerpt
    assert obs.answered_at is not None
    deadline = time.time() + 5
    while not (root / "answer").exists() and time.time() < deadline:
        time.sleep(0.1)
    assert (root / "answer").read_bytes() == b"\x1b"


def test_driver_times_out_when_no_prompt_appears(tmp_path):
    t0 = time.monotonic()
    obs, clean, root = _drive_fake(tmp_path, "silent", prompt_wait=2.0)
    assert obs.permission_at is None and obs.stop_reason.startswith("timeout")
    assert time.monotonic() - t0 < 12


def test_driver_sees_the_marker(tmp_path):
    obs, clean, root = _drive_fake(tmp_path, "run")
    assert obs.marker_at is not None and obs.permission_at is None and obs.stop_reason == "call resolved"


def test_driver_proceeds_by_quiet_when_the_input_box_is_unrecognised(tmp_path):
    rules = pl.Rules(
        ready=r"NEVER MATCHES", permission=r"Do you want to proceed\?", onboarding=list(pl.RULES["claude"].onboarding)
    )
    script = tmp_path / "fake_tui.py"
    script.write_text(FAKE_TUI)
    env = {**os.environ, "FAKE_MODE": "prompt", "MARKER": str(tmp_path / "m"), "MARKER_DIR": str(tmp_path)}
    proc, master = pl.spawn([sys.executable, str(script)], env, tmp_path)
    try:
        obs, _, _ = pl.drive(proc, master, rules, "x", tmp_path / "m", tmp_path / "r.jsonl", True, prompt_wait=5, startup_wait=30)
    finally:
        pl.kill_group(proc)
        os.close(master)
    assert obs.ready_by == "quiet" and obs.permission_at is not None


# ------------------------------------------------------------------------------------------------ the detector, from a real pty
FAKE_HARNESS = textwrap.dedent("""\
    #!{python}
    import json, os, subprocess, sys
    event = {{"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "s1",
             "tool_input": {{"command": "touch ran-nzfake.txt"}}, "cwd": os.getcwd()}}
    done = subprocess.run([{python!r}, {hook!r}, "claude", "--builtin-tools", "--eval-verdict", "ask", "--eval-translate", "on",
                           "--pty-log", {log!r}],
                          input=json.dumps(event), capture_output=True, text=True,
                          env={{**os.environ, "INTENTSHIELD_HARNESS_VERSION": "2.1.316",
                                "INTENTSHIELD_HOOK_DB": {db!r}, "INTENTSHIELD_THREAT_MEMORY": "0"}})
    sys.stdout.write("HOOK-REPLY " + done.stdout.replace("\\n", " ") + "\\n")
    sys.stdout.flush()
""")


def _run_fake_harness(tmp_path, tty: bool) -> dict:
    harness = tmp_path / "bin" / "claude"
    harness.parent.mkdir()
    log = tmp_path / "pty-hooks.jsonl"
    harness.write_text(
        FAKE_HARNESS.format(python=sys.executable, hook=str(BENCH / "pty_hook.py"), log=str(log), db=str(tmp_path / "h.db"))
    )
    harness.chmod(0o755)
    env = {**os.environ}
    env.pop("INTENTSHIELD_HARNESS_MODE", None)
    env.pop("INTENTSHIELD_HOOK_TRANSLATE", None)
    if tty:
        proc, master = pl.spawn([str(harness), "--model", "m"], env, tmp_path)
        out = b""
        end = time.time() + 40
        import select

        while time.time() < end:
            if select.select([master], [], [], 0.3)[0]:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
            elif proc.poll() is not None:
                break
        pl.kill_group(proc)
        os.close(master)
    else:
        done = subprocess.run([str(harness), "--model", "m"], env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=40)
        out = done.stdout
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    return {
        "start": next(r for r in rows if r["phase"] == "start"),
        "end": next(r for r in rows if r["phase"] == "end"),
        "out": out.decode(errors="replace"),
    }


def test_detector_reads_interactive_from_a_real_pty_and_keeps_the_ask(tmp_path):
    got = _run_fake_harness(tmp_path, tty=True)
    assert got["start"]["probe_mode"] == "interactive", got["start"]
    decision = got["end"]["ask_decisions"][0]
    assert decision["mode"] == "interactive" and decision["sent"] == "ask"
    assert '"permissionDecision": "ask"' in got["end"]["reply_stdout"] or "ask" in got["end"]["reply_stdout"]


def test_detector_reads_headless_without_a_terminal_and_denies(tmp_path):
    got = _run_fake_harness(tmp_path, tty=False)
    assert got["start"]["probe_mode"] == "headless", got["start"]
    decision = got["end"]["ask_decisions"][0]
    assert decision["mode"] == "headless" and decision["sent"] == "deny"


def test_hook_wrapper_does_not_change_the_reply(tmp_path):
    """The observer must not alter what mitigation_hook sends: run it with and without the wrapper on the same event."""
    event = json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "session_id": "s2",
            "tool_input": {"command": "touch x"},
            "cwd": str(tmp_path),
        }
    )
    env = {
        **os.environ,
        "INTENTSHIELD_HARNESS_MODE": "interactive",
        "INTENTSHIELD_HARNESS_VERSION": "2.1.316",
        "INTENTSHIELD_HOOK_DB": str(tmp_path / "h.db"),
        "INTENTSHIELD_THREAT_MEMORY": "0",
    }
    common = ["claude", "--builtin-tools", "--eval-verdict", "ask", "--eval-translate", "on"]
    plain = subprocess.run(
        [sys.executable, str(BENCH / "mitigation_hook.py"), *common], input=event, capture_output=True, text=True, env=env
    )
    wrapped = subprocess.run(
        [sys.executable, str(BENCH / "pty_hook.py"), *common, "--pty-log", str(tmp_path / "l.jsonl")],
        input=event,
        capture_output=True,
        text=True,
        env=env,
    )
    assert plain.returncode == wrapped.returncode
    assert plain.stdout == wrapped.stdout and plain.stdout


# ------------------------------------------------------------------------------------------------ added after the live runs
def test_controls_are_one_allow_cell_for_the_two_harnesses_whose_ask_can_prompt():
    cases = pl.controls()
    assert [(c["harness"], c["cell"]) for c in cases] == [("claude", "allow-on"), ("gemini", "allow-on")]
    assert pl.cell_traits("allow-on")["verdict"] == "allow"


def test_send_keys_splits_escape_sequences(monkeypatch):
    written = []
    monkeypatch.setattr(pl.os, "write", lambda fd, data: written.append(data))
    monkeypatch.setattr(pl.time, "sleep", lambda s: None)
    pl.send_keys(7, b"\x1b[B\r")
    assert written == [b"\x1b[B", b"\r"]
    written.clear()
    pl.send_keys(7, b"\x1b")
    assert written == [b"\x1b"]


def test_ps_relay_returns_real_ps_output_and_refuses_other_shapes(tmp_path):
    sock = f"/tmp/hfps-test-{os.getpid()}.sock"
    relay = pl.PsRelay(sock).start()
    try:
        shim = tmp_path / "ps"
        shim.write_text(pl.ps_shim_text(sock))
        shim.chmod(0o755)
        args = ["-o", "ppid=,tty=,command=", "-p", str(os.getpid())]
        real = subprocess.run(["/bin/ps", *args], capture_output=True, text=True).stdout
        got = subprocess.run([str(shim), *args], capture_output=True, text=True)
        assert got.stdout == real and got.returncode == 0
        bad = subprocess.run([str(shim), "-ef"], capture_output=True, text=True)
        assert bad.returncode == 2 and "not allowed" in bad.stderr
    finally:
        relay.stop()
    assert not os.path.exists(sock)


def test_ps_shim_is_written_only_when_asked(fake_release, tmp_path):
    case = {"harness": "claude", "version": "2.1.316", "cell": "ask-on", "rep": 0}
    pl.build(case, tmp_path / "a", "http://127.0.0.1:1", "nz", "att", "/tmp/x.sock")
    pl.build(case, tmp_path / "b", "http://127.0.0.1:1", "nz", "att")
    assert (tmp_path / "a" / "shim" / "ps").exists() and not (tmp_path / "b" / "shim" / "ps").exists()


def test_reply_decision_reads_truncated_replies():
    assert pl.reply_decision({"stdout": '{"hookSpecificOutput": {"permissionDecision": "ask", "permissionDec'}) == "ask"
    assert pl.reply_decision({"stdout": '{"decision": "deny", "reason": "x"}'}) == "deny"
    assert pl.reply_decision({"stdout": ""}) == "none (empty reply)"


def test_table_separates_rows_without_a_working_ps_and_lists_attempts():
    blind = _row(rep=0, ps_relay=False, outcome="BLOCKED-NO-PROMPT", prompt_appeared=False, detector=[{"probe_mode": "headless"}])
    seen = _row(rep=1, ps_relay=True)
    excluded = _row(
        rep=0,
        cell="r0",
        attempt=5,
        outcome="TIMEOUT-NO-PROMPT",
        prompt_appeared=False,
        hook="none",
        ps_relay=True,
        detector=[],
        hook_replies=[],
        wall_s=71.0,
    )
    invalid = _row(
        rep=0,
        cell="r0",
        attempt=0,
        outcome="INVALID",
        invalid_reason="the prompt was never typed",
        prompt_appeared=False,
        hook="none",
        wall_s=0.5,
    )
    text = pl.table([blind, seen, excluded, invalid])
    assert "ps blocked in the sandbox" in text and "headless 1" in text and "PROMPT-DENIED 1/1" in text
    log = pl.attempt_log([blind, seen, excluded, invalid])
    assert "auto mode" in log and "never typed" in log and log.count("\n| ") == 2
    # the excluded and invalid rows are not data: the r0 cell has no valid run
    assert "| r0 | interactive-pty | none | - | " not in text or "0 (2)" in text


def test_pinned_claude_permission_mode_and_seeded_state(fake_release, tmp_path):
    argv, env, work, facts = _build("claude", "r0", tmp_path)
    assert argv[argv.index("--permission-mode") + 1] == "default"
    state = json.loads((tmp_path / "home" / "claude" / ".claude.json").read_text())
    assert state["hasCompletedOnboarding"] is True and "customApiKeyResponses" in state
    assert "hasCompletedOnboarding" in facts["seeded"]


def test_codex_interactive_runs_in_process_and_headless_does_not_need_it(fake_release, tmp_path):
    interactive = _build("codex", "ask-on", tmp_path / "i")[0]
    headless = _build("codex", "headless-on", tmp_path / "h")[0]
    assert "--no-daemon" in interactive and "--no-daemon" not in headless
