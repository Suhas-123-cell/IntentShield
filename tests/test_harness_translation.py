"""Verdict translation (src/intentshield/translation.py): the guard's ask, deny and failure become the reply each harness build,
in its mode, is measured to honour. The measurements are in the study's working notes
(docs/research-notes/hook-fidelity/hook-fidelity-study.md) and in results/hook-fidelity/mitigation."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from timelimits import limit

from intentshield import doctor, harness, install, translation
from intentshield.harness import HarnessGuard, Verdict, handle

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "hook-fidelity" / "mitigation"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "benchmarks" / "hook_fidelity" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# ------------------------------------------------------------------------------------------------ the table and its derivation
PINNED_TO_ALL_RELEASES = True    # the shipped table is the refit on every release; the held-out check ran on the fit-only one


def test_the_table_is_pinned_to_the_derivation_from_the_lane_outcomes():
    derive = _load("derive_table")
    features = json.loads(derive.FEATURES.read_text())
    derived = derive.derive_all(features, use_all=PINNED_TO_ALL_RELEASES)
    for harness_name, by_feature in translation.RANGES.items():
        for feature, spans in by_feature.items():
            assert spans == derived[harness_name]["ranges"][feature], (harness_name, feature)


def test_the_fit_only_table_is_kept_and_reproducible():
    """The table the held-out check ran against, derived from every other release only."""
    derive = _load("derive_table")
    features = json.loads(derive.FEATURES.read_text())
    frozen = json.loads((RESULTS / "ranges-fit-only.json").read_text())
    assert derive.derive_all(features) == frozen
    for harness_name, entry in frozen.items():
        assert not set(entry["fit"]) & set(entry["held_out"])
        releases = derive.usable_releases(features, harness_name)
        assert entry["fit"] == releases[0::2] and entry["held_out"] == releases[1::2]


def test_derive_separates_runs_by_a_gap_that_belongs_to_neither_side():
    derive = _load("derive_table")
    classes = {"1.0.0": "a", "1.0.5": "a", "1.2.0": "b", "1.3.0": "b", "1.4.0": "a"}
    assert derive.derive(classes) == [["run", "1.0.0", "1.0.5", "a"], ["gap", "1.0.5", "1.2.0", "uncertain"],
                                      ["run", "1.2.0", "1.3.0", "b"], ["gap", "1.3.0", "1.4.0", "uncertain"],
                                      ["run", "1.4.0", "1.4.0", "a"]]
    assert derive.derive(classes, fit={"1.0.0", "1.3.0"}) == [["run", "1.0.0", "1.0.0", "a"],
                                                              ["gap", "1.0.0", "1.3.0", "uncertain"],
                                                              ["run", "1.3.0", "1.3.0", "b"]]


def test_lookup_between_below_and_beyond_the_measured_releases():
    v = translation.parse_version
    assert translation.lookup("gemini", "ask", v("0.37.1")) == "dropped"
    assert translation.lookup("gemini", "ask", v("0.45.0")) == "hangs"
    assert translation.lookup("gemini", "ask", v("0.20.0")) == "unmeasured"      # below the oldest measured release
    assert translation.lookup("gemini", "ask", v("0.99.0")) == "hangs"           # newer than any: assumed unchanged
    assert translation.lookup("claude", "ask", None) == "unmeasured"
    assert translation.lookup("claude", "nonsense", v("2.1.200")) == "unmeasured"


def test_a_version_between_two_measured_releases_that_differ_is_uncertain():
    spans = translation.RANGES["gemini"]["ask"]     # (the Claude gap, 2.1.84 to 2.1.85, has no version strictly inside it)
    gap = next(s for s in spans if s[0] == "gap")
    lo, hi = (translation.parse_version(gap[1]), translation.parse_version(gap[2]))
    between = (lo[0], lo[1], lo[2] + 1)
    assert lo < between < hi
    assert translation.lookup("gemini", "ask", between) == "uncertain"
    assert translation.lookup("gemini", "ask", lo) != "uncertain" and translation.lookup("gemini", "ask", hi) != "uncertain"


# ------------------------------------------------------------------------------------------------ ask: ask or deny
def _sem(harness_name: str, version: str | None, mode: str):
    parsed = translation.parse_version(version) if version else None
    sem = translation.Semantics(harness_name, parsed, classes={f: translation.lookup(harness_name, f, parsed)
                                                               for f in translation.RANGES.get(harness_name, {})})
    sem._mode = (mode, "test")
    sem._chain, sem._checked = [], True       # no process lookup, and no `--version` probe of a real harness
    return sem


@pytest.mark.parametrize("mode", ["headless", "yolo"])
@pytest.mark.parametrize("harness_name,version", [("claude", "2.1.200"), ("claude", "2.1.47"), ("codex", "0.166.0"),
                                                   ("gemini", "0.66.0"), ("gemini", "0.37.1")])
def test_an_ask_is_a_refusal_where_no_one_can_answer(harness_name, version, mode):
    decision, why = _sem(harness_name, version, mode).ask_reply("shell", gemini_ask=True)
    assert decision == "deny" and why


@pytest.mark.parametrize("version,expected", [("2.0.41", "deny"), ("2.1.69", "deny"), ("2.1.84", "deny"), ("2.1.85", "ask"),
                                              ("2.1.89", "ask"), ("2.1.300", "ask"), (None, "deny")])
def test_claude_interactive_ask_only_where_the_ask_is_read(version, expected):
    assert _sem("claude", version, "interactive").ask_reply("shell")[0] == expected


def test_gemini_interactive_ask_needs_the_opt_in_a_shell_call_and_a_release_that_keeps_it():
    assert _sem("gemini", "0.66.0", "interactive").ask_reply("shell", gemini_ask=True)[0] == "ask"
    assert _sem("gemini", "0.66.0", "interactive").ask_reply("shell", gemini_ask=False)[0] == "deny"
    assert _sem("gemini", "0.66.0", "interactive").ask_reply("mcp", gemini_ask=True)[0] == "deny"     # a trusted server drops it
    assert _sem("gemini", "0.37.1", "interactive").ask_reply("shell", gemini_ask=True)[0] == "deny"   # yolo ran it
    assert _sem("gemini", "0.38.0", "interactive").ask_reply("shell", gemini_ask=True)[0] == "ask"    # held in yolo, so a prompt
    assert _sem("gemini", "0.20.0", "interactive").ask_reply("shell", gemini_ask=True)[0] == "deny"   # below the measured ones


def test_codex_never_asks_and_cursor_keeps_its_hand_written_mapping():
    assert _sem("codex", "0.166.0", "interactive").ask_reply("shell")[0] == "deny"
    guard = HarnessGuard.__new__(HarnessGuard)
    guard.translation, guard.gemini_ask = _sem("cursor", None, "headless"), False
    assert harness._ask_as(guard, "cursor", "shell")[0] == "ask" and harness._ask_as(guard, "cursor", "mcp")[0] == "deny"


# ------------------------------------------------------------------------------------------------ the replies the hook builds
def _guard(tmp_path: Path, sem=None, **kwargs) -> HarnessGuard:
    g = HarnessGuard(tmp_path / "h.db", builtin_tools=True, **kwargs)
    g.translation = sem
    return g


def _force(monkeypatch, decision: str, reason: str = "because"):
    verdict = lambda self, *a, **k: Verdict(decision, reason, user_reason="shown to the user")
    for name in ("shell", "call", "file", "fetch"):
        monkeypatch.setattr(HarnessGuard, name, verdict)


def _claude_pre(tool="Bash", **extra):
    return {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": tool, "tool_input": {"command": "touch x"}, **extra}


def test_claude_headless_ask_becomes_a_deny_that_says_what_was_wanted(tmp_path, monkeypatch):
    _force(monkeypatch, "ask")
    reply = handle("claude", _claude_pre(), _guard(tmp_path, _sem("claude", "2.1.47", "headless")))["hookSpecificOutput"]
    assert reply["permissionDecision"] == "deny"
    text = reply["permissionDecisionReason"]
    assert "wanted the user to confirm" in text and "Do not retry" in text


def test_claude_interactive_ask_stays_an_ask_with_the_users_own_reason(tmp_path, monkeypatch):
    _force(monkeypatch, "ask")
    reply = handle("claude", _claude_pre(), _guard(tmp_path, _sem("claude", "2.1.200", "interactive")))["hookSpecificOutput"]
    assert reply["permissionDecision"] == "ask" and reply["permissionDecisionReason"].startswith("shown to the user")
    assert "IntentShield read this session as interactive" in reply["permissionDecisionReason"]   # the reading rides along


def test_translation_off_is_the_hook_as_it_was(tmp_path, monkeypatch):
    _force(monkeypatch, "ask")
    claude = handle("claude", _claude_pre(), _guard(tmp_path, None))["hookSpecificOutput"]
    assert claude["permissionDecision"] == "ask"                                 # the old mapping, in a headless run too
    codex = handle("codex", _claude_pre(), _guard(tmp_path, None))["hookSpecificOutput"]
    assert codex["permissionDecision"] == "deny"
    gemini_event = {"hook_event_name": "BeforeTool", "session_id": "s", "tool_name": "run_shell_command",
                    "tool_input": {"command": "touch x"}}
    assert handle("gemini", gemini_event, _guard(tmp_path, None))["decision"] == "deny"
    assert handle("gemini", gemini_event, _guard(tmp_path, None, gemini_ask=True))["decision"] == "ask"


def test_gemini_ask_with_the_opt_in_is_refused_headless_and_asked_interactively(tmp_path, monkeypatch):
    _force(monkeypatch, "ask")
    event = {"hook_event_name": "BeforeTool", "session_id": "s", "tool_name": "run_shell_command", "tool_input": {"command": "x"}}
    refused = handle("gemini", event, _guard(tmp_path, _sem("gemini", "0.66.0", "yolo"), gemini_ask=True))
    assert refused["decision"] == "deny" and "wanted the user to confirm" in refused["reason"]
    asked = handle("gemini", event, _guard(tmp_path, _sem("gemini", "0.66.0", "interactive"), gemini_ask=True))
    assert asked["decision"] == "ask"


def test_a_deny_always_carries_a_reason(tmp_path, monkeypatch):
    """Codex ignores a deny with an empty reason (source) and a harness shows nothing for one: never send it."""
    _force(monkeypatch, "deny", reason="")
    for name in ("claude", "codex"):
        reply = handle(name, _claude_pre(), _guard(tmp_path, None))["hookSpecificOutput"]
        assert reply["permissionDecision"] == "deny" and reply["permissionDecisionReason"].strip()


# ------------------------------------------------------------------------------------------------ mode and version
def test_mode_needs_positive_evidence_of_a_person():
    detect = translation.detect_mode
    interactive = [("ttys001", "/usr/local/bin/claude")]
    assert detect("claude", {}, {}, interactive)[0] == "interactive"
    assert detect("claude", {}, {}, [("??", "claude --resume")])[0] == "headless"                       # no terminal
    assert detect("claude", {}, {}, [("ttys001", "claude -p do it")])[0] == "headless"
    assert detect("claude", {}, {"CLAUDE_CODE_SESSION_ATTENDED": "0"}, interactive)[0] == "headless"
    assert detect("claude", {"permission_mode": "bypassPermissions"}, {}, interactive)[0] == "yolo"
    assert detect("claude", {}, {}, [])[0] == "headless"                                                  # harness not found
    assert detect("codex", {}, {}, [("ttys001", "/x/codex exec --json hi")])[0] == "headless"
    assert detect("codex", {}, {}, [("ttys001", "/x/codex --dangerously-bypass-approvals-and-sandbox")])[0] == "yolo"
    chain = [("ttys001", "/bin/bash -c hook"), ("ttys001", "node /x/node_modules/.bin/gemini")]
    assert detect("gemini", {}, {}, chain)[0] == "interactive"
    assert detect("gemini", {}, {}, [("ttys001", "node /x/.bin/gemini -p hi")])[0] == "headless"
    assert detect("gemini", {}, {}, [("ttys001", "node /x/.bin/gemini -p hi --approval-mode yolo")])[0] == "yolo"
    assert detect("gemini", {}, {}, [("ttys001", "node /x/.bin/gemini --approval-mode yolo")])[0] == "yolo"
    assert detect("claude", {}, {"INTENTSHIELD_HARNESS_MODE": "interactive"}, [])[0] == "interactive"


def test_the_recorded_version_is_ignored_once_the_binary_changes(tmp_path):
    binary = tmp_path / "claude"
    binary.write_text("v1")
    translation.record_version("claude", "2.1.200", str(binary), tmp_path)
    assert translation.recorded_version("claude", tmp_path) == ((2, 1, 200), "")
    binary.write_text("version two, longer")
    version, why = translation.recorded_version("claude", tmp_path)
    assert version is None and "changed" in why
    binary.unlink()
    assert translation.recorded_version("claude", tmp_path)[0] is None
    assert translation.recorded_version("codex", tmp_path)[1].startswith("no version recorded")


def test_the_environment_can_state_the_version(monkeypatch, tmp_path):
    monkeypatch.setenv("INTENTSHIELD_HARNESS_VERSION", "2.1.200")
    assert translation.recorded_version("claude", tmp_path)[0] == (2, 1, 200)


# ------------------------------------------------------------------------------------------------ the fail-closed launcher
def _sh(command: str) -> subprocess.CompletedProcess:
    return subprocess.run(["/bin/sh", "-c", command], capture_output=True, text=True, timeout=20)


def test_the_launcher_turns_every_failure_into_exit_2_with_a_reason(tmp_path):
    ok = tmp_path / "ok"
    ok.write_text("#!/bin/sh\necho '{\"ok\": 1}'\n")
    dead = tmp_path / "dead"
    dead.write_text("#!/nonexistent/interpreter\n")
    refuses = tmp_path / "refuses"
    refuses.write_text("#!/bin/sh\necho 'because' >&2\nexit 2\n")
    for path in (ok, dead, refuses):
        path.chmod(0o755)
    passed = _sh(translation.launcher(str(ok)))
    assert (passed.returncode, passed.stdout.strip(), passed.stderr) == (0, '{"ok": 1}', "")
    # A dead interpreter is 126 under bash (macOS /bin/sh) and 127 under dash (Debian and Ubuntu /bin/sh).
    for command, codes in ((str(dead), (126, 127)), (str(tmp_path / "missing"), (127,)), ("sh -c 'exit 1'", (1,)),
                           ("sh -c 'kill -9 $$'", (137,))):
        failed = _sh(translation.launcher(command))
        assert failed.returncode == 2, command
        assert any(f"exit code {code}" in failed.stderr for code in codes), (command, failed.stderr)
        assert "refused" in failed.stderr, (command, failed.stderr)
    kept = _sh(translation.launcher(str(refuses)))
    assert kept.returncode == 2 and kept.stderr.strip() == "because"        # the hook's own reason is not buried


def test_launcher_is_not_applied_twice_and_not_on_windows(monkeypatch):
    once = translation.launcher("hook claude")
    assert translation.launcher(once) == once
    monkeypatch.setattr(os, "name", "nt")
    assert translation.launcher("hook claude") == "hook claude"


# ------------------------------------------------------------------------------------------------ the deadline
def _hook(tmp_path: Path) -> list[str]:
    return [sys.executable, str(ROOT / "benchmarks" / "hook_fidelity" / "mitigation_hook.py")]


def _run_hook(tmp_path, args, event, env_extra=None):
    env = {**os.environ, "HOME": str(tmp_path), "INTENTSHIELD_HOOK_DB": str(tmp_path / "h.db"), "INTENTSHIELD_THREAT_MEMORY": "0",
           "PYTHONPATH": str(ROOT / "src"), **(env_extra or {})}
    env.pop("INTENTSHIELD_HOOK_TRANSLATE", None)   # conftest turns translation off for the other tests; here it is the subject
    t0 = time.monotonic()
    out = subprocess.run([*_hook(tmp_path), *args], input=json.dumps(event), capture_output=True, text=True, env=env, timeout=60)
    return out, time.monotonic() - t0


@pytest.mark.parametrize("harness_name,event,key", [
    ("claude", _claude_pre(), "hookSpecificOutput"),
    ("gemini", {"hook_event_name": "BeforeTool", "session_id": "s", "tool_name": "run_shell_command",
                "tool_input": {"command": "x"}}, "decision"),
])
def test_a_slow_guard_is_refused_at_the_deadline_not_left_to_the_harness_timeout(tmp_path, harness_name, event, key):
    args = [harness_name, "--builtin-tools", "--deadline", "1", "--eval-verdict", "deny", "--eval-stall", "6"]
    out, took = _run_hook(tmp_path, args, event)
    assert out.returncode == 0, out.stderr
    assert took < limit(4.5), took
    reply = json.loads(out.stdout)
    text = json.dumps(reply)
    assert key in reply and "deny" in text and "did not finish checking this call within 1 s" in text


def test_without_the_deadline_or_with_translation_off_a_slow_guard_just_runs_long(tmp_path):
    off = ["claude", "--builtin-tools", "--deadline", "1", "--eval-verdict", "deny", "--eval-stall", "2",
           "--eval-translate", "off"]
    out, took = _run_hook(tmp_path, off, _claude_pre())
    assert took >= 2 and "did not finish" not in out.stdout
    out, took = _run_hook(tmp_path, ["claude", "--builtin-tools", "--eval-verdict", "deny", "--eval-stall", "2"], _claude_pre())
    assert took >= 2 and "did not finish" not in out.stdout


def test_the_deadline_does_not_touch_events_that_are_not_calls(tmp_path):
    event = {"hook_event_name": "PostToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {}, "tool_response": "ok"}
    out, took = _run_hook(tmp_path, ["claude", "--builtin-tools", "--deadline", "0.2", "--eval-verdict", "allow"], event)
    assert out.returncode == 0 and "did not finish" not in out.stdout


# ------------------------------------------------------------------------------------------------ install and doctor
@pytest.mark.parametrize("harness_name", ["claude", "codex", "gemini"])
def test_install_puts_the_launcher_on_the_hooks_that_check_calls_only(harness_name):
    command = install.hook_command(harness_name, "/opt/bin/hook", deadline=30)
    assert command.endswith("--deadline 30")
    entries = install.hook_entries(harness_name, command)
    for event, groups in entries.items():
        for group in groups:
            for hook in group["hooks"]:
                assert (translation.LAUNCHER in hook["command"]) == (event in translation.CALL_EVENTS), event
    plain = install.hook_entries(harness_name, command, translate=False)
    assert all(translation.LAUNCHER not in h["command"] for groups in plain.values() for g in groups for h in g["hooks"])


def test_cursor_keeps_failclosed_and_gets_no_launcher():
    command = install.hook_command("cursor", "/opt/bin/hook", builtin_tools=True, deadline=30)
    entries = install.hook_entries("cursor", command, builtin_tools=True)
    assert all(translation.LAUNCHER not in h["command"] for groups in entries.values() for h in groups)
    assert entries["beforeMCPExecution"][0]["failClosed"] is True


def test_installed_commands_are_still_recognised_as_ours(tmp_path):
    command = install.hook_command("claude", "/opt/bin/intentshield-hook", deadline=30)
    for groups in install.hook_entries("claude", command).values():
        assert all(install._ours(h) for g in groups for h in g["hooks"])
    with pytest.raises(ValueError):
        install.hook_command("claude", "/opt/bin/hook", deadline=0)


def test_install_translate_default_and_opt_out(tmp_path):
    home = tmp_path / "home"
    path = install.install("claude", "user", hook="/opt/bin/intentshield-hook", home=home)
    on = path.read_text()
    assert "--deadline 30" in on and translation.LAUNCHER.split(";")[0] in on
    install.uninstall("claude", "user", home=home)
    path = install.install("claude", "user", hook="/opt/bin/intentshield-hook", home=home, translate=False)
    assert "--deadline" not in path.read_text()


def test_the_translated_hook_still_runs_under_a_posix_shell_when_the_guard_breaks(tmp_path):
    """The hook the installer writes, run the way a harness runs it, with the interpreter gone."""
    dead = tmp_path / "intentshield-hook"
    dead.write_text("#!/nonexistent/python\n")
    dead.chmod(0o755)
    entries = install.hook_entries("claude", install.hook_command("claude", str(dead), deadline=30))
    command = entries["PreToolUse"][0]["hooks"][0]["command"]
    out = _sh(command)
    assert out.returncode == 2 and "this call is refused" in out.stderr


def _hook_file(harness_name, tmp_path, command, translate=True):
    home = tmp_path / "home"
    path = install.settings_path(harness_name, "user", home, tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if harness_name == "codex":
        path.write_text(install.codex_toml(command, False, translate))
    else:
        path.write_text(json.dumps({"hooks": install.hook_entries(harness_name, command, translate=translate)}))
    return home


def _dead_hook(tmp_path):
    dead = tmp_path / "intentshield-hook"
    dead.write_text("#!/nonexistent/python\n")
    dead.chmod(0o755)
    return dead


@pytest.mark.parametrize("version,words", [((0, 28, 2), "runs the call unguarded"), ((0, 29, 7), "runs the call unguarded"),
                                           ((0, 30, 0), "blocks every call"), ((0, 66, 0), "blocks every call"),
                                           (None, "not measured exactly")])
def test_doctor_words_the_gemini_dead_interpreter_by_the_measured_boundary(tmp_path, capsys, monkeypatch, version, words):
    dead = _dead_hook(tmp_path)
    home = _hook_file("gemini", tmp_path, install.hook_command("gemini", str(dead)), translate=False)   # no launcher
    monkeypatch.setattr(doctor, "gemini_version", lambda: version)
    doctor.doctor(home, tmp_path, home / ".intentshield" / "hooks.db")
    out = capsys.readouterr().out
    assert words in out and "FAIL" in out


def test_doctor_says_the_launcher_makes_a_dead_interpreter_a_refusal(tmp_path, capsys, monkeypatch):
    dead = _dead_hook(tmp_path)
    home = _hook_file("claude", tmp_path, install.hook_command("claude", str(dead), deadline=30))
    doctor.doctor(home, tmp_path, home / ".intentshield" / "hooks.db")
    out = capsys.readouterr().out
    assert "the launcher in front of the hook turns that into a refusal" in out
    assert "starts with #!/nonexistent/python" in out and "FAIL claude" not in out.split("starts with")[0].splitlines()[-1]


def test_doctor_flags_a_hook_installed_without_the_translation(tmp_path, capsys):
    ok = tmp_path / "intentshield-hook"
    ok.write_text("#!/bin/sh\n")
    ok.chmod(0o755)
    home = _hook_file("codex", tmp_path, install.hook_command("codex", str(ok)), translate=False)
    doctor.doctor(home, tmp_path, home / ".intentshield" / "hooks.db", verbose=True)
    out = capsys.readouterr().out
    assert "installed without the verdict translation" in out
    assert "version unknown" in out                      # no version recorded here: the doctor says what that costs
    doctor.doctor(home, tmp_path, home / ".intentshield" / "hooks.db")
    assert "version unknown" not in capsys.readouterr().out   # a note is printed with --verbose only


def test_findings_name_the_measured_conditions_per_version():
    codex_old = [m for _, m in translation.findings("codex", (0, 140, 0))]
    assert any("through 0.140.0" in m for m in codex_old)
    codex_new = [m for _, m in translation.findings("codex", (0, 166, 0))]
    assert not any("through 0.140.0" in m for m in codex_new)
    assert any("ask" in m for m in codex_new)
    assert any("through 2.1.84" in m for _, m in translation.findings("claude", (2, 1, 47)))
    assert not any("through 2.1.84" in m for _, m in translation.findings("claude", (2, 1, 300)))
    assert any("onFailure" in m for _, m in translation.findings("claude", (2, 1, 281)))
    assert not any("is documented from 2.1.295" in m for _, m in translation.findings("claude", (2, 1, 300)))
    assert any("version unknown" in m for _, m in translation.findings("gemini", None))
    gem = [m for _, m in translation.findings("gemini", (0, 29, 7))]
    assert any("0.30.0" in m for m in gem) and any("dead" in m or "cannot start" in m for m in gem)


def test_gemini_ask_check_follows_the_measured_ranges(tmp_path, capsys):
    report = doctor.Report()
    doctor._check_gemini_ask(report, "gemini", (0, 37, 1))
    assert report.problems == 1 and "through 0.37.2" in capsys.readouterr().out
    report = doctor.Report()
    doctor._check_gemini_ask(report, "gemini", (0, 66, 0))
    assert report.problems == 0 and "waits for an answer" in capsys.readouterr().out
    report = doctor.Report()
    doctor._check_gemini_ask(report, "gemini", (0, 38, 0))
    assert report.problems == 0                                  # 0.38.0 waits (measured), as 0.38.2 and later do
    report = doctor.Report()
    doctor._check_gemini_ask(report, "gemini", (0, 20, 0))
    assert report.problems == 1                                  # below the oldest measured release: not assumed safe
