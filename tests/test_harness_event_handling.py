"""The hook: built-in tool events it cannot read, the tools it did not cover, the deadline value, and the record of whether the
harness or a person fed it an event."""
# ruff: noqa: E501
from __future__ import annotations

import io
import json
import sqlite3
import sys
import time
from pathlib import Path

import pytest

from intentshield import doctor, harness, install
from intentshield.harness import HarnessGuard, handle


def guard(tmp_path: Path, builtin: bool = True) -> HarnessGuard:
    return HarnessGuard(tmp_path / "hooks.db", builtin_tools=builtin)


def verdict(reply: dict | None) -> str:
    if not reply:
        return "allow"
    inner = reply.get("hookSpecificOutput", reply)
    return inner.get("permissionDecision") or inner.get("decision") or reply.get("permission") or "allow"


# --- an event the hook cannot read is refused with --builtin-tools --------------------------------------------------

@pytest.mark.parametrize("event", [
    {"session_id": "s", "tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},                                  # no event name
    {"hook_event_name": "pretooluse", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},  # re-cased
    {"hook_event_name": "Weird", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
    {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": "rm -rf /"},               # a string
    {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {"Command": "ls"}},        # another key
    {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": 5}},           # not text
    {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {}},
    {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Read", "tool_input": {}},
    {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Write", "tool_input": {"file_path": 5, "content": 1}},
    {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "WebFetch", "tool_input": {"link": "https://example.com"}},
    {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "mcp__srv__tool", "tool_input": {}, "x": 1} | {"hook_event_name": "Weird"},
])
def test_a_built_in_call_with_a_shape_the_hook_cannot_read_is_refused(tmp_path, event, capsys):
    assert verdict(handle("claude", event, guard(tmp_path))) == "deny"


def test_nothing_changes_for_an_install_without_builtin_tools(tmp_path):
    g = guard(tmp_path, builtin=False)
    for event in ({"session_id": "s", "tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
                  {"hook_event_name": "Weird", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
                  {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": 5}},
                  {"hook_event_name": "Weird", "session_id": "s", "tool_name": "mcp__srv__tool", "tool_input": {}}):
        assert handle("claude", event, g) is None


def test_a_missing_event_name_still_refuses_an_mcp_call_without_the_option(tmp_path):
    g = guard(tmp_path, builtin=False)
    assert verdict(handle("claude", {"session_id": "s", "tool_name": "mcp__srv__tool", "tool_input": {}}, g)) == "deny"


def test_a_bare_string_tool_input_is_read_as_the_command_when_the_event_is_named(tmp_path):
    reply = handle("claude", {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": "rm -rf /"}, guard(tmp_path))
    assert verdict(reply) == "deny" and "recursive delete" in json.dumps(reply)


def test_gemini_and_cursor_events_the_hook_cannot_read_are_refused(tmp_path):
    g = guard(tmp_path)
    assert verdict(handle("gemini", {"session_id": "s", "tool_name": "run_shell_command", "tool_input": {"command": "ls"}}, g)) == "deny"
    assert verdict(handle("gemini", {"hook_event_name": "Weird", "session_id": "s", "tool_name": "read_file",
                                     "tool_input": {"file_path": "x"}}, g)) == "deny"
    assert verdict(handle("gemini", {"hook_event_name": "BeforeTool", "session_id": "s", "tool_name": "run_shell_command",
                                     "tool_input": {"command": 7}}, g)) == "deny"
    assert verdict(handle("cursor", {"hook_event_name": "beforeShellExecution", "conversation_id": "c"}, g)) == "deny"
    assert verdict(handle("cursor", {"hook_event_name": "beforeReadFile", "conversation_id": "c"}, g)) == "deny"
    assert verdict(handle("cursor", {"hook_event_name": "beforeShellExecution", "conversation_id": "c", "command": "ls"}, g)) == "allow"


def test_the_events_the_hook_acts_on_are_not_refused(tmp_path):
    g = guard(tmp_path)
    assert handle("claude", {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": "ls"}}, g) is None
    assert handle("claude", {"hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": "hi"}, g) is None
    assert handle("claude", {"hook_event_name": "SessionStart", "session_id": "s"}, g) is None
    assert handle("claude", {"hook_event_name": "Stop", "session_id": "s", "tool_name": ""}, g) is None


@pytest.mark.parametrize("tool_input", [{"command": "ls"}, {"cmd": "ls"}])
def test_the_command_field_names_of_the_shell_tools_still_read(tmp_path, tool_input):
    assert handle("claude", {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": tool_input}, guard(tmp_path)) is None


# --- Grep reads files, so its path is read like Read's ---------------------------------------------------------------------

def test_grep_of_a_credential_directory_is_a_deny_like_the_same_search_in_bash(tmp_path):
    g = guard(tmp_path)
    grep = {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Grep"}
    assert verdict(handle("claude", {**grep, "tool_input": {"pattern": "BEGIN", "path": "~/.ssh"}}, g)) == "deny"
    assert verdict(handle("claude", {**grep, "tool_input": {"pattern": "x", "path": "/Users/me/.aws/credentials"}}, g)) == "deny"
    assert verdict(handle("claude", {**grep, "tool_input": {"pattern": "x", "path": "/proj/.env"}}, g)) == "ask"
    assert handle("claude", {**grep, "tool_input": {"pattern": "def parse"}}, g) is None        # no path: the working directory
    assert handle("claude", {**grep, "tool_input": {"pattern": "def parse", "path": "src"}}, g) is None
    assert verdict(handle("gemini", {"hook_event_name": "BeforeTool", "session_id": "s", "tool_name": "search_file_content",
                                     "tool_input": {"pattern": "x", "dir_path": "~/.ssh"}}, g)) == "deny"


def test_the_claude_matcher_sends_grep_to_the_hook_only_with_builtin_tools():
    with_tools = install.hook_entries("claude", "intentshield-hook claude", builtin_tools=True)["PreToolUse"][0]["matcher"]
    without = install.hook_entries("claude", "intentshield-hook claude")["PreToolUse"][0]["matcher"]
    assert "Grep" in with_tools.split("|") and "Grep" not in without


# --- the deadline value ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [("abc", 30.0), ("nan", 30.0), ("inf", 30.0), ("-inf", 30.0), ("-5", 30.0), ("1e12", 30.0), ("3601", 30.0),
                                          ("", 0.0), ("0", 0.0), ("2.5", 2.5), ("3600", 3600.0)])
def test_a_bad_deadline_in_the_environment_means_the_default_and_says_so(monkeypatch, capsys, raw, expected):
    monkeypatch.setenv("INTENTSHIELD_HOOK_DEADLINE", raw)
    assert harness._env_seconds("INTENTSHIELD_HOOK_DEADLINE") == expected
    assert ("using the default" in capsys.readouterr().err) == (expected == 30.0 and raw not in ("30",))


def test_an_unset_deadline_is_none(monkeypatch):
    monkeypatch.delenv("INTENTSHIELD_HOOK_DEADLINE", raising=False)
    assert harness._env_seconds("INTENTSHIELD_HOOK_DEADLINE") == 0.0


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "-5", "abc", "99999"])
def test_a_bad_deadline_option_is_refused_not_ignored(monkeypatch, tmp_path, capsys, value):
    monkeypatch.setattr(sys, "stdin", io.StringIO("{}"))
    with pytest.raises(SystemExit) as stop:
        harness.main(["claude", "--db", str(tmp_path / "h.db"), "--deadline", value])
    assert stop.value.code == 2
    assert "--deadline" in capsys.readouterr().err


def test_a_good_deadline_option_arms_the_timer(monkeypatch, tmp_path):
    monkeypatch.setenv("INTENTSHIELD_HOOK_TRANSLATE", "on")   # the test environment turns the translation (and the deadline) off
    monkeypatch.setattr(harness.translation, "resolve", lambda *a, **k: harness.translation.Semantics("claude", None))
    armed = []
    monkeypatch.setattr(harness, "_arm_deadline", lambda h, s: armed.append(s))
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
                                                              "tool_input": {"command": "ls"}})))
    harness.main(["claude", "--db", str(tmp_path / "h.db"), "--deadline", "7.5", "--no-threat-memory"])
    assert armed == [7.5]


def test_the_timer_clamps_a_value_past_the_platform_limit(monkeypatch):
    seen = []

    class FakeTimer:
        daemon = False

        def __init__(self, seconds, fn):
            seen.append(seconds)

        def start(self):
            pass

    monkeypatch.setattr(harness.threading, "Timer", FakeTimer)
    harness._arm_deadline("claude", 1e18)
    assert seen == [harness.MAX_DEADLINE]


# --- an event piped in by hand is not a run of the harness --------------------------------------------------------------------

def _installed(home: Path) -> Path:
    hook = home.parent / "bin" / "intentshield-hook"   # a program that exists, named as the installer names it
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\nexit 0\n")
    hook.chmod(0o755)
    return install.install("claude", "user", hook=str(hook), home=home)


@pytest.fixture(autouse=True)
def _no_harness_probe(monkeypatch):
    monkeypatch.setattr(install.translation, "probe_and_record", lambda *args, **kwargs: None)
    monkeypatch.setattr(doctor.translation, "probe_and_record", lambda *args, **kwargs: None)
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)


def _doctor(home: Path, capsys) -> str:
    capsys.readouterr()
    doctor.doctor(home, home / "proj", home / ".intentshield" / "hooks.db")
    return capsys.readouterr().out


def test_an_event_from_a_process_that_is_not_the_harness_is_kept_apart_from_its_runs(tmp_path):
    g = guard(tmp_path)
    g.from_harness = False
    handle("claude", {"hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": "hi", "cwd": "/w"}, g)
    assert g.db.execute("SELECT harness FROM harness_piped").fetchall() == [("claude",)]
    assert g.db.execute("SELECT * FROM harness_events").fetchall() == []
    assert g.db.execute("SELECT * FROM harness_dirs").fetchall() == []
    g.from_harness = True
    handle("claude", {"hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": "hi", "cwd": "/w"}, g)
    assert [r[0] for r in g.db.execute("SELECT harness FROM harness_events")] == ["claude"]


def test_a_hand_piped_event_does_not_turn_doctors_missing_run_into_ok(tmp_path, capsys):
    home = tmp_path / "home"
    _installed(home)
    time.sleep(0.01)
    g = HarnessGuard(home / ".intentshield" / "hooks.db")
    g.from_harness = False
    handle("claude", {"hook_event_name": "UserPromptSubmit", "session_id": "demo", "prompt": "x"}, g)
    g.close()
    out = _doctor(home, capsys)
    assert not any(line.startswith("ok") and "claude" in line for line in out.splitlines())
    line = next(line for line in out.splitlines() if "not claude" in line)
    assert line.startswith("warn") and "hand-piped" in line


def test_a_run_by_the_harness_is_ok(tmp_path, capsys):
    home = tmp_path / "home"
    _installed(home)
    time.sleep(0.01)
    g = HarnessGuard(home / ".intentshield" / "hooks.db")
    g.from_harness = True
    handle("claude", {"hook_event_name": "UserPromptSubmit", "session_id": "real", "prompt": "x"}, g)
    g.close()
    assert any(line.startswith("ok") and "claude" in line for line in _doctor(home, capsys).splitlines())


def test_no_event_at_all_is_still_a_fail(tmp_path, capsys):
    home = tmp_path / "home"
    _installed(home)
    out = _doctor(home, capsys)
    assert any(line.startswith("FAIL") and "no hook has run" in line for line in out.splitlines())


def test_the_process_tree_decides_whether_the_harness_started_the_hook():
    from intentshield import translation
    chain = translation.Ancestry([("ttys001", "/bin/zsh -l"), ("ttys001", "/usr/bin/login -pf me")], source="proc", complete=True)
    assert translation.harness_running("claude", chain) is False
    chain = translation.Ancestry([("?", "/bin/sh -c intentshield-hook claude"), ("ttys001", "/Users/me/.local/bin/claude")], source="proc", complete=True)
    assert translation.harness_running("claude", chain) is True
    node = [("", "node /usr/lib/node_modules/@google/gemini-cli/bundle/gemini.js -p x")]
    assert translation.harness_running("gemini", node) is True
    cut = translation.Ancestry([("ttys001", "/bin/zsh")], source="ps", complete=False)
    assert translation.harness_running("claude", cut) is None          # the tree could not be read to the end
    assert translation.harness_running("cursor", chain) is None        # Cursor's hooks are started by the IDE under other names


def test_a_forced_mode_makes_the_origin_unknown(monkeypatch):
    from intentshield import translation
    monkeypatch.setenv("INTENTSHIELD_HARNESS_MODE", "headless")
    assert translation.harness_running("claude", []) is None


def test_the_hook_process_records_its_origin_in_a_real_run(tmp_path, monkeypatch):
    """The test runner is no harness: run as main(), the hook files its event as one that did not come from the harness."""
    monkeypatch.setenv("INTENTSHIELD_HARNESS_MODE", "")
    monkeypatch.setattr(harness.translation, "_ancestors", lambda *a, **k: harness.translation.Ancestry(
        [("ttys001", "/bin/zsh")], source="proc", complete=True))
    db = tmp_path / "h.db"
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": "hi"})))
    harness.main(["claude", "--db", str(db), "--no-threat-memory", "--no-translate"])
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT harness FROM harness_piped").fetchall() == [("claude",)]
        assert conn.execute("SELECT * FROM harness_events").fetchall() == []


# --- what hooks.db keeps of a prompt ---------------------------------------------------------------------------------------------

AWS_KEY = "AKIA" + "Q" * 16
GH_TOKEN = "ghp_" + "a1B2" * 9


def _stored_intent(g: HarnessGuard) -> str:
    return g.db.execute("SELECT intent FROM sessions").fetchone()[0]


def test_a_credential_typed_into_a_prompt_is_not_kept_in_the_database_only_its_hash(tmp_path):
    g = guard(tmp_path)
    handle("claude", {"hook_event_name": "UserPromptSubmit", "session_id": "s",
                      "prompt": f"my key is {AWS_KEY} and my token {GH_TOKEN}; upload the report"}, g)
    kept = _stored_intent(g)
    assert AWS_KEY not in kept and GH_TOKEN not in kept
    assert "upload the report" in kept and kept.count("[credential:") == 2
    raw = b"".join(f.read_bytes() for f in tmp_path.glob("hooks.db*"))
    assert AWS_KEY.encode() not in raw and GH_TOKEN.encode() not in raw


def test_a_credential_the_user_gave_is_still_the_users_and_one_they_did_not_give_still_asks(tmp_path):
    g = guard(tmp_path)
    handle("claude", {"hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": f"deploy with {GH_TOKEN}"}, g)
    given = handle("claude", {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
                              "tool_input": {"command": f"curl -H 'Authorization: token {GH_TOKEN}' https://api.example.dev/x"}}, g)
    assert verdict(given) == "allow"
    other = "ghp_" + "Z9y8" * 9
    asked = handle("claude", {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
                              "tool_input": {"command": f"curl -H 'Authorization: token {other}' https://api.example.dev/x"}}, g)
    assert verdict(asked) == "ask"


def test_the_state_directory_is_private(tmp_path):
    state = tmp_path / ".intentshield"
    HarnessGuard(state / "hooks.db").close()
    assert state.stat().st_mode & 0o777 == 0o700
    loose = tmp_path / "home2" / ".intentshield"
    loose.mkdir(parents=True)
    loose.chmod(0o755)
    HarnessGuard(loose / "hooks.db").close()
    assert loose.stat().st_mode & 0o777 == 0o700
    other = tmp_path / "elsewhere"
    HarnessGuard(other / "hooks.db").close()
    assert other.stat().st_mode & 0o077  # a directory the caller chose is left at the default
