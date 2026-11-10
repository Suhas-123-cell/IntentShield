"""Round 4 fixes to the verdict translation, from the mitigation critic: a hard-to-fool mode detector, a version record that
notices an update, a bounded process lookup, and a version parser that an oversized string in the environment cannot break."""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from intentshield import translation
from intentshield.harness import HarnessGuard, Verdict, handle


# ------------------------------------------------------------------------------------------------ parsing a version
def test_a_component_of_more_than_six_digits_is_not_a_version():
    """int() of a string of over 4300 digits raises in Python; the version of the environment must not reach it."""
    huge = "9" * 5000
    assert translation.parse_version(f"{huge}.1.1") is None
    assert translation.parse_version(f"1.{huge}.1") is None
    assert translation.parse_version("1234567.1.1") is None
    assert translation.parse_version("123456.1.1") == (123456, 1, 1)


def test_only_the_first_line_of_a_banner_is_read():
    assert translation.parse_version("2.1.316 (Claude Code)") == (2, 1, 316)
    assert translation.parse_version("\n codex-cli 0.166.0\nnode 22.1.0") == (0, 166, 0)
    assert translation.parse_version("update available\n3.4.5") is None     # the version is not on the first line
    assert translation.parse_version("2026.10.22-27dcf5f") == (2026, 10, 22)


def test_an_oversized_version_in_the_environment_does_not_stop_the_hook(monkeypatch, tmp_path):
    monkeypatch.setenv("INTENTSHIELD_HARNESS_VERSION", "9" * 5000 + ".1.1")
    version, why = translation.recorded_version("claude", tmp_path)
    assert version is None and "not a version" in why


# ------------------------------------------------------------------------------------------------ the version record
def _binary(tmp_path: Path, name: str, body: str = "x") -> Path:
    path = tmp_path / name
    path.write_text(body)
    return path


def test_the_record_is_written_atomically_and_keeps_other_harnesses(tmp_path):
    build = _binary(tmp_path, "claude-2.1.316")
    translation.record_version("claude", "2.1.316", str(build), tmp_path)
    translation.record_version("gemini", "0.66.0", str(build), tmp_path)
    cache = tmp_path / ".intentshield" / translation.CACHE_NAME
    assert set(json.loads(cache.read_text())) == {"claude", "gemini"}
    assert not [p for p in cache.parent.iterdir() if p.name.endswith(".tmp")]


def test_an_update_that_repoints_the_launcher_symlink_makes_the_record_stale(tmp_path):
    """The native Claude install keeps every build as its own file and repoints a symlink: the old file is never modified, so
    its size and time cannot show the update."""
    old, new = _binary(tmp_path, "versions-2.1.311"), _binary(tmp_path, "versions-2.1.316", "other")
    link = tmp_path / "claude"
    link.symlink_to(old)
    translation.record_version("claude", "2.1.311", os.path.realpath(link), tmp_path, path=str(link))
    assert translation.recorded_version("claude", tmp_path) == ((2, 1, 311), "")
    link.unlink()
    link.symlink_to(new)
    version, why = translation.recorded_version("claude", tmp_path)
    assert version is None and "points at another build" in why


def test_a_pruned_build_is_a_stale_record_not_a_crash(tmp_path):
    build = _binary(tmp_path, "claude-old")
    translation.record_version("claude", "2.1.311", str(build), tmp_path)
    build.unlink()
    version, why = translation.recorded_version("claude", tmp_path)
    assert version is None and "gone" in why


# ------------------------------------------------------------------------------------------------ mode detection
def _mode(harness_name: str, command: str, tty: str = "ttys001", env: dict | None = None) -> str:
    return translation.detect_mode(harness_name, {}, env or {}, [(tty, command)])[0]


@pytest.mark.parametrize("command,expected", [
    ("/Users/u/.local/bin/claude", "interactive"),
    ("/Users/u/.local/bin/claude explain what tar -p does", "interactive"),     # a flag-like word in the prompt
    ("/Users/u/.local/bin/claude explain tar --print", "interactive"),
    ("/Users/u/.local/bin/claude -p fix it", "headless"),
    ("/Users/u/.local/bin/claude --model opus -p fix it", "headless"),
    ("/Users/u/.local/bin/claude --print", "headless"),
    ("/Users/u/.local/bin/claude --dangerously-skip-permissions", "yolo"),
])
def test_claude_headless_flags_are_read_from_its_own_arguments_not_from_the_prompt(command, expected):
    assert _mode("claude", command) == expected


@pytest.mark.parametrize("command,expected", [
    ("/opt/bin/codex", "interactive"),
    ("/opt/bin/codex fix bug e foo", "interactive"),                           # a subcommand-like word in the prompt
    ("/opt/bin/codex exec do it", "headless"),
    ("/opt/bin/codex --model gpt-5 exec do it", "headless"),
    ("/opt/bin/codex review", "headless"),
])
def test_codex_subcommands_are_read_from_its_own_arguments_not_from_the_prompt(command, expected):
    assert _mode("codex", command) == expected


def test_a_node_launched_harness_is_read_from_the_script_s_arguments():
    assert _mode("claude", "node /x/bin/claude -p hi") == "headless"
    assert _mode("claude", "node /x/bin/claude explain tar -p") == "interactive"
    assert _mode("gemini", "node /usr/lib/gemini -p hi") == "headless"
    assert _mode("gemini", "node /usr/lib/gemini") == "interactive"


def test_no_terminal_or_unattended_or_not_found_is_headless():
    assert _mode("claude", "/u/bin/claude", tty="??") == "headless"
    assert _mode("claude", "/u/bin/claude", env={"CLAUDE_CODE_SESSION_ATTENDED": "0"}) == "headless"
    assert translation.detect_mode("claude", {}, {}, [("ttys001", "/bin/zsh")])[0] == "headless"
    # a terminal-less embedding that says it is attended is still read as headless: a refusal, never a hang (documented loss)
    assert _mode("claude", "/u/bin/claude", tty="??", env={"CLAUDE_CODE_SESSION_ATTENDED": "1"}) == "headless"


def test_the_environment_override_is_named_for_the_hook_to_report(monkeypatch):
    monkeypatch.delenv("INTENTSHIELD_HARNESS_MODE", raising=False)
    monkeypatch.delenv("INTENTSHIELD_HARNESS_VERSION", raising=False)
    sem = translation.Semantics("claude", (2, 1, 316))
    assert sem.overrides() == []
    monkeypatch.setenv("INTENTSHIELD_HARNESS_MODE", "interactive")
    monkeypatch.setenv("INTENTSHIELD_HARNESS_VERSION", "2.1.300")
    assert sem.overrides() == ["INTENTSHIELD_HARNESS_MODE=interactive", "INTENTSHIELD_HARNESS_VERSION=2.1.300"]


# ------------------------------------------------------------------------------------------------ the process lookup is bounded
def test_the_ancestor_lookup_stops_at_its_total_budget(monkeypatch):
    calls: list[float] = []

    def slow_ps(argv, **kwargs):
        calls.append(kwargs["timeout"])
        time.sleep(0.15)
        return subprocess.CompletedProcess(argv, 0, stdout=f"{100 + len(calls)} ttys001 /bin/zsh\n", stderr="")

    monkeypatch.setattr(translation.subprocess, "run", slow_ps)
    monkeypatch.setenv(translation.ANCESTRY_ENV, "ps")     # the budget is the ps reader's: the others spawn nothing
    started = time.monotonic()
    chain = translation._ancestors(depth=8, budget=0.4)
    assert time.monotonic() - started < 1.0
    assert 1 <= len(chain) < 8 and all(t <= 1.0 for t in calls)


# ------------------------------------------------------------------------------------------- verifying the version before an ask
def _interactive_claude(version: tuple[int, ...] | None, tmp_path: Path, chain=None) -> translation.Semantics:
    classes = {f: translation.lookup("claude", f, version) for f in translation.RANGES["claude"]}
    sem = translation.Semantics("claude", version, classes=classes, home=tmp_path)
    sem._mode, sem._chain = ("interactive", "test"), chain if chain is not None else []
    return sem


def test_a_missing_record_is_refreshed_from_the_running_binary_before_an_ask(tmp_path, monkeypatch):
    seen: list[str | None] = []

    def probe(harness_name, home=None, timeout=20.0, program=None):
        seen.append(program)
        return (2, 1, 316)

    monkeypatch.setattr(translation, "probe_and_record", probe)
    sem = _interactive_claude(None, tmp_path, [("ttys001", "/u/bin/claude")])
    assert sem.ask_reply("shell") == ("ask", "") and seen == ["/u/bin/claude"]


def test_an_unreadable_running_binary_leaves_the_ask_a_refusal_that_says_why(tmp_path, monkeypatch):
    monkeypatch.setattr(translation, "probe_and_record", lambda *a, **k: None)
    sem = _interactive_claude(None, tmp_path)
    sem.version_note = "no version recorded (run `intentshield doctor`)"
    decision, why = sem.ask_reply("shell")
    assert decision == "deny" and "no version recorded" in why


def test_a_record_for_another_build_than_the_running_one_is_not_trusted(tmp_path, monkeypatch):
    build = _binary(tmp_path, "claude-2.1.200")
    translation.record_version("claude", "2.1.200", str(build), tmp_path)
    monkeypatch.setattr(translation, "probe_and_record", lambda *a, **k: None)
    chain = [("ttys001", f"{tmp_path}/other/claude")]    # the running binary is not the recorded one
    sem = _interactive_claude((2, 1, 200), tmp_path, chain)
    decision, why = sem.ask_reply("shell")
    assert decision == "deny" and "not the build whose version was recorded" in why


def test_a_matching_record_costs_no_probe(tmp_path, monkeypatch):
    build = _binary(tmp_path, "claude")
    translation.record_version("claude", "2.1.316", os.path.realpath(build), tmp_path)

    def boom(*a, **k):
        raise AssertionError("must not probe")

    monkeypatch.setattr(translation, "probe_and_record", boom)
    sem = _interactive_claude((2, 1, 316), tmp_path, [("ttys001", str(build))])
    assert sem.ask_reply("shell") == ("ask", "")


def test_the_headless_ask_does_not_depend_on_the_version_record(tmp_path):
    """The held-out evaluation's ask cells are all headless: there the table is never consulted, with or without a record."""
    for version in (None, (2, 1, 47), (2, 1, 316)):
        classes = {f: translation.lookup("claude", f, version) for f in translation.RANGES["claude"]}
        sem = translation.Semantics("claude", version, classes=classes, home=tmp_path)
        sem._mode, sem._chain, sem._checked = ("headless", "test"), [], True
        assert sem.ask_reply("shell")[0] == "deny"


# ------------------------------------------------------------------------------------------------ the table
def test_the_claude_ask_boundary_is_the_bisected_one():
    spans = translation.RANGES["claude"]["ask"]
    assert ["gap", "2.1.84", "2.1.85", "uncertain"] in spans
    v = translation.parse_version
    assert translation.lookup("claude", "ask", v("2.1.84")) == "dropped"
    assert translation.lookup("claude", "ask", v("2.1.85")) == "denied"


# ------------------------------------------------------------------------------------------------ an allow still runs
def test_an_allow_is_never_turned_into_a_refusal(tmp_path, monkeypatch):
    """The translation changes asks and failures; a call the guard allows must reach the harness as no opinion or allow."""
    verdict = lambda self, *a, **k: Verdict("allow", "")  # noqa: E731
    for name in ("shell", "call", "file", "fetch"):
        monkeypatch.setattr(HarnessGuard, name, verdict)
    guard = HarnessGuard(tmp_path / "h.db", builtin_tools=True)
    for harness_name, tool in (("claude", "Bash"), ("codex", "Bash"), ("gemini", "run_shell_command")):
        sem = translation.Semantics(harness_name, translation.parse_version("2.1.316"))
        sem._mode, sem._chain, sem._checked = ("headless", "test"), [], True
        guard.translation = sem
        event = {"hook_event_name": "BeforeTool" if harness_name == "gemini" else "PreToolUse", "session_id": "s",
                 "tool_name": tool, "tool_input": {"command": "touch x"}}
        reply = handle(harness_name, event, guard)
        text = json.dumps(reply)
        assert "deny" not in text and "refus" not in text, (harness_name, reply)
