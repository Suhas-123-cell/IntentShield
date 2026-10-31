"""A judge that is down (offline, rate-limited, no key) leaves the rules to decide: no extra ask or deny on
state-changing calls (audit hooks-8), and the hook skips it for a while instead of waiting it out on every
call."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from intentshield import harness as harness_module
from intentshield.harness import HarnessGuard, handle


class DownJudge:
    errors, unread = 0, 0
    last_error = "URLError: <urlopen error [Errno 8] nodename nor servname provided, or not known>"

    def __init__(self) -> None:
        self.tries = 0

    def call(self, _intent, _tool, _arguments):
        self.tries += 1
        self.errors += 1
        return None

    def output(self, _intent, _tool, _result):
        self.tries += 1
        self.errors += 1
        return None


class Objecting(DownJudge):
    def call(self, _intent, _tool, _arguments):
        self.tries += 1
        return "the user never asked for this"


def _event(name: str, **fields):
    return {"hook_event_name": name, "session_id": "j", "cwd": "/p", **fields}


def _pre(harness: str, guard: HarnessGuard, tool: str) -> dict | None:
    handle(harness, _event("UserPromptSubmit", prompt="open an issue titled 'typo' in the repo"), guard)
    return handle(harness, _event("PreToolUse", tool_name=tool, tool_input={"title": "typo"}), guard)


@pytest.mark.parametrize("harness", ["claude", "codex"])
@pytest.mark.parametrize("tool", ["mcp__github__create_issue", "mcp__github__get_issue"])
def test_a_down_judge_adds_a_note_but_no_ask_or_deny(harness, tool, tmp_path: Path):
    guard = HarnessGuard(tmp_path / "h.db")
    guard.judge = DownJudge()
    reply = _pre(harness, guard, tool)
    out = reply["hookSpecificOutput"]
    assert "permissionDecision" not in out, out
    assert "only the rules checked" in out["additionalContext"]


def test_a_judge_without_a_key_does_not_refuse_codex_writes(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr(harness_module, "ENV_FILE", tmp_path / "none.env")
    guard = HarnessGuard(tmp_path / "h.db", judge="groq")
    out = _pre("codex", guard, "mcp__github__create_issue")["hookSpecificOutput"]
    assert "permissionDecision" not in out and "no API key" in out["additionalContext"]


def test_a_judge_objection_still_asks(tmp_path: Path):
    guard = HarnessGuard(tmp_path / "h.db")
    guard.judge = Objecting()
    out = _pre("claude", guard, "mcp__github__create_issue")["hookSpecificOutput"]
    assert out["permissionDecision"] == "ask"


def test_the_hook_skips_a_failed_judge_for_a_while_then_tries_again(tmp_path: Path, monkeypatch):
    now = [1_000_000.0]
    monkeypatch.setattr(harness_module.time, "time", lambda: now[0])
    judge = DownJudge()

    def hook() -> HarnessGuard:  # each hook event is its own process with its own guard
        guard = HarnessGuard(tmp_path / "h.db", judge_pause=True, judge_outputs=True)
        guard.judge = judge
        return guard

    _pre("claude", hook(), "mcp__github__create_issue")
    assert judge.tries == 1
    out = _pre("claude", hook(), "mcp__github__create_issue")["hookSpecificOutput"]
    handle("claude", _event("PostToolUse", tool_name="mcp__web__fetch", tool_input={}, tool_response="A calm page."),
           hook())
    assert judge.tries == 1, "skipped while paused, calls and results alike"
    assert "offline or unavailable" in out["additionalContext"] and "permissionDecision" not in out
    now[0] += harness_module.JUDGE_PAUSE + 1
    _pre("claude", hook(), "mcp__github__create_issue")
    assert judge.tries == 2


@pytest.mark.parametrize("error", ["HTTP 429: rate limited", "TimeoutError: timed out",
                                   "out of time (the judge's 20 s budget is spent)", "ValueError: bad reply"])
def test_failures_a_tool_output_could_cause_do_not_pause_the_judge(error, tmp_path: Path):
    judge = DownJudge()
    judge.last_error = error
    for _ in range(2):  # a hostile output that makes the judge time out must not switch it off for the next
        guard = HarnessGuard(tmp_path / "h.db", judge_pause=True)
        guard.judge = judge
        _pre("claude", guard, "mcp__github__create_issue")
    assert judge.tries == 2 and not (tmp_path / "judge-paused").exists()


def test_only_the_hook_pauses_the_judge(tmp_path: Path):
    judge = DownJudge()
    for _ in range(2):  # benchmarks build guards directly: every call is judged
        guard = HarnessGuard(tmp_path / "h.db")
        guard.judge = judge
        _pre("claude", guard, "mcp__github__create_issue")
    assert judge.tries == 2 and not (tmp_path / "judge-paused").exists()


def test_a_pause_file_from_the_far_future_is_ignored(tmp_path: Path):
    (tmp_path / "judge-paused").write_text(json.dumps(1e12))  # a clock jump must not switch the judge off for good
    guard = HarnessGuard(tmp_path / "h.db", judge_pause=True)
    guard.judge = judge = DownJudge()
    _pre("claude", guard, "mcp__github__create_issue")
    assert judge.tries == 1
