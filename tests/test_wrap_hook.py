"""``intentshield wrap-hook``: any third-party hook command under the fail-closed launcher, deadline and verdict translation.

The guards here are small Python scripts that print fixed replies (fixture bytes shaped like the captured guards in
``results/hook-fidelity/guards``); nothing here runs a real third-party guard.
"""
from __future__ import annotations

import io
import json
import subprocess
import sys
import time

import pytest

from intentshield import translation, wrap_hook

EVENT = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "touch x"}}
GEMINI_EVENT = {"hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "tool_input": {"command": "touch x"}}


def guard(tmp_path, stdout: str = "", stderr: str = "", code: int = 0, sleep: float = 0.0, name: str = "g.py") -> list[str]:
    path = tmp_path / name
    path.write_text(
        "import sys, time\n"
        "sys.stdin.read()\n"
        f"time.sleep({sleep!r})\n"
        f"sys.stdout.write({stdout!r}); sys.stderr.write({stderr!r}); sys.exit({code})\n")
    return [sys.executable, str(path)]


def run(harness: str, argv: list[str], event: dict | None = None, **kw) -> tuple[int, dict | None, str, str]:
    out, err = io.StringIO(), io.StringIO()
    raw = json.dumps(event if event is not None else (GEMINI_EVENT if harness == "gemini" else EVENT))
    kw.setdefault("mode", "headless")
    kw.setdefault("version", {"claude": "2.1.316", "codex": "0.166.0", "gemini": "0.66.0"}.get(harness, "1.0.0"))
    code = wrap_hook.wrap(harness, argv, raw, stdout=out, stderr=err, **kw)
    text = out.getvalue().strip()
    return code, (json.loads(text) if text else None), text, err.getvalue()


def verdict(reply: dict | None) -> tuple[str, str]:
    """(decision, reason) of a harness-native reply."""
    assert reply is not None
    hso = reply.get("hookSpecificOutput")
    if hso:
        return hso["permissionDecision"], hso["permissionDecisionReason"]
    if "permission" in reply:
        return reply["permission"], reply["user_message"]
    return reply["decision"], reply["reason"]


CLAUDE_DENY = json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                 "permissionDecisionReason": "no rm -rf"}})
CLAUDE_ASK = json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                                "permissionDecisionReason": "railway: confirm"}})
GEMINI_DENY = json.dumps({"decision": "deny", "reason": "blocked by guard"})


@pytest.mark.parametrize("harness", ["claude", "codex", "gemini", "cursor"])
def test_deny_is_sent_in_the_harness_native_shape(tmp_path, harness):
    stdout = GEMINI_DENY if harness == "gemini" else CLAUDE_DENY
    code, reply, _text, _err = run(harness, guard(tmp_path, stdout), event=None)
    assert code == 0
    decision, reason = verdict(reply)
    assert decision == "deny" and ("no rm -rf" in reason or "blocked by guard" in reason)
    assert ("hookSpecificOutput" in reply) == (harness in ("claude", "codex"))
    assert ("permission" in reply) == (harness == "cursor")


def test_exit_two_with_stderr_is_a_deny_with_that_reason(tmp_path):
    _c, reply, _t, _e = run("claude", guard(tmp_path, "", "BLOCKED: destructive git operation\n", 2))
    assert verdict(reply) == ("deny", "BLOCKED: destructive git operation")


def test_exit_two_with_empty_stderr_is_still_a_deny_with_a_reason(tmp_path):
    """Codex 0.166.0 ran a call whose hook exited 2 with nothing on stderr; the shim never forwards a bare exit 2."""
    code, reply, _t, _e = run("codex", guard(tmp_path, "", "", 2))
    assert code == 0
    decision, reason = verdict(reply)
    assert decision == "deny" and reason.strip() and "no reason" in reason


def test_exit_two_with_empty_stderr_takes_the_reason_from_stdout_json(tmp_path):
    body = json.dumps({"decision": "block", "reason": "--no-verify is not allowed"})
    _c, reply, _t, _e = run("claude", guard(tmp_path, body, "", 2))
    assert verdict(reply) == ("deny", "--no-verify is not allowed")


@pytest.mark.parametrize("rc", [1, 3, 126, 127])
def test_a_failing_guard_is_refused(tmp_path, rc):
    _c, reply, _t, _e = run("claude", guard(tmp_path, "", "Traceback (most recent call last)\n", rc))
    decision, reason = verdict(reply)
    assert decision == "deny" and f"exited with code {rc}" in reason and "Traceback" in reason


def test_a_guard_that_cannot_be_started_is_refused(tmp_path):
    _c, reply, _t, _e = run("claude", ["/nonexistent/guard-binary", "--flag"])
    decision, reason = verdict(reply)
    assert decision == "deny" and "could not be started" in reason


def test_a_shell_string_with_a_dead_interpreter_is_refused(tmp_path):
    script = tmp_path / "dead"
    script.write_text("#!/nonexistent/interpreter\nprint('x')\n")
    script.chmod(0o755)
    _c, reply, _t, _e = run("claude", [str(script)])   # one argument: run through a shell, as a harness runs a hook string
    decision, reason = verdict(reply)
    assert decision == "deny" and ("exited with code" in reason or "could not be started" in reason)


def test_a_guard_still_running_at_the_deadline_is_refused_and_killed(tmp_path):
    t0 = time.monotonic()
    _c, reply, _t, _e = run("claude", guard(tmp_path, GEMINI_DENY, sleep=20), deadline=1.0)
    assert time.monotonic() - t0 < 6
    decision, reason = verdict(reply)
    assert decision == "deny" and "did not answer within 1 s" in reason and "Do not retry" in reason


def test_the_deadline_is_kept_under_the_harness_timeout():
    assert wrap_hook.effective_deadline(30, 3) == 2.0       # the study's 3 s hook timeout
    assert wrap_hook.effective_deadline(30, 15) == 14.0
    assert wrap_hook.effective_deadline(30, 1) == 0.5
    assert wrap_hook.effective_deadline(30, 0) == 30
    assert wrap_hook.effective_deadline(5, 60) == 5


def test_the_hook_timeout_bounds_a_slow_guard(tmp_path):
    t0 = time.monotonic()
    _c, reply, _t, _e = run("claude", guard(tmp_path, CLAUDE_DENY, sleep=20), deadline=30, hook_timeout=3)
    assert time.monotonic() - t0 < 5
    assert verdict(reply)[0] == "deny"


@pytest.mark.parametrize("stdout", ["not json at all", "[1, 2]", '{"decision": ', '"deny"',
                                    json.dumps({"hookSpecificOutput": {"permissionDecision": "defer"}}),
                                    json.dumps({"decision": 7}), json.dumps({"decision": None})])
def test_malformed_or_unknown_replies_are_refused(tmp_path, stdout):
    _c, reply, _t, _e = run("claude", guard(tmp_path, stdout))
    decision, reason = verdict(reply)
    assert decision == "deny" and ("malformed" in reason or "not JSON" in reason or "not a JSON object" in reason)


def test_oversized_output_is_refused(tmp_path):
    _c, reply, _t, _e = run("claude", guard(tmp_path, "x" * (wrap_hook.MAX_OUTPUT + 10)))
    assert verdict(reply)[0] == "deny"


def test_empty_reply_is_refused_by_default_and_allowed_on_request(tmp_path):
    _c, reply, text, _e = run("claude", guard(tmp_path, ""))
    assert verdict(reply)[0] == "deny" and "printed nothing" in verdict(reply)[1]
    code, reply, text, _e = run("claude", guard(tmp_path, ""), on_empty="allow")
    assert code == 0 and reply is None and text == ""


ALLOWS = ["{}", '{"decision": "allow"}', json.dumps({"hookSpecificOutput": {"permissionDecision": "allow"}}),
          json.dumps({"additionalContext": "note"})]


@pytest.mark.parametrize("stdout", ALLOWS)
def test_an_allow_or_no_opinion_reply_is_passed_through_unchanged(tmp_path, stdout):
    code, _reply, text, _e = run("claude", guard(tmp_path, stdout))
    assert code == 0 and text == stdout.strip()


def test_continue_false_is_a_deny(tmp_path):
    _c, reply, _t, _e = run("gemini", guard(tmp_path, json.dumps({"continue": False, "stopReason": "stop it"})))
    assert verdict(reply) == ("deny", "stop it")


def test_an_ask_is_denied_where_no_one_can_answer(tmp_path):
    """Headless: an ask is a deny that says what the guard wanted (Claude Code 2.1.84 and Codex would run the call)."""
    for harness, version in (("claude", "2.1.84"), ("claude", "2.1.316"), ("codex", "0.166.0")):
        _c, reply, _t, _e = run(harness, guard(tmp_path, CLAUDE_ASK), version=version)
        decision, reason = verdict(reply)
        assert decision == "deny" and "railway: confirm" in reason and "confirm this call" in reason and "Do not retry" in reason


def test_an_ask_is_kept_where_a_person_can_answer_and_the_build_enforces_it(tmp_path):
    _c, reply, _t, _e = run("claude", guard(tmp_path, CLAUDE_ASK), mode="interactive", version="2.1.316")
    assert verdict(reply) == ("ask", "railway: confirm")
    _c, reply, _t, _e = run("claude", guard(tmp_path, CLAUDE_ASK), mode="interactive", version="2.1.84")
    assert verdict(reply)[0] == "deny"   # 2.1.84 is measured to run an asked, pre-approved call
    _c, reply, _t, _e = run("codex", guard(tmp_path, CLAUDE_ASK), mode="interactive", version="0.166.0")
    assert verdict(reply)[0] == "deny"   # Codex has no ask
    _c, reply, _t, _e = run("claude", guard(tmp_path, CLAUDE_ASK), mode="interactive", version=None)
    assert verdict(reply)[0] == "deny"   # unknown build: the worse neighbour


def test_a_gemini_ask_needs_the_opt_in_and_a_shell_call(tmp_path):
    ask = json.dumps({"decision": "ask", "reason": "confirm?"})
    _c, reply, _t, _e = run("gemini", guard(tmp_path, ask), mode="interactive", version="0.66.0")
    assert verdict(reply)[0] == "deny"
    _c, reply, _t, _e = run("gemini", guard(tmp_path, ask), mode="interactive", version="0.66.0", gemini_ask=True)
    assert verdict(reply) == ("ask", "confirm?")
    _c, reply, _t, _e = run("gemini", guard(tmp_path, ask), mode="headless", version="0.66.0", gemini_ask=True)
    assert verdict(reply)[0] == "deny"


def test_the_mode_override_and_the_recorded_version_are_used(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("INTENTSHIELD_HARNESS_MODE", "interactive")
    exe = tmp_path / "claude"
    exe.write_text("")
    translation.record_version("claude", "2.1.316", str(exe), home)
    out, err = io.StringIO(), io.StringIO()
    wrap_hook.wrap("claude", guard(tmp_path, CLAUDE_ASK), json.dumps(EVENT), version=None, home=home, stdout=out, stderr=err)
    assert verdict(json.loads(out.getvalue()))[0] == "ask"


def test_a_malformed_event_is_refused_with_exit_two(tmp_path):
    out, err = io.StringIO(), io.StringIO()
    assert wrap_hook.wrap("claude", guard(tmp_path, ""), "not json", stdout=out, stderr=err) == 2
    assert "refused" in err.getvalue() and out.getvalue() == ""


def test_events_that_do_not_check_a_call_are_passed_through(tmp_path):
    out, err = io.StringIO(), io.StringIO()
    event = {"hook_event_name": "PostToolUse", "tool_name": "Bash"}
    code = wrap_hook.wrap("claude", guard(tmp_path, "{}", "note", 0), json.dumps(event), stdout=out, stderr=err)
    assert code == 0 and out.getvalue() == "{}" and err.getvalue() == "note"
    code = wrap_hook.wrap("claude", guard(tmp_path, "", "", 1), json.dumps(event), stdout=out, stderr=err)
    assert code == 1   # not a call check: the guard's own exit code, no translation


def test_the_guard_gets_the_harnesss_stdin(tmp_path):
    seen = tmp_path / "seen.json"
    path = tmp_path / "echo.py"
    path.write_text(f"import sys\nopen({str(seen)!r}, 'w').write(sys.stdin.read())\nprint('{{}}')\n")
    run("claude", [sys.executable, str(path)])
    assert json.loads(seen.read_text()) == EVENT


def test_wrapped_command_has_the_shim_the_guard_and_the_launcher():
    command = wrap_hook.wrapped_command("claude", "pnpm dlx block-no-verify", version="2.1.316", deadline=2.0, hook_timeout=3.0,
                                        on_empty="allow")
    assert command.startswith("intentshield wrap-hook --harness claude --version 2.1.316 --deadline 2 --hook-timeout 3 "
                              "--on-empty allow -- pnpm dlx block-no-verify")
    assert command.endswith(translation.LAUNCHER)


def test_the_cli_runs_end_to_end_and_exits_zero_with_a_reply(tmp_path):
    cmd = [sys.executable, "-m", "intentshield", "wrap-hook", "--harness", "claude", "--version", "2.1.316", "--mode", "headless",
           "--deadline", "5", "--", *guard(tmp_path, CLAUDE_ASK)]
    done = subprocess.run(cmd, input=json.dumps(EVENT), capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    assert verdict(json.loads(done.stdout))[0] == "deny"
    done = subprocess.run([sys.executable, "-m", "intentshield", "wrap-hook", "--harness", "claude"], input="{}",
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 2 and "no guard command" in done.stderr
