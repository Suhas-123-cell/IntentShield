"""A call that goes past a limit of the reader (too long, too many commands or words, too deeply nested, too many substitutions,
wrappers, brace alternatives, loop words, links or a path that is too long) is asked about, so that a deny after the limit cannot
slip through. With ``--review never`` there is no prompt, and the call is refused. An ask of any other rule is still dropped
there.

Built-in tools only (``--builtin-tools``). Every command is a string; nothing is run."""
from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from intentshield.dangerous import assess_file, assess_shell, links
from intentshield.harness import HarnessGuard, handle

MODES = ("tainted", "always", "never")


def nested(command: str, levels: int) -> str:
    for _ in range(levels):
        command = "bash -c " + shlex.quote(command)
    return command


LONG_PATH = "/tmp/" + "d/" * 600 + "notes.txt"
LIMITS = {
    "characters": "echo " + "a" * 60_000 + "; ls",
    "commands": "true;" * 401 + "ls",
    "words": "a " * 20_001 + "; ls",
    "nesting of bash -c": nested("ls", 4),
    "nesting of command substitution": "echo $(echo $(echo $(echo $(ls))))",
    "nesting of here-strings": "bash <<< 'bash <<< \"bash <<< \\\"bash <<< x\\\"\"'",
    "substitutions": "echo " + "$(date) " * 201,
    "wrappers": "sudo " * 9 + "ls",
    "brace alternatives": "rm -rf /tmp/x/{" + ",".join(f"a{i}" for i in range(17)) + "}",
    "words of a loop": "for f in " + " ".join(f"a{i}" for i in range(40)) + "; do rm -rf $f; done",
    "a path in a command": f"cat {LONG_PATH}",
}


def shell_reply(tmp_path: Path, command: str, mode: str, harness: str = "claude") -> tuple[str, str]:
    guard = HarnessGuard(tmp_path / "hooks.db", builtin_tools=True, review=mode)
    if harness == "codex":
        event = {"hook_event_name": "PreToolUse", "session_id": "s", "cwd": "/tmp/proj", "tool_name": "shell",
                 "tool_input": {"command": ["bash", "-lc", command]}}
    else:
        event = {"hook_event_name": "PreToolUse", "session_id": "s", "cwd": "/tmp/proj", "tool_name": "Bash",
                 "tool_input": {"command": command}}
    return decided(handle(harness, event, guard))


def decided(reply: dict | None) -> tuple[str, str]:
    if not reply:
        return "allow", ""
    out = reply.get("hookSpecificOutput", reply)
    return out.get("permissionDecision", out.get("decision", "allow")), out.get("permissionDecisionReason", out.get("reason", ""))


def file_reply(tmp_path: Path, tool: str, path: str, mode: str) -> tuple[str, str]:
    guard = HarnessGuard(tmp_path / "hooks.db", builtin_tools=True, review=mode)
    fields = {"file_path": path, **({"content": "x"} if tool == "Write" else {})}
    event = {"hook_event_name": "PreToolUse", "session_id": "s", "cwd": "/tmp/proj", "tool_name": tool, "tool_input": fields}
    return decided(handle("claude", event, guard))


@pytest.mark.parametrize("limit", sorted(LIMITS))
def test_a_limit_asks_by_default_and_under_review_always(tmp_path, limit):
    assert assess_shell(LIMITS[limit]).limit
    for mode in ("tainted", "always"):
        assert shell_reply(tmp_path, LIMITS[limit], mode)[0] == "ask", mode


@pytest.mark.parametrize("limit", sorted(LIMITS))
def test_a_limit_is_refused_under_review_never_with_the_reason(tmp_path, limit):
    decision, reason = shell_reply(tmp_path, LIMITS[limit], "never")
    assert decision == "deny"
    assert "could not be read in full" in reason and "no prompt" in reason


@pytest.mark.parametrize("limit", ["commands", "characters", "nesting of bash -c", "wrappers"])
def test_a_deny_behind_a_limit_does_not_run_under_review_never(tmp_path, limit):
    command = LIMITS[limit].replace("ls", "rm -rf /", 1) if limit != "characters" else "echo " + "a" * 60_000 + "; rm -rf /"
    for mode in MODES:
        assert shell_reply(tmp_path, command, mode)[0] in ("ask", "deny"), mode
    assert shell_reply(tmp_path, command, "never")[0] == "deny"


@pytest.mark.parametrize("limit", sorted(LIMITS))
def test_a_limit_is_refused_in_the_codex_shape_too(tmp_path, limit):
    for mode in MODES:
        assert shell_reply(tmp_path, LIMITS[limit], mode, "codex")[0] == "deny", mode


def test_the_limit_on_links_is_refused_under_review_never(tmp_path, monkeypatch):
    monkeypatch.setattr(links, "_BUDGET", 5)
    command = "ls " + " ".join(f"/tmp/p{i}" for i in range(12))
    assert [shell_reply(tmp_path, command, mode)[0] for mode in MODES] == ["ask", "ask", "deny"]


@pytest.mark.parametrize("tool", ["Read", "Write"])
def test_a_path_that_is_too_long_is_refused_under_review_never(tmp_path, tool):
    assert [file_reply(tmp_path, tool, LONG_PATH, mode)[0] for mode in MODES] == ["ask", "ask", "deny"]
    assert "could not be read in full" in file_reply(tmp_path, tool, LONG_PATH, "never")[1]


def test_a_path_that_is_too_long_in_an_mcp_argument_is_refused_under_review_never(tmp_path):
    decisions = []
    for mode in MODES:
        guard = HarnessGuard(tmp_path / f"{mode}.db", builtin_tools=True, review=mode)
        event = {"hook_event_name": "PreToolUse", "session_id": "s", "cwd": "/tmp/proj", "tool_name": "mcp__fs__read_file",
                 "tool_input": {"path": LONG_PATH}}
        decisions.append(decided(handle("claude", event, guard))[0])
    assert decisions == ["ask", "ask", "deny"]


def test_assess_file_marks_the_limit(tmp_path):
    assert assess_file(LONG_PATH).limit
    assert assess_file(LONG_PATH, "x", write=True).limit
    assert not assess_file("/tmp/proj/notes.txt", "x", write=True)


# --- an ask of another rule is still dropped under review never --------------------------------------------------------------

@pytest.mark.parametrize("command", ["git clean -fd build/", "git checkout -f", "scp a.txt host.example.org:/tmp/"])
def test_an_ordinary_ask_is_asked_by_default_and_dropped_under_review_never(tmp_path, command):
    hit = assess_shell(command)
    assert hit is not None and hit.decision == "ask" and not hit.limit
    assert shell_reply(tmp_path, command, "tainted")[0] == "ask"
    assert shell_reply(tmp_path, command, "never")[0] == "allow"


def test_an_ordinary_ask_in_a_path_is_still_dropped_under_review_never(tmp_path):
    assert file_reply(tmp_path, "Write", "/home/dev/.zshrc", "tainted")[0] == "ask"
    assert file_reply(tmp_path, "Write", "/home/dev/.zshrc", "never")[0] == "allow"


@pytest.mark.parametrize("command", [
    "git clean -fd build/; " + "true;" * 401,                       # the limit is met first
    "git clean -fd build/; echo " + "$(date) " * 201,               # the limit is met after the other ask
    "echo " + "$(date) " * 201 + "; git clean -fd build/",
])
def test_a_limit_beside_another_ask_is_not_lost(tmp_path, command):
    hit = assess_shell(command)
    assert hit is not None and hit.decision == "ask" and hit.limit
    assert [shell_reply(tmp_path, command, mode)[0] for mode in MODES] == ["ask", "ask", "deny"]


def test_a_command_just_inside_each_limit_is_not_a_limit():
    for command in ("true;" * 399 + "ls", "echo $(echo $(date))", nested("ls", 3), "sudo " * 8 + "ls",
                    "rm -rf /tmp/x/{" + ",".join(f"a{i}" for i in range(16)) + "}"):
        hit = assess_shell(command)
        assert hit is None or not hit.limit, command[:60]
