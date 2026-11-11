"""A call whose tool name is missing, empty, not text, or named like an MCP tool without the MCP part is refused with a reason
that says what was wrong, not let through as an allow."""
from __future__ import annotations

from pathlib import Path

import pytest

from intentshield.harness import HarnessGuard, handle


def guard(tmp_path: Path, **kwargs) -> HarnessGuard:
    return HarnessGuard(tmp_path / "hooks.db", **kwargs)


def denial(reply: dict | None) -> str:
    assert reply is not None
    if "hookSpecificOutput" in reply:
        return reply["hookSpecificOutput"].get("permissionDecision", "")
    return reply.get("decision", "")


@pytest.mark.parametrize("harness", ["claude", "codex"])
@pytest.mark.parametrize("fields", [
    {"tool_input": {"command": "rm -rf /"}},
    {"tool_name": "", "tool_input": {"command": "rm -rf /"}},
    {"tool_name": None, "tool_input": {"command": "rm -rf /"}},
    {"tool_input": {"cmd": "rm -rf /"}},
    {"tool_name": ""},
    {"tool_input": {}},
])
def test_a_call_without_a_tool_name_is_refused_with_builtin_tools(tmp_path: Path, harness: str, fields: dict):
    event = {"hook_event_name": "PreToolUse", "session_id": "s", **fields}
    reply = handle(harness, event, guard(tmp_path, builtin_tools=True))
    assert denial(reply) == "deny"
    assert "tool_name" in reply["hookSpecificOutput"]["permissionDecisionReason"] or "tool name" in reply[
        "hookSpecificOutput"]["permissionDecisionReason"]


@pytest.mark.parametrize("name", [None, 5, ["Bash"], {"a": 1}])
def test_a_tool_name_that_is_not_text_is_refused_by_name_not_by_an_attribute_error(tmp_path: Path, name):
    event = {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": name, "tool_input": {"command": "ls"}}
    for builtin_tools in (False, True):
        reply = handle("claude", event, guard(tmp_path, builtin_tools=builtin_tools))
        assert denial(reply) == "deny"
        assert "not text" in reply["hookSpecificOutput"]["permissionDecisionReason"]


def test_a_call_without_a_tool_name_is_left_alone_when_the_built_in_tools_are_not_watched(tmp_path: Path):
    event = {"hook_event_name": "PreToolUse", "session_id": "s", "tool_input": {"command": "ls"}}
    assert handle("claude", event, guard(tmp_path)) is None


def test_a_named_built_in_call_is_still_read_as_before(tmp_path: Path):
    event = {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": "ls -la"}}
    assert handle("claude", event, guard(tmp_path, builtin_tools=True)) is None


@pytest.mark.parametrize("review", ["tainted", "always"])
def test_a_gemini_tool_named_like_an_mcp_tool_without_mcp_context_is_refused(tmp_path: Path, review: str):
    event = {"hook_event_name": "BeforeTool", "session_id": "s", "tool_name": "mcp_server_delete_x", "tool_input": {"id": 1}}
    reply = handle("gemini", event, guard(tmp_path, review=review))
    assert reply and reply["decision"] == "deny"
    assert "mcp_context" in reply["reason"]


def test_a_gemini_built_in_tool_and_a_call_with_mcp_context_are_read_as_before(tmp_path: Path):
    g = guard(tmp_path)
    assert handle("gemini", {"hook_event_name": "BeforeTool", "session_id": "s", "tool_name": "read_file",
                             "tool_input": {"file_path": "a.txt"}}, g) is None
    with_context = {"hook_event_name": "BeforeTool", "session_id": "s", "tool_name": "mcp_srv_get_thing",
                    "mcp_context": {"server_name": "srv", "tool_name": "get_thing"}, "tool_input": {"id": 1}}
    reply = handle("gemini", with_context, g)
    assert reply is None or reply.get("decision") != "deny" or "mcp_context" not in reply["reason"]


@pytest.mark.parametrize(("harness", "tool", "field", "key"), [("codex", "exec_command", "workdir", "cmd"),
                                                                ("codex", "shell", "workdir", "command"),
                                                                ("gemini", "run_shell_command", "dir_path", "command")])
def test_a_directory_the_shell_call_names_is_where_its_relative_paths_are_read_from(tmp_path: Path, harness, tool, field, key):
    name = "BeforeTool" if harness == "gemini" else "PreToolUse"
    base = {"hook_event_name": name, "session_id": "s", "cwd": str(tmp_path), "tool_name": tool}
    here = handle(harness, {**base, "tool_input": {key: "cat etc/shadow"}}, guard(tmp_path, builtin_tools=True))
    assert here is None, "from a project directory, etc/shadow is a project file"
    there = handle(harness, {**base, "tool_input": {key: "cat etc/shadow", field: "/"}}, guard(tmp_path, builtin_tools=True))
    assert there is not None and "shadow" in str(there)
    up = handle(harness, {**base, "tool_input": {key: "cat shadow", field: "/etc"}}, guard(tmp_path, builtin_tools=True))
    assert up is not None
