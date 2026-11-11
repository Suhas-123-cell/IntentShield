"""Every tool that runs a shell command is held to the same rules as Bash with ``--builtin-tools``: Claude Code's PowerShell
and Monitor, and Codex's ``apply_patch`` when it is run through the shell tool. Event shapes follow the harnesses' hook
documentation; nothing is run."""
from __future__ import annotations

from pathlib import Path

import pytest

from intentshield import install
from intentshield.harness import HarnessGuard, handle


def decision(tmp_path: Path, harness: str, tool: str, **tool_input) -> str:
    g = HarnessGuard(tmp_path / "hooks.db", builtin_tools=True)
    try:
        event = {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": tool, "tool_input": tool_input}
        reply = handle(harness, event, g)
    finally:
        g.close()
    return reply["hookSpecificOutput"].get("permissionDecision", "allow") if reply else "allow"


@pytest.mark.parametrize("tool", ["Bash", "PowerShell", "Monitor"])
def test_every_claude_shell_tool_is_judged_by_the_dangerous_command_rules(tmp_path, tool):
    assert decision(tmp_path, "claude", tool, command="rm -rf /") == "deny"
    assert decision(tmp_path, "claude", tool, command="git push --force origin main") == "deny"
    assert decision(tmp_path, "claude", tool, command="cat ~/.ssh/id_rsa") == "deny"
    assert decision(tmp_path, "claude", tool, command="git status") == "allow"


def test_a_shell_tool_call_that_carries_no_command_is_refused_not_passed(tmp_path):
    assert decision(tmp_path, "claude", "Monitor", description="watch") == "deny"


def test_the_install_matcher_sends_the_shell_tools_to_the_hook(tmp_path):
    entries = install.hook_entries("claude", "intentshield-hook claude --builtin-tools", builtin_tools=True)
    matchers = {g["matcher"] for g in entries["PreToolUse"]}
    assert any({"Bash", "PowerShell", "Monitor"} <= set(m.split("|")) for m in matchers), matchers
    results = {g["matcher"] for g in entries["PostToolUse"]}
    assert any("PowerShell" in m.split("|") for m in results), results
    without = install.hook_entries("claude", "intentshield-hook claude", builtin_tools=False)
    assert not any("PowerShell" in g["matcher"] for g in without["PreToolUse"])


PATCH = "*** Begin Patch\n*** Add File: /Users/x/.ssh/authorized_keys\n+ssh-ed25519 AAAAC3Nza example\n*** End Patch\n"
HARMLESS = "*** Begin Patch\n*** Add File: notes/todo.md\n+- write the docs\n*** End Patch\n"


def test_the_patch_tool_and_the_same_patch_through_the_shell_get_the_same_verdict(tmp_path):
    direct = decision(tmp_path, "codex", "apply_patch", input=PATCH)
    assert direct == "deny"
    shell_forms = [
        ("shell", {"command": ["apply_patch", PATCH]}),
        ("shell", {"command": ["bash", "-lc", f"apply_patch <<'PATCH'\n{PATCH}PATCH"]}),
        ("exec_command", {"cmd": f"apply_patch <<'PATCH'\n{PATCH}PATCH"}),
    ]
    for tool, tool_input in shell_forms:
        assert decision(tmp_path, "codex", tool, **tool_input) == direct, (tool, tool_input)
    assert decision(tmp_path, "claude", "Bash", command=f"apply_patch <<'PATCH'\n{PATCH}PATCH") == direct


def test_a_harmless_patch_through_the_shell_is_allowed(tmp_path):
    assert decision(tmp_path, "codex", "apply_patch", input=HARMLESS) == "allow"
    assert decision(tmp_path, "codex", "shell", command=["apply_patch", HARMLESS]) == "allow"
    assert decision(tmp_path, "claude", "Bash", command=f"apply_patch <<'PATCH'\n{HARMLESS}PATCH") == "allow"


def test_a_patch_header_in_a_command_that_is_not_apply_patch_is_not_read_as_a_patch(tmp_path):
    assert decision(tmp_path, "claude", "Bash", command="echo '*** Add File: .ssh/authorized_keys'") == "allow"
