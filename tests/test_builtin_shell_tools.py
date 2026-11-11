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


# --- what a harness sends that the text rules must still read ------------------------------------------------------------

def test_a_nul_byte_in_a_shell_command_or_a_path_does_not_hide_it(tmp_path):
    assert decision(tmp_path, "claude", "Bash", command="rm -rf /\x00") == "deny"
    assert decision(tmp_path, "claude", "Bash", command="r\x00m -rf /") == "deny"
    assert decision(tmp_path, "claude", "Bash", command="git push --for\x00ce origin main") == "deny"
    assert decision(tmp_path, "claude", "Read", file_path="/Users/x/.ssh/id_r\x00sa") == "deny"


def test_a_padded_path_is_not_a_way_around_the_file_tools(tmp_path):
    padded = "/Users/x/.ssh/" + "./" * 600 + "id_rsa"
    assert decision(tmp_path, "claude", "Read", file_path=padded) == "deny"
    assert decision(tmp_path, "claude", "Read", file_path="/Users/x/" + "d/" * 600 + "notes.txt") == "ask"
    settings = "/Users/x/.claude/" + "/" * 1200 + "settings.json"
    assert decision(tmp_path, "claude", "Write", file_path=settings, content="{}") == "ask"
    assert decision(tmp_path, "claude", "Bash", command="cat ~/.aws/" + "./" * 600 + "credentials") == "deny"


def test_a_patch_that_touches_more_than_eight_special_files_is_still_read_whole(tmp_path):
    from intentshield import harness

    def verdict(patch: str) -> str:
        g = HarnessGuard(tmp_path / "hooks.db", builtin_tools=True)
        try:
            return harness._patch_verdict(g, "s", "builtin:apply_patch", f"*** Begin Patch\n{patch}*** End Patch\n").decision
        finally:
            g.close()

    special = "".join(f"*** Add File: /Users/x/.github/workflows/w{i}.yml\n+x\n" for i in range(9))
    keys = "*** Add File: /Users/x/.ssh/authorized_keys\n+x\n"
    assert verdict("".join(f"*** Add File: notes/f{i}.md\n+x\n" for i in range(12))) == "allow"
    assert verdict(special) == "ask"
    assert verdict(special + keys) == "deny"  # the tenth special file is past the eight the guard reads one by one
