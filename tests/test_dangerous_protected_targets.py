"""One verdict for one target, whichever way it is reached.

The guard's rules are written per command, so a target that one command protects can be left open to a sibling. This file holds
the target and asks every way of removing, moving or writing it: ``rm``, ``mv``, ``find -delete``, a shell redirect, the Write, Edit
and MultiEdit tools, and an MCP server's delete and move tools. The table at the top gives each kind of target one verdict and
writes down every operation that is meant to differ, with the reason. Below it are the cases the table was written from: the
directories that hold a harness's hook settings, a partial-name glob over a protected path, and a block device given to a file
tool. Every command is a string; nothing is run."""
# ruff: noqa: E501
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest
from timelimits import limit

from intentshield.dangerous import assess_file, assess_shell, guard_dir
from intentshield.harness import HarnessGuard, handle

CWD = "/work/proj"
OPERATIONS = ("rm", "mv", "find", "redirect", "write", "mcp_delete", "mcp_move")


@pytest.fixture(autouse=True)
def _own_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home that is nobody's: the rules read ``HOME``, and nothing here may depend on the machine's own."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("USERPROFILE", raising=False)
    return home


def decision(reply: dict[str, Any] | None) -> str:
    if not reply:
        return "allow"
    return reply.get("hookSpecificOutput", {}).get("permissionDecision", "allow")


def shell_decision(command: str, cwd: str = CWD) -> str:
    hit = assess_shell(command, cwd=cwd)
    return hit.decision if hit else "allow"


def tool_decision(guard: HarnessGuard, tool: str, arguments: dict[str, Any]) -> str:
    event = {"hook_event_name": "PreToolUse", "session_id": "s", "cwd": CWD, "tool_name": tool, "tool_input": arguments}
    return decision(handle("claude", event, guard))


def verdicts(guard: HarnessGuard, target: str) -> dict[str, str]:
    """The verdict of every operation on the target. The three file tools are one operation: they must agree among themselves."""
    writes = {tool: tool_decision(guard, tool, args) for tool, args in (
        ("Write", {"file_path": target, "content": "x"}), ("Edit", {"file_path": target, "old_string": "a", "new_string": "b"}),
        ("MultiEdit", {"file_path": target, "edits": [{"old_string": "a", "new_string": "b"}]}))}
    assert len(set(writes.values())) == 1, f"{target}: the file tools disagree: {writes}"
    return {
        "rm": shell_decision(f"rm -rf {target}"), "mv": shell_decision(f"mv {target} /work/elsewhere"),
        "find": shell_decision(f"find {target} -delete"), "redirect": shell_decision(f"echo x > {target}"),
        "write": next(iter(writes.values())),
        "mcp_delete": tool_decision(guard, "mcp__fs__delete_directory", {"path": target}),
        "mcp_move": tool_decision(guard, "mcp__fs__move_file", {"source": target, "destination": "/work/elsewhere"}),
    }


DIRECTORIES = ["/", "~", "~/Documents", "~/Desktop", "~/Library", "~/.config", "~/.kube", "/etc", "/usr", "/usr/bin", "/System",
               "/var", "/bin", "/Users", "/home", "/root", "/dev"]
CREDENTIAL_DIRECTORIES = ["~/.ssh", "~/.aws", "~/.gnupg"]
KEYS = ["~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.aws/credentials", "~/.netrc"]
ACCESS_FILES = ["~/.ssh/authorized_keys", "/etc/shadow", "/etc/sudoers", "/etc/passwd"]
SETTINGS_DIRECTORIES = ["~/.claude", "~/.codex", "~/.cursor", "~/.gemini", ".claude", ".cursor", ".gemini", ".codex",
                        "~/.claude/hooks", ".claude/hooks"]
SETTINGS_FILES = ["~/.claude/settings.json", ".claude/settings.json", "~/.codex/config.toml", ".cursor/hooks.json",
                  "~/.gemini/settings.json"]
BLOCK_DEVICES = ["/dev/sda", "/dev/disk2", "/dev/rdisk0", "/dev/nvme0n1p1", "/dev/mapper/root", "/dev/vda1", "/dev/mmcblk0"]

# kind of target: (targets, the verdict of every operation, {operation: (verdict, why it differs)})
TABLE = {
    "a root, home or system directory": (DIRECTORIES, "deny", {
        "redirect": ("allow", "a directory is not written by a redirect: the shell refuses it, and there is nothing to refuse"),
        "write": ("allow", "a directory is not written by the file tools: they refuse it"),
    }),
    "a credential directory": (CREDENTIAL_DIRECTORIES, "deny", {
        "redirect": ("ask", "a write over a credential path is an ask, never a deny, as the user may be installing the file"),
        "write": ("ask", "the same, by the file tools"),
    }),
    "a key or a cloud credential file": (KEYS, "ask", {
        "mcp_move": ("deny", "the source of a move is read as well, and a read of a key is a deny"),
    }),
    "an access file or a system secret": (ACCESS_FILES, "deny", {
        "rm": ("ask", "deleting a file that holds access is an ask, as for a key: it is lost, not read or replaced"),
        "mv": ("ask", "the same, by mv: the file is moved out of the place that is read"),
    }),
    "the directory of a harness's hook settings": (SETTINGS_DIRECTORIES, "ask", {
        "redirect": ("allow", "a directory is not written by a redirect"),
        "write": ("allow", "a directory is not written by the file tools"),
    }),
    "a harness's hook settings file": (SETTINGS_FILES, "ask", {}),
    "a block device": (BLOCK_DEVICES, "deny", {
        "rm": ("allow", "rm removes the device node, not what the disk holds"),
        "mv": ("allow", "mv moves the device node, not what the disk holds"),
    }),
}
CASES = [(kind, target) for kind, (targets, _, _) in TABLE.items() for target in targets]


@pytest.mark.parametrize("kind, target", CASES, ids=[f"{target}" for _, target in CASES])
def test_a_protected_target_has_one_verdict_whichever_way_it_is_reached(tmp_path: Path, kind: str, target: str):
    _, expected, exceptions = TABLE[kind]
    got = verdicts(HarnessGuard(tmp_path / "hooks.db", builtin_tools=True), target)
    want = {op: exceptions[op][0] if op in exceptions else expected for op in OPERATIONS}
    assert got == want, f"{target} ({kind})"


@pytest.mark.parametrize("target", [t for t in DIRECTORIES + CREDENTIAL_DIRECTORIES + KEYS if t.startswith("~")])
def test_the_home_spelled_out_gets_the_verdict_of_the_tilde(tmp_path: Path, _own_home: Path, target: str):
    guard = HarnessGuard(tmp_path / "hooks.db", builtin_tools=True)
    assert verdicts(guard, str(_own_home) + target[1:]) == verdicts(guard, target)
    assert verdicts(guard, "$HOME" + target[1:]) == verdicts(guard, target)


def test_every_exception_in_the_table_names_an_operation_and_a_reason():
    for kind, (_, expected, exceptions) in TABLE.items():
        for op, (verdict, why) in exceptions.items():
            assert op in OPERATIONS and verdict in ("allow", "ask", "deny") and verdict != expected and len(why) > 20, kind


# --- the directory that holds a harness's hook settings ---------------------------------------------------------------------

TAKES_THE_SETTINGS = [
    "rm -rf ~/.claude", "rm -rf .claude", "rm -r .claude/", "rm -rf ~/.claude/", "rm -rf ./.claude", "rm -fr ~/.codex",
    "rm -rf .cursor", "rm -rf ~/.gemini", "rm -rf .gemini/", "rm --recursive --force ~/.claude", "rm -rf ~/.claude/hooks",
    "rm -rf .claude/hooks/", "rm -rf ~/.claude/*", "rm ~/.claude/*", "rm .claude/*", "rm -rf ~/.cursor/*", "rm ~/.claude/set*",
    "rm -f .claude/settings.*", "rm -rf ~/.cl*", "rmdir ~/.claude", "rmdir .cursor", "rm -d .claude",
    "mv .claude .claude.off", "mv ~/.claude ~/.claude.off", "mv ~/.codex /tmp/codex", "mv .cursor .cursor.off",
    "mv ~/.claude/ /tmp/x/", "mv ~/.gemini /tmp", "mv ~/.claude/* /tmp", "mv .claude/hooks /tmp/hooks",
    "find ~/.claude -delete", "find .claude -type f -delete", "find ~/.codex -exec rm -rf {} +", "find .cursor -mtime +1 -delete",
    "find ~/.claude -name '*.json' -delete", "find ~/.claude -name settings.json -delete", "find .gemini -delete",
    "find ~/.claude -name 'set*' -delete", "find ~/.claude ! -name '*.jsonl' -delete",
    "chmod -R 000 ~/.claude", "chmod -R go-w .cursor", "sudo chown -R root ~/.codex",
    "sudo rm -rf ~/.claude", "cd ~ && rm -rf .claude", "cd ~/.claude && rm -rf *", "bash -c 'rm -rf ~/.claude'",
    "rm -rf /etc/claude-code", "rm -rf '/Library/Application Support/ClaudeCode'",
]

WORKS_IN_THE_SETTINGS_DIRECTORY = [
    "rm -rf .claude/worktrees/x", "rm -rf .claude/worktrees/*", "rm -rf ~/.claude/projects", "rm -rf ~/.claude/projects/-work-proj",
    "rm -f .claude/commands/old.md", "rm ~/.claude/history.jsonl", "rm ~/.claude/*.log", "rm .claude/commands/*",
    "rm -rf .cursor/rules/old", "rm .gemini/tmp/x", "rm -rf ~/.codex/sessions", "rm -rf ~/.claude/plugins/cache",
    "mv .claude/commands/a.md .claude/commands/b.md", "mv notes.md .claude/", "mv x ~/.claude/commands/",
    "find ~/.claude/projects -mtime +30 -delete", "find .claude/worktrees -delete", "find .claude/worktrees -name 'x*' -delete",
    "find ~/.claude -name '*.jsonl' -mtime +30 -delete", "find ~/.claude -name '*.log' -delete",
    "find .claude -name '*.md' -type f", "find ~/.claude -mtime +30", "find ~/.claude -name '*.json' -print",
    "chmod -R u+w ~/.claude/projects", "chmod 700 ~/.claude", "chown $USER ~/.codex", "chmod +x .claude/commands/run.sh",
    "ls ~/.claude", "ls -la .claude/", "cat .claude/commands/review.md", "mkdir -p .claude/commands", "touch .claude/x",
    "cp -r ~/.claude/commands /tmp/", "cp template/.claude/commands/x.md .claude/commands/", "rm -rf projects/claude-code",
    "rm -rf ~/code/claude-code", "rm ~/.claude", "rm -rf .claude-old", "rm -rf .claude.off", "rm -rf ~/.claudette",
    "rm -rf node_modules/.cache/*", "rm -rf build*", "rm *.pyc", "rm -rf .c*ache",
]


@pytest.mark.parametrize("command", TAKES_THE_SETTINGS)
def test_taking_the_directory_of_the_hook_settings_asks_as_taking_the_settings_file_does(command: str):
    hit = assess_shell(command, cwd=CWD)
    assert hit is not None and hit.decision in ("ask", "deny"), command
    if "sudo" not in command and "chown" not in command:
        assert hit.decision == "ask", command


@pytest.mark.parametrize("command", WORKS_IN_THE_SETTINGS_DIRECTORY)
def test_working_in_the_directory_of_the_hook_settings_is_not_asked_about(command: str):
    assert shell_decision(command) == "allow", command


def test_the_settings_file_and_its_directory_get_the_same_verdict_by_every_command():
    for settings, directory in (("~/.claude/settings.json", "~/.claude"), (".cursor/hooks.json", ".cursor"),
                                ("~/.codex/config.toml", "~/.codex"), ("~/.gemini/settings.json", "~/.gemini")):
        for template in ("rm -rf {}", "mv {} /tmp/x", "find {} -delete"):
            assert shell_decision(template.format(settings)) == shell_decision(template.format(directory)) == "ask", template


@pytest.mark.parametrize("path, whole, asks", [
    ("~/.claude", True, True), ("~/.claude", False, False), ("~/.claude/*", False, True), (".codex/*", False, True),
    ("~/.claude/settings.json", True, False), ("~/.claude/projects", True, False), ("~/proj/.claude/worktrees/x", True, False),
    ("~/.claude/s*", False, True), ("~/.claude/p*", False, False), ("", True, False), ("/", True, False)])
def test_guard_dir_reads_the_directory_and_what_a_glob_over_it_reaches(path: str, whole: bool, asks: bool):
    assert (guard_dir(path, whole) is not None) is asks


@pytest.mark.parametrize("tool, arguments, expected", [
    ("mcp__fs__delete_directory", {"path": "~/.claude"}, "ask"), ("mcp__fs__remove_directory", {"path": ".cursor"}, "ask"),
    ("mcp__fs__move_file", {"source": "~/.claude", "destination": "/tmp/x"}, "ask"),
    ("mcp__fs__rename_file", {"path": "~/.codex", "new_path": "/tmp/x"}, "ask"),
    ("mcp__fs__delete_file", {"path": "~/.claude/settings.json"}, "ask"),
    ("mcp__fs__delete_directory", {"path": ".claude/worktrees/x"}, "allow"),
    ("mcp__fs__delete_file", {"path": "build/out.js"}, "allow"),
    ("mcp__fs__create_directory", {"path": "~/.claude"}, "allow"), ("mcp__fs__create_directory", {"path": ".claude/commands"}, "allow"),
    ("mcp__fs__move_file", {"source": "a.txt", "destination": "~/.claude"}, "allow"),
    ("mcp__fs__move_file", {"source": "a.txt", "destination": "~/Documents"}, "allow"),
    ("mcp__fs__write_file", {"path": ".claude/commands/review.md", "content": "Review the diff."}, "allow"),
    ("mcp__fs__list_directory", {"path": "~/.claude"}, "allow"),
    ("mcp__fs__delete_directory", {"path": "~"}, "deny"), ("mcp__fs__delete_directory", {"path": "/"}, "deny"),
    ("mcp__fs__move_file", {"source": "~/Documents", "destination": "/tmp/x"}, "deny"),
    ("mcp__fs__delete_directory", {"path": "~/Doc*"}, "deny"),
])
def test_an_mcp_servers_delete_and_move_tools_read_their_path_like_rm_and_mv(tmp_path: Path, tool: str, arguments: dict[str, Any],
                                                                            expected: str):
    assert tool_decision(HarnessGuard(tmp_path / "hooks.db", builtin_tools=True), tool, arguments) == expected


def test_an_mcp_delete_tool_is_not_read_without_builtin_tools(tmp_path: Path):
    assert tool_decision(HarnessGuard(tmp_path / "hooks.db"), "mcp__fs__delete_directory", {"path": "~/.claude"}) == "allow"


# --- a partial-name glob over a protected path ------------------------------------------------------------------------------

GLOBS_OF_PROTECTED_PATHS = [
    "rm -rf /us*", "rm -rf /[u]sr", "rm -rf /e*", "rm -rf /e?c", "rm -rf /us?", "rm -rf /us?/lo*", "rm -rf /usr/loc*",
    "rm -rf /usr/local/b*", "rm -rf /Sys*", "rm -rf /var/l*", "rm -rf ~/D*", "rm -rf ~/Doc*", "rm -rf ~/[D]ocuments",
    "rm -rf ~/.s*", "rm -rf ~/.aw?", "rm -rf ~/.c*", "rm -rf ~/Lib*", "rm -rf $HOME/Doc*", "rm -rf ${HOME}/Doc*",
    "rm -rf \"~/Doc*\"", "rm -fr /Us*", "rm -rf -- /et*", "rm -r -f ~/Desk*", "sudo rm -rf /us*",
    "mv /et* /tmp", "mv ~/Doc* /tmp/x", "mv /usr/loc* /tmp/x", "find /us* -delete", "find ~/Doc* -name x -delete",
    "find /et? -exec rm -rf {} +", "rm -rf /Users/su*", "rm -rf /hom*", "rm -rf /ro?t",
]

GLOBS_INSIDE_A_PROJECT = [
    "rm -rf build*", "rm *.pyc", "rm -rf node_modules/.cache/*", "rm -rf dist/*", "rm -rf ./build*", "rm -rf src/*/__pycache__",
    "rm -rf ../shop-*", "rm -f *.log", "rm -rf .pytest_cache* .mypy_cache*", "rm -rf /tmp/x*", "rm -rf /tmp/pytest-of-*",
    "rm -rf /var/tmp/build-*", "rm -rf /var/log/*.log", "rm -rf /usr/local/lib/python*", "rm -rf /usr/lib/python3*",
    "rm -rf ~/proj*", "rm -rf ~/.cache*", "rm -rf ~/.npm/_cacache*", "rm -rf ~/Dev*/old", "rm -rf ~/code/*/node_modules",
    "rm -rf ~/Library/Caches/com.foo.*", "rm -rf ~/Library/Developer/Xcode/DerivedData/*", "rm -rf ~/Documents/proj/build*",
    "rm -rf ~/Downloads/old*", "rm -rf ~/.config/Code/Cache*", "rm -rf ~/.local/share/Trash/*", "rm -rf /opt/homebrew/Cellar/foo*",
    "mv build* /tmp/old", "mv *.pyc /tmp", "mv ~/Downloads/*.pdf docs/", "find . -name '*.pyc' -delete",
    "find ~/code -name 'node_modules' -prune -exec rm -rf {} +", "rm -rf ~/D", "ls ~/Doc*", "cat /etc/ho*", "cp ~/Doc*.txt /tmp",
]


@pytest.mark.parametrize("command", GLOBS_OF_PROTECTED_PATHS)
def test_a_glob_that_names_a_protected_path_among_its_matches_gets_that_paths_verdict(command: str):
    hit = assess_shell(command, cwd=CWD)
    assert hit is not None and hit.decision in ("ask", "deny"), command
    if command.startswith(("rm", "sudo rm", "mv")):
        assert hit.decision == "deny", command


@pytest.mark.parametrize("command", GLOBS_INSIDE_A_PROJECT)
def test_a_glob_that_cannot_name_a_protected_path_is_not_asked_about(command: str):
    hit = assess_shell(command, cwd=CWD)
    assert hit is None or hit.decision == "allow", command


def test_a_partial_glob_gets_the_verdict_of_the_path_it_names_with_the_home_spelled_out(_own_home: Path):
    for spelled in (f"{_own_home}/Doc*", "~/Doc*", "$HOME/Doc*"):
        assert shell_decision(f"rm -rf {spelled}") == shell_decision("rm -rf ~/Documents") == "deny"


def test_a_relative_glob_is_the_projects_unless_the_working_directory_is_the_home(_own_home: Path):
    assert shell_decision("rm -rf Doc*", cwd=str(_own_home / "proj")) == "allow"
    assert shell_decision("rm -rf Doc*", cwd=CWD) == "allow"
    assert shell_decision("cd ~ && rm -rf Doc*") == "deny"


PATHOLOGICAL_GLOBS = ["/" + "[" * 600, "/" + "*" * 900 + "a", "~/" + "[a-" * 300, "/e" + "?*" * 400 + "x", "~/" + "[!" * 400 + "]",
                      "/" + "*a" * 450, "~/D" + "*" * 800 + "[", "/" + "[]" * 500, "/us*" + "/*" * 300]


@pytest.mark.parametrize("pattern", PATHOLOGICAL_GLOBS)
def test_a_pathological_glob_never_raises_and_never_slows_the_rules(pattern: str):
    for command in (f"rm -rf {pattern}", f"mv {pattern} /tmp", f"find {pattern} -delete"):
        start = time.perf_counter()
        hit = assess_shell(command, cwd=CWD)
        assert time.perf_counter() - start < limit(1.0), command
        assert hit is None or hit.decision in ("ask", "deny", "allow")


def test_many_globs_in_one_command_stay_fast():
    command = "rm -rf " + " ".join(f"~/proj{i}*/x{i}?" for i in range(300))
    start = time.perf_counter()
    assess_shell(command, cwd=CWD)
    assert time.perf_counter() - start < limit(1.5)


def test_the_glob_spellings_of_the_working_directory_and_its_hidden_files_ask_alike():
    assert shell_decision("rm -rf .*") == shell_decision("rm -rf ./.*") == shell_decision("rm -rf ./*") == "ask"
    assert shell_decision("rm -rf build/.*") == "allow"


@pytest.mark.parametrize("variable", ["$env:USERPROFILE", "${env:USERPROFILE}", '"${env:USERPROFILE}"', '"$env:USERPROFILE"',
                                      "$HOME", "$home"])
def test_powershell_spellings_of_the_home_directory_are_one_target(variable: str):
    hit = assess_shell(f"Remove-Item -Recurse -Force {variable}", powershell=True, cwd=CWD)
    assert hit is not None and hit.decision == "deny", variable


def test_a_braced_powershell_variable_is_one_word():
    assert shell_decision("Get-Content ${env:USERPROFILE}\\.ssh\\id_rsa") == "allow"   # not read as PowerShell by the shell rules
    hit = assess_shell("Get-Content ${env:USERPROFILE}\\.ssh\\id_rsa", powershell=True, cwd=CWD)
    assert hit is not None and hit.decision == "deny"
    assert assess_shell("Remove-Item -Recurse -Force ${env:TEMP}\\build", powershell=True, cwd=CWD) is None


# --- a block device given to a file tool -----------------------------------------------------------------------------------

@pytest.mark.parametrize("path", BLOCK_DEVICES + ["/dev//sda", "/dev/./sda", "/dev/../dev/sda", "/dev/mem_not_a_disk/../sda"])
@pytest.mark.parametrize("tool, arguments", [
    ("Write", {"content": "x"}), ("Edit", {"old_string": "a", "new_string": "b"}),
    ("MultiEdit", {"edits": [{"old_string": "a", "new_string": "b"}]}),
])
def test_the_file_tools_get_the_deny_that_a_shell_redirect_into_a_block_device_gets(tmp_path: Path, path: str, tool: str,
                                                                                    arguments: dict[str, Any]):
    guard = HarnessGuard(tmp_path / "hooks.db", builtin_tools=True)
    assert tool_decision(guard, tool, {"file_path": path, **arguments}) == "deny"
    assert shell_decision(f"echo x > {path}") == "deny"


@pytest.mark.parametrize("path", ["/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/urandom",
                                  "/work/proj/dev/sda", "/work/proj/sda", "dev/sda", "/devices/sda", "/dev/shm/x", "/dev/fd/3"])
def test_the_file_tools_may_write_what_is_not_a_block_device(tmp_path: Path, path: str):
    guard = HarnessGuard(tmp_path / "hooks.db", builtin_tools=True)
    assert tool_decision(guard, "Write", {"file_path": path, "content": "x"}) == "allow", path


def test_a_block_device_is_a_deny_for_every_tool_that_writes_a_file():
    for path in ("/dev/sda", "/dev/disk2"):
        hit = assess_file(path, "x", write=True)
        assert hit is not None and hit.decision == "deny" and "block device" in hit.reason
        assert assess_file(path, None, write=False) is None   # a read of a device is not a write of it


def test_a_notebook_edit_and_a_patch_that_name_a_block_device_are_denied(tmp_path: Path):
    guard = HarnessGuard(tmp_path / "hooks.db", builtin_tools=True)
    assert tool_decision(guard, "NotebookEdit", {"notebook_path": "/dev/sda", "new_source": "x"}) == "deny"
    patch = "*** Begin Patch\n*** Update File: /dev/sda\n@@\n-a\n+b\n*** End Patch"
    event = {"hook_event_name": "PreToolUse", "session_id": "s", "cwd": CWD, "tool_name": "apply_patch", "tool_input": {"input": patch}}
    assert decision(handle("codex", event, guard)) == "deny"
