"""A symbolic link must not turn a denied path into an allowed one, and must not make an ordinary path asked about.

Every link here is made under ``tmp_path`` with a home directory of the test's own, so the tests do not depend on the machine's
real home, on ``/private`` or ``/Users``, or on a case-insensitive file system. For a path that exists the rules read the real
path
as well as the text, and the stricter verdict counts (``intentshield.dangerous.links``)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from timelimits import within

from intentshield import dangerous
from intentshield.dangerous import links

KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nnot a real key\n-----END OPENSSH PRIVATE KEY-----\n"


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """A home with a key, a project with links into it, and the process's home set to that home."""
    home, proj = tmp_path / "home", tmp_path / "proj"
    (home / ".ssh").mkdir(parents=True)
    proj.mkdir()
    (home / ".ssh" / "id_rsa").write_text(KEY, encoding="utf-8")
    (home / ".ssh" / "known_hosts").write_text("example.test ssh-ed25519 AAAA\n", encoding="utf-8")
    (home / "notes").mkdir()
    (proj / "src").mkdir()
    (proj / "README.md").write_text("hello\n", encoding="utf-8")
    os.symlink(home / ".ssh" / "id_rsa", proj / "notes.txt")        # a file name that is a key
    os.symlink(home / ".ssh" / "authorized_keys", proj / "keys")    # a link to a file that is not there yet
    os.symlink(home, proj / "h")                                    # a link to the home directory
    os.symlink(home / ".ssh", proj / "dotssh")
    os.symlink(tmp_path, proj / "up")
    os.symlink(proj / "src", proj / "lib")                          # a link that stays inside the project
    monkeypatch.setenv("HOME", str(home))
    return {"home": home, "proj": proj, "tmp": tmp_path}


def shell(command: str, w: dict[str, Path], cwd: str | None = None) -> str:
    hit = dangerous.assess_shell(command, cwd=cwd if cwd is not None else str(w["proj"]), homes=(str(w["home"]),))
    return hit.decision if hit else "allow"


def tool(path: str, w: dict[str, Path], write: bool = False, cwd: str | None = None) -> str:
    hit = dangerous.assess_file(path, "x\n", write=write, cwd=cwd if cwd is not None else str(w["proj"]),
                                homes=(str(w["home"]),))
    return hit.decision if hit else "allow"


# --- the file tools ------------------------------------------------------------------------------------------------------------

def test_the_direct_paths_are_the_documented_verdicts(world):
    home = world["home"]
    assert tool(str(home / ".ssh" / "id_rsa"), world) == "deny"
    assert tool(str(home / ".ssh" / "authorized_keys"), world, write=True) == "deny"


def test_a_read_through_a_link_to_a_key_is_the_verdict_of_the_key(world):
    assert tool("notes.txt", world) == "deny"
    assert tool(str(world["proj"] / "notes.txt"), world) == "deny"
    assert tool("dotssh/id_rsa", world) == "deny"


def test_a_write_through_a_link_to_a_file_that_is_not_there_yet_is_the_verdict_of_that_file(world):
    assert tool("keys", world, write=True) == "deny"
    assert tool("h/.ssh/authorized_keys", world, write=True) == "deny"
    assert tool("h/.zshrc", world, write=True) == "ask"
    assert tool("dotssh/authorized_keys", world, write=True) == "deny"


def test_a_search_through_a_link_to_the_home_is_a_search_of_the_home(world):
    assert tool("h", world) == "ask"
    assert tool("h/", world) == "ask"
    assert tool("up", world) == "ask"   # a directory above the home reaches it as well
    assert tool("h/notes", world) == "allow"


def test_a_link_that_stays_inside_the_project_keeps_the_verdict_of_the_project(world):
    assert tool("lib/a.py", world) == "allow"
    assert tool("lib/a.py", world, write=True) == "allow"
    assert tool("README.md", world) == "allow"
    assert tool("h/notes/todo.txt", world, write=True) == "allow"


# --- the shell rules -----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("command", ["cat notes.txt", "head -1 notes.txt", "cp notes.txt /tmp/copy", "grep -r BEGIN notes.txt",
                                     "cat dotssh/id_rsa", "tr a b < notes.txt", "sort notes.txt", "cat < notes.txt",
                                     "tail -n 3 ./notes.txt", "xxd notes.txt"])
def test_a_reader_given_a_link_to_a_key_is_denied(world, command):
    assert shell(command, world) == "deny", command


def test_a_reader_given_an_ordinary_file_is_allowed(world):
    for command in ("cat README.md", "head -1 lib/a.py", "grep -r BEGIN src", "sort README.md", "cat h/notes/todo.txt"):
        assert shell(command, world) == "allow", command


@pytest.mark.parametrize("command", ["echo x | tee keys", "echo ssh-rsa AAAA > keys", "cp /tmp/k keys",
                                     "echo x >> h/.ssh/authorized_keys"])
def test_a_write_through_a_link_to_the_authorized_keys_is_denied(world, command):
    assert shell(command, world) == "deny", command


@pytest.mark.parametrize("command", ["rm -rf h/*", "rm -rf h/", "rm -rf dotssh/", "rm -rf h/.*", "rm -rf up/home",
                                     "chmod -R 777 h/", "rm -rf ./h/"])
def test_a_recursive_delete_through_a_link_to_the_home_is_a_deny(world, command):
    assert shell(command, world) == "deny", command


def test_removing_the_link_itself_is_not_removing_what_it_leads_to(world):
    assert shell("rm h", world) == "allow"
    assert shell("rm -rf h", world) == "allow"
    assert shell("rm -f notes.txt", world) == "allow"
    assert shell("unlink dotssh", world) == "allow"
    assert shell("mv h h.old", world) == "allow"


def test_the_working_directory_may_itself_be_behind_a_link(world):
    through = str(world["proj"] / "h")
    assert shell("cat .ssh/id_rsa", world, cwd=through) == "deny"
    assert shell("rm -rf .", world, cwd=through) == "deny"
    assert shell("ls", world, cwd=through) == "allow"
    assert shell("cd h && rm -rf *", world) == "deny"


def test_a_write_through_a_link_to_a_startup_file_is_asked_about(world):
    assert shell("echo 'alias x=y' >> h/.zshrc", world) == "ask"
    assert shell("echo x > h/notes/todo.txt", world) == "allow"
    assert shell("sed -i s/a/b/ h/.bashrc", world) == "ask"


def test_a_symbolic_link_to_the_home_a_root_or_a_system_directory_is_asked_about(world):
    for target in ("~", "$HOME", "/", "/etc", "/usr", "/System", "/Users", "~/Documents"):
        assert shell(f"ln -s {target} link", world) == "ask", target
        assert shell(f"ln -sf {target} link", world) == "ask", target
        assert shell(f"ln -sfn {target} link", world) == "ask", target
        assert shell(f"ln --symbolic {target} link", world) == "ask", target
        assert shell(f"ln -s -t somedir {target}", world) == "ask", target
    assert shell("ln -s .. up2", world, cwd=str(world["home"])) == "ask"   # one level up from the home is /Users or /home


@pytest.mark.parametrize("command", ["ln -s ~/proj/src lib", "ln -s ../src lib", "ln -sf /usr/local/bin/tool bin/tool",
                                     "ln -s /tmp/build out", "ln file other", "ln -s node_modules/.bin/x bin/x",
                                     "ln -s ~/dotfiles/vimrc ~/.vimrc2"])
def test_an_ordinary_link_is_not_asked_about(world, command):
    assert shell(command, world) == "allow", command


# --- what must not change ------------------------------------------------------------------------------------------------------

def test_a_project_that_is_reached_through_a_link_keeps_its_verdicts(world):
    proj_link = world["tmp"] / "work"
    os.symlink(world["proj"], proj_link)
    for command in ("cat README.md", "rm -rf build", "rm -rf src/", "git status", "chmod 644 README.md", "echo x > out.txt"):
        assert shell(command, world, cwd=str(proj_link)) == shell(command, world), command
    assert tool("README.md", world, cwd=str(proj_link)) == "allow"
    assert tool("out.txt", world, write=True, cwd=str(proj_link)) == "allow"


def test_a_home_that_is_behind_a_link_reads_as_the_same_home(world, monkeypatch):
    shown = world["tmp"] / "homelink"
    os.symlink(world["home"], shown)
    monkeypatch.setenv("HOME", str(shown))
    for homes in ((str(shown),), (str(world["home"]),), (str(shown), str(world["home"]))):
        def ask(command: str, cwd: str, homes=homes) -> str:
            hit = dangerous.assess_shell(command, cwd=cwd, homes=homes)
            return hit.decision if hit else "allow"
        assert ask("cat ~/.ssh/id_rsa", str(shown)) == "deny"
        assert ask("cat .ssh/id_rsa", str(shown)) == "deny"
        assert ask("cat notes/todo.txt", str(shown)) == "allow"
        assert ask("rm -rf ~", str(shown / "notes")) == "deny"
        assert ask("rm -rf build", str(shown / "notes")) == "allow"
        assert ask("cat README.md", str(world["proj"])) == "allow"


def test_the_macos_links_into_private_do_not_make_a_project_a_system_path(world, monkeypatch):
    """/tmp, /var and /etc are links into /private on macOS: a path through one is in the place it was written in."""
    real = world["tmp"] / "private" / "tmp"
    real.mkdir(parents=True)
    os.symlink(world["tmp"] / "private", world["tmp"] / "alias")   # alias/tmp -> private/tmp, like /tmp -> /private/tmp
    assert links.real_path(str(world["tmp"] / "alias" / "tmp" / "x")) == str(real / "x")   # a real difference is reported
    assert links._ALIAS.match("/private/tmp/x") and links._ALIAS.match("/private/var/folders/x")
    assert links._ALIAS.match("/private/etc/hosts") and links._ALIAS.match("/System/Volumes/Data/home/x")
    assert not links._ALIAS.match("/private/other") and not links._ALIAS.match("/private/tmpfile")
    assert links.real_path("/tmp/does-not-exist/x") is None   # whatever /tmp is here, the same place
    assert links.real_path("/var/folders/x/y") is None
    assert links.real_path("/etc/hostname-not-there") is None
    for command in ("rm -rf /tmp/build-x", "cat /var/tmp/log.txt", "mkdir /tmp/new-x", "cp README.md /tmp/copy-x"):
        assert shell(command, world) == "allow", command


# --- it never raises, and it stays fast ----------------------------------------------------------------------------------------

def test_a_loop_of_links_a_dangling_link_and_a_name_that_is_too_long_do_not_raise(world):
    proj = world["proj"]
    os.symlink("b", proj / "a")
    os.symlink("a", proj / "b")
    os.symlink("nowhere", proj / "dangling")
    long_name = "n" * 300
    for name in ("a", "b", "a/x", "dangling", "dangling/x", long_name, long_name + "/" + long_name, "a/" * 50):
        assert shell(f"cat {name}", world) in ("allow", "ask")
        assert tool(name, world) in ("allow", "ask")
        assert tool(name, world, write=True) in ("allow", "ask")
    assert shell("cat a b dangling", world) == "allow"


def test_a_directory_that_cannot_be_read_does_not_raise(world):
    locked = world["proj"] / "locked"
    locked.mkdir()
    os.symlink(world["home"], locked / "h")
    locked.chmod(0)
    try:
        assert shell("cat locked/h/.ssh/known_hosts", world) in ("allow", "ask", "deny")
        assert tool("locked/h", world) in ("allow", "ask")
    finally:
        locked.chmod(0o755)


def test_a_path_that_is_not_a_path_is_left_alone(world):
    for word in ("", "-", "--x", "https://x.test/a", "a\x00b", "$UNSET/x", "`x`", "~nobody-here-xyz/a", "a b"):
        assert links.real_path(word, str(world["proj"])) is None


def test_thousands_of_path_words_are_read_once_each_and_stay_fast(world):
    proj = world["proj"]
    words = " ".join(f"d{i % 97}/f{i}" for i in range(3000))
    within(1.5, shell, "cat " + words, world)
    within(1.5, shell, "echo " + " ".join(f"/tmp/p{i}" for i in range(2000)), world)
    repeated = "cat " + "notes.txt " * 2000
    assert within(1.5, shell, repeated, world) == "deny"
    assert (proj / "README.md").exists()


def test_a_call_that_names_more_paths_than_the_budget_is_asked_about(world, monkeypatch):
    monkeypatch.setattr(links, "_BUDGET", 50)
    command = "cat " + " ".join(f"f{i}" for i in range(200))
    hit = dangerous.assess_shell(command, cwd=str(world["proj"]), homes=(str(world["home"]),))
    assert hit is not None and hit.decision == "ask" and "symbolic links" in hit.reason
    hit = dangerous.assess_file("f1", "", False, cwd=str(world["proj"]))
    assert hit is None


def test_no_cwd_and_a_relative_path_leave_the_path_as_it_is(world):
    assert links.real_path("notes.txt", "") is None
    assert links.real_path("notes.txt", "relative/dir") is None
    assert links.real_path("notes.txt", str(world["proj"])) == str(world["home"] / ".ssh" / "id_rsa")


# --- the hook: the file tools, the shell tool and a patch -----------------------------------------------------------------

def _hook(tool: str, tool_input: dict, world: dict[str, Path], tmp_path: Path) -> str:
    from intentshield.harness import HarnessGuard, handle

    guard = HarnessGuard(tmp_path / "hooks.db", builtin_tools=True)
    reply = handle("claude", {"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": str(world["proj"]), "tool_name": tool,
                              "tool_input": tool_input}, guard)
    return reply["hookSpecificOutput"].get("permissionDecision", "allow") if reply else "allow"


def test_the_hook_reads_a_link_in_the_file_tools_the_shell_tool_and_a_patch(world, tmp_path):
    assert _hook("Read", {"file_path": "notes.txt"}, world, tmp_path) == "deny"
    assert _hook("Write", {"file_path": "keys", "content": "ssh-rsa AAAA x"}, world, tmp_path) == "deny"
    assert _hook("Bash", {"command": "cat notes.txt"}, world, tmp_path) == "deny"
    assert _hook("Bash", {"command": "cat README.md"}, world, tmp_path) == "allow"
    assert _hook("Grep", {"pattern": "x", "path": "h"}, world, tmp_path) == "ask"
    assert _hook("Grep", {"pattern": "x", "path": "src"}, world, tmp_path) == "allow"
    assert _hook("Grep", {"pattern": "x"}, world, tmp_path) == "allow"
    files = "".join(f"*** Update File: src/f{i}.py\n@@\n+x = {i}\n" for i in range(12))
    patch = f"*** Begin Patch\n{files}*** Update File: keys\n@@\n+ssh-rsa AAAA x\n*** End Patch"
    assert _hook("apply_patch", {"input": patch}, world, tmp_path) == "deny"
    plain = f"*** Begin Patch\n{files}*** End Patch"
    assert _hook("apply_patch", {"input": plain}, world, tmp_path) == "allow"


def test_a_search_with_no_path_in_a_working_directory_that_is_the_home_asks(world, tmp_path):
    from intentshield.harness import HarnessGuard, handle

    guard = HarnessGuard(tmp_path / "hooks.db", builtin_tools=True)
    event = {"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": str(world["home"]), "tool_name": "Grep",
             "tool_input": {"pattern": "BEGIN"}}
    reply = handle("claude", event, guard)
    assert reply is not None and reply["hookSpecificOutput"]["permissionDecision"] == "ask"
    event["tool_input"] = {"pattern": "BEGIN", "path": "notes"}
    assert handle("claude", event, guard) is None
