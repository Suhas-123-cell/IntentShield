"""One path, one verdict: every spelling of a path the rules decide on (dot segments, a climb and a return, doubled slashes, a
trailing slash, a climb above the home directory and back down) gets the verdict of the plain spelling, in the shell rules, the
file rules and through the hook. Also the homes outside ``/Users``, ``/home`` and ``/root``, the case of the listed names, and
a cleanup of a home folder by age.

Every command is a string; nothing is run. The paths are the ones the other rule tests already decide on."""
# ruff: noqa: E501
from __future__ import annotations

import re
from pathlib import Path

import pytest
import test_dangerous_rules as rule_tests

from intentshield import dangerous
from intentshield.dangerous import assess_file, assess_shell, paths
from intentshield.harness import HarnessGuard, handle

HOME = "/Users/x"
HOME_NAME = "x"


@pytest.fixture(autouse=True)
def _home(monkeypatch):
    """The running user's home is ``/Users/x``: the climb ``~/../x`` comes back to it."""
    monkeypatch.setenv("HOME", HOME)
    monkeypatch.delenv("USERPROFILE", raising=False)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: Path(HOME)))


def decision(hit) -> str:
    return hit.decision if hit else "allow"


def shell_decision(command: str) -> str:
    return decision(assess_shell(command))


# --- the spellings ------------------------------------------------------------------------------------------------------

_HOME_HEAD = re.compile(r"^(~|\$HOME|\$\{HOME\})(?=/|$)")


def spellings(path: str) -> dict[str, str]:
    """``path`` written other ways that name the same place."""
    head = _HOME_HEAD.match(path)
    if head:
        top, rest = head[1], path[head.end():]
    elif path.startswith("/"):
        top, rest = "", path
    else:
        top, rest = "", "/" + path   # a relative path: the first part is its first name, so the rest hangs from a dot
    relative = not (head or path.startswith("/"))
    out: dict[str, str] = {}
    if relative:
        first, _, tail = path.partition("/")
        out["dot segments"] = f"{first}/./{tail}"
        out["climb and return"] = f"{first}/x/../{tail}"
        out["doubled slashes"] = path.replace("/", "//")
        out["climb and return first"] = f"x/../{path}"
    else:
        body = rest if rest.startswith("/") else "/" + rest if rest else ""
        out["dot segments"] = top + "/." + body if body else top + "/."
        out["dots between names"] = top + body.replace("/", "/./")
        out["climb and return"] = top + "/x/.." + body
        out["doubled slashes"] = top + body.replace("/", "//") if body else top + "//"
    if not path.endswith(("/", "*")):
        out["trailing slash"] = path + "/"
    if head:
        out["home climb and return"] = f"{top}/../{HOME_NAME}{rest}"
        out["home climb and return twice"] = f"{top}/../{HOME_NAME}/../{HOME_NAME}{rest}"
        out["home climb mixed with dots"] = f"{top}/./../{HOME_NAME}/.{rest.replace('/', '//')}"
        out["absolute home"] = f"{HOME}{rest}"
        out["absolute home with a climb"] = f"{HOME}/../{HOME_NAME}{rest}"
    elif path.startswith(HOME + "/") or path == HOME:
        out["home climb and return"] = f"{HOME}/../{HOME_NAME}{path[len(HOME):]}"
    elif re.match(r"/(?:Users|home)/[^/]+(?:/|$)", path):
        user = path.split("/")[2]
        out["home climb and return"] = path.replace(f"/{user}", f"/{user}/../{user}", 1)
    return out


def _sensitive(word: str) -> bool:
    """``word`` is a path one of the path rules reads."""
    if "://" in word or not ("/" in word or word.startswith(("~", "$"))) or re.match(r"/dev/(?:tcp|udp)/", word):
        return False
    return bool(paths._cred_level(word) or paths.persistence_path(word) or paths._protected(word) or paths._system(word)
                or dangerous.guard_surface(word))


def path_words(command: str) -> list[str]:
    """The words of ``command`` that are a path the rules read (the part after ``=`` or ``@`` of an option)."""
    found = []
    for word in re.split(r"[\s;|&<>()]+", command):
        word = word.rpartition("@")[2] if "@" in word else word
        word = word.rpartition("=")[2] if "=" in word else word
        word = word.strip("'\"")
        if word and _sensitive(word) and word not in found:
            found.append(word)
    return found


def rewritten(command: str) -> list[tuple[str, str]]:
    """(label, the command with one path word spelled another way) for every path of the command the rules read."""
    out = []
    for word in path_words(command):
        for label, spelled in spellings(word).items():
            out.append((f"{word} as {label}", command.replace(word, spelled, 1)))
    return out


def _commands(expected: str) -> list[str]:
    return [c for c in (rule_tests.DENY if expected == "deny" else rule_tests.ASK) if rewritten(c)]


def _file_cases() -> list[tuple[str, str, bool]]:
    """(path, verdict, a write) of the file rules' own tests that are a deny or an ask."""
    cases = []
    for test, write in ((rule_tests.test_reading_credential_stores, False), (rule_tests.test_writing_places_that_run_code_later, True)):
        for mark in test.pytestmark:
            if mark.name == "parametrize":
                for path, expected in mark.args[1]:
                    if expected in ("deny", "ask"):
                        cases.append((path, expected, write))
                        if path.startswith(HOME + "/"):   # the same file named from the home directory
                            cases += [("~" + path[len(HOME):], expected, write), ("$HOME" + path[len(HOME):], expected, write)]
    return cases


COMMAND_CASES = [(c, e, label, variant) for e in ("deny", "ask") for c in _commands(e) for label, variant in rewritten(c)]
FILE_CASES = [(p, e, w, label, variant) for p, e, w in _file_cases() for label, variant in spellings(p).items()]


def test_the_rule_tests_supply_paths_to_rewrite():
    assert len(COMMAND_CASES) > 400 and len(FILE_CASES) > 200
    assert {label.partition(" as ")[2] for _, _, label, _ in COMMAND_CASES} >= {
        "dot segments", "climb and return", "doubled slashes", "trailing slash", "home climb and return"}


@pytest.mark.parametrize("command,expected,label,variant", COMMAND_CASES, ids=[f"{c} | {label}" for c, _, label, _ in COMMAND_CASES])
def test_a_command_gets_the_same_verdict_whatever_way_its_path_is_spelled(command, expected, label, variant):
    assert shell_decision(command) == expected
    assert shell_decision(variant) == expected, variant


@pytest.mark.parametrize("path,expected,write,label,variant", FILE_CASES, ids=[f"{p} | {label}" for p, _, _, label, _ in FILE_CASES])
def test_a_file_tool_gets_the_same_verdict_whatever_way_its_path_is_spelled(path, expected, write, label, variant):
    content = "echo hello" if write else None
    assert decision(assess_file(path, content, write=write)) == expected
    assert decision(assess_file(variant, content, write=write)) == expected, variant


@pytest.mark.parametrize("tool,field,path,expected", [
    ("Read", "file_path", "~/.ssh/id_rsa", "deny"), ("Read", "file_path", "$HOME/.aws/credentials", "deny"),
    ("Write", "file_path", "~/.zshrc", "ask"), ("Edit", "file_path", "~/.ssh/authorized_keys", "deny"),
    ("Grep", "path", "~", "ask"),
])
@pytest.mark.parametrize("climb", ["/../x/", "/./../x/./", "/x/../../x/", "/../x/../x/"])
def test_a_built_in_tool_reads_a_climb_above_the_home_directory_as_the_home_directory(tmp_path, tool, field, path, expected, climb):
    head, _, rest = path.partition("/")
    spelled = head + climb + rest if rest else head + climb.rstrip("/")
    guard = HarnessGuard(tmp_path / "hooks.db", builtin_tools=True)
    event = {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": tool,
             "tool_input": {field: spelled, **({"content": "export A=1"} if tool == "Write" else {}),
                            **({"old_string": "a", "new_string": "b"} if tool == "Edit" else {})}}
    reply = handle("claude", event, guard)
    assert (reply["hookSpecificOutput"].get("permissionDecision", "allow") if reply else "allow") == expected, spelled


@pytest.mark.parametrize("argument,path,expected", [
    ("path", "~/../x/.ssh/id_rsa", "deny"), ("file", "$HOME/../x/.aws/credentials", "deny"),
    ("path", "~/./../x/ok/../.zshrc", "ask"),
])
def test_an_mcp_path_argument_reads_a_climb_above_the_home_directory_as_the_home_directory(tmp_path, argument, path, expected):
    guard = HarnessGuard(tmp_path / "hooks.db", builtin_tools=True)
    event = {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "mcp__files__write_file" if expected == "ask" else "mcp__files__read_file",
             "tool_input": {argument: path, "content": "export A=1"}}
    reply = handle("claude", event, guard)
    assert (reply["hookSpecificOutput"].get("permissionDecision", "allow") if reply else "allow") == expected


@pytest.mark.parametrize("command", [
    "cat ~/../x/.ssh/id_rsa", "cat $HOME/../x/.ssh/id_rsa", "cat ~/../x/.aws/credentials", "cat ~/foo/../../x/.aws/credentials",
    "cat ~/../x/.ssh/*", "cat ${HOME}/../x/../x/.ssh/id_rsa", "rm -rf ~/../x", "rm -rf ~/../x/Documents", "rm -rf $HOME/../x/*",
])
def test_a_climb_above_the_home_directory_and_back_is_denied_like_the_plain_path(command):
    assert shell_decision(command) == "deny"


@pytest.mark.parametrize("command,expected", [
    ("echo x >> ~/../x/.zshrc", "ask"), ("echo ssh-rsa AAAAB3Nza >> ~/../x/.ssh/authorized_keys", "deny"),
    ("cat ~/../x/.env", "ask"), ("echo x >> ~/../x/proj/../.bashrc", "ask"), ("cat ~/../x/proj/README.md", "allow"),
    ("cat ~/../y/proj/README.md", "allow"), ("rm -rf ~/../x/proj/build", "allow"),
])
def test_a_climb_above_the_home_directory_does_not_change_what_lies_beneath_it(command, expected):
    assert shell_decision(command) == expected


@pytest.mark.parametrize("command", [
    "echo x > .git/x/../hooks/pre-commit", "echo x > .github/x/../workflows/ci.yml", "echo x >> ./sub/../.zshrc",
])
def test_a_relative_path_with_a_climb_is_read_without_it(command):
    assert shell_decision(command) == "ask"


@pytest.mark.parametrize("device", ["/dev/sda", "/dev//sda", "/dev/./sda", "/dev/x/../sda", "//dev/sda"])
def test_a_block_device_is_one_device_however_its_path_is_spelled(device):
    assert shell_decision(f"dd if=/dev/zero of={device} bs=1M") == "deny"


# --- a home that is not /Users/x, /home/x or /root ------------------------------------------------------------------------

@pytest.mark.parametrize("home", ["/mnt/c/Users/x", "/data/home/x", "/workspace", "/opt/work/home/me", "/Volumes/Data/x"])
def test_a_home_outside_the_usual_places_is_a_home_directory(monkeypatch, home):
    monkeypatch.setenv("HOME", home)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: Path(home)))
    for command in (f"rm -rf {home}", f"rm -rf {home}/", f"rm -rf {home}/*", f"rm -rf {home}/Documents", f"find {home} -delete",
                    f"rm -rf {home}/sub/..", f"rm -rf {home}//", f"cat {home}/.ssh/id_rsa", f"cat {home}/.aws/credentials"):
        assert shell_decision(command) == "deny", command
    assert decision(assess_file(home)) == "ask"
    assert decision(assess_file(f"{home}/.zshrc", "export A=1", write=True)) == "ask"
    for command in (f"rm -rf {home}/projects/app/build", f"cat {home}/projects/app/README.md", f"ls {home}"):
        assert shell_decision(command) == "allow", command


def test_the_directory_that_holds_the_homes_is_not_deleted_either(monkeypatch):
    monkeypatch.setenv("HOME", "/data/home/x")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: Path("/data/home/x")))
    assert shell_decision("rm -rf /data/home") == "deny"
    assert shell_decision("rm -rf /data/home/../home/x/Documents") == "deny"
    assert shell_decision("rm -rf /data/cache") == "allow"


@pytest.mark.parametrize("unsafe", ["/", "/tmp", "/etc", "relative/dir", ""])
def test_a_home_that_names_no_home_is_not_taken_for_one(monkeypatch, unsafe):
    monkeypatch.setenv("HOME", unsafe)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: Path("/Users/x")))
    assert shell_decision("rm -rf /tmp/work") == "allow"
    assert shell_decision("rm -rf /tmp/work/build") == "allow"
    assert shell_decision("cat /var/log/app.log") == "allow"


def test_the_home_the_event_names_is_a_home_directory(tmp_path):
    guard = HarnessGuard(tmp_path / "hooks.db", builtin_tools=True)

    def run(**event) -> str:
        reply = handle("claude", {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
                                  "tool_input": {"command": "rm -rf /mnt/c/Users/q"}, **event}, guard)
        return reply["hookSpecificOutput"].get("permissionDecision", "allow") if reply else "allow"
    assert run() == "allow"   # nothing says that this is a home
    assert run(transcript_path="/mnt/c/Users/q/.claude/projects/p/s.jsonl") == "deny"
    assert run(env={"HOME": "/mnt/c/Users/q"}) == "deny"
    assert run(env={"USERPROFILE": "/mnt/c/Users/q"}) == "deny"
    assert run(env={"HOME": "/tmp"}, transcript_path="/Users/q/notes/.claude/x") == "allow"


# --- the case of the listed names -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("command", [
    "rm -rf ~/documents", "rm -rf ~/DOCUMENTS/", "rm -rf ~/documents/*", "rm -rf ~/desktop", "rm -rf ~/Library", "rm -rf ~/library",
    "rm -rf ~/.SSH", "rm -rf /ETC", "rm -rf /Etc", "rm -rf /system", "rm -rf /users", "rm -rf /USERS/x", "rm -rf /Home/x",
    "rm -rf /usr/LOCAL", "sudo rm -rf /VAR/lib", "rsync -a --delete /tmp/empty/ ~/downloads/", "mv ~/documents /tmp/old",
    "find ~/downloads -delete", "chmod -R 000 ~/DOCUMENTS",
])
def test_the_listed_directories_are_matched_without_regard_to_case(command):
    assert shell_decision(command) == "deny"


@pytest.mark.parametrize("command", [
    "rm -rf ~/documents/old/build", "rm -rf ~/Documents/old", "rm -rf ~/projects/Library", "rm -rf ~/projects/documents",
    "rm -rf build/Documents", "rm -rf /tmp/ETC", "rm -rf /tmp/etc/x", "rm -rf ./Library", "rm -rf ~/Developer/app",
    "rm -rf ~/documents.bak", "rm -rf /Applicationsx",
])
def test_a_path_that_only_contains_a_listed_name_is_not_denied(command):
    assert shell_decision(command) == "allow"


def test_a_system_path_is_compared_without_regard_to_case_by_its_prefix():
    assert shell_decision("sudo rm -rf /ETC/ssh/old") == "allow"   # deep inside: unchanged, as /etc/ssh/old is
    assert shell_decision("sudo chmod 777 /ETC/passwd") == "ask"
    assert shell_decision("sudo chmod 777 /etc/passwd") == "ask"


# --- an age or size cleanup of a home folder --------------------------------------------------------------------------------

@pytest.mark.parametrize("command", [
    "find ~/Downloads -mtime +30 -delete", "find ~/Downloads -type f -mtime +30 -delete", "find ~/Desktop -size +1G -delete",
    "find ~/Documents -empty -delete", "find ~/Downloads -atime +90 -type f -delete", "find ~/Downloads -mmin +600 -delete",
    "find ~/Downloads -mtime +30 -type f -exec rm {} +", "find $HOME/Downloads -mtime +30 -delete",
    "find ~/Downloads -name '*.dmg' -delete", "find ~/Downloads -newer ref.txt -delete",
    "find ~/Downloads -newermt 2020-01-01 -delete", "find ~/Downloads -user x -type f -delete",
])
def test_an_age_or_size_cleanup_of_a_home_folder_asks_like_one_by_name(command):
    hit = assess_shell(command)
    assert decision(hit) == "ask"
    assert "deletes the files that match" in hit.reason and "everything" not in hit.reason


def test_the_reason_for_a_cleanup_by_age_names_the_test():
    hit = assess_shell("find ~/Downloads -mtime +30 -delete")
    assert "-mtime +30" in hit.reason and "~/Downloads" in hit.reason and "check that the test is what you mean" in hit.reason
    assert "-name *.dmg" in assess_shell("find ~/Downloads -name '*.dmg' -delete").reason


@pytest.mark.parametrize("command", [
    "find ~ -delete", "find / -delete", "find ~/Downloads -delete", "find ~/Downloads -type f -delete",
    "find ~/Downloads -mtime -3 -delete", "find ~/Downloads ! -mtime +30 -delete", "find ~/Downloads -mtime +30 -o -delete",
    "find ~ -mtime +365 -delete", "find ~ -empty -delete", "find /etc -mtime +30 -delete", "find / -size +1G -delete",
])
def test_a_find_with_no_test_that_limits_it_is_still_denied(command):
    assert shell_decision(command) == "deny"


def test_the_reason_for_a_find_with_no_limiting_test_says_what_is_missing():
    assert "no test on the name, age or size" in assess_shell("find ~/Downloads -delete").reason
    assert "only a test on the name limits it enough" in assess_shell("find ~ -mtime +365 -delete").reason


@pytest.mark.parametrize("command", ["find ~/Library/Caches -mtime +30 -delete", "find ~/projects -mtime +30 -delete",
                                     "find . -mtime +30 -delete", "find ~/Downloads -mtime +30 -print"])
def test_an_age_cleanup_of_an_ordinary_folder_or_a_listing_is_left_alone(command):
    assert shell_decision(command) == "allow"
