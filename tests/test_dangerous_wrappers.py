"""Programs that run another program, and ``find -exec``, must not hide what they run.

A deny behind ``sudo``, ``flock``, ``taskset``, ``ssh host`` or ``find -exec`` is the same deny. The wrappers are read from the
manual
pages of coreutils, util-linux, the BSD and macOS base systems and the usual debugging, sandbox and multiplexer tools (see
``_RUNNERS``
in ``dangerous``); a wrapper missing from this list fails ``test_every_wrapper_has_a_form``. Every command is a string; nothing is
run."""
from __future__ import annotations

import re
import shlex

import pytest
from test_dangerous_rules import DENY

from intentshield import dangerous
from intentshield.dangerous import assess_shell


def verdict(command: str) -> str:
    hit = assess_shell(command)
    return hit.decision if hit else "allow"


# A command that is one simple command (no operator, group or function), so that a wrapper can stand in front of it.
SIMPLE = [c for c in DENY if not re.search(r"[;&|(){}]", c) and not c.startswith(("sudo", "env", "bash -c", "sh -c"))]

# How each wrapper is written in front of a command: {c} is the command, {q} the same as one quoted word.
FORMS = {
    "nohup": "nohup {c}", "time": "time -p {c}", "command": "command {c}", "exec": "exec -a x {c}", "nice": "nice -n 5 {c}",
    "ionice": "ionice -c 3 {c}", "setsid": "setsid -f {c}", "stdbuf": "stdbuf -o L {c}", "caffeinate": "caffeinate -t 5 {c}",
    "builtin": "builtin {c}", "timeout": "timeout -s KILL 5 {c}", "gtimeout": "gtimeout 5 {c}", "chronic": "chronic {c}",
    "unbuffer": "unbuffer -p {c}", "xargs": "xargs -n 1 {c}", "watch": "watch -n 1 {c}", "env": "env -i A=1 {c}",
    "sudo": "sudo -u root {c}", "doas": "doas -u root {c}",
    "flock": "flock -n /tmp/l {c}", "lockf": "lockf -t 5 /tmp/l {c}", "taskset": "taskset -c 0,1 {c}", "chrt": "chrt -f 1 {c}",
    "unshare": "unshare -r --map-user 0 {c}", "nsenter": "nsenter -t 1 -m {c}", "chroot": "chroot --userspec=x:y / {c}",
    "setpriv": "setpriv --reuid 1000 {c}", "setarch": "setarch x86_64 {c}", "linux32": "linux32 {c}", "linux64": "linux64 {c}",
    "runuser": "runuser -u bob -- {c}", "sg": "sg staff -c {q}", "script": "script -q /dev/null {c}",
         "strace": "strace -f -o /tmp/t {c}",
    "ltrace": "ltrace -o /tmp/t {c}", "arch": "arch -arm64 {c}", "busybox": "busybox {c}", "toybox": "toybox {c}",
    "xcrun": "xcrun -sdk macosx {c}", "sandbox-exec": "sandbox-exec -p '(version 1)' {c}", "parallel": "parallel -j2 {c}",
    "sshpass": "sshpass -p x {c}", "ssh-agent": "ssh-agent {c}", "pkexec": "pkexec --user root {c}", "run0": "run0 -u root {c}",
    "systemd-run": "systemd-run --scope -p MemoryMax=1G {c}", "systemd-inhibit": "systemd-inhibit --what=idle {c}",
    "fakeroot": "fakeroot {c}", "eatmydata": "eatmydata {c}", "fakechroot": "fakechroot {c}", "proxychains": "proxychains -q {c}",
    "proxychains4": "proxychains4 -q {c}", "torsocks": "torsocks {c}", "tsocks": "tsocks {c}",
         "faketime": "faketime '2020-01-01' {c}",
    "xvfb-run": "xvfb-run -a {c}", "dbus-run-session": "dbus-run-session -- {c}", "dbus-launch": "dbus-launch {c}",
    "numactl": "numactl --cpubind=0 {c}", "cpulimit": "cpulimit -l 50 -- {c}", "prlimit": "prlimit --nofile=64 {c}",
    "choom": "choom -n 5 -- {c}", "screen": "screen -dmS x {c}", "valgrind": "valgrind --leak-check=full {c}",
         "gdb": "gdb --args {c}",
    "firejail": "firejail --quiet {c}", "bwrap": "bwrap --ro-bind / / {c}",
}
# Programs that take a subcommand first: ``uv run -- cmd``, ``bundle exec cmd``.
SUBCOMMAND_FORMS = {
    "uv": "uv run -- {c}", "poetry": "poetry run {c}", "pipenv": "pipenv run {c}", "pdm": "pdm run {c}", "hatch": "hatch run {c}",
    "rye": "rye run {c}", "conda": "conda run -n base {c}", "mamba": "mamba run -n base {c}", "micromamba": "micromamba run {c}",
    "bundle": "bundle exec {c}", "direnv": "direnv exec . {c}", "mise": "mise exec -- {c}", "asdf": "asdf exec {c}",
    "rbenv": "rbenv exec {c}", "pyenv": "pyenv exec {c}", "nodenv": "nodenv exec {c}", "npm": "npm exec -- {c}",
    "pnpm": "pnpm exec {c}", "yarn": "yarn exec {c}",
}
# Programs that hand the words after them to a shell as one text, or run a remote command.
SHELL_TEXT_FORMS = {
    "flock -c": "flock -n /tmp/l -c {q}", "script -c": "script -qc {q} /dev/null", "watch (one word)": "watch -n 1 {q}",
    "ssh": "ssh -p 22 -i ~/.ssh/k host {q}", "ssh (words)": "ssh host {c}", "runuser -c": "runuser -l bob -c {q}",
    "su -c": "su -c {q} root", "sudo -s": "sudo -s {c}", "sudo -i": "sudo -i {c}",
}
ALL_FORMS = {**FORMS, **SUBCOMMAND_FORMS, **SHELL_TEXT_FORMS}


def wrapped(form: str, command: str) -> str:
    return ALL_FORMS[form].format(c=command, q=shlex.quote(command))


def test_every_wrapper_has_a_form():
    assert set(dangerous._WRAPPERS) <= set(FORMS), "a wrapper with no form in this test"
    assert set(dangerous._SUB_RUNNERS) <= set(SUBCOMMAND_FORMS), "a subcommand runner with no form in this test"


def test_the_commands_in_front_of_which_the_wrappers_stand_are_plain_commands():
    assert len(SIMPLE) >= 50
    assert all(verdict(c) == "deny" for c in SIMPLE)


@pytest.mark.parametrize("form", sorted(ALL_FORMS))
def test_a_deny_behind_a_wrapper_is_still_a_deny(form):
    lost = [c for c in SIMPLE if verdict(wrapped(form, c)) != "deny"]
    assert lost == [], f"{ALL_FORMS[form]} hides: {lost[:3]}"


@pytest.mark.parametrize("form", sorted(ALL_FORMS))
def test_an_ordinary_command_behind_a_wrapper_stays_allowed(form):
    for command in ("ls -la", "git status", "python -m pytest -q", "rm -rf build/", "cat README.md"):
        assert verdict(wrapped(form, command)) == "allow", wrapped(form, command)


@pytest.mark.parametrize("name", ["sudo", "env", "nohup", "command", "time", "nice", "setsid", "flock -n x"])
@pytest.mark.parametrize("count", [9, 12, 100])
def test_more_wrappers_than_are_read_through_ask_and_never_allow(name, count):
    deny = verdict((name + " ") * count + "rm -rf /")
    assert deny in ("ask", "deny")
    assert verdict((name + " ") * count + "ls") == "ask"


def test_the_limit_is_named_and_a_command_just_inside_it_is_read():
    hit = assess_shell("sudo " * 9 + "ls")
    assert hit is not None and "wrappers" in hit.reason
    assert verdict("sudo " * 8 + "rm -rf /") == "deny"
    assert verdict("sudo " * 8 + "ls") == "allow"
    assert verdict("env " * 5 + "nohup " * 3 + "ls") == "allow"


def test_a_wrapper_chain_of_different_programs_counts_each_wrapper():
    assert verdict("sudo env nohup command time nice setsid stdbuf timeout 5 rm -rf /") in ("ask", "deny")


# --- find -exec ----------------------------------------------------------------------------------------------------------

FIND_DENY = [
    "find . -exec rm -rf / \\;", "find . -exec rm -rf ~ {} \\;", "find . -execdir rm -rf / \\;", "find . -ok rm -rf / \\;",
    "find . -exec git push --force origin main \\;", "find . -exec sh -c 'rm -rf /' \\;",
             "find . -maxdepth 1 -exec dd if=/dev/zero of=/dev/sda \\;",
    "find . -name a -exec chmod -R 777 / \\;", "find . -exec cat ~/.ssh/id_rsa \\;",
             "find . -name x -exec bash -c 'cat ~/.aws/credentials' \\;",
    "find . -type f -exec sudo rm -rf / {} +", "find . -exec nohup rm -rf / \\;",
    "find . -exec rm -rf / ';'", "find . -exec rm -rf '/' \\; -print", "find . -type d -exec env X=1 rm -rf ~ \\;",
]
FIND_ALLOW = [
    "find . -name '*.pyc' -exec rm -f {} +", "find . -type f -exec chmod 644 {} \\;", "find . -exec grep -l foo {} +",
    "find src -name '*.py' -exec wc -l {} \\;", "find . -type f -exec sh -c 'echo \"$1\"' _ {} \\;",
              "find . -name '*.log' -exec rm {} \\;",
    "find ~/proj -name node_modules -prune -exec rm -rf {} +", "find . -exec ls {} \\;", "find . -ok rm {} \\;",
]


@pytest.mark.parametrize("command", FIND_DENY)
def test_a_deny_that_find_runs_is_a_deny(command):
    assert verdict(command) == "deny"


@pytest.mark.parametrize("command", FIND_ALLOW)
def test_what_find_runs_on_each_file_it_finds_is_allowed_when_it_is_ordinary(command):
    assert verdict(command) == "allow"


def test_find_names_the_file_it_finds_with_a_harmless_placeholder():
    """``rm -rf {}`` deletes what find found, not a root: only a literal target in the command counts."""
    assert verdict("find . -name x -exec rm -rf {} +") == "allow"
    assert verdict("find . -name x -exec rm -rf {}/ \\;") == "allow"
    assert verdict("find / -exec rm -rf {} +") == "deny"


def test_fd_runs_a_command_like_find():
    assert verdict("fd -x rm -rf /") == "deny"
    assert verdict("fd --exec rm -rf ~ \\;") == "deny"
    assert verdict("fd -e pyc -x rm {}") == "allow"


# --- the forms of env, sudo and parallel -----------------------------------------------------------------------------------

@pytest.mark.parametrize("command", [
    "env -S 'rm -rf /'", "env -S'rm -rf /'", "env -iS'rm -rf /'", "env --split-string='rm -rf /'", "env -P /bin rm -rf /",
    "env -u A -C / rm -rf /", "env - rm -rf /", "env A=1 B=2 rm -rf /", "env -i -- rm -rf /",
    "sudo -s rm -rf /", "sudo --shell rm -rf /", "sudo -i rm -rf /", "sudo -u root -- rm -rf /",
    "parallel rm -rf ::: /", "parallel rm -rf {} ::: /", "parallel -j4 --jobs 2 rm -rf ::: /", "echo / | parallel rm -rf",
    "echo / | xargs -n 1 rm -rf", "time -f %e rm -rf /", "time rm -rf /", "exec -a x rm -rf /", "caffeinate -t 5 -w 1 rm -rf /",
    "stdbuf -oL -eL rm -rf /", "stdbuf -o L rm -rf /", "setarch -R x86_64 rm -rf /", "taskset 0x1 rm -rf /",
                                     "taskset -c0 rm -rf /",
    "chrt -d --sched-runtime 1 --sched-period 2 --sched-deadline 3 0 rm -rf /", "script -qc 'rm -rf /' /dev/null",
    "screen -dmS x rm -rf /", "ssh -o StrictHostKeyChecking=no host rm -rf /", "ssh host 'cd /tmp && rm -rf /'",
])
def test_the_spellings_of_the_wrappers_that_run_a_deny(command):
    assert verdict(command) == "deny"


def test_ssh_to_a_host_with_a_key_is_not_a_read_of_the_key():
    assert verdict("ssh -i ~/.ssh/id_ed25519 host") == "allow"
    assert verdict("ssh -i ~/.ssh/id_ed25519 host ls -la") == "allow"
    assert verdict("ssh host 'cat ~/.ssh/id_rsa'") == "deny"
