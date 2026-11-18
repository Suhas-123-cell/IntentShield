"""A program that is read as a wrapper is still a program that is given the words after it.

Some programs became wrappers after 0.4.4 (``tmux``, ``osascript``, ``zellij run`` and twenty more). Reading what they run
must not make a verdict weaker than it was when they were ordinary programs: ``tmux load-buffer ~/.ssh/id_rsa`` names a key, and
the rule that asks about a key named as an argument still sees it. The expected verdict is taken from that rule, not written down.

Every command is a string; nothing is run."""
from __future__ import annotations

import shlex

import pytest

from intentshield import dangerous
from intentshield.dangerous import assess_shell
from intentshield.dangerous.core import _EVENT_HOMES

HOME = "/Users/someone"
RANK = {"allow": 0, "ask": 1, "deny": 2}

# The wrappers and subcommand runners of 0.4.4: every other program of the tables was added after it.
IN_0_4_4 = frozenset("""
nohup command nice ionice setsid builtin timeout gtimeout chronic unbuffer xargs doas env sudo flock lockf taskset chrt unshare
nsenter chroot setpriv setarch linux32 linux64 runuser sg script strace ltrace time exec stdbuf caffeinate watch arch busybox
toybox xcrun sandbox-exec parallel sshpass ssh-agent pkexec run0 systemd-run systemd-inhibit fakeroot eatmydata fakechroot
proxychains proxychains4 torsocks tsocks faketime xvfb-run dbus-run-session dbus-launch numactl cpulimit prlimit choom screen
valgrind gdb firejail bwrap uv poetry pipenv pdm hatch rye conda mamba micromamba bundle direnv mise asdf rbenv pyenv nodenv npm
pnpm yarn""".split())


def verdict(command: str, cwd: str = "") -> str:
    hit = assess_shell(command, cwd=cwd, homes=(HOME,))
    return hit.decision if hit else "allow"


def asked_about(words: list[str]) -> bool:
    """What the rule for a key or credential file named as an argument says of ``words``, read as an ordinary program."""
    token = _EVENT_HOMES.set((HOME,))
    try:
        return dangerous._named_secret(words) is not None
    finally:
        _EVENT_HOMES.reset(token)


ADDED = sorted(dangerous._ADDED_WRAPPERS)
# What follows the program: a key, a credential file, in the positions the programs take their words.
ARGUMENTS = [
    "~/.ssh/id_rsa", "-x ~/.ssh/id_rsa y", "load-buffer ~/.ssh/id_rsa", "save-buffer ~/.ssh/id_ed25519",
    "source-file ~/.ssh/id_rsa",
    "-f ~/.ssh/id_rsa ls", "-c ~/.ssh/id_rsa", "--config-file ~/.ssh/id_rsa", "-t x ~/.ssh/id_rsa", "~/.aws/credentials",
    "/etc/shadow", "--opt=~/.ssh/id_rsa", "~/.ssh/{id_rsa,x}", "a b ~/.gnupg/secring.gpg", "run ~/.ssh/id_rsa",
]
PREFIXES = ["", "sudo ", "env A=1 ", "nohup "]


def test_every_program_of_the_wrapper_tables_is_in_0_4_4_or_in_the_added_set():
    tables = set(dangerous._WRAPPERS) | set(dangerous._SUB_RUNNERS)
    assert tables - IN_0_4_4 == set(dangerous._ADDED_WRAPPERS)
    assert len(ADDED) == 23


@pytest.mark.parametrize("program", ADDED)
def test_a_program_read_as_a_wrapper_still_asks_about_a_key_it_is_given(program):
    weaker, asks = [], 0
    for prefix in PREFIXES:
        for arguments in ARGUMENTS:
            command = f"{prefix}{program} {arguments}"
            if asked_about([program, *shlex.split(arguments)]):
                asks += 1
                if RANK[verdict(command)] < RANK["ask"]:
                    weaker.append(command)
    assert asks >= 10, "the rule that asks about a named key reads none of these calls, so nothing here is checked"
    assert not weaker, weaker[:5]


@pytest.mark.parametrize("program", ADDED)
def test_a_relative_path_to_a_key_is_read_from_the_working_directory_behind_a_wrapper_program(program):
    command, absolute = f"{program} id_rsa", [program, f"{HOME}/.ssh/id_rsa"]
    assert asked_about(absolute)
    assert RANK[verdict(command, cwd=f"{HOME}/.ssh")] >= RANK["ask"], command


@pytest.mark.parametrize("command", [
    "tmux load-buffer ~/.ssh/id_rsa", "tmux save-buffer ~/.ssh/id_rsa", "tmux source-file ~/.ssh/id_rsa",
    "tmux -f ~/.ssh/id_rsa ls", "osascript ~/.ssh/id_rsa", "alacritty --config-file ~/.ssh/id_rsa",
    "runcon -t x cat ~/.ssh/id_rsa", "zellij run ~/.ssh/id_rsa", "xterm ~/.ssh/id_rsa",
])
def test_the_calls_that_named_a_key_to_a_program_still_ask(command):
    assert RANK[verdict(command)] >= RANK["ask"], command


# --- a word ; --------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("command", [
    "watch echo a \\; rm -rf /", "watch -n1 echo a ';' rm -rf /", "watch -n1 echo a \\; cat ~/.ssh/id_rsa",
    "parallel echo a \\; rm -rf / ::: x", "watchexec -e py -- echo a \\; rm -rf /", "firejail echo a \\; rm -rf /",
    "eval echo a \\; rm -rf /", "ssh host echo a \\; rm -rf /",
])
def test_a_program_that_hands_its_words_to_a_shell_reads_a_word_semicolon_as_the_end_of_a_command(command):
    assert verdict(command) == "deny", command


# What a shell passes on as an argument: the words are literal there, so the rm is one more word of echo.
LITERAL_SEMICOLON = [
    "echo a \\; rm -rf /", "bash -c 'echo a \\; rm -rf /'", "sudo -s echo a \\; rm -rf /", "sudo -i echo a \\; rm -rf /",
    "su -c 'echo a \\; rm -rf /'", "env echo a \\; rm -rf /", "nohup echo a \\; rm -rf /", "timeout 5 echo a \\; rm -rf /",
    "xargs echo a \\; rm -rf /", "time echo a \\; rm -rf /",
]


@pytest.mark.parametrize("command", LITERAL_SEMICOLON)
def test_where_the_shell_passes_a_semicolon_on_as_an_argument_it_is_one(command):
    assert verdict(command) == "allow", command


def test_find_exec_still_ends_at_the_semicolon_and_reads_what_follows():
    assert verdict("find . -exec echo {} \\; -exec rm -rf / \\;") == "deny"
    assert verdict("find . -name x -exec echo {} \\;") == "allow"


# --- osascript -------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("command", [
    "osascript -e 'tell application \"Terminal\" to do script \"ls\"'",
    "osascript -e 'tell application \"iTerm\" to write text \"ls\"'",
    "osascript -l JavaScript -e 'Application(\"Terminal\").doScript(\"ls\")'",
    "osascript -l JavaScript -e 'app = Application.currentApplication(); app.doShellScript(\"ls\")'",
    "osascript -e 'do shell script \"rm \" & x'", "osascript -e 'set c to \"ls\"' -e 'do shell script c'",
    "osascript -e 'do shell script (\"ls\")'", "osascript <<'EOF'\nbeep\nEOF", "osascript -", "osascript < run.scpt",
    "echo beep | osascript", "osascript",
])
def test_a_script_that_runs_a_command_in_a_form_that_is_not_read_asks(command):
    assert verdict(command) == "ask", command


@pytest.mark.parametrize("command", [
    "osascript -e 'beep'", "osascript -e 'display dialog \"hi\"'", "osascript -e 'do shell script \"ls\"'",
    "osascript -e 'do shell script \"ls\" with administrator privileges'", "osascript script.scpt",
    "osascript -l JavaScript -e 'Application(\"Finder\").name()'",
])
def test_a_script_that_runs_nothing_unread_stays_as_it_is(command):
    assert verdict(command) == "allow", command


def test_do_shell_script_with_a_text_that_is_read_is_judged_by_that_text():
    assert verdict("osascript -e 'do shell script \"rm -rf /\"'") == "deny"
    assert verdict("osascript -e 'do shell script \"cat ~/.ssh/id_rsa\"'") == "deny"


# --- the options of the programs added since 0.4.4 --------------------------------------------------------------------------

@pytest.mark.parametrize("command", [
    "runcon -t x rm -rf /", "runcon -u u -r r -t t -l s0 rm -rf /", "runcon system_u:object_r:t_t rm -rf /",
    "runcon --type t rm -rf /", "dtach -c s -r winch rm -rf /", "dtach -n s -z rm -rf /", "dtach -A s -e ^x rm -rf /",
    "cgexec --sticky -g cpu:x rm -rf /", "cgexec -g cpu:x rm -rf /", "gnome-terminal -e 'rm -rf /'",
    "gnome-terminal --title t --command='rm -rf /'", "terminator -e 'rm -rf /'", "entr -s 'rm -rf /'", "entr -r -s 'rm -rf /'",
    "zellij -l layout run -- rm -rf /", "zellij --session s run -n name --cwd /tmp -- rm -rf /", "zellij run -c -- rm -rf /",
    "runcon -c rm -rf /", "runcon --compute -t t rm -rf /", "abduco -n s -e ^T rm -rf /", "abduco -e ^T -c s rm -rf /",
    "abduco -A s rm -rf /",
])
def test_the_options_of_the_added_programs_are_read_to_the_command_behind_them(command):
    assert verdict(command) == "deny", command


@pytest.mark.parametrize("command", [
    "runcon -t x ls", "dtach -n s -z ls", "cgexec --sticky -g cpu:x make", "gnome-terminal -e 'make'", "entr -s 'make test'",
    "zellij -l layout run -- ls", "runcon -c make", "abduco -n s -e ^T make", "abduco -a s",
])
def test_an_ordinary_command_behind_them_is_allowed(command):
    assert verdict(command) == "allow", command


# --- clients of a remote shell other than ssh ---------------------------------------------------------------------------------

@pytest.mark.parametrize("command", [
    "autossh -M 0 host echo a \\; rm -rf /", "rsh host echo a \\; rm -rf /", "rexec host echo a ';' rm -rf /",
    "plink -P 22 host echo a \\; rm -rf /", "mosh host -- echo a \\; rm -rf /", "slogin host echo a \\; rm -rf /",
    "tsh ssh node echo a \\; rm -rf /", "gcloud compute ssh vm -- echo a \\; rm -rf /",
])
def test_a_remote_shell_client_reads_what_follows_a_word_semicolon_as_a_command(command):
    assert verdict(command) == "deny", command


@pytest.mark.parametrize("command", [
    "autossh -M 0 host uptime", "rsh host echo a \\; ls", "gcloud compute instances list", "tsh ls",
    "gcloud compute ssh vm -- echo a \\; uptime",
])
def test_an_ordinary_remote_command_is_allowed(command):
    assert verdict(command) == "allow", command


# --- a variable set from $HOME ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("command, expected", [
    ("d=$HOME; rm -rf $d", "deny"), ("d=$HOME/; rm -rf $d", "deny"), ("d=$HOME/Documents; rm -rf $d", "deny"),
    ("d=$HOME/proj; rm -rf $d", "allow"), ("rm -rf ~/proj", "allow"), ("rm -rf ~/Documents", "deny"), ("rm -rf ~", "deny"),
])
def test_a_variable_set_from_home_is_followed_as_the_path_it_names(command, expected):
    assert verdict(command) == expected, command
