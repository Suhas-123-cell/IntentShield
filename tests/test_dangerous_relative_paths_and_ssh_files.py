"""A relative path means the same target as the absolute one, files in ~/.ssh are told apart by what they are, and a redirect
over a key asks like the Write tool does. Benign marker text only: no test holds a real key."""
from __future__ import annotations

from pathlib import Path

import pytest

from intentshield.dangerous import assess_file, assess_shell


def verdict(command: str, cwd: str = "") -> str:
    hit = assess_shell(command, cwd=cwd)
    return hit.decision if hit else "allow"


def file_verdict(path: str, write: bool = False, cwd: str = "", content: str = "") -> str:
    hit = assess_file(path, content, write=write, cwd=cwd)
    return hit.decision if hit else "allow"


# --- a relative path from the event's working directory ---------------------------------------------------------

# (a command with an absolute target, the same command spelled relative, the directory it runs in)
SAME_TARGET = [
    ("cat /etc/shadow", "cat etc/shadow", "/"),
    ("cat /etc/shadow", "cat ../../etc/shadow", "/tmp/proj"),
    ("cat /etc/shadow", "cat ./etc/../etc/shadow", "/"),
    ("head -n1 /etc/shadow", "head -n1 shadow", "/etc"),
    ("rm -rf /usr", "rm -rf ../../usr", "/tmp/proj"),
    ("rm -rf /etc", "rm -rf etc", "/"),
    ("rm -rf /etc", "rm -rf ../etc", "/tmp"),
    ("rm -rf /", "rm -rf ../../..", "/Users/x/proj"),
    ("rm -rf /", "rm -rf ../../..", "/home/dev/proj"),
    ("rm -rf /Users", "rm -rf ../..", "/Users/x/proj"),
    ("find / -delete", "find ../.. -delete", "/Users/x"),
    ("rm -rf /var/log", "rm -rf *", "/var/log"),
    ("rm -rf ~/Documents", "rm -rf Documents", "/Users/x"),
    ("chmod -R 777 /usr", "chmod -R 777 ../../usr", "/tmp/proj"),
    ("chown -R nobody /etc", "chown -R nobody etc", "/"),
    ("find /usr -delete", "find usr -delete", "/"),
    ("mv /usr /tmp/gone", "mv usr /tmp/gone", "/"),
    ("sudo cat /etc/sudoers", "sudo cat etc/sudoers", "/"),
    ("cat /proc/self/environ", "cat proc/self/environ", "/"),
]


@pytest.mark.parametrize(("absolute", "relative", "cwd"), SAME_TARGET)
def test_a_relative_path_gets_the_verdict_of_the_absolute_one(absolute: str, relative: str, cwd: str):
    expected = verdict(absolute)
    assert expected != "allow", "the absolute spelling is an objection"
    assert verdict(relative, cwd) == expected


@pytest.mark.parametrize(("path", "cwd", "write"), [("etc/shadow", "/", False), ("../../etc/shadow", "/tmp/proj", False),
                                                    ("shadow", "/etc", False), ("etc/sudoers", "/", False),
                                                    ("../.ssh/id_rsa", "/Users/x/proj", False)])
def test_the_file_tools_read_a_relative_path_from_the_working_directory(path: str, cwd: str, write: bool):
    assert file_verdict(path, write=write, cwd=cwd) != "allow"


def test_the_whole_home_directory_by_a_relative_path_asks():
    assert file_verdict("..", cwd="/Users/x/proj") == file_verdict("~") == "ask"


@pytest.mark.parametrize(("command", "cwd"), [("cat etc/shadow", ""), ("rm -rf usr", ""), ("rm -rf usr", "relative/dir"),
                                              ("cat etc/shadow", "/tmp/proj")])
def test_without_a_working_directory_or_from_a_project_a_relative_path_stays_a_project_file(command: str, cwd: str):
    assert verdict(command, cwd) == "allow"


@pytest.mark.parametrize("command", ["rm -rf build", "rm -rf node_modules dist", "cat README.md", "chmod -R 755 scripts",
                                     "find . -name '*.pyc' -delete", "rm -rf ./build/*", "mv a.txt b.txt"])
def test_ordinary_project_work_from_a_project_directory_is_not_held(command: str):
    assert verdict(command, "/Users/x/proj") == "allow"
    assert verdict(command, "/tmp/proj") == "allow"


def test_a_cd_inside_the_command_moves_the_directory_a_relative_target_is_read_from():
    assert verdict("cd / && rm -rf usr", "/tmp/proj") == "deny"
    assert verdict("cd /tmp/proj && rm -rf usr", "/") == "allow"
    assert verdict("cd / && cat etc/shadow", "/tmp/proj") == "deny"


def test_a_shell_started_by_the_command_reads_its_relative_paths_from_the_same_directory():
    assert verdict("bash -c 'cat etc/shadow'", "/") == "deny"
    assert verdict("bash -c 'rm -rf usr'", "/") == "deny"
    assert verdict("cd /tmp/proj && bash -c 'rm -rf usr'", "/") == "allow"
    assert verdict("cd / && bash -c 'rm -rf usr'", "/tmp/proj") == "deny"


# --- ~/.ssh ------------------------------------------------------------------------------------------------------

@pytest.fixture
def ssh(tmp_path: Path, monkeypatch) -> Path:
    home = tmp_path / "home"
    (home / ".ssh" / "config.d").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    return home / ".ssh"


NOT_SECRET = ["config", "config.bak", "config~", "known_hosts", "known_hosts.old", "known_hosts.bak", "authorized_keys",
              "authorized_keys.bak", "environment", "rc", "allowed_signers", "config.d/work", "id_ed25519.pub"]


@pytest.mark.parametrize("name", NOT_SECRET)
def test_a_file_of_hosts_options_or_public_keys_is_not_held(ssh: Path, name: str):
    path = f"~/.ssh/{name}"
    assert verdict(f"cat {path}") == "allow"
    assert file_verdict(path) == "allow"


def test_a_glob_over_the_config_directory_is_not_held_but_one_over_the_whole_directory_is(ssh: Path):
    assert verdict("grep Host ~/.ssh/config.d/*") == "allow"
    assert verdict("cat ~/.ssh/*") == "deny"


@pytest.mark.parametrize("name", ["id_rsa", "id_ed25519", "id_rsa.bak", "id_rsa_work", "id_ecdsa_sk", "work_rsa", "deploy.pem",
                                  "github_ed25519", "identity", "server.key"])
def test_a_key_by_its_name_is_a_deny_and_says_so(ssh: Path, name: str):
    hit = assess_shell(f"cat ~/.ssh/{name}")
    assert hit and hit.decision == "deny" and "SSH private key" in hit.reason


def test_a_file_that_holds_a_private_key_is_a_deny_whatever_its_name(ssh: Path):
    (ssh / "work").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nnot a real key\n-----END OPENSSH PRIVATE KEY-----\n")
    (ssh / "config.bak").write_text("-----BEGIN RSA PRIVATE KEY-----\nnot a real key\n")
    for name in ("work", "config.bak"):
        hit = assess_shell(f"cat ~/.ssh/{name}")
        assert hit and hit.decision == "deny" and "SSH private key" in hit.reason
    assert file_verdict("~/.ssh/work") == "deny"
    assert file_verdict(str(ssh / "work")) == "deny"


def test_any_other_file_in_the_directory_is_asked_about_and_the_reason_says_what_it_is(ssh: Path):
    (ssh / "notes").write_text("remember to rotate the deploy key\n")
    for name in ("notes", "github", "work_key", "missing-file"):
        hit = assess_shell(f"cat ~/.ssh/{name}")
        assert hit and hit.decision == "ask"
        assert "not a known public one" in hit.reason and "may be a private key" in hit.reason
    assert file_verdict("~/.ssh/notes") == "ask"


def test_an_unknown_file_is_asked_about_when_it_is_written_too(ssh: Path):
    assert file_verdict("~/.ssh/github", write=True) == "ask"
    assert verdict("echo x > ~/.ssh/github") == "ask"


def test_removing_a_copy_of_the_config_is_not_held_but_removing_a_key_asks(ssh: Path):
    assert verdict("rm -f ~/.ssh/config.bak") == "allow"
    assert verdict("diff ~/.ssh/config ~/.ssh/config.bak") == "allow"
    assert verdict("rm -f ~/.ssh/id_rsa") == "ask"


def test_a_relative_path_to_a_key_file_is_read_from_the_working_directory(ssh: Path):
    (ssh / "work").write_text("-----BEGIN PRIVATE KEY-----\nnot a real key\n")
    assert verdict("cat work", str(ssh)) == "deny"
    assert verdict("cat .ssh/work", str(ssh.parent)) == "deny"
    assert verdict("cat config", str(ssh)) == "allow"


# --- a redirect over a key or a cloud credential ----------------------------------------------------------------

REDIRECTS = [
    ("> ~/.ssh/id_rsa", "~/.ssh/id_rsa"),
    (": > ~/.ssh/id_rsa", "~/.ssh/id_rsa"),
    ("echo x > ~/.ssh/id_rsa", "~/.ssh/id_rsa"),
    ("echo x >> ~/.ssh/id_ed25519", "~/.ssh/id_ed25519"),
    ("cat /dev/null > ~/.ssh/id_rsa", "~/.ssh/id_rsa"),
    ("> ~/.aws/credentials", "~/.aws/credentials"),
    ("cp /tmp/x ~/.ssh/id_rsa", "~/.ssh/id_rsa"),
]


@pytest.mark.parametrize(("command", "path"), REDIRECTS)
def test_a_redirect_over_a_key_asks_like_the_write_tool(command: str, path: str):
    assert file_verdict(path, write=True) == "ask"
    hit = assess_shell(command)
    assert hit and hit.decision == "ask" and path in hit.reason


@pytest.mark.parametrize("command", ["echo x > notes.txt", "echo x > ~/.ssh/known_hosts", "echo x >> ~/.bashrc.bak",
                                     "echo x > /dev/null", "cat ~/.ssh/id_rsa.pub > /tmp/key.pub", "echo x > ~/.aws/config"])
def test_a_redirect_that_overwrites_no_key_is_not_made_an_ask_by_this_rule(command: str):
    hit = assess_shell(command)
    assert hit is None or "private key" not in hit.reason and "credential store" not in hit.reason


# --- what rm -rf is denied for, by other programs ---------------------------------------------------------------

@pytest.mark.parametrize("command", ["rsync -a --delete /tmp/empty/ /", "rsync -a --delete-before /tmp/empty/ ~/",
                                     "rsync -a --delete-after /tmp/empty/ /usr/", "rsync -a --del /tmp/empty/ ~",
                                     "rsync -a --remove-source-files / /tmp/x", "tar --remove-files -czf x.tgz /",
                                     "tar --remove-f -czf x.tgz ~", "chattr -R +i /", "chattr -R -i /usr", "rm -rf ~/.[a-z]*",
                                     "rm -rf ~/.??*", "rm -rf ~/.[!.]*"])
def test_other_ways_to_wipe_a_root_home_or_system_directory_are_denied(command: str):
    assert verdict(command) == "deny"


@pytest.mark.parametrize("command", ["rsync -a --delete build/ host:/var/www/", "rsync -a --delete src/ backup/",
                                     "rsync -av src/ ~/backup/", "tar -czf x.tgz src", "tar --remove-files -czf x.tgz build",
                                     "chattr +i notes.txt", "rm -rf ~/.cache/pip", "rm -rf ./.[a-z]*"])
def test_the_same_programs_on_ordinary_targets_are_not_denied(command: str):
    assert verdict(command) != "deny"
