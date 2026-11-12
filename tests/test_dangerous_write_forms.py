"""A command that writes a path gets the verdict of a plain write to it, however the program is told to write.

The write forms are in-place edits (``perl -pi``, ``sed -ni``, ``awk -i inplace``), editors, copies and archives that name a
target directory (``cp -t``, ``tar -C``, ``unzip -d``), ``rsync`` and ``scp`` to a local destination, ``ln``, ``tee``, ``dd of=``
and the root of a ``find`` that deletes or runs a command. Each is tried on every class of protected path, written in full and
relative from the directory that holds the file, and must be at least as strict as the plain write; where the plain write is a
deny (an access file such as ``/etc/sudoers``, ``/etc/shadow``, ``authorized_keys``) it must be that deny. Ordinary uses stay
allowed.

The paths the interpreters and shells are given are read from the working directory like any program's."""
from __future__ import annotations

import posixpath
from pathlib import Path

import pytest

from intentshield.dangerous import assess_shell
from intentshield.dangerous.writes import written_paths

HOMES = ["/Users/x", "/workspace", "/mnt/c/Users/x"]
_RANK = {"allow": 0, "ask": 1, "deny": 2}

# Protected paths: access files, keys, cloud credentials, startup and persistence files, the guard's own files.
PROTECTED = [
    "/etc/sudoers", "/etc/sudoers.d/90-x", "/etc/shadow", "/etc/passwd", "/etc/ld.so.preload",
    "~/.ssh/authorized_keys", "~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.aws/credentials", "~/.netrc",
    "~/.bashrc", "~/.zshrc", "~/.profile", "~/.config/autostart/x.desktop", "~/Library/LaunchAgents/x.plist",
    "/etc/cron.d/job", "~/proj/.git/hooks/pre-commit", "~/proj/.github/workflows/ci.yml",
    "~/.claude/settings.json", "~/.intentshield/state.db",
]

# In-place edits and editors: the plain write is ``sed -i``, which reads the file as well as writing it.
EDITS = [
    "perl -pi -e 1 {p}", "perl -ni -e print {p}", "perl -pi.bak -e 1 {p}", "perl -i.bak -pe 1 {p}", "perl -lpi -e 1 {p}",
    "perl -0pi -e 1 {p}", "perl -0777pi -e 1 {p}", "perl -0777 -pi -e 1 {p}", "perl -i -pe 1 {p}", "perl -lni.orig -e 1 {p}",
    "perl -pi script.pl {p}", "ruby -pi -e 1 {p}", "ruby -ni -e 1 {p}", "ruby -i.bak -pe 1 {p}", "ruby -lpi -e 1 {p}",
    "sed -i s/a/b/ {p}", "sed -ni p {p}", "sed -i.bak s/a/b/ {p}", "sed -Ei s/a/b/ {p}", "sed -nEi p {p}",
    "sed --in-place s/a/b/ {p}", "sed --in-place=.bak s/a/b/ {p}", "sed --in-pl s/a/b/ {p}", "sed -i -e s/a/b/ {p}",
    "sed -n -i p {p}", "sed -i -e s/a/b/ -e s/c/d/ {p}", "sed -i '' s/a/b/ {p}", "sed -i -f script.sed {p}",
    "awk -i inplace 1 {p}", "gawk -i inplace 1 {p}", "gawk -iinplace 1 {p}", "gawk --include=inplace 1 {p}",
    "gawk -i inplace -v x=1 1 {p}", "gawk -i inplace -f prog.awk {p}",
    "vim {p}", "vi {p}", "nvim {p}", "nano {p}", "emacs {p}", "ed {p}", "ex {p}", "vim -es {p}", "ex -s {p}", "ed -s {p}",
    "vim -u NONE -es {p}", "vim -c wq {p}", "nvim --headless {p}", "emacs --batch {p}", "emacs -nw {p}", "nano -w {p}",
    "nano +5 {p}", "vim +10 {p}",
]

# Copies, archives, links and the roots of a find that deletes or runs a command: the plain write is a redirect or
# ``cp /tmp/x PATH`` (the two give the same verdict on every path below).
COPIES = [
    "find {p} -delete", "find {p} -type f -exec rm -rf {} +", "find {p} -type f -exec shred {} \\;",
    "find {p} -execdir rm {} \\;",
    "find {p} -ok rm {} \\;", "find {p} -name x -exec sh -c true {} +", "find . -name x -exec rm -rf {p} \\;",
    "find . -name x -execdir rm {p} \\;", "find . -type f -exec cp x {p} \\;", "find . -fprint {p}",
    "cp /tmp/x {p}", "cp -t {p} /tmp/x", "cp --target-directory={p} /tmp/x", "cp --target-directory {p} /tmp/x",
    "cp --target-dir={p} /tmp/x", "cp -at {p} /tmp/x", "cp -t{p} /tmp/x", "cp -T /tmp/x {p}", "mv -t {p} /tmp/x",
    "mv --target-directory={p} /tmp/x", "install -t {p} /tmp/x", "install -m 644 -t {p} /tmp/x", "install /tmp/x {p}",
    "install -m 600 /tmp/x {p}", "install -d {p}", "ln -s /tmp/x {p}", "ln -sf /tmp/x {p}", "ln -t {p} /tmp/x",
    "rsync -a /tmp/x {p}", "rsync -e ssh /tmp/x {p}", "rsync -a -e 'ssh -p 22' /tmp/x {p}", "scp host:x {p}",
    "scp -i key host:x {p}", "scp -P 22 host:x {p}",
    "tar -xf /tmp/o.tar -C {p}", "tar -xf /tmp/o.tar --directory={p}", "tar -C {p} -xzf a.tgz", "tar xf a.tar -C {p}",
    "tar xzf a.tar.gz --directory {p}", "tar -xvf /tmp/o.tar -C {p} --strip-components=1", "tar -xf a.tar -C {p} --overwrite",
    "tar -cf {p} src", "tar -czf {p} src", "tar -rf {p} src",
    "unzip a.zip -d {p}", "unzip -o a.zip -d{p}", "unzip -q -o a.zip -d {p}",
    "tee {p}", "tee -a {p}", "echo x | tee {p}", "dd of={p}", "dd if=/tmp/x of={p}", "dd if=/tmp/x of={p} bs=1M",
    "dcfldd if=/tmp/x of={p}",
]


def verdict(command: str, cwd: str = "") -> str:
    hit = assess_shell(command, cwd=cwd)
    return hit.decision if hit else "allow"


@pytest.fixture
def at_home(monkeypatch):
    def use(home: str) -> None:
        monkeypatch.setenv("HOME", home)
        monkeypatch.delenv("USERPROFILE", raising=False)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: Path(home)))
    return use


def _full(path: str, home: str) -> str:
    return home + path[1:] if path.startswith("~") else path


def _cases(forms: list[str]):
    return [(form, path) for form in forms for path in PROTECTED]


def _check(form: str, path: str, plain_form: str, home: str) -> None:
    absolute = _full(path, home)
    plain = verdict(plain_form.replace("{p}", absolute))
    assert plain != "allow", f"{plain_form} {absolute} is allowed, so it is no baseline"
    written = verdict(form.replace("{p}", absolute))
    assert _RANK[written] >= _RANK[plain], f"{form} {absolute}: {written}, a plain write is {plain}"
    if plain == "deny":
        assert written == "deny", f"{form} {absolute}: {written}, a plain write is deny"
    directory, name = posixpath.split(absolute)
    relative = verdict(form.replace("{p}", name), directory)
    assert _RANK[relative] >= _RANK[plain], f"{form.replace('{p}', name)} from {directory}: {relative}, a plain write is {plain}"
    if plain == "deny":
        assert relative == "deny", f"{form.replace('{p}', name)} from {directory}: {relative}, a plain write is deny"


@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize(("form", "path"), _cases(EDITS))
def test_an_in_place_edit_or_editor_gets_the_verdict_of_sed_in_place(at_home, home, form, path):
    at_home(home)
    _check(form, path, "sed -i s/a/b/ {p}", home)


@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize(("form", "path"), _cases(COPIES))
def test_a_copy_archive_link_or_find_gets_the_verdict_of_a_plain_write(at_home, home, form, path):
    at_home(home)
    _check(form, path, "echo x > {p}", home)
    _check(form, path, "cp /tmp/x {p}", home)


# --- ordinary uses stay allowed ---------------------------------------------------------------------------------------------

ORDINARY = [
    "perl -pi -e s/a/b/ main.py", "perl -pi -e 1 src/app.py", "perl -pi.bak -e s/a/b/ src/*.py", "perl -ne print notes.txt",
    "perl -e 1", "perl script.pl input.txt", "ruby -pi -e 1 app.rb", "ruby x.rb input",
    "sed -i s/a/b/ README.md", "sed -ni p notes.txt", "sed -i.bak s/a/b/ src/*.py", "sed -n p input.txt",
    "sed -e s/a/b/ input.txt",
    "awk -i inplace 1 data.csv", "awk '{print $1}' data.csv", "gawk -i inplace -f prog.awk data.csv",
    "vim README.md", "vi notes.txt", "nvim src/main.py", "nano notes.txt", "emacs -nw notes.org", "emacs --batch -l init.el",
    "ed -s config.txt", "ex -s -c wq file.txt", "vim -u NONE -es README.md", "vim -c 'set ft=sh' README.md",
    "cp -t build src/*.py", "cp -t build a.py b.py", "cp --target-directory=build a.py", "cp -at build src/a.py",
    "mv -t out x.txt", "install -m 755 -t bin tool", "install -d build/out", "cp a.py b.py", "cp -r src build/",
    "tar -C /tmp/x -xf a.tar", "tar -xzf a.tgz -C build", "tar xf a.tar -C build", "tar -czf out.tgz src", "tar -cf out.tar src",
    "tar -tf a.tar", "tar -xf a.tar", "unzip a.zip -d out", "unzip -o a.zip -d build", "unzip -l a.zip", "unzip a.zip",
    "rsync -a src/ build/", "scp host:x.log .",
    "ln -s target link", "ln -sf ../shared build/shared", "tee out.log", "echo x | tee -a out.log", "dd if=in of=out.img",
    "find . -name '*.pyc' -exec rm {} +", "find . -name '*.o' -delete", "find build -type f -exec chmod 644 {} +",
    "find . -name x -exec grep -l foo {} +", "find src -name '*.py' -exec sed -i s/a/b/ {} +", "find . -type f -exec cat {} +",
    "find . -fprint files.txt", "find /tmp/x -name '*.log' -delete",
    "python3 script.py data.txt", "python3 -m json.tool data.json", "python3 -m pytest tests", "node app.js config.json",
    "ruby x.rb input", "bash run.sh build", "sh run.sh", "perl script.pl notes.txt", "php x.php input",
]


@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize("cwd", ["/Users/x/proj", "/workspace/proj", "/tmp/build", "/srv/app/src"])
def test_ordinary_uses_of_the_write_forms_stay_allowed(at_home, home, cwd):
    at_home(home)
    wrong = [f"{c!r}: {verdict(c, cwd)}" for c in ORDINARY if verdict(c, cwd) != "allow"]
    assert not wrong, f"from {cwd}: {wrong}"


# --- the paths of interpreters and shells ----------------------------------------------------------------------------------

RUNNERS = ["python3 script.py {n}", "python3 -u script.py {n}", "node app.js {n}", "ruby x.rb {n}", "python3 -m json.tool {n}",
           "bash run.sh {n}", "sh run.sh {n}", "perl script.pl {n}", "php x.php {n}", "python3 -c pass {n}", "bash -c true {n}",
           "perl -e 1 {n}"]
NAMED = [("~/.ssh", "id_rsa"), ("~/.ssh", "id_ed25519"), ("~/.aws", "credentials"), ("/etc", "shadow")]


@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize("form", RUNNERS)
@pytest.mark.parametrize(("where", "name"), NAMED)
def test_a_relative_path_given_to_an_interpreter_or_shell_gets_the_verdict_of_the_absolute_one(at_home, home, form, where, name):
    at_home(home)
    directory = _full(where, home)
    expected = verdict(form.replace("{n}", f"{directory}/{name}"))
    assert expected != "allow", f"{form} {directory}/{name} is allowed, so it is no baseline"
    assert verdict(form.replace("{n}", name), directory) == expected, f"{form} {name} from {directory}"


@pytest.mark.parametrize("home", HOMES)
def test_a_cd_before_an_interpreter_moves_its_relative_paths_too(at_home, home):
    at_home(home)
    assert verdict("cd /etc && python3 script.py shadow", "/tmp") == verdict("python3 script.py /etc/shadow") == "deny"
    assert verdict(f"cd {home}/.ssh && node app.js id_rsa", "/tmp") == verdict(f"node app.js {home}/.ssh/id_rsa") == "deny"


@pytest.mark.parametrize("home", HOMES)
def test_a_relative_name_inside_code_given_with_c_is_not_read(at_home, home):
    """The limit that is documented: the text of ``python3 -c`` or ``bash -c`` is read as written, so a name in it is not
    read from the working directory."""
    at_home(home)
    assert verdict("python3 -c \"open('shadow').read()\"", "/etc") == verdict("python3 -c \"open('shadow').read()\"")


def test_code_given_to_an_interpreter_is_not_taken_for_a_path(at_home):
    at_home("/Users/x")
    assert verdict("python3 -c 'print(1)' notes.txt", "/Users/x/.ssh") != "deny"
    assert verdict("bash -c 'ls build' notes", "/etc") == "allow"


# --- the parser of option clusters ------------------------------------------------------------------------------------------

WRITES = [
    ("perl", ["perl", "-pi", "-e", "1", "f"], ["f"]),
    ("perl", ["perl", "-ni", "-e", "1", "f", "g"], ["f", "g"]),
    ("perl", ["perl", "-lpi.bak", "-e", "1", "f"], ["f"]),
    ("perl", ["perl", "-0777pi", "-e", "1", "f"], ["f"]),
    ("perl", ["perl", "-i.bak", "-pe", "1", "f"], ["f"]),
    ("perl", ["perl", "-pi", "script.pl", "f"], ["f"]),
    ("perl", ["perl", "-pe", "1", "f"], []),
    ("perl", ["perl", "-ne", "print", "f"], []),
    ("perl", ["perl", "-e", "1", "f"], []),
    ("perl", ["perl", "-lne", "print", "f"], []),
    ("ruby", ["ruby", "-pi", "-e", "1", "f"], ["f"]),
    ("ruby", ["ruby", "-i.bak", "-ne", "1", "f"], ["f"]),
    ("ruby", ["ruby", "-ne", "1", "f"], []),
    ("sed", ["sed", "-ni", "p", "f"], ["f"]),
    ("sed", ["sed", "-i.bak", "s/a/b/", "f"], ["f"]),
    ("sed", ["sed", "-Ei", "s/a/b/", "f"], ["f"]),
    ("sed", ["sed", "--in-place=.bak", "s/a/b/", "f"], ["f"]),
    ("sed", ["sed", "-i", "-e", "s/a/b/", "f"], ["f"]),
    ("sed", ["sed", "-i", "", "s/a/b/", "f"], ["f"]),
    ("sed", ["sed", "-n", "p", "f"], []),
    ("sed", ["sed", "-e", "p", "-s", "f"], []),
    ("sed", ["sed", "-n", "-e", "p", "f"], []),
    ("gawk", ["gawk", "-i", "inplace", "1", "f"], ["f"]),
    ("gawk", ["gawk", "-iinplace", "-v", "x=1", "1", "f", "y=2", "g"], ["f", "g"]),
    ("awk", ["awk", "--include=inplace", "1", "f"], ["f"]),
    ("gawk", ["gawk", "-i", "other.awk", "1", "f"], []),
    ("awk", ["awk", "1", "f"], []),
    ("vim", ["vim", "-u", "NONE", "-c", "wq", "+5", "f"], ["f"]),
    ("vim", ["vim", "-es", "f", "g"], ["f", "g"]),
    ("nano", ["nano", "-r", "80", "+3", "f"], ["f"]),
    ("emacs", ["emacs", "--batch", "-l", "init.el", "--eval", "(x)", "f"], ["f"]),
    ("ed", ["ed", "-s", "-p", "> ", "f"], ["f"]),
    ("cp", ["cp", "-t", "d", "a", "b"], ["d", "d/a", "d/b"]),
    ("cp", ["cp", "-at", "d", "a"], ["d", "d/a"]),
    ("cp", ["cp", "-td", "a"], ["d", "d/a"]),
    ("cp", ["cp", "--target-directory=d", "a"], ["d", "d/a"]),
    ("cp", ["cp", "--target-directory", "d", "a"], ["d", "d/a"]),
    ("cp", ["cp", "a", "b"], ["b"]),
    ("cp", ["cp", "a", "d/"], ["d/", "d/a"]),
    ("install", ["install", "-m", "644", "-t", "d", "a"], ["d", "d/a"]),
    ("install", ["install", "-m", "644", "a", "b"], ["b"]),
    ("ln", ["ln", "-s", "a", "b"], ["b"]),
    ("rsync", ["rsync", "-e", "ssh", "a", "b"], ["b"]),
    ("rsync", ["rsync", "-a", "a", "host:b"], []),
    ("scp", ["scp", "-i", "k", "host:a", "b"], ["b"]),
    ("scp", ["scp", "a", "user@host:/etc/b"], []),
    ("tar", ["tar", "-xf", "a.tar", "-C", "d"], ["d"]),
    ("tar", ["tar", "xzf", "a.tgz", "--directory=d", "m"], ["d", "d/m"]),
    ("tar", ["tar", "-C", "d", "-xf", "a.tar", "etc/m"], ["d", "d/etc/m"]),
    ("tar", ["tar", "-xf", "a.tar"], []),
    ("tar", ["tar", "-xOf", "a.tar", "-C", "d"], []),
    ("tar", ["tar", "-czf", "out.tgz", "src"], ["out.tgz"]),
    ("tar", ["tar", "-tf", "a.tar"], []),
    ("unzip", ["unzip", "a.zip", "-d", "d"], ["d"]),
    ("unzip", ["unzip", "-o", "a.zip", "m", "-d", "d"], ["d", "d/m"]),
    ("unzip", ["unzip", "a.zip", "-x", "skip", "-d", "d"], ["d"]),
    ("unzip", ["unzip", "-l", "a.zip", "-d", "d"], []),
    ("tee", ["tee", "-a", "f"], ["f"]),
    ("dd", ["dd", "if=a", "of=f", "bs=1M"], ["f"]),
    ("find", ["find", "r", "-delete"], ["r"]),
    ("find", ["find", "r", "-name", "x", "-exec", "rm", "{}", "+"], ["r"]),
    ("find", ["find", "r", "-exec", "cat", "{}", ";"], []),
    ("find", ["find", ".", "-exec", "rm", "-rf", "/p", ";"], [".", "/p"]),
    ("find", ["find", "r", "-fprint", "o"], ["o"]),
    ("find", ["find", "-L", "r", "-type", "f"], []),
]


@pytest.mark.parametrize(("name", "argv", "expected"), WRITES)
def test_the_paths_a_command_writes(name, argv, expected):
    assert written_paths(name, argv) == expected


def test_the_targets_of_redirects_are_written_paths():
    assert written_paths("echo", ["echo", "x"], [(">", "f"), (">>", "g"), ("<", "h"), (">", "/dev/null")]) == ["f", "g"]


@pytest.mark.parametrize("command", [
    "install -t ~/.ssh /tmp/authorized_keys",
    "ln -s -t ~/.ssh /tmp/authorized_keys",
    "mv --target-directory=~/.ssh /tmp/authorized_keys",
    "cp -t~/.ssh /tmp/authorized_keys",
    "cp -at~/.ssh /tmp/authorized_keys",
])
def test_a_copy_into_the_ssh_directory_is_judged_by_the_access_file_it_makes(command):
    hit = assess_shell(command, cwd="/tmp/proj")
    assert hit is not None and hit.decision == "deny" and "authorized_keys" in hit.reason


def test_a_copy_into_the_ssh_directory_of_an_ordinary_file_still_asks():
    hit = assess_shell("install -t ~/.ssh /tmp/config", cwd="/tmp/proj")
    assert hit is not None and hit.decision == "ask"


@pytest.mark.parametrize("program", ["dd", "dcfldd", "dc3dd"])
def test_dd_and_its_variants_get_one_verdict_over_a_key_and_none_on_project_images(program):
    over_key = assess_shell(f"{program} if=/tmp/x of=~/.ssh/id_rsa", cwd="/tmp/proj")
    assert over_key is not None and over_key.decision == "deny"
    assert assess_shell(f"{program} if=in.img of=out.img", cwd="/tmp/proj") is None
