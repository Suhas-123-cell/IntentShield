"""The rules of one command: git, rm, find, disks, modes, persistence and what a command sends over the network."""
from __future__ import annotations

import re
import shlex

from intentshield import shell

from .core import ASK, DENY, Hit, _bin, _canon, _is_opt, _Stage
from .paths import (
    _cred_args,
    _cred_level,
    _default_target,
    _device,
    _is_empty_var_target,
    _norm,
    _protected,
    _system,
    persistence_path,
)
from .selfguard import guard_surface

# --- the rules ---------------------------------------------------------------------------------------------------

_FORK_BOMB = re.compile(r"([\w:.-]{1,40})\s{0,3}\(\s{0,3}\)\s{0,3}\{[^}]{0,120}?\|\s{0,3}[\w:.-]{1,40}\s{0,3}&?[^}]{0,60}\}")
_FORK_LOOP = re.compile(r"\bwhile\s+(?:true|:|\[\s{0,3}1\s{0,3}\]|\(\(\s{0,3}1\s{0,3}\)\))\s{0,3};\s{0,3}do\s[^;&|]{0,60}"
                        r"(?:\$0|\bsh\b|\bbash\b|\bzsh\b|\byes\b|\$SHELL)[^;|]{0,40}&\s{0,3}(?:;\s{0,3})?done")
_FORK_CODE = re.compile(r"os\.fork\(\)|\bfork\s+while\b|while\s*\(?\s*(?:1|true)\s*\)?\s*[{:]?\s*(?:os\.)?fork\b|"
                        r"forkbomb|:\(\)\s*\{", re.I)
_PIPE_SHELL_SUBST = re.compile(r"(?:\b(?:ba|z|da|k)?sh|\beval|\bsource|\bpython3?|\bperl|\bruby|\bnode|\.)\s{1,5}"
                               r"(?:-[a-z]{1,3}\s{1,5})?(?:[\"']?\$\(|<\(|[\"']?`)\s{0,5}(?:sudo\s{1,5})?(?:curl|wget|fetch)\b")
_REVERSE_SHELL = re.compile(r"/dev/(?:tcp|udp)/[^\s/'\"]{1,100}/\d{1,5}|\bnc(?:at)?\s[^;|&]{0,60}-[a-z]{0,4}[ec]\s|"
                            r"\bsocat\b[^;|&]{0,80}\bexec:|\bbash\s{1,4}-i\s{1,4}>&|\bsh\s{1,4}-i\s{1,4}>&", re.I)
_REVERSE_STRICT = re.compile(r"(?:\bbash|\bsh|\bzsh)\s{1,4}-i\s{1,4}>&?\s{0,3}/dev/(?:tcp|udp)/|\bnc(?:at)?\s[^;|&]{0,60}\s"
                             r"-[a-z]{0,4}[ec]\s{1,4}"
                             r"[\w/.-]{1,40}\b|\bsocat\b[^;|&]{0,80}\bexec:", re.I)
# ``exec 3<>/dev/tcp/host/80`` alone is how a script probes a port. It is a shell handed to the socket when something is
# read from the socket and run, or a shell is told to use it.
_EXEC_SOCKET = re.compile(r"\bexec\s{1,4}\d{1,2}<>\s{0,3}/dev/(?:tcp|udp)/", re.I)
_SOCKET_FEED = re.compile(r"\bwhile\b[^;\n]{0,40}\bread\b|(?:^|[|;&\s(])(?:ba|z|da|k)?sh\b|\beval\b|<&\s{0,3}\d|"
                          r"\$\{?line\b", re.I)

_RM_SHORT_RECURSIVE = frozenset("rR")
_PROTECTED_BRANCH = re.compile(r"^(?:main|master|develop|development|dev|trunk|prod|production|stable|staging|release|"
                               r"release/[\w.-]{1,40}|release-v?\d[\w.-]{0,40}|releases/[\w.-]{1,40}|hotfix|next|latest)$")
_WORLD_WRITABLE = re.compile(r"^[0-7]?[0-7]{2}[2367]$|(?:^|,)(?:[ao]|ugo)[+=][rwxXst]{0,4}w|^a[+=]rwx|^[+=]rwx")
_SETUID = re.compile(r"^[4-7][0-7]{3}$|(?:^|,)[ugo]{0,3}\+[rwxXt]{0,3}s")


def path_risk(path: str) -> bool:
    """True for a path the file rules look at."""
    return bool(_cred_level(path) or persistence_path(path) or guard_surface(path))


def _git(argv: list[str]) -> tuple[str, list[str], list[str]]:
    """(subcommand, its arguments, the ``-c k=v`` settings) of a git command."""
    args, settings, i = argv[1:], [], 0
    while i < len(args):
        a = args[i]
        if a == "-c" and i + 1 < len(args):
            settings.append(args[i + 1])
            i += 2
        elif a in ("-C", "--git-dir", "--work-tree", "--namespace", "--exec-path") and i + 1 < len(args):
            i += 2
        elif a.startswith("-c") and len(a) > 2 and "=" in a:
            settings.append(a[2:])
            i += 1
        elif a.startswith("-"):
            i += 1
        else:
            return a, args[i + 1:], settings
    return "", [], settings


def _branch(ref: str) -> str:
    ref = ref.lstrip("+")
    ref = ref.rpartition(":")[2] if ":" in ref else ref
    ref = ref.removeprefix("refs/heads/")
    return ref


_GIT_CONFIG_READS = ("--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "--unset", "--unset-all")


def _sets_hooks_path(args: list[str]) -> bool:
    """``git config core.hooksPath VALUE`` (or ``--add``, ``--replace-all``) sets it; ``--get``, ``--list``, ``--unset`` and a
    name with no value read it or put the repository's own hooks back."""
    if any(_is_opt(a, *_GIT_CONFIG_READS) or a == "-l" for a in args if a.startswith("-")):
        return False
    positional = [a for a in args if not a.startswith("-")]
    return any(a.lower().startswith("core.hookspath") and ("=" in a or k + 1 < len(positional)) for k, a in enumerate(positional))


def _git_hit(argv: list[str], assigns: list[str]) -> Hit | None:
    sub, args, settings = _git(argv)
    flags = [a for a in args if a.startswith("-")]
    hooks = [s for s in settings if s.lower().startswith(("core.hookspath", "core.fsmonitor"))]
    if hooks:
        return Hit(ASK, "git run with a hooks path or fsmonitor override, which bypasses or replaces the repository's hooks.")
    if any(a.split("=")[0].upper() in ("HUSKY", "HUSKY_SKIP_HOOKS", "SKIP", "PRE_COMMIT_ALLOW_NO_CONFIG") for a in assigns):
        return Hit(ASK, "git run with the hook-skipping environment variable set.")
    if sub in ("commit", "push", "merge", "am", "cherry-pick", "rebase", "revert") and any(_is_opt(a, "--no-verify")
        for a in flags):
        return Hit(ASK, f"git {sub} --no-verify skips the repository's hooks.")
    if sub == "commit":
        for a in flags:
            if a.startswith("--"):
                continue
            for ch in a[1:]:
                if ch in "mFcCtSu":
                    break
                if ch == "n":
                    return Hit(ASK, "git commit -n skips the repository's pre-commit hooks.")
    if sub == "config" and _sets_hooks_path(args):
        return Hit(ASK, "git config core.hooksPath replaces the repository's hooks.")
    if sub == "push":
        pos = [a for a in args if not a.startswith("-")]
        refs = pos[1:]
        forced = any(a == "-f" or _is_opt(a, "--force", "--force-with-lease", "--force-if-includes") for a in flags) or any(
            len(a) > 1 and a[0] == "-" and a[1] != "-" and "f" in a[1:] and "n" not in a[1:] for a in flags) or any(
            r.startswith("+") for r in refs)
        deleting = "-d" in flags or any(_is_opt(a, "--delete") for a in flags) or any(r.startswith(":") for r in refs)
        branches = {_branch(r) for r in refs}
        protected = any(_PROTECTED_BRANCH.match(b) for b in branches) or any(
            _PROTECTED_BRANCH.match(b) for b in {_branch(r.partition(":")[0]) for r in refs if ":" in r})
        if any(_is_opt(a, "--mirror") for a in flags):
            return Hit(ASK, "git push --mirror overwrites every ref of the remote.")
        if (forced or deleting) and protected:
            return Hit(DENY, "force-push or deletion of a shared branch rewrites history others build on.")
        if forced or deleting:
            return Hit(ASK, "git force-push or branch deletion on the remote rewrites or removes history; confirm it.")
    if sub in ("filter-branch", "filter-repo"):
        return Hit(ASK, f"git {sub} rewrites the whole history.")
    if sub == "reset" and any(_is_opt(a, "--hard") for a in flags):
        return Hit(ASK, "git reset --hard discards uncommitted work and moves the branch.")
    if sub == "clean" and any(a.startswith("-") and not a.startswith("--") and "f" in a for a in args) or (
            sub == "clean" and any(_is_opt(a, "--force") for a in flags)):
        dry = any(_is_opt(a, "--dry-run") for a in flags) or any(a.startswith("-") and not a.startswith("--") and "n" in a
                                                                 for a in args)
        return None if dry else Hit(ASK, "git clean -f deletes untracked files for good.")
    if sub == "reflog" and "expire" in args or sub == "gc" and any(_is_opt(a, "--prune") and a.partition("=")[2] == "now"
                                                                   for a in flags):
        return Hit(ASK, "this removes the reflog or unreachable commits, the way back from a bad rewrite.")
    if sub == "update-ref" and "-d" in args:
        return Hit(ASK, "git update-ref -d deletes a ref.")
    if sub == "branch" and any(_is_opt(a, "--delete") or a in ("-d", "-D") or a[:1] == "-" and a[1:2] != "-"
                               and set("dD") & set(a) for a in flags):
        # a local delete: -d refuses an unmerged branch itself, -D (or -d -f) drops it whatever it holds
        force = any(_is_opt(a, "--force") or a[:1] == "-" and a[1:2] != "-" and ("D" in a or "f" in a) for a in flags)
        if force and any(_PROTECTED_BRANCH.match(a) for a in args if not a.startswith("-")):
            return Hit(ASK, "git branch -D deletes a shared branch locally, even with commits that are not merged.")
    if sub == "restore" and (any(_is_opt(a, "--staged") for a in flags) or "-S" in args) and not (
            any(_is_opt(a, "--worktree") for a in flags) or any(a[:1] == "-" and a[1:2] != "-" and "W" in a for a in flags)):
        return None  # only unstages
    if sub == "checkout" and args and args[-1] in (".", "--") or sub == "restore" and "." in args:
        return Hit(ASK, "this discards every uncommitted change in the tree.")
    return None


def _rm_hit(argv: list[str], sudo: bool) -> Hit | None:
    flags, targets, done = [], [], False
    for a in argv[1:]:
        if not done and a == "--":
            done = True
        elif not done and a.startswith("-") and len(a) > 1:
            flags.append(a)
        else:
            targets.append(a)
    recursive = any(_is_opt(a, "--recursive") or (not a.startswith("--") and any(c in _RM_SHORT_RECURSIVE for c in a[1:]))
                    for a in flags)
    force = any(_is_opt(a, "--force") or (not a.startswith("--") and "f" in a[1:]) for a in flags)
    if any(_is_opt(a, "--no-preserve-root") for a in flags) and any(_norm(t) == "/" for t in targets):
        return Hit(DENY, "rm --no-preserve-root on /.", "/")
    if not recursive and not (force and len(targets) > 0 and any(_norm(t) in ("/", "~") for t in targets)):
        return None
    small_system = None
    for t in targets:
        if _protected(t) or (default := _default_target(t)) and _protected(default):
            return Hit(DENY, f"recursive delete of {t}, a root, home or system directory.", t)
        if sudo and _system(t) and _norm(t).count("/") <= 2 and small_system is None:
            small_system = Hit(ASK, f"sudo recursive delete inside the system directory {t}; confirm it.", t)
    if small_system:
        return small_system
    for t in targets:
        if _is_empty_var_target(t) and (force or recursive):
            return Hit(ASK, f"recursive delete of {t}: if the variable is empty this is the root directory.", t)
        if _norm(t) in (".", "*", "..", "../..") or t in ("*", ".*", "./*", "../*", ".", ".."):
            return Hit(ASK, f"recursive delete of {t} removes everything in or above the working directory.", t)
    return None


_FIND_NAMED = frozenset({"-name", "-iname", "-regex", "-iregex", "-path", "-ipath", "-wholename", "-iwholename", "-lname",
                         "-ilname"})


def _find_hit(argv: list[str]) -> Hit | None:
    """``find START ... -delete`` (or ``-exec rm``) at a root, home or system directory. With no test on the name it removes
    everything under START (``-type f``, an age or a size do not narrow that enough): denied. With a test on the name
    (``-name .DS_Store``, ``-name '*.pyc'``) it removes only what matches, like ``rm`` of those files: allowed under the home
    directory, asked at a system directory, and asked when an ``-o`` or ``-prune`` lets other files through."""
    args = argv[1:]
    starts = []
    for a in args:
        if a.startswith("-") or a in ("(", "!", ")"):
            break
        starts.append(a)
    if not ("-delete" in args or ("-exec" in args and any(_bin(a) in ("rm", "shred", "unlink") for a in args))):
        return None
    protected = [s for s in starts if _protected(s)]
    if not protected:
        return None
    start = protected[0]
    named = any(a in _FIND_NAMED and k + 1 < len(args) and re.search(r"[A-Za-z0-9_]", args[k + 1]) for k, a in enumerate(args))
    widened = any(a in ("-o", "-or", "!", "-not") for a in args)
    if not named or (widened and "-prune" not in args):
        return Hit(DENY, f"find {start} deletes everything under a root, home or system directory.", start)
    if not widened and _norm(start) == "~":
        return None
    return Hit(ASK, f"find {start} deletes the files it matches under a root, home or system directory; check the test.", start)


def _disk_hit(name: str, argv: list[str], sudo: bool) -> Hit | None:
    args = argv[1:]
    dev = [a for a in args if _device(a)]
    if name == "dd":
        for a in args:
            if a.startswith("of=") and _device(a[3:]):
                return Hit(DENY, f"dd writes to the block device {a[3:]}.", a[3:])
        return None
    if name.startswith("mkfs") or name in ("mke2fs", "mkswap", "mkdosfs", "mkntfs", "newfs",
                                           "mkfs.ext4") or name.startswith("newfs_"):
        return Hit(DENY, f"{name} formats {dev[0]}.", dev[0]) if dev else None
    if name == "wipefs":
        return Hit(DENY, "wipefs erases filesystem signatures.", dev[0] if dev else "")
    if name == "shred":
        return Hit(DENY, f"shred overwrites the device {dev[0]}.", dev[0]) if dev else Hit(ASK, "shred destroys files for good.")
    if name in ("blkdiscard", "ddrescue", "dcfldd", "pv") and dev and name != "pv":
        return Hit(DENY, f"{name} writes over {dev[0]}.", dev[0])
    if name == "diskutil" and args:
        verbs = {"erasedisk", "erasevolume", "reformat", "zerodisk", "randomdisk", "secureerase", "partitiondisk",
                 "splitpartition", "mergepartitions", "deletecontainer", "deletevolume"}
        if any(a.lower() in verbs for a in args) or (args[0].lower() in ("apfs", "corestorage") and any(
                a.lower() in ("deletecontainer", "deletevolume", "delete", "erasevolume") for a in args)):
            return Hit(DENY, "diskutil erases or repartitions a disk.")
    if name in ("sgdisk", "sfdisk", "gdisk", "fdisk", "cfdisk", "parted") and dev:
        if any(a in ("--zap-all", "-Z", "--zap", "mklabel", "rm", "mkpart", "--delete", "-o", "--clear") for a in args):
            return Hit(DENY, f"{name} rewrites the partition table of {dev[0]}.", dev[0])
        return Hit(ASK, f"{name} edits the partition table of {dev[0]}.", dev[0])
    if name == "hdparm" and any(a.startswith(("--security-erase", "--trim-sector", "--security-set-pass", "--yes-i-know"))
                                for a in args):
        return Hit(DENY, "hdparm security-erase destroys the disk.")
    if name == "nvme" and "format" in args or name == "cryptsetup" and any(a in ("luksFormat", "erase", "luksErase")
                                                                           for a in args):
        return Hit(DENY, f"{name} destroys the device's data.")
    if name in ("zpool", "zfs") and "destroy" in args or name in ("lvremove", "vgremove", "pvremove"):
        return Hit(DENY if name in ("zpool", "zfs") else ASK, f"{name} removes storage.")
    if name in ("cp", "mv", "tee", "cat", "pv", "install") and name != "cat":
        pos = [a for a in args if not a.startswith("-")]
        if name == "tee":
            hit = [a for a in pos if _device(a)]
        else:
            hit = [pos[-1]] if pos and _device(pos[-1]) else []
        if hit:
            return Hit(DENY, f"{name} writes to the block device {hit[0]}.", hit[0])
    return None


_BREW_DIRS = frozenset({"/usr/local", "/usr/local/bin", "/usr/local/lib", "/usr/local/share", "/usr/local/etc",
                        "/usr/local/include",
                        "/usr/local/sbin", "/usr/local/var"})
_OWN_NAME = (re.compile(r"\$\{?(?:USER|LOGNAME)\}?(?::\$?\{?[\w-]{0,40}\}?)?|\$\(\s{0,3}(?:whoami|id\s{1,3}-un|logname)\s"
                        r"{0,3}\)|`\s{0,3}whoami\s{0,3}`"))


def _mode_hit(name: str, argv: list[str], sudo: bool) -> Hit | None:
    flags = [a for a in argv[1:] if a.startswith("-") and len(a) > 1 and not a[1:].isdigit()]
    pos = [a for a in argv[1:] if a not in flags]
    recursive = any(_is_opt(a, "--recursive") or (not a.startswith("--") and "R" in a[1:]) for a in flags)
    if not pos:
        return None
    mode, targets = pos[0], pos[1:]
    if name == "chmod" and mode.startswith("-") and len(pos) > 1:
        mode, targets = pos[1], pos[2:]
    if name == "chmod":  # a mode such as -w or -x is read as an option by the parser above, but chmod takes it as the mode
        symbolic = next((a for a in flags if not a.startswith("--") and set(a[1:]) - set("RfvchHLP")), None)
        if symbolic:
            mode, targets = symbolic, pos
    if any(_is_opt(a, "--reference") for a in flags):  # the mode or owner comes from a file: every word is a target
        mode, targets = "", pos
    prot = [t for t in targets if _protected(t)]
    syst = [t for t in targets if _system(t)]
    note = " (with sudo)" if sudo else ""
    if name == "chmod":
        bad = bool(_WORLD_WRITABLE.search(mode)) or mode in ("000", "0000", "a-rwx", "ugo-rwx", "a=")
        if recursive and prot:  # whatever the mode: 644 or go-rwx on / or /usr stops a system from working
            home = [t for t in prot if _norm(t) == "~" or _norm(t).startswith("~/") or _norm(t) in _BREW_DIRS]
            if bad or len(home) < len(prot) or sudo and not all(_norm(t) in _BREW_DIRS for t in prot):
                return Hit(DENY, f"recursive chmod {mode} on {prot[0]}, a root, home or system directory{note}.", prot[0])
            return Hit(ASK, f"recursive chmod {mode} on {prot[0]}{note}; confirm it.", prot[0])
        if bad and syst:
            return Hit(ASK, f"chmod {mode} on the system path {syst[0]}{note}.", syst[0])
        if bad and recursive and _WORLD_WRITABLE.search(mode):
            return Hit(ASK, f"recursive chmod {mode} makes the whole tree world-writable.")
        if _WORLD_WRITABLE.search(mode) and re.fullmatch(r"0?777|a\+rwx|ugo\+rwx", mode):
            return Hit(ASK, f"chmod {mode} makes files writable by everyone.")
        if _SETUID.search(mode) and targets:
            return Hit(ASK, f"chmod {mode} sets a setuid or setgid bit{note}.")
        return None
    if (name in ("chown", "chgrp") and recursive and prot and _OWN_NAME.fullmatch(mode)
            and all(_norm(t) in _BREW_DIRS for t in prot)):
        # Homebrew's own advice: `sudo chown -R $(whoami) /usr/local/...`. One ask, not a refusal.
        return Hit(ASK, f"recursive {name} of {prot[0]} to the current user{note}.", prot[0])
    if recursive and prot and (_norm(prot[0]) != "~" or sudo) and any(_norm(t) != "~" for t in prot):
        return Hit(DENY, f"recursive {name} on {prot[0]}{note}.", prot[0])
    if recursive and prot:
        return Hit(ASK, f"recursive {name} on the home directory{note}.", prot[0])
    if syst:
        return Hit(ASK, f"{name} on the system path {syst[0]}{note}.", syst[0])
    return None


_PERSIST_WRITERS = frozenset({"cp", "mv", "ln", "install", "rsync", "ditto", "dd"})


def _persist_hit(name: str, argv: list[str], stage: _Stage) -> Hit | None:
    args = argv[1:]
    targets = [t for op, t in stage.redirects if op.startswith(">") and t not in ("/dev/null", "/dev/stderr", "/dev/stdout")]
    pos = [a for a in args if not a.startswith("-")]
    if name == "tee":
        targets += pos
    elif name in _PERSIST_WRITERS:
        if name == "dd":
            targets += [a[3:] for a in args if a.startswith("of=")]
        elif pos:
            targets.append(pos[-1])
    elif name in ("sed", "perl", "ruby", "python3") and any(a.startswith("-i") or _is_opt(a, "--in-place") for a in args):
        targets += pos[1:] if name == "sed" else pos
    elif name == "touch" or name == "chmod":
        targets += []
    elif name == "crontab":
        if not any(a == "-l" for a in args):
            return Hit(ASK, "crontab installs or removes scheduled jobs.")
    elif name == "launchctl" and any(a in ("load", "bootstrap", "submit", "enable", "bootout", "unload", "kickstart")
                                     for a in args):
        return Hit(ASK, "launchctl loads or changes a launch agent or daemon.")
    elif name == "systemctl" and any(a in ("enable", "link", "mask", "edit", "preset") for a in args):
        return Hit(ASK, "systemctl enables or edits a unit that starts later.")
    elif name in ("at", "batch", "atq"):
        return Hit(ASK, "at schedules a job.") if name != "atq" else None
    elif name == "gh" and "secret" in args and any(a in ("set", "delete", "remove") for a in args):
        return Hit(ASK, "gh secret changes a repository's CI secrets.")
    elif name == "defaults" and "write" in args and any("LoginItems" in a or "loginwindow" in a for a in args):
        return Hit(ASK, "defaults write sets up a login item.")
    for t in targets:
        hit = persistence_path(t) or guard_surface(t)
        if hit:
            return Hit(hit[0], f"writes {t}, {hit[1]}.", t)
    return None


_REMOTE = re.compile(r"^(?:[\w.+-]{1,64}@)?[\w.-]{1,255}:(?!//)[^\s]*$|^[a-z]{2,10}://")
_URL = re.compile(r"[a-z][a-z0-9+.-]{1,10}://[^\s'\"<>]{1,500}", re.I)
_CURL_DATA = frozenset({"-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "--data-ascii", "-F", "--form",
                        "--form-string", "-T", "--upload-file", "--json"})
_NET_SINKS = frozenset({"curl", "wget", "nc", "ncat", "netcat", "socat", "scp", "sftp", "rsync", "ssh", "ftp", "telnet", "http",
                        "https",
                        "xh", "rclone", "gsutil", "mail", "mailx", "sendmail", "aws", "az"})


def _remote_hosts(argv: list[str]) -> list[str]:
    """Hosts the arguments reach that are not this machine."""
    hosts = []
    for a in argv[1:]:
        for url in _URL.findall(a) or ([a] if "." in a and not a.startswith(("-", "/", ".", "~")) and "/" not in a.split(":")[0]
                                       else []):
            for v in shell.network_values(url):
                if not shell.is_loopback(v):
                    hosts.append(shell.host(v))
    return hosts


_FETCH_LONG = ("--data", "--data-binary", "--data-raw", "--data-urlencode", "--data-ascii", "--form", "--form-string",
               "--upload-file", "--json", "--post-file", "--body-file", "--output", "--output-document", "--remote-name")


def _data_files(name: str, argv: list[str]) -> list[str]:
    """Files a curl or wget command sends: ``-d @f``, ``-F x=@f``, ``-T f``, ``--post-file f``."""
    out, args = [], [_canon(a, _FETCH_LONG) for a in argv[1:]]
    for i, a in enumerate(args):
        val = None
        if a in _CURL_DATA and i + 1 < len(args):
            val = args[i + 1]
            if a in ("-T", "--upload-file"):
                out.append(val)
                continue
        elif a.startswith(("--data", "--form", "--json", "--upload-file=")) and "=" in a:
            val = a.partition("=")[2]
            if a.startswith("--upload-file="):
                out.append(val)
                continue
        elif a.startswith("--post-file=") or a.startswith("--body-file="):
            out.append(a.partition("=")[2])
            continue
        elif a in ("--post-file", "--body-file") and i + 1 < len(args):
            out.append(args[i + 1])
            continue
        elif len(a) > 2 and a.startswith(("-d", "-F", "-T")) and a[1] in "dFT":
            val = a[2:]
            if a[1] == "T":
                out.append(val)
                continue
        if val is not None and "@" in val:
            out.append(val.partition("@")[2])
    return out


def _source_level(paths: list[str]) -> str | None:
    """DENY when one of the paths a command sends out is a key, a cloud credential, a system secret or a protected directory,
    ASK when it is only an ``.env``, a kube config or another file that holds secrets, None otherwise."""
    level = None
    for path in paths:
        cred = _cred_level(path)
        if (path == "-" or _protected(path) or (cred and cred[0] == DENY)
                or re.search(r"(?:^|/)\.(?:ssh|aws|gnupg|kube)(?:/|$)", _norm(path))):
            return DENY
        if cred:
            level = ASK
    return level


# Options of the copy tools whose next word is a setting (an identity file, a remote shell), not a file that is sent.
_SSH_VALUED = {
    "scp": frozenset({"-i", "-F", "-o", "-J", "-c", "-D", "-l", "-P", "-S", "-X"}),
    "sftp": frozenset({"-i", "-F", "-o", "-J", "-c", "-D", "-l", "-P", "-S", "-X", "-b", "-B", "-R", "-s"}),
    "rsync": frozenset({"-e", "--rsh", "--rsync-path", "--exclude", "--include", "--filter", "-f", "--port", "--bwlimit",
                        "--timeout"}),
}


def _net_hit(name: str, stage: _Stage, argv: list[str], sensitive_upstream: bool, intent: str) -> Hit | None:
    if name in ("curl", "wget", "http", "https", "xh"):
        hosts = _remote_hosts(argv) or ([] if any(shell.is_loopback(v) for a in argv[1:] for v in shell.network_values(a))
                                        else ["?"])
        if not hosts:
            return None
        named = all(_named(h, intent) for h in hosts if h != "?") and "?" not in hosts
        files = [f for f in _data_files(name, argv) if f]
        if named:  # a destination the user named takes their files, unless it is a key or a cloud credential
            files = [f for f in files if (_cred_level(f) or ("", ""))[0] == DENY or f != "-" and _protected(f)]
        stdin_data = "-" in files or stage.piped and any(a in ("-d", "@-", "--data-binary", "-T") or a.endswith("@-")
                                                         for a in argv[1:])
        for f in files:
            if f != "-" and (level := _source_level([f])):
                return Hit(level, f"uploads {f}, a sensitive file, to {hosts[0]}." if level == DENY else
                           f"uploads {f}, a file that holds secrets, to {hosts[0]}; confirm it.", f, escalate=True)
        if sensitive_upstream and (stdin_data or files):
            return Hit(DENY, f"sends credential or home-directory data on to {hosts[0]}.")
        if files and not named:
            return Hit(ASK, f"uploads {files[0]} to {hosts[0]}, which the user did not name.", hosts[0])
        for a in argv[1:]:
            if re.search(r"\$\(\s{0,3}(?:cat|base64|tar|printenv|env|zip)\b|`\s{0,3}(?:cat|base64|tar|printenv)\b", a):
                if _cred_args(["cat", *shlex_args(a)]):
                    return Hit(DENY, f"sends the contents of a credential file to {hosts[0]}.")
                if not named and any(_data_flag_before(argv, a)):
                    return Hit(ASK, f"sends command output to {hosts[0]}, which the user did not name.", hosts[0])
        return None
    if name in ("scp", "sftp", "rsync", "rclone", "gsutil"):
        valued = _SSH_VALUED.get(name, frozenset())
        pos = [a for k, a in enumerate(argv[1:]) if not a.startswith("-") and (k == 0 or argv[k] not in valued)]
        if name in ("rclone", "gsutil") and pos:
            pos = pos[1:] if pos[0] in ("copy", "sync", "copyto", "move", "moveto", "cp", "rsync", "mv") else pos
        if len(pos) < 2:
            return None
        dest, srcs = pos[-1], pos[:-1]
        if not _REMOTE.match(dest) or shell.is_loopback(shell.host(next(iter(shell.network_values(dest)), dest))):
            return None
        if any(_REMOTE.match(s) for s in srcs):
            return None
        for s in srcs:
            if level := _source_level([s]):
                return Hit(level, f"{name} sends {s}, a sensitive path, to {dest}." if level == DENY else
                           f"{name} sends {s}, a file that holds secrets, to {dest}; confirm it.", s, escalate=True)
        host = dest.partition(":")[0].rpartition("@")[2]
        if host and _named(host, intent):
            return None
        return Hit(ASK, f"{name} copies local files to the remote {dest}, which the user did not name.", dest)
    if name in ("nc", "ncat", "netcat", "socat"):
        pos = [a for a in argv[1:] if not a.startswith("-")]
        if any(a in ("-e", "-c", "--exec", "--sh-exec") for a in argv[1:]) and pos:
            return Hit(DENY, f"{name} hands a shell to {pos[0]}: a reverse or bind shell.")
        if any(a.startswith(("exec:", "EXEC:", "system:", "SYSTEM:")) for a in pos):
            return Hit(DENY, "socat hands a shell to a remote peer.")
        if any(a in ("-l", "-lp", "-lvp", "-lk") or (a.startswith("-") and "l" in a[1:])
               for a in argv[1:]) and not stage.piped and not stage.redirects:
            return None
        if pos and not all(shell.is_loopback(p) for p in pos[:1]):
            fed = [t for op, t in stage.redirects if op == "<"]
            level = _source_level(fed)
            if level == DENY or sensitive_upstream:
                return Hit(DENY, f"{name} sends a sensitive file to {pos[0]}.")
            if level == ASK:
                return Hit(ASK, f"{name} sends a file that holds secrets to {pos[0]}; confirm it.", pos[0], escalate=True)
            if fed or stage.piped:
                return Hit(ASK, f"{name} sends data to {pos[0]}.", pos[0])
        return None
    if name in ("mail", "mailx", "sendmail"):
        fed = [t for op, t in stage.redirects if op == "<"]
        level = _source_level(fed)
        if level == DENY or sensitive_upstream:
            return Hit(DENY, f"{name} mails a sensitive file.")
        return Hit(ASK, f"{name} mails a file that holds secrets; confirm it.", escalate=True) if level == ASK else None
    if name == "aws" and len(argv) > 3 and argv[1] == "s3" and argv[2] in ("cp", "sync", "mv"):
        pos = [a for a in argv[3:] if not a.startswith("-")]
        if len(pos) >= 2 and pos[-1].startswith("s3://") and not pos[0].startswith("s3://"):
            if _source_level(pos[:-1]) == DENY:
                return Hit(DENY, f"aws s3 {argv[2]} uploads {pos[0]}, a sensitive path.", pos[0])
            return Hit(ASK, f"aws s3 {argv[2]} uploads local files to {pos[-1]}.", pos[-1])
    return None


def shlex_args(text: str) -> list[str]:
    try:
        return shlex.split(text.replace("$(", " ").replace("`", " ").replace(")", " "))
    except ValueError:
        return text.split()


def _data_flag_before(argv: list[str], arg: str) -> list[bool]:
    i = argv.index(arg)
    return [i > 0 and argv[i - 1] in _CURL_DATA]


# --- what the user named --------------------------------------------------------------------------------------

_NEGATION = re.compile(r"\b(?:never|not|no|don'?t|do\s+not|doesn'?t|shouldn'?t|mustn'?t|can'?t|cannot|won'?t|avoid|without|stop|"
                       r"forbid\w*|prohibit\w*|refuse\w*|nor|neither|instead\s+of|rather\s+than)\b|n't\b", re.I)
_HOST_LIKE = re.compile(r"[a-z0-9][a-z0-9.-]{2,253}(?::\d{1,5})?", re.I)
_SENTENCE_END = re.compile(r"[!?\n;]|\.\s")


def _named(needle: str, intent: str) -> bool:
    """True when the user's prompts name ``needle`` itself: a path, host or command that stands alone in the text, not a
    part of a longer path or host (``/Users/me`` is not named by ``open /Users/me/proj``, ``evil.com`` not by ``notevil.com``),
    and not in a sentence that forbids it (``never run rm -rf /``, ``don't touch ~/.ssh/id_rsa``)."""
    needle = needle.strip()
    if needle[:1] in ("/", "~", "$") and len(needle) > 1:
        needle = needle.rstrip("/")
    if len(needle) <= 3 or not intent:
        return False
    # a host sits in a URL (after ``//``, before ``/path`` or ``:port``)
    host = bool(_HOST_LIKE.fullmatch(needle)) and "." in needle and ".." not in needle
    for count, m in enumerate(re.finditer(re.escape(needle), intent, re.I)):
        if count >= 50:
            break
        start, end = m.span()
        before = intent[start - 1:start]
        if before and (before.isalnum() or before in ("_.-" if host else "_/.~$-")):
            continue
        after = intent[end:end + 1]
        if after and (after.isalnum() or after in "_~$-"):
            continue
        if after == "." or (after == "/" and not host):
            following = intent[end + 1:end + 2]
            if following and (following.isalnum() or following in "_~$-.*"):
                continue  # a child path, a file extension or a longer host name
        sentence = _SENTENCE_END.split(intent[max(0, start - 120):start])[-1]
        if _NEGATION.search(" ".join(sentence.split()[-6:])):
            continue
        return True
    return False
