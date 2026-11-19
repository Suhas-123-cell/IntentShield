"""Programs that run another program (sudo, env, flock, ssh...): how their words are read to the command behind them."""
from __future__ import annotations

import re
import shlex
from contextvars import ContextVar
from dataclasses import dataclass

from .core import _bin, _canon, _Stage
from .parsing import _ASSIGN, _ENV_LONG, _NICE_LONG, _SUDO_LONG, _SUDO_VALUED, _TIMEOUT_LONG, _XARGS_VALUED, _strip_keywords

# Set while a stage is read once more as 0.4.4 read it, with the programs added as wrappers since then taken for ordinary
# programs.
AS_IN_0_4_4: ContextVar[bool] = ContextVar("as_in_0_4_4", default=False)
_UNWRAP_LIMIT = 8   # wrappers (sudo, env, nohup...) read through in front of one command
_TOO_MANY_WRAPPERS = f"more than {_UNWRAP_LIMIT} wrappers (sudo, env, nohup...) in front of the command, too many to read through"


@dataclass(frozen=True)
class _Runner:
    """How a program that runs another program takes its words: the options with a value in the next word, the operands that
    stand before the command (``flock FILE``, ``chroot ROOT``), the option that gives those operands instead (``taskset -c``),
    the options whose value is shell text (``flock -c``) and whether the words that are left are one shell command line."""
    valued: frozenset[str] = frozenset()
    skip: int = 0
    pairs: frozenset[str] = frozenset()   # options that take two words (bwrap --bind SRC DEST)
    unless: frozenset[str] = frozenset()
    code: frozenset[str] = frozenset()
    string: bool = False
    # -dmS name is the options -d, -m and -S with a value; off where an option is one word of several letters
    cluster: bool = True
    # the program joins the words that are left with spaces and hands them to a shell (``watch``): a word ``;`` ends a command
    shell: bool = False


def _runner(valued: str = "", skip: int = 0, unless: str = "", code: str = "", string: bool = False, cluster: bool = True,
            pairs: str = "", shell: bool = False) -> _Runner:
    return _Runner(frozenset(valued.split()), skip, frozenset(pairs.split()), frozenset(unless.split()), frozenset(code.split()),
                   string, cluster, shell)


# The programs that run the program given in their last words, read from the manual pages of coreutils (env, nice, nohup, stdbuf,
# timeout, chroot), util-linux (chrt, flock, ionice, nsenter, runuser, script, setarch, setsid, setpriv, taskset, unshare), the
# BSD and macOS base systems (arch, caffeinate, lockf, sandbox-exec, script, xcrun), the usual debugging and sandbox wrappers and
# the terminal multiplexers. nice, ionice, timeout, xargs, env, sudo and doas have their own rules in ``_unwrap``.
_RUNNERS: dict[str, _Runner] = {
    "flock": _runner("-w --wait --timeout -E --conflict-exit-code", skip=1, code="-c --command"),
    "lockf": _runner("-t", skip=1),
    "taskset": _runner("-c --cpu-list", skip=1, unless="-c --cpu-list"),
    "chrt": _runner("-T -P -D --sched-runtime --sched-period --sched-deadline", skip=1),
    "unshare": _runner("-S --setuid -G --setgid -R --root -w --wd --map-user --map-group --map-users --map-groups --propagation "
                       "--setgroups --monotonic --boottime"),
    "nsenter": _runner("-t --target -S --setuid -G --setgid"),
    "chroot": _runner("--userspec --groups -u -g -G", skip=1),
    "setpriv": _runner("--reuid --regid --euid --egid --ruid --rgid --groups --inh-caps --bounding-set --ambient-caps "
                       "--securebits --pdeathsig --selinux-label --apparmor-profile"),
    "setarch": _runner(),
    "linux32": _runner(), "linux64": _runner(),
    "runuser": _runner("-u --user -g --group -G --supp-group -s --shell -w", skip=1, unless="-u --user", code="-c --command"),
    "sg": _runner(skip=1, code="-c", string=True),
    "script": _runner("-E -I -O -B -m -o -T -t -F", skip=1, code="-c --command"),
    "strace": _runner("-a -b -e -E -I -o -O -p -P -s -S -u -U -X --output --trace --signal --env --attach"),
    "ltrace": _runner("-a -A -e -F -l -n -o -p -s -u -w -x -D"),
    "time": _runner("-f -o --format --output"),
    "exec": _runner("-a"),
    "stdbuf": _runner("-i -o -e --input --output --error"),
    "caffeinate": _runner("-t -w"),
    "watch": _runner("-n --interval", string=True),
    "arch": _runner("-arch -e -d", cluster=False),
    "busybox": _runner(), "toybox": _runner(),
    "xcrun": _runner("-sdk --sdk -toolchain --toolchain", cluster=False),
    "sandbox-exec": _runner("-f -n -p -D"),
    "parallel": _runner("-j --jobs -n -N --max-args -S --sshlogin -a --arg-file -I -L -P -E -d --delimiter -C --colsep "
                        "--results", shell=True),
    "sshpass": _runner("-p -f -d -P"),
    "ssh-agent": _runner("-a -E -P -t"),
    "pkexec": _runner("--user"),
    "run0": _runner("-u --user -g --group -D --chdir -E --setenv"),
    "systemd-run": _runner("-u --unit -p --property --description --slice --uid --gid -E --setenv -M --machine -H --host "
                           "--working-directory --service-type --nice --on-active --on-boot --on-calendar --on-unit-active "
                           "--on-unit-inactive --on-startup --timer-property -r --remain-after-exit"),
    "systemd-inhibit": _runner("--what --who --why --mode"),
    "fakeroot": _runner("-l --lib -i -s -b --faked"),
    "eatmydata": _runner(), "fakechroot": _runner(),
    "proxychains": _runner("-f"), "proxychains4": _runner("-f"), "torsocks": _runner("-u -p -a -i"), "tsocks": _runner(),
    "faketime": _runner("-f", skip=1, unless="-f"),
    "xvfb-run": _runner("-n --server-num -e --error-file -f --auth-file -s --server-args -p --xauth-protocol -w --wait"),
    "dbus-run-session": _runner("--config-file --dbus-daemon"), "dbus-launch": _runner(),
    "numactl": _runner("-C --physcpubind -N --cpunodebind -m --membind -i --interleave -p --preferred"),
    "cpulimit": _runner("-l --limit -p --pid -e --exe -P --path"),
    "prlimit": _runner("-p --pid"),
    "choom": _runner("-n -p"),
    "screen": _runner("-S -t -p -c -s -T -e -h"),
    "valgrind": _runner(),
    "gdb": _runner(),
    "firejail": _runner(shell=True),
    "bwrap": _runner("--tmpfs --proc --dev --chdir --uid --gid --hostname --unsetenv --perms --size --dir --mqueue --lock-file "
                     "--sync-fd --userns --userns2 --pidns --cap-add --cap-drop --seccomp --block-fd --info-fd --json-status-fd",
                     pairs="--bind --bind-try --dev-bind --dev-bind-try --ro-bind --ro-bind-try --symlink --file --bind-data "
                           "--ro-bind-data --chmod --setenv --remount-ro"),
}
# Programs that became wrappers after 0.4.4. Their own words are still read by the rule that asks about a key or a credential
# file named as an argument (see ``_unwrap``), so that reading them as wrappers never gives a weaker verdict than before.
_ADDED_RUNNERS: dict[str, _Runner] = {
    # Container init programs, user switchers, process supervisors and terminal emulators that run the command given to them.
    "gosu": _runner(skip=1), "su-exec": _runner(skip=1), "setuidgid": _runner(skip=1),
    # runcon CONTEXT COMMAND, or runcon -t TYPE -u USER... COMMAND: the context is a word of its own only when no option gives it
    "runcon": _runner("-t -u -r -l --type --user --role --range", skip=1,
                      unless="-c --compute -t -u -r -l --type --user --role --range"),
    "chpst": _runner("-u -U -b -e -/ -n -l -L -m -d -o -p -f -c"),
    "dumb-init": _runner("-r --rewrite"), "tini": _runner("-p -e"),
    "watchexec": _runner("-w --watch -e --exts -i --ignore -f --filter -E --env -d --debounce --shell --workdir", shell=True),
    "entr": _runner(code="-s"),
    # dtach -c SOCKET COMMAND (also -a, -A, -n): the socket is the value of the mode, and -z takes no value
    "dtach": _runner("-a -A -c -n -e -r"),
    # abduco -n NAME COMMAND (also -a, -A, -c): the session name is the value of the mode, and -e takes the detach key
    "abduco": _runner("-a -A -c -n -e"),
    "rlwrap": _runner("-b -C -D -f -F -H -l -N -P -s -S -t -z"),
    "cgexec": _runner("-g"),
    "xterm": _runner("-T -title -geometry -fn -bg -fg -display -class -name -xrm"),
    "uxterm": _runner("-T -title -geometry -fn -bg -fg -display -class -name -xrm"),
    "urxvt": _runner("-T -title -geometry -fn -bg -fg -display -name"),
    "alacritty": _runner("-t --title --class --working-directory -o --option --config-file"),
    "konsole": _runner("--workdir --profile -p"),
    "gnome-terminal": _runner("--title --working-directory --profile --geometry --role --zoom", code="-e --command"),
    "terminator": _runner("-T --title -p --profile --working-directory -g --geometry", code="-e --command"),
}
_RUNNERS.update(_ADDED_RUNNERS)
# Programs whose first operand names a subcommand that runs a program: ``uv run -- cmd``, ``bundle exec cmd``.
_SUB_RUNNERS: dict[str, tuple[frozenset[str], _Runner]] = {
    "uv": (frozenset({"run"}),
           _runner("--with --python -p --project --directory --env-file --extra --group --with-requirements")),
    "poetry": (frozenset({"run"}), _runner()), "pipenv": (frozenset({"run"}), _runner()), "pdm": (frozenset({"run"}), _runner()),
    "hatch": (frozenset({"run"}), _runner()), "rye": (frozenset({"run"}), _runner()),
    "conda": (frozenset({"run"}), _runner("-n --name -p --prefix")),
    "mamba": (frozenset({"run"}), _runner("-n --name -p --prefix")),
    "micromamba": (frozenset({"run"}), _runner("-n --name -p --prefix")),
    "bundle": (frozenset({"exec"}), _runner()),
    "direnv": (frozenset({"exec"}), _runner(skip=1)),
    "mise": (frozenset({"exec", "x"}), _runner("-t --tool")), "asdf": (frozenset({"exec"}), _runner()),
    "rbenv": (frozenset({"exec"}), _runner()), "pyenv": (frozenset({"exec"}), _runner()),
    "nodenv": (frozenset({"exec"}), _runner()),
    "npm": (frozenset({"exec"}), _runner("-w --workspace")), "pnpm": (frozenset({"exec"}), _runner()),
    "yarn": (frozenset({"exec"}), _runner()),
    "zellij": (frozenset({"run", "r"}), _runner("-n --name --cwd -d --direction --width --height -x -y --pinned --borderless")),
}
# Options of a program with subcommands that come before the subcommand and take a value in the next word.
_SUB_GLOBAL_VALUED = {"zellij": frozenset({"-c", "--config", "--config-dir", "-l", "--layout", "-n", "--new-session-with-layout",
                                           "-s", "--session", "--data-dir", "--max-panes"})}
_WRAPPERS = frozenset({"nohup", "command", "nice", "ionice", "setsid", "builtin", "timeout", "gtimeout", "chronic", "unbuffer",
                       "xargs", "doas", "env", "sudo", "tmux", "osascript"}) | frozenset(_RUNNERS)
_ADDED_WRAPPERS = frozenset({"tmux", "osascript", "zellij"}) | frozenset(_ADDED_RUNNERS)   # wrappers since 0.4.4
_ARCH_WORDS = frozenset({"x86_64", "i386", "i686", "aarch64", "arm64", "armv7l", "ppc64", "ppc64le", "s390x", "riscv64",
                         "linux32", "linux64", "uname26"})
_OPERATOR_WORDS = frozenset({";", "&", "&&", "|", "||", "|&", ";;", "(", ")", "<", ">", ">>"})
_SHELL_WORDS = frozenset({"-s", "-i", "--shell", "--login"})   # sudo -s, sudo -i: the words that are left are run by a shell


def _read_runner(spec: _Runner, words: list[str]) -> tuple[list[str], list[str]]:
    """The words of ``words`` that are left after the options and operands of ``spec``, and the shell text its options carried."""
    argv, code, supplied = list(words), [], False
    longs = tuple(n for n in (*spec.valued, *spec.pairs, *spec.code, *spec.unless) if n.startswith("--"))
    names = spec.valued | spec.pairs | spec.code | spec.unless

    def options() -> None:
        nonlocal supplied
        while argv and argv[0].startswith("-") and argv[0] != "--":
            flag = argv.pop(0)
            head, eq, value = flag.partition("=")
            head = _canon(head, longs) if head.startswith("--") else head
            take = not eq
            if head not in names and spec.cluster and len(flag) > 2 and flag[1] != "-":
                # -dmS name: the letters are options, the last one may take the next word
                for k, letter in enumerate(flag[1:], 1):
                    if f"-{letter}" in names:
                        head, take, value = f"-{letter}", k == len(flag) - 1, flag[k + 1:]
                        break
            if head not in names:
                continue
            supplied = supplied or head in spec.unless
            if take and (head in spec.valued or head in spec.pairs or head in spec.code):   # runcon -c is a flag with no value
                value = argv.pop(0) if argv else ""
                if head in spec.pairs and argv:
                    argv.pop(0)
            if head in spec.code and value:
                code.append(value)
        if argv and argv[0] == "--":
            argv.pop(0)

    options()
    for _ in range(0 if supplied else spec.skip):
        if argv:
            argv.pop(0)
    if spec.code:
        options()
    if code:
        return [], code
    if spec.string and len(argv) == 1 and re.search(r"\s", argv[0]):
        return [], [argv[0]]
    return argv, code


# --- tmux and osascript ------------------------------------------------------------------------------------------------------

# The aliases of the tmux commands that run a shell command or hand text to a shell, and the letters of each one's options that
# take a value (the next word, or the rest of the cluster).
_TMUX_ALIASES = {"new": "new-session", "neww": "new-window", "splitw": "split-window", "respawnp": "respawn-pane",
                 "respawnw": "respawn-window", "run": "run-shell", "if": "if-shell", "popup": "display-popup",
                 "pipep": "pipe-pane", "send": "send-keys", "confirm": "confirm-before", "bind": "bind-key"}
_TMUX_VALUED = {"new-session": "cefFnstxy", "new-window": "ceFnt", "split-window": "ceFltp", "respawn-pane": "cet",
                "respawn-window": "cet", "run-shell": "dt", "if-shell": "t", "display-popup": "bcdehsStTwxy", "pipe-pane": "t",
                "send-keys": "Ntc", "confirm-before": "cpt", "bind-key": "NT", "set-hook": "t"}
_TMUX_KEY = re.compile(r"(?:Enter|C-m|C-j|KPEnter|Tab|Space|Escape|BSpace|Up|Down|Left|Right|Home|End|PageUp|PageDown|"
                       r"(?:[CMS]-)+\S)", re.I)


def _tmux_split(words: list[str], valued: str) -> tuple[list[str], list[str]]:
    """(the operands, the flags) of one tmux command's words: options come first, a cluster of them is read letter by letter, and
    a letter that takes a value takes the rest of the cluster or else the next word. The words from the first operand on are
    operands."""
    flags: list[str] = []
    i = 0
    while i < len(words):
        a = words[i]
        if a == "--":
            i += 1
            break
        if not (a.startswith("-") and len(a) > 1):
            break
        i += 1
        for k, letter in enumerate(a[1:], 1):
            flags.append(letter)
            if letter in valued:
                if k == len(a) - 1:
                    i += 1
                break
    return words[i:], flags


def _one_command(words: list[str]) -> str:
    """The words of a shell command as the text a shell reads: one word is already that text, several are quoted into one line."""
    return words[0] if len(words) == 1 else shlex.join(words)


def _tmux_command(words: list[str]) -> str:
    """The words of a tmux command that another tmux command carries (``if-shell``, ``bind-key``), as a tmux command line."""
    return f"tmux {words[0]}" if len(words) == 1 else shlex.join(["tmux", *words])


def _tmux_codes(words: list[str]) -> list[str]:
    """The shell text a tmux command line runs (``new-session``, ``split-window``, ``run-shell``, ``send-keys``...), and the tmux
    commands that others carry (``if-shell``, ``bind-key``, a second command after ``;``) as tmux command lines to read again."""
    segments: list[list[str]] = [[]]
    for w in words:
        if w == ";":
            segments.append([])
        else:
            segments[-1].append(w)
    first, codes = segments[0], [shlex.join(["tmux", *seg]) for seg in segments[1:] if seg]
    i = 0
    while i < len(first) and first[i].startswith("-") and first[i] != "--":   # the options of tmux itself
        if first[i] == "-c" and i + 1 < len(first):
            codes.append(first[i + 1])   # tmux -c COMMAND runs the command with the default shell
        i += 2 if first[i][1:2] in "cfLST" and len(first[i]) == 2 else 1
    if i >= len(first):
        return codes
    rest = first[i:]
    if len(rest) == 1 and re.search(r"\s", rest[0]):   # a whole tmux command given as one word ("run-shell 'make'")
        try:
            rest = shlex.split(rest[0])
        except ValueError:
            return codes
    name = _TMUX_ALIASES.get(rest[0], rest[0])
    valued = _TMUX_VALUED.get(name)
    if valued is None:
        return codes
    operands, flags = _tmux_split(rest[1:], valued)
    if name in ("new-session", "new-window", "split-window", "respawn-pane", "respawn-window", "pipe-pane", "display-popup") or (
            name == "run-shell" and "C" not in flags):
        if operands:
            codes.append(_one_command(operands))
    elif name == "send-keys":   # the text goes to the pane's shell: what is not the name of a key is typed
        text = [w for w in operands if not _TMUX_KEY.fullmatch(w)]
        if text:
            codes.append(" ".join(text))
    elif name == "if-shell" and operands:
        codes.append(operands[0])
        codes += [_tmux_command(shlex.split(c) if re.search(r"\s", c) else [c]) for c in operands[1:3] if c.strip()]
    elif name in ("bind-key", "set-hook") and len(operands) > 1:   # the key (or the hook) and then a tmux command
        codes.append(_tmux_command(operands[1:]))
    elif name == "confirm-before" and operands:
        codes.append(_tmux_command(operands))
    return codes


_APPLESCRIPT_SHELL = re.compile(r'do\s+shell\s+script\s+"((?:[^"\\]|\\.){1,2000})"', re.I)


def _osascript_codes(words: list[str]) -> list[str]:
    """The shell text of ``do shell script "..."`` in the AppleScript that ``osascript -e`` is given."""
    codes = []
    for k, a in enumerate(words[:-1]):
        if a == "-e":
            for m in _APPLESCRIPT_SHELL.finditer(words[k + 1]):
                codes.append(re.sub(r"\\(.)", r"\1", m[1]))
    return codes


_APPLESCRIPT_RUNS = re.compile(r"\bdo\s+script\b|\bdoShellScript\b|\bdoScript\b|\bwrite\s+text\b|\brun\s+script\b", re.I)
_APPLESCRIPT_STRING = re.compile(r'do\s+shell\s+script\s+"(?:[^"\\]|\\.){0,2000}"(?P<rest>[^\n\r]*)', re.I)
_OSASCRIPT_VALUED = frozenset({"-l", "-s"})


def _osascript_unread(argv: list[str]) -> list[str]:
    """Why the script ``osascript`` is given runs a shell command that is not read: it comes in on the standard input, it runs the
    command through ``do script``, ``doShellScript`` or ``write text``, or it builds the text of ``do shell script`` from parts.
    A script in a file is not read either, and not asked about."""
    scripts, files, i = [], [], 0
    while i < len(argv):
        a = argv[i]
        if a == "-e" and i + 1 < len(argv):
            scripts.append(argv[i + 1])
            i += 2
        elif a in _OSASCRIPT_VALUED:
            i += 2
        elif a.startswith("<"):   # a redirect that the lexer left among the words (a here document): its text is the script
            i += 2 if a in ("<", "<<", "<<-", "<<<") else 1
        elif a.startswith("-") and a != "-":
            i += 1
        else:
            files.append(a)
            i += 1
    if not scripts and (not files or files[0] == "-"):
        return ["osascript reads its script from the standard input, which is not read; check what it runs."]
    text = "\n".join(scripts)
    if _APPLESCRIPT_RUNS.search(text):
        return ["osascript runs a command through do script, doShellScript or write text, which is not read; check what it runs."]
    for m in re.finditer(r"do\s+shell\s+script\b", text, re.I):
        found = _APPLESCRIPT_STRING.match(text, m.start())
        if not found or "&" in found["rest"]:
            return ["osascript builds the text of do shell script from parts, which is not read; check what it runs."]
    return []


def _stdin_of(stage: _Stage) -> str:
    """The input redirects of ``stage`` as text, to follow the command line that a wrapper hands to a shell: the shell it starts
    reads them too (``sudo -s nc host 1 < ~/.ssh/id_rsa``)."""
    return "".join(f" {op} {shlex.quote(target)}" for op, target in stage.redirects if op in ("<", "<<<"))


def _skip_flags(name: str, argv: list[str]) -> tuple[list[str], bool]:
    """The words after a wrapper's flags (and the values those flags take). True when ``sudo`` was given a flag that starts a
    shell, which is then handed the rest as one command line."""
    shell_words = False
    while argv and argv[0].startswith("-") and argv[0] != "--":
        flag = argv.pop(0)
        if name in ("sudo", "doas"):
            flag = _canon(flag, _SUDO_LONG)
            shell_words = shell_words or flag in _SHELL_WORDS
        elif name == "env":
            flag = _canon(flag, _ENV_LONG)
        elif name in ("nice", "ionice"):
            flag = _canon(flag, _NICE_LONG)
        elif name in ("timeout", "gtimeout"):
            flag = _canon(flag, _TIMEOUT_LONG)
        if name in ("sudo", "doas") and flag in _SUDO_VALUED and argv:
            argv.pop(0)
        # env -S'cmd', --split-string=cmd
        elif name == "env" and (split := re.fullmatch(r"-[iv0]*S(.+)|--split-string=(.*)", flag, re.S)):
            try:
                argv = [*shlex.split(split[1] or split[2]), *argv]
            except ValueError:
                pass
        elif name == "env" and flag in ("-S", "--split-string") and argv:  # the program and its arguments, as one word
            try:
                argv = [*shlex.split(argv.pop(0)), *argv]
            except ValueError:
                pass
        elif name == "env" and flag in ("-u", "-C", "--unset", "--chdir", "-a", "--argv0", "-P") and argv:
            argv.pop(0)
        elif name in ("nice", "ionice") and flag in ("-n", "-c", "-p", "--adjustment", "--class") and argv:
            argv.pop(0)
        elif name in ("timeout", "gtimeout") and flag in ("-s", "-k", "--signal", "--kill-after") and argv:
            argv.pop(0)
        elif name == "xargs" and flag in _XARGS_VALUED and argv:
            argv.pop(0)
    return argv, shell_words


def _runner_tail(name: str, argv: list[str]) -> list[str]:
    """What is left of a runner's words once its own settings are read: ``setarch``'s architecture, and the placeholders of
    ``parallel`` and the values it is fed after ``:::``."""
    if name == "setarch" and argv and argv[0] in _ARCH_WORDS:
        argv.pop(0)
    if name == "parallel" and (marks := [k for k, a in enumerate(argv) if a in (":::", "::::", ":::+", "::::+")]):
        head, fed = argv[:marks[0]], [a for a in argv[marks[0] + 1:] if a not in (":::", "::::", ":::+", "::::+")]
        argv = [*(a for a in head if not re.fullmatch(r"\{[^{}]{0,4}\}", a)), *fed]
    return argv


def _sub_index(name: str, argv: list[str]) -> int | None:
    """Where the subcommand that runs a program stands in ``argv`` (``argv[0]`` is the program: ``uv run``, ``zellij -l x run``),
    or None when the words are not such a call."""
    sub = _SUB_RUNNERS.get(name)
    if not sub:
        return None
    valued, i = _SUB_GLOBAL_VALUED.get(name, frozenset()), 1
    while i < len(argv) and argv[i].startswith("-") and argv[i] != "--":
        i += 2 if argv[i] in valued else 1
    return i if i < len(argv) and argv[i] in sub[0] else None


def _unwrap(stage: _Stage) -> tuple[_Stage, list[tuple[str, str]]]:
    """Strips assignments, sudo, env, nohup, time... from the front. Returns the bare stage and what the wrappers carried: shell
    text they run (``("code", text)``, ``flock -c``, ``sudo -s``), a limit that stopped the reading (``("limit", why)``) and a
    script that is not read (``("note", why)``).
    Where ``AS_IN_0_4_4`` is set, a program that became a wrapper after 0.4.4 is left as it was, a program like any other."""
    argv = list(stage.argv)
    sudo, assigns = stage.sudo, list(stage.assigns)
    xargs = stage.xargs
    inner: list[tuple[str, str]] = []
    for _ in range(_UNWRAP_LIMIT):
        argv = _strip_keywords(argv)
        while argv and _ASSIGN.match(argv[0]):
            assigns.append(argv.pop(0))
        if not argv:
            break
        name = _bin(argv[0])
        sub, at = _SUB_RUNNERS.get(name), _sub_index(name, argv)
        if sub and at is None:
            break
        if name not in _WRAPPERS and not sub:
            break
        if name in _ADDED_WRAPPERS and AS_IN_0_4_4.get():
            break
        argv.pop(0)
        sudo = sudo or name in ("sudo", "doas")
        xargs = xargs or name in ("xargs", "parallel")
        if sub and at is not None:
            del argv[:at]
            argv, code = _read_runner(sub[1], argv)
            inner.extend(("code", c) for c in code)
            continue
        if name in ("tmux", "osascript"):   # what they are given is shell text, and there is nothing left to unwrap
            if name == "tmux":
                inner.extend(("code", c) for c in _tmux_codes(argv))
            else:
                inner.extend(("code", c) for c in _osascript_codes(argv))
                inner.extend(("note", why) for why in _osascript_unread(argv))
            argv = []
            break
        if name in _RUNNERS:
            argv, code = _read_runner(_RUNNERS[name], argv)
            inner.extend(("code", c) for c in code)
            argv = _runner_tail(name, argv)
            if (_RUNNERS[name].shell or _RUNNERS[name].string) and ";" in argv:
                # the words are joined with spaces and run by a shell, which reads a word ``;`` as the end of a command
                inner.append(("code", " ".join(shlex.quote(a) if re.search(r"\s", a) else a for a in argv)))
                argv = []
            continue
        argv, shell_words = _skip_flags(name, argv)
        if argv and argv[0] == "--":
            argv.pop(0)
        if name in ("timeout", "gtimeout") and argv:
            argv.pop(0)
        if name == "nice" and argv and argv[0].lstrip("+-").isdigit():
            argv.pop(0)
        if shell_words and argv:   # sudo -s rm -rf /: the shell is given the words as one command line
            # sudo puts a backslash before the characters the shell reads as syntax, so a word that is an operator stays a word
            inner.append(("code", " ".join(shlex.quote(a) if a in _OPERATOR_WORDS else a for a in argv)))
            argv = []
    else:
        rest = _strip_keywords(argv)
        while rest and _ASSIGN.match(rest[0]):
            rest.pop(0)
        if rest and (_bin(rest[0]) in _WRAPPERS or _sub_index(_bin(rest[0]), rest) is not None):
            inner.append(("limit", _TOO_MANY_WRAPPERS))
    inner = [(kind, text + _stdin_of(stage) if kind == "code" else text) for kind, text in inner]
    return _Stage(argv, stage.redirects, stage.piped, stage.pipeline, sudo, assigns, xargs), inner
