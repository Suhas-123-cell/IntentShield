"""Programs that run another program (sudo, env, flock, ssh...): how their words are read to the command behind them."""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from .core import _bin, _canon, _Stage
from .parsing import _ASSIGN, _ENV_LONG, _NICE_LONG, _SUDO_LONG, _SUDO_VALUED, _TIMEOUT_LONG, _XARGS_VALUED, _strip_keywords

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


def _runner(valued: str = "", skip: int = 0, unless: str = "", code: str = "", string: bool = False, cluster: bool = True,
            pairs: str = "") -> _Runner:
    return _Runner(frozenset(valued.split()), skip, frozenset(pairs.split()), frozenset(unless.split()), frozenset(code.split()),
                   string, cluster)


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
                        "--results"),
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
    "firejail": _runner(),
    "bwrap": _runner("--tmpfs --proc --dev --chdir --uid --gid --hostname --unsetenv --perms --size --dir --mqueue --lock-file "
                     "--sync-fd --userns --userns2 --pidns --cap-add --cap-drop --seccomp --block-fd --info-fd --json-status-fd",
                     pairs="--bind --bind-try --dev-bind --dev-bind-try --ro-bind --ro-bind-try --symlink --file --bind-data "
                           "--ro-bind-data --chmod --setenv --remount-ro"),
}
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
}
_WRAPPERS = frozenset({"nohup", "command", "nice", "ionice", "setsid", "builtin", "timeout", "gtimeout", "chronic", "unbuffer",
                       "xargs", "doas", "env", "sudo"}) | frozenset(_RUNNERS)
_ARCH_WORDS = frozenset({"x86_64", "i386", "i686", "aarch64", "arm64", "armv7l", "ppc64", "ppc64le", "s390x", "riscv64",
                         "linux32", "linux64", "uname26"})
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
            if take:
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


def _unwrap(stage: _Stage) -> tuple[_Stage, list[tuple[str, str]]]:
    """Strips assignments, sudo, env, nohup, time... from the front. Returns the bare stage and what the wrappers carried: shell
    text they run (``("code", text)``, ``flock -c``, ``sudo -s``) and a limit that stopped the reading (``("note", why)``)."""
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
        sub = _SUB_RUNNERS.get(name)
        if sub and not (len(argv) > 1 and argv[1] in sub[0]):
            break
        if name not in _WRAPPERS and not sub:
            break
        argv.pop(0)
        sudo = sudo or name in ("sudo", "doas")
        xargs = xargs or name in ("xargs", "parallel")
        if sub:
            argv.pop(0)
            argv, code = _read_runner(sub[1], argv)
            inner.extend(("code", c) for c in code)
            continue
        if name in _RUNNERS:
            argv, code = _read_runner(_RUNNERS[name], argv)
            inner.extend(("code", c) for c in code)
            argv = _runner_tail(name, argv)
            continue
        argv, shell_words = _skip_flags(name, argv)
        if argv and argv[0] == "--":
            argv.pop(0)
        if name in ("timeout", "gtimeout") and argv:
            argv.pop(0)
        if name == "nice" and argv and argv[0].lstrip("+-").isdigit():
            argv.pop(0)
        if shell_words and argv:   # sudo -s rm -rf /: the shell is given the words as one command line
            inner.append(("code", " ".join(argv)))
            argv = []
    else:
        rest = _strip_keywords(argv)
        while rest and _ASSIGN.match(rest[0]):
            rest.pop(0)
        if rest and (_bin(rest[0]) in _WRAPPERS or _bin(rest[0]) in _SUB_RUNNERS and len(rest) > 1
                     and rest[1] in _SUB_RUNNERS[_bin(rest[0])][0]):
            inner.append(("note", _TOO_MANY_WRAPPERS))
    inner = [(kind, text + _stdin_of(stage) if kind == "code" else text) for kind, text in inner]
    return _Stage(argv, stage.redirects, stage.piped, stage.pipeline, sudo, assigns, xargs), inner
