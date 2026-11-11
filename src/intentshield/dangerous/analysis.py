"""A command read in full (stages, wrappers, nested shells, pipes) and the verdicts ``assess_shell`` and ``assess_file``."""
from __future__ import annotations

import posixpath
import re
from typing import Any

from intentshield import shell

from .core import (
    _MAX,
    _MAX_DEPTH,
    _MAX_SUBSTITUTIONS,
    _MAX_WORDS,
    _PATH_CAP,
    _PATH_CAP_WHY,
    _TOO_DEEP,
    _WORKDIR,
    ASK,
    DENY,
    Hit,
    _bin,
    _canon,
    _Stage,
)
from .parsing import _FETCHERS, _INTERPRETERS, _SHELLS, _mask_data, _normalise, _stages, _substitutions
from .paths import (
    _CLI_SECRETS,
    _CRED_TEXT,
    _MALICIOUS_CONTENT,
    _READERS,
    _clean_path,
    _cred_args,
    _cred_level,
    _device,
    _from_workdir,
    _in_order,
    _named_secret,
    _norm,
    _protected,
    overwrite_level,
    persistence_path,
)
from .powershell import _POWERSHELLS, _ps_command_text, _ps_posix
from .rules import (
    _EXEC_SOCKET,
    _FETCH_LONG,
    _FORK_BOMB,
    _FORK_CODE,
    _FORK_LOOP,
    _NET_SINKS,
    _PIPE_SHELL_SUBST,
    _REVERSE_STRICT,
    _SOCKET_FEED,
    _disk_hit,
    _find_hit,
    _git_hit,
    _mode_hit,
    _named,
    _net_hit,
    _persist_hit,
    _remote_hosts,
    _rm_hit,
    _wipe_hit,
)
from .runners import _stdin_of, _unwrap
from .selfguard import _erase_hit, _guard_hit, _guard_text, guard_surface
from .variables import _EXPANDED, _braces, _expand_vars, _in_dir, _track


def _inner_hits(extras: list[tuple[str, str]], intent: str, depth: int, state: dict[str, Any], sudo: bool) -> list[Hit]:
    """What the wrappers of a stage carried: a limit that stopped their reading asks, and the shell text they run is read."""
    out: list[Hit] = []
    for kind, text in extras:
        if kind == "note":
            out.append(Hit(ASK, text))
        elif depth < _MAX_DEPTH:
            out.extend(_analyse(text, intent, depth + 1, state, sudo))
        else:
            out.append(Hit(ASK, _TOO_DEEP))
    return out


# What stands at the end of a loop or block that is fed from a file, and the shell's own reads: they show the file's text.
_SHELL_READS = frozenset({"done", "fi", "esac", "}", ")", "read", "mapfile", "readarray", "eval", "exec"})
_FIND_RUNS = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
_FD_RUNS = frozenset({"-x", "-X", "--exec", "--exec-batch"})
_SSH_OPTIONS = frozenset({"-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R",
                          "-S",
                         "-W", "-w"})


def _placeholder(words: list[str], marks: tuple[str, ...]) -> list[str]:
    """``words`` with the places where find or fd put a file name filled with one harmless relative name."""
    return [re.sub(r"\{(?:/|//|\.|/\.)?\}", "found", w) if any(m in w for m in marks) else w for w in words]


def _run_by_find(argv: list[str]) -> list[list[str]]:
    """The commands ``find`` runs for each file (``-exec``, ``-execdir``, ``-ok``, ``-okdir``; up to ``;`` or ``{} +``)."""
    out: list[list[str]] = []
    i = 1
    while i < len(argv):
        if argv[i] not in _FIND_RUNS:
            i += 1
            continue
        j = i + 1
        while j < len(argv) and argv[j] != ";" and not (argv[j] == "+" and argv[j - 1].endswith("{}")):
            j += 1
        out.append(_placeholder(argv[i + 1:j], ("{}",)))
        i = j + 1
    return out


def _run_by_fd(argv: list[str]) -> list[list[str]]:
    """The command ``fd -x`` or ``-X`` runs: everything after the option, up to a ``;``."""
    for i, a in enumerate(argv[1:], 1):
        if a in _FD_RUNS or a.startswith("--exec=") or a.startswith("--exec-batch="):
            rest = argv[i + 1:] if "=" not in a else [a.partition("=")[2], *argv[i + 1:]]
            end = rest.index(";") if ";" in rest else len(rest)
            return [_placeholder(rest[:end], ("{",))]
    return []


def _remote_command(argv: list[str]) -> str:
    """The command line ``ssh [options] host command...`` has the remote shell run."""
    i = 1
    while i < len(argv) and argv[i].startswith("-") and argv[i] != "--":
        i += 2 if argv[i] in _SSH_OPTIONS else 1
    if i < len(argv) and argv[i] == "--":
        i += 1
    return " ".join(argv[i + 1:])


def _ps_hits(text: str, intent: str, depth: int, state: dict[str, Any], sudo: bool) -> list[Hit]:
    """What the PowerShell cmdlets of ``text`` do, by the rules for the commands they correspond to."""
    posix = _ps_posix(text)
    if not posix:
        return []
    return _inner_hits([("code", posix)], intent, depth, state, sudo)


def _bare_redirect_hits(redirects: list[tuple[str, str]]) -> list[Hit]:
    """A command line that is only redirects (``> file``, ``$(< file)``): what it overwrites or reads."""
    out: list[Hit] = []
    for op, target in redirects:
        if op.startswith(">"):
            if _device(target):
                out.append(Hit(DENY, f"redirect into the block device {target}.", target))
            elif (p := persistence_path(target) or guard_surface(target) or overwrite_level(target)):
                out.append(Hit(p[0], f"writes {target}, {p[1]}.", target))
        elif op == "<" and (level := _cred_level(target)) and level[0] == DENY:  # $(< file), a loop fed from a file
            out.append(Hit(DENY, f"the shell reads {target}, {level[1]}.", target))
    return out


def _expanded_argv(argv: list[str]) -> tuple[list[str], str, bool]:
    """(the words with their brace lists expanded, the program's name, True when a list was too long to expand in full)."""
    cut: list[bool] = []
    if "{" in argv[0] and "," in argv[0]:  # {rm,-rf,/} is the words rm -rf /
        argv = [*_braces(argv[0], 0, cut), *argv[1:]]
    name = _bin(argv[0])
    if name in _EXPANDED and any("{" in a for a in argv[1:]):
        words = [argv[0], *(w for a in argv[1:] for w in _braces(a, 0, cut))]
        if len(words) > _MAX_WORDS:
            cut.append(True)
        argv = words[:_MAX_WORDS]
    return argv, name, bool(cut)


def _shell_text_hits(name: str, argv: list[str], intent: str, depth: int, state: dict[str, Any], sudo: bool) -> list[Hit]:
    """The text a shell runs: ``bash -c '...'``, ``eval ...``, ``su -c``."""
    if name not in _SHELLS and name not in ("su", "eval"):
        return []
    code = None
    if name == "eval":
        code = " ".join(argv[1:])
    else:
        for k, a in enumerate(argv[1:], 1):
            if a.startswith("-") and not a.startswith("--") and "c" in a[1:] and k + 1 < len(argv):
                code = argv[k + 1]
                break
    if code and depth < _MAX_DEPTH:
        return _analyse(code, intent, depth + 1, state, sudo)
    return [Hit(ASK, _TOO_DEEP)] if code else []


def _redirect_hits(name: str, argv: list[str], redirects: list[tuple[str, str]], intent: str, depth: int, state: dict[str, Any],
                   sudo: bool) -> list[Hit]:
    """What the redirects of a command do: into a block device, a here-string a shell runs, a credential file fed to a program."""
    out: list[Hit] = []
    for op, target in redirects:
        if op.startswith(">"):
            if _device(target):
                out.append(Hit(DENY, f"redirect into the block device {target}.", target))
        elif op == "<<<" and name in _SHELLS and depth < _MAX_DEPTH and not any(not a.startswith("-") or "c" in a[1:]
                                                                                for a in argv[1:]):
            out.extend(_analyse(target, intent, depth + 1, state, sudo))  # bash <<< 'rm -rf /': the string is the program
        elif op == "<<<" and name in _SHELLS and not any(not a.startswith("-") or "c" in a[1:] for a in argv[1:]):
            out.append(Hit(ASK, _TOO_DEEP))
        elif op == "<" and (level := _cred_level(target)) and level[0] == DENY:
            # the readers show it or send it on; another program (``gh secret set X < key``) is only asked about
            shows = name in _READERS or name in _NET_SINKS or name in _SHELL_READS
            out.append(Hit(DENY if shows else ASK, f"{name} reads {target}, {level[1]}.", target))
    return out


def _destruction_hits(name: str, argv: list[str], bare: _Stage, intent: str, depth: int, state: dict[str, Any],
                      sudo: bool) -> list[Hit]:
    """What a command removes, moves or changes, and the programs that run another command (``find -exec``, ``fd -x``,
    PowerShell, ``ssh host command``)."""
    out: list[Hit] = []
    if name == "rm" or name == "unlink" or name == "rmdir":
        hit = _rm_hit(argv, sudo)
        if hit:
            out.append(hit)
    elif name == "find":
        hit = _find_hit(argv)
        if hit:
            out.append(hit)
        for words in _run_by_find(argv):
            out.extend(_stage_hits(_Stage(words, [], False, 0, sudo, list(bare.assigns)), intent, depth, dict(state)))
    elif name in ("fd", "fdfind"):
        for words in _run_by_fd(argv):
            out.extend(_stage_hits(_Stage(words, [], False, 0, sudo, list(bare.assigns)), intent, depth, dict(state)))
    elif name in _POWERSHELLS:
        if code := _ps_command_text(argv):
            out.extend(_inner_hits([("code", code)], intent, depth, state, sudo))
            out.extend(_ps_hits(code, intent, depth, state, sudo))
    elif name == "ssh":
        remote = _remote_command(argv)
        if remote.strip():
            out.extend(_inner_hits([("code", remote + _stdin_of(bare))], intent, depth, state, sudo))
    elif name == "mv" and any(_protected(a) for a in argv[1:-1] if not a.startswith("-")):
        out.append(Hit(DENY, "mv moves a root, home or system directory away.", argv[1]))
    elif name == "git":
        hit = _git_hit(argv, bare.assigns)
        if hit:
            out.append(hit)
    elif name in ("chmod", "chown", "chgrp", "chattr"):
        hit = _mode_hit(name, argv, sudo)
        if hit:
            out.append(hit)
    for hit in (_disk_hit(name, argv, sudo), _wipe_hit(name, argv), _erase_hit(name, argv), _guard_hit(name, argv, bare)):
        if hit:
            out.append(hit)
    return out


def _credential_read_hits(name: str, argv: list[str], state: dict[str, Any]) -> list[Hit]:
    """A reader or an interpreter given a credential file, and the CLIs that print credentials; marks ``state`` as holding a
    secret (``secret``) or a weak one (``weak_secret``) for the stages that come after."""
    out: list[Hit] = []
    cred = None
    if name in _READERS or name in _INTERPRETERS:
        cred = _cred_args(argv) if name in _READERS and name not in _NET_SINKS else None  # those are read by _net_hit
        if name in _INTERPRETERS:
            m = _CRED_TEXT.search(" ".join(argv[1:]))
            if m:
                cred = (DENY, "a credential store", m[0])
        if name == "find" and cred and "-exec" not in argv:
            cred = None
        if name in ("ln", "install") and cred:
            cred = None
        if name == "grep" and cred and any(a in ("-l", "-L", "-c", "-q", "--files-with-matches", "-lr", "-rl") for a in argv[1:]):
            cred = None
    if cred:
        out.append(Hit(cred[0], f"{name} reads {cred[2]}, {cred[1]}.", cred[2]))
        if cred[0] == ASK:
            state["weak_secret"] = True
        else:
            state["secret"] = True
    for needle, decision in _CLI_SECRETS:
        if _bin(argv[0]) == needle[0] and _in_order([_bin(argv[0]), *argv[1:]], needle):
            out.append(Hit(decision, f"{' '.join(needle)} prints credentials."))
            state["secret"] = state.get("secret") or decision == DENY
            break
    return out


def _stage_hits(stage: _Stage, intent: str, depth: int, state: dict[str, Any]) -> list[Hit]:
    bare, extras = _unwrap(stage)
    argv = bare.argv
    out: list[Hit] = _inner_hits(extras, intent, depth, state, bare.sudo)
    if not argv:
        out.extend(_bare_redirect_hits(bare.redirects))
        return out
    if bare.xargs and (fed := [w for op, t in bare.redirects if op == "<<<" for w in t.split()]):
        out.extend(_stage_hits(_Stage([*argv, *fed], [], False, 0, bare.sudo, list(bare.assigns)), intent, depth, dict(state)))
    argv, name, too_long = _expanded_argv(argv)
    sudo = bare.sudo
    if too_long:
        out.append(Hit(ASK, "a brace list in the command is too long to expand in full (over 300 characters, 16 alternatives, "
                            "64 words or 4 levels); check the paths it names."))
    out.extend(_shell_text_hits(name, argv, intent, depth, state, sudo))
    out.extend(_redirect_hits(name, argv, bare.redirects, intent, depth, state, sudo))
    out.extend(_destruction_hits(name, argv, bare, intent, depth, state, sudo))
    out.extend(_credential_read_hits(name, argv, state))
    # exfiltration, persistence
    hit = _net_hit(name, bare, argv, bool(state.get("secret") or (bare.piped and state.get("prev_secret"))), intent)
    if hit:
        out.append(hit)
    hit = _persist_hit(name, argv, bare)
    if hit:
        out.append(hit)
    if not out and (named := _named_secret(argv)):  # a program no rule above reads that is given a key or a credential file
        out.append(Hit(named[0], f"{argv[0]} is given {named[2]}, {named[1]}; confirm it.", named[2]))
    if name in _FETCHERS or name == "nc":
        state["fetched"] = True
    return out


_STDOUT = frozenset({"-", "/dev/stdout", "/dev/fd/1", "/proc/self/fd/1"})


def _writes(argv: list[str]) -> bool:
    """True when a fetcher saves the download to a file; ``-O -`` and ``-o /dev/stdout`` send it to the next stage."""
    args = [_canon(a, _FETCH_LONG) for a in argv[1:]]
    for i, a in enumerate(args):
        if a in ("-o", "-O", "--output", "--output-document"):
            val = args[i + 1] if i + 1 < len(args) else ""
        elif a.startswith(("--output=", "--output-document=")):
            val = a.partition("=")[2]
        elif a.startswith("-o") and not a.startswith("--") and len(a) > 2:
            val = a[2:]
        elif a == "--remote-name":
            val = ""
        else:
            continue
        if val not in _STDOUT:
            return True
    return False


def _pipe_hits(stages: list[_Stage], intent: str) -> list[Hit]:
    """Downloads run as code, and sensitive data on the way to the network."""
    out: list[Hit] = []
    by_pipe: dict[int, list[_Stage]] = {}
    for s in stages:
        by_pipe.setdefault(s.pipeline, []).append(s)
    for chain in by_pipe.values():
        fetched: str | None = None
        secret: str | None = None  # DENY after a key or cloud credential, ASK after an .env or kube config
        for st in chain:
            bare, _ = _unwrap(st)
            if not bare.argv:
                continue
            name = _bin(bare.argv[0])
            reader = _cred_args(bare.argv) if name in _READERS else None
            if reader and secret != DENY:
                secret = DENY if reader[0] == DENY else ASK
            if bare.piped and secret and name in _NET_SINKS:
                host = (_remote_hosts(bare.argv) or ["a remote host"])[0]
                if name in ("curl", "wget", "nc", "ncat", "netcat", "socat", "scp", "ssh", "ftp", "telnet", "http", "https",
                            "xh"):
                    out.append(Hit(secret, f"credential data is piped to {name} for {host}." if secret == DENY else
                                   f"a file that holds secrets is piped to {name} for {host}; confirm it.",
                                   escalate=secret != DENY))
            if bare.piped and fetched and (name in _SHELLS or (name in _INTERPRETERS and not [a for a in bare.argv[1:]
                if not a.startswith("-")]) or name in ("xargs",)):
                plain = _tls_less(chain)
                sudo = st.sudo or bare.sudo  # root only when sudo is on the shell: ``sudo curl | sh`` runs the script as the user
                out.append(Hit(DENY if (sudo or plain) else ASK,
                               f"{fetched} output is piped into {name}: code downloaded and run unread"
                               f"{' as root' if sudo else ''}.", ""))
            if name in _FETCHERS and not _writes(bare.argv):
                fetched = name
            elif name in ("nc", "ncat", "netcat") and bare.argv[1:] and not any(a.startswith("-l")
                                                                                for a in bare.argv[1:]) and not bare.piped:
                fetched = name
    return out


def _local(value: str) -> bool:
    """A URL or host on this machine, with or without a port (``http://localhost:8000/x``)."""
    return shell.is_loopback(re.sub(r"(?<=[\w\]]):\d{1,5}(?=/|$)", "", value, count=1))


def _plain_download(data: str) -> bool:
    """The text has an http URL or a bare IP address that is not on this machine."""
    return any(not _local(m[0]) for m in re.finditer(r"http://[^\s'\"<>)]{1,300}|\b\d{1,3}(?:\.\d{1,3}){3}\b", data))


def _tls_less(chain: list[_Stage]) -> bool:
    """A download over plain http, or from a bare IP address, that is then run. Not one from this machine."""
    for st in chain:
        bare, _ = _unwrap(st)
        if bare.argv and _bin(bare.argv[0]) in _FETCHERS:
            for a in bare.argv[1:]:
                if a.lower().startswith("http://") and not _local(a):
                    return True
                if re.match(r"^(?:https?://)?\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/|$)", a) and not _local(a):
                    return True
    return False


def _download_run(stages: list[_Stage]) -> Hit | None:
    """curl -o x ... ; bash x   (a download, then the file run)."""
    saved: set[str] = set()
    for st in stages:
        bare, _ = _unwrap(st)
        if not bare.argv:
            continue
        name = _bin(bare.argv[0])
        if name in _FETCHERS:
            args = [_canon(a, _FETCH_LONG) for a in bare.argv[1:]]
            for i, a in enumerate(args):
                if a in ("-o", "-O", "--output", "--output-document") and i + 1 < len(args):
                    saved.add(posixpath.basename(args[i + 1]))
                elif a.startswith("-o") and len(a) > 2 and not a.startswith("--"):
                    saved.add(posixpath.basename(a[2:]))
                elif a.startswith("--output="):
                    saved.add(posixpath.basename(a.partition("=")[2]))
        elif saved:
            run = None
            if name in _SHELLS | _INTERPRETERS:
                run = next((a for a in bare.argv[1:] if not a.startswith("-")), None)
            elif name in ("chmod",) and any("x" in a or a[:1] in "0123456789" for a in bare.argv[1:2] + bare.argv[2:3]):
                run = next((a for a in bare.argv[2:] if not a.startswith("-")), None)
            elif name.startswith("./") or bare.argv[0].startswith(("./", "/")):
                run = bare.argv[0]
            if run and posixpath.basename(run) in saved:
                return Hit(ASK, "a downloaded file is made executable or run straight after the download.")
    return None


def _piped_text(prev: _Stage, st: _Stage, intent: str, depth: int, sudo: bool) -> list[Hit]:
    """What ``echo`` or ``printf`` pipes into a shell that reads its stdin is run as a command."""
    maker, _ = _unwrap(prev)
    shell_stage, _ = _unwrap(st)
    if not maker.argv or not shell_stage.argv or _bin(maker.argv[0]) not in ("echo", "printf"):
        return []
    if _bin(shell_stage.argv[0]) not in _SHELLS or any(not a.startswith("-") for a in shell_stage.argv[1:]) or any(
            "c" in a[1:] for a in shell_stage.argv[1:] if not a.startswith("--")):
        return []  # a script file or -c has its own text
    words = [a for a in maker.argv[1:] if a not in ("-n", "-e", "-E", "-ne", "-en")]
    if _bin(maker.argv[0]) == "printf" and words and "%" in words[0]:
        words = words[1:]
    if not words:
        return []
    return _analyse(" ".join(words), intent, depth + 1, {}, sudo or shell_stage.sudo)


def _piped_xargs(prev: _Stage, st: _Stage, intent: str, depth: int, state: dict[str, Any]) -> list[Hit]:
    """``echo / | xargs rm -rf``: the words that echo or printf print are the last arguments of the program xargs runs."""
    maker, _ = _unwrap(prev)
    bare, _ = _unwrap(st)
    if not bare.xargs or not bare.argv or not maker.argv or _bin(maker.argv[0]) not in ("echo", "printf"):
        return []
    words = [a for a in maker.argv[1:] if a not in ("-n", "-e", "-E", "-ne", "-en")]
    if _bin(maker.argv[0]) == "printf" and words and "%" in words[0]:
        words = words[1:]
    words = [w for a in words for w in a.split()]
    if not words:
        return []
    return _stage_hits(_Stage([*bare.argv, *words], [], False, 0, bare.sudo, list(bare.assigns)), intent, depth, dict(state))


def _analyse(command: str, intent: str, depth: int, state: dict[str, Any], sudo: bool = False) -> list[Hit]:
    hits: list[Hit] = []
    text = _normalise(command[:_MAX + 4096])[:_MAX]
    data = _mask_data(text)  # what the raw patterns read: single-quoted data is not code
    if _FORK_BOMB.search(data) and re.search(r"\|\s{0,3}[\w:.-]{1,40}\s{0,3}&", data) or _FORK_LOOP.search(data):
        hits.append(Hit(DENY, "a fork bomb: a function or loop that starts copies of itself until the machine stops."))
    if _FORK_CODE.search(data) and ("while" in data.lower()
                                    or "fork" in data.lower()) and re.search(r"fork\s{0,3}\(\)\s{0,"
                                                                             r"3}(?:#|;|\n|$|\))|fork\s+while|:\(\)", data,
                                                                             re.I) and len(data) < 2000:
        if re.search(r"while[^;\n]{0,40}fork|fork\s+while|:\(\)\s*\{", data, re.I):
            hits.append(Hit(DENY, "a fork bomb: code that forks without end."))
    if _PIPE_SHELL_SUBST.search(data):
        plain = _plain_download(data)
        hits.append(Hit(DENY if sudo or plain else ASK,
                        "code downloaded and run unread (a shell or eval given a download's output)."))
    if _REVERSE_STRICT.search(data) or (_EXEC_SOCKET.search(data) and _SOCKET_FEED.search(data)):
        hits.append(Hit(DENY, "a reverse shell: a shell handed to a network socket."))
    elif "/dev/tcp/" in data or "/dev/udp/" in data:
        for m in re.finditer(r"/dev/(?:tcp|udp)/([^/\s'\"]{1,100})/\d{1,5}", data):
            if not (shell.is_loopback(m[1]) or m[1].lower() in ("localhost", "ip6-localhost")):
                hits.append(Hit(ASK, f"a raw network socket to {m[1]}.", m[1]))
                break
    if re.search(r"rmtree\(\s{0,3}(?:os\.path\.expanduser\(\s{0,3}['\"]~['\"]\s{0,3}\)|['\"](?:/|~|\$HOME)['\"]|Path\.home\(\)|"
                 r"os\.environ\[['\"]HOME['\"]\])", data):
        hits.append(Hit(DENY, "code that deletes the home or root directory tree."))
    own = _guard_text(data, text) if depth == 0 else None
    if own:
        hits.append(own)
    notes: list[str] = []
    stages = _stages(text, notes)
    for note in notes:
        hits.append(Hit(ASK, f"the command has {note}, too long to read in full; check the part after that."))
    if stages is None:
        return hits
    state_pipe_secret = False
    env: dict[str, list[str]] = {}
    # The directory after the cd and pushd of this command line, from where the command runs: a relative path means the same
    # target as the absolute one (``cat etc/shadow`` from ``/``, ``rm -rf ../..`` from a project).
    where: dict[str, Any] = {"cwd": state["cwd"] if "cwd" in state else _start_dir(), "stack": []}
    for k, st in enumerate(stages):
        if st.piped and k and depth < _MAX_DEPTH:  # echo 'rm -rf /' | sh: the text is the program
            hits.extend(_piped_text(stages[k - 1], st, intent, depth, sudo))
            hits.extend(_piped_xargs(stages[k - 1], st, intent, depth, state))
        elif st.piped and k and _piped_text(stages[k - 1], st, intent, 0, sudo):
            hits.append(Hit(ASK, _TOO_DEEP))
        local = dict(state)
        local["prev_secret"] = state_pipe_secret
        local["cwd"] = where["cwd"]   # a shell this stage starts reads its relative paths from here
        st.sudo = st.sudo or sudo
        loop_notes: list[str] = []
        variants = _expand_vars(st, env, loop_notes)
        for note in dict.fromkeys(loop_notes):
            hits.append(Hit(ASK, f"the command uses {note}, too many to follow; check what it does."))
        for variant in variants:
            found = _stage_hits(variant, intent, depth, local)
            hits.extend(found)
            cwd = where["cwd"]
            if cwd:  # after a cd, a relative target is read from where the cd went
                bare, _ = _unwrap(variant)
                name = _bin(bare.argv[0]) if bare.argv else ""
                if name in _EXPANDED:
                    moved = _Stage(_in_dir(cwd, name, bare.argv), variant.redirects, variant.piped, variant.pipeline, bare.sudo,
                                   list(bare.assigns), bare.xargs)
                    if moved.argv != bare.argv:
                        hits.extend(h for h in _stage_hits(moved, intent, depth, dict(local)) if h not in found)
        _track(st, env, where)
        if not st.piped:
            state_pipe_secret = False
        if local.get("secret") and not state.get("secret"):
            state_pipe_secret = True
    for pipe in _pipe_hits(stages, intent):
        if not any(h.reason == pipe.reason for h in hits):
            hits.append(pipe)
    run = _download_run(stages)
    if run:
        hits.append(run)
    spans = _substitutions(data)
    for a, b in spans[:_MAX_SUBSTITUTIONS]:
        body = text[a:b]  # from the unmasked text: the code inside may quote
        if body.strip() and depth < _MAX_DEPTH:
            hits.extend(_analyse(body, intent, depth + 1, {}, sudo))
        elif body.strip():
            hits.append(Hit(ASK, _TOO_DEEP))
    if len(spans) > _MAX_SUBSTITUTIONS:
        hits.append(Hit(ASK, f"the command has more than {_MAX_SUBSTITUTIONS} command substitutions, too many to read in full."))
    return hits


def _start_dir() -> str | None:
    """The working directory the call runs in as the rules spell paths (``~`` for the home directory), or None when the event
    carried none or not an absolute one."""
    cwd = _WORKDIR.get()
    return _norm(cwd) if cwd.startswith("/") else None


def _worst(hits: list[Hit], intent: str, review: str = "tainted") -> Hit | None:
    """The hit that decides. A deny becomes an ask only when every deny of the command is for a target the user's prompts name
    exactly (``_named``: the whole path or host, not a part of a longer one, and not in a sentence that forbids it)."""
    if not hits:
        return None
    denies = [h for h in hits if h.decision == DENY]
    if denies:
        unnamed = [h for h in denies if not (h.trigger and _named(h.trigger, intent))]
        if unnamed:
            return unnamed[0]
        return Hit(ASK, denies[0].reason + " (the user named it, so confirm it)", denies[0].trigger)
    left = [h for h in hits if not (h.trigger and "did not name" in h.reason and _named(h.trigger, intent))]
    return left[0] if left else None


def assess_shell(command: str, intent: str = "", powershell: bool = False, cwd: str = "") -> Hit | None:
    """The verdict on a shell command by its text, or None when nothing here objects. ``powershell``: the command is the input of
    the PowerShell tool, read as POSIX shell as well as by its cmdlets (see ``_ps_posix``). ``cwd``: the directory the command
    runs in, from which a relative path is opened where a rule must look inside the file."""
    if not command or not command.strip():
        return None
    token = _WORKDIR.set(cwd)
    try:
        hits = _analyse(command, intent, 0, {})
        if powershell:
            hits.extend(_ps_hits(command, intent, 0, {}, False))
    finally:
        _WORKDIR.reset(token)
    if len(command) > _MAX and not any(h.decision == DENY for h in hits):  # the rest was not read: do not pass it as safe
        hits.append(Hit(ASK,
                        f"the command is longer than {_MAX} characters, too long to read in full; check the part after that."))
    if command.strip() and hits and all(h.decision == DENY for h in hits) and _named(command.strip(), intent):
        return Hit(ASK, hits[0].reason + " (the user typed this command, so confirm it)")
    return _worst(hits, intent)


def assess_file(path: str, content: Any = None, write: bool = False, intent: str = "", cwd: str = "") -> Hit | None:
    """The verdict on a file read or write by a built-in tool. ``cwd``: the directory a relative ``path`` is read from."""
    token = _WORKDIR.set(cwd)
    try:
        return _assess_file(path, content, write, intent)
    finally:
        _WORKDIR.reset(token)


def _assess_file(path: str, content: Any, write: bool, intent: str) -> Hit | None:
    if not path:
        return None
    if len(_clean_path(path)) > _PATH_CAP:  # a path, whatever it looks like: not read in full, so asked about
        return Hit(ASK, f"{'writing' if write else 'reading'} {path}, {_PATH_CAP_WHY}.", path)
    if not write:
        cred = _cred_level(path)
        if cred:
            hit = Hit(cred[0], f"reading {path}, {cred[1]}.", path)
            return _worst([hit], intent)
        if _norm(path) == "~" or (resolved := _from_workdir(path)) is not None and _norm(resolved) == "~":
            # a search of the whole home directory reaches ~/.ssh and ~/.aws as well
            return _worst([Hit(ASK, f"reading {path}, the whole home directory, which holds ~/.ssh and ~/.aws.", path)], intent)
        return None
    pers = persistence_path(path)
    text = _text(content)[:_MAX]
    hits: list[Hit] = []
    if pers:
        hits.append(Hit(pers[0], f"writing {path}, {pers[1]}.", path))
        if _MALICIOUS_CONTENT.search(text) or any(h.decision == DENY or h.escalate for h in _analyse(text, intent, 1, {})):
            hits.append(Hit(DENY, f"the new text of {path} downloads and runs code, opens a shell or sends data out."))
    if cred := overwrite_level(path):
        hits.append(Hit(cred[0], f"writing {path}, {cred[1]}.", path))
    own = guard_surface(path)
    if own:
        hits.append(Hit(own[0], f"writing {path}, {own[1]}.", path))
    return _worst(hits, intent)


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, (list, tuple)):
        return "\n".join(_text(c) for c in content)
    if isinstance(content, dict):
        return "\n".join(_text(c) for c in content.values())
    return "" if content is None else str(content)
