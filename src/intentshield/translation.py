"""Verdict translation: what the guard means -> the reply the harness, in its version and mode, is measured to honour.

IntentShield decides allow, ask or deny. A harness does not always do what the matching reply says (the hook-fidelity study,
docs/hook-fidelity-study.md): Codex CLI drops an ask and runs the call, Gemini CLI waits on one in a headless yolo
run (to the 90 s to 900 s caps measured; no answer came), Claude Code before 2.1.85 ran a pre-approved call its hook asked
about, a hook that dies or is slow is let through by every harness measured. This module keeps those findings as data, by
(harness, version range, mode), and answers four questions:

* ``ask_reply``: send an ask as an ask, or as a deny that tells the user what was wanted;
* ``launcher``: the command suffix that turns a hook that cannot run (exit 126, 127, a crash) into a refusal;
* ``resolve``: which version and mode the hook is running under, from what ``intentshield install`` and ``doctor`` recorded;
* ``findings``: the fail-open conditions measured for a version, for ``intentshield doctor``.

A version the study did not measure is treated as the worse of its neighbours, never as the better: between two measured
releases that behave differently the class is "uncertain", below the oldest measured release "unmeasured". A release newer than
the newest measured one is assumed to behave like it (``doctor`` says so), because otherwise every update of a harness would turn
its asks into refusals until this table caught up. The ranges are derived
by benchmarks/hook_fidelity/derive_table.py from the per-release outcomes of the study's lanes, and a test pins this table to
that derivation. Every range was measured against a local stub model that issues one scripted call, in headless runs on macOS:
that is the evidence, and nothing here is a statement about interactive runs, other platforms, or a real model.

Only the standard library is imported.
"""
from __future__ import annotations

import ctypes
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

Version = tuple[int, ...]
MODES = ("interactive", "headless", "yolo")

# [kind, lo, hi, class]. "run": lo..hi inclusive, measured. "gap": strictly between two measured releases of different class.
# Derived by derive_table.py --all from every release the study's lanes measured, plus the round 4 Claude bisect
# (lane-features-r4.json: the ask flip lies between 2.1.84 and 2.1.85). The held-out check ran on the table derived from every
# other round 3 release only (results/hook-fidelity/mitigation/ranges-fit-only.json); a test pins this table to the derivation.
RANGES: dict[str, dict[str, list[list[str]]]] = {
    "claude": {
        "ask": [["run", "2.0.41", "2.1.84", "dropped"],
                ["gap", "2.1.84", "2.1.85", "uncertain"],
                ["run", "2.1.85", "2.1.316", "denied"]],
        "timeout": [["run", "2.0.41", "2.1.316", "runs"]],
        "dead": [["run", "2.0.41", "2.1.316", "runs"]],
    },
    "codex": {
        "ask": [["run", "0.131.0", "0.166.0", "dropped"]],
        "timeout": [["run", "0.143.0", "0.166.0", "runs"]],
        "dead": [["run", "0.165.0", "0.166.0", "runs"]],
        "bypass": [["run", "0.131.0", "0.140.0", "hook-skipped"],
                   ["gap", "0.140.0", "0.141.0", "uncertain"],
                   ["run", "0.141.0", "0.166.0", "hook-runs"]],
    },
    "gemini": {
        "ask": [["run", "0.24.5", "0.37.2", "dropped"],
                ["gap", "0.37.2", "0.38.0", "uncertain"],
                ["run", "0.38.0", "0.66.0", "hangs"]],
        "dead": [["run", "0.24.5", "0.29.7", "runs"],
                 ["gap", "0.29.7", "0.30.0", "uncertain"],
                 ["run", "0.30.0", "0.66.0", "blocks"]],
        "timeout": [["run", "0.66.0", "0.66.0", "runs"]],
    },
}
# The classes, worst first, for merging an unknown version with what is known.
UNSAFE = ("unmeasured", "uncertain")

CALL_EVENTS = ("PreToolUse", "BeforeTool", "beforeMCPExecution", "beforeShellExecution", "beforeReadFile")
# Harnesses whose hook command is measured to run through a shell that honours ``||`` (the evaluation's launcher cells). Cursor is
# not measured: its hooks keep ``failClosed`` instead.
LAUNCHER_HARNESSES = ("claude", "codex", "gemini")
DEFAULT_DEADLINE_S = 30.0  # under the shortest default hook timeout of the harnesses measured (Gemini CLI: 60 s)
# Where the version of each harness is recorded by install and doctor, and read by the hook (stat only: no process is spawned).
CACHE_NAME = "harness-versions.json"


_VERSION = re.compile(r"(?<!\d)(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?!\d)")


def parse_version(text: str) -> Version | None:
    """The first ``X.Y.Z`` of the first non-empty line of ``text`` (a ``--version`` banner puts the version first; a later line
    may name another program's). Components of more than six digits are not versions (``int`` of a longer string is an error
    in Python, so an oversized one in the environment must not reach it)."""
    line = next((ln for ln in (text or "").splitlines() if ln.strip()), "")
    match = _VERSION.search(line)
    return tuple(int(part) for part in match.groups()) if match else None


def _v(text: str) -> Version:
    return tuple(int(part) for part in text.split(".")[:3])


def lookup(harness: str, feature: str, version: Version | None) -> str:
    """The class of ``feature`` for a harness version: a measured class, "uncertain" between two measured releases that differ,
    the newest class for a newer release, "unmeasured" below the oldest measured release or for an unknown version."""
    spans = RANGES.get(harness, {}).get(feature, [])
    if version is None or not spans:
        return "unmeasured"
    for kind, lo, hi, cls in spans:
        if kind == "run" and _v(lo) <= version <= _v(hi):
            return cls
        if kind == "gap" and _v(lo) < version < _v(hi):
            return cls
    if version > _v(spans[-1][2]) and spans[-1][0] == "run":
        return spans[-1][3]  # a release newer than the newest measured one: assumed unchanged (``newer_than_measured`` says so)
    return "unmeasured"


def newer_than_measured(harness: str, feature: str, version: Version | None) -> bool:
    spans = RANGES.get(harness, {}).get(feature, [])
    return bool(version and spans and version > _v(spans[-1][2]))


# ---------------------------------------------------------------------------------------------------- version and mode
def _cache(home: Path | None) -> Path:
    return (home or Path.home()) / ".intentshield" / CACHE_NAME


def record_version(harness: str, version: str, binary: str, home: Path | None = None, path: str = "") -> None:
    """Remember ``harness``'s version, the binary it was read from (its size and modification time, to notice an update in
    place) and the path it was found at (``path``: a symlink such as ``~/.local/bin/claude`` that an auto-update repoints to a new
    versioned file, which the size and time of the old file cannot show). The write is atomic: a hook reading the cache never sees
    half of it."""
    cache = _cache(home)
    try:
        data = json.loads(cache.read_text())
    except (OSError, ValueError):
        data = {}
    try:
        st = os.stat(binary)
        stamp = {"size": st.st_size, "mtime": st.st_mtime}
    except OSError:
        stamp = {}
    data[harness] = {"version": version, "binary": binary, "checked": time.time(), **stamp, **({"path": path} if path else {})}
    cache.parent.mkdir(parents=True, exist_ok=True)
    tmp = cache.with_name(f"{cache.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=1))
    os.replace(tmp, cache)


def probe_and_record(harness: str, home: Path | None = None, timeout: float = 20.0, program: str | None = None) -> Version | None:
    """Ask the harness (``program``, else the one on PATH) for its version (``<harness> --version``) and record it; None when it
    cannot be read. ``intentshield install`` and ``doctor`` call this; the hook calls it only to refresh a record that
    is missing or stale, on an ask in a session that is positively interactive."""
    program = program or shutil.which(_PROCESS[harness])
    if not program:
        return None
    try:
        out = subprocess.run([program, "--version"], capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    version = parse_version(out.stdout or out.stderr)
    if version is not None:
        record_version(harness, ".".join(map(str, version)), os.path.realpath(program), home, path=program)
    return version


def recorded_version(harness: str, home: Path | None = None) -> tuple[Version | None, str]:
    """(version, why not): the recorded version when the binary is unchanged since, else None and the reason."""
    override = os.getenv("INTENTSHIELD_HARNESS_VERSION")
    if override:
        return parse_version(override), "" if parse_version(override) else "INTENTSHIELD_HARNESS_VERSION is not a version"
    try:
        entry = json.loads(_cache(home).read_text())[harness]
        version = parse_version(entry["version"])
    except (OSError, ValueError, KeyError, TypeError):
        return None, "no version recorded (run `intentshield doctor`)"
    try:
        st = os.stat(entry["binary"])
    except (OSError, KeyError):
        return None, "the recorded binary is gone (run `intentshield doctor`)"
    if "size" in entry and (st.st_size != entry["size"] or abs(st.st_mtime - entry["mtime"]) > 1):
        return None, "the harness changed since its version was recorded (run `intentshield doctor`)"
    path = entry.get("path")
    if isinstance(path, str) and path and os.path.realpath(path) != entry["binary"]:
        return None, f"{path} now points at another build than the one recorded (run `intentshield doctor`)"
    return version, ""


ANCESTOR_BUDGET_S = 2.0   # in all, across every source: an ask must not spend the hook's deadline on reading processes
ANCESTRY_ENV = "INTENTSHIELD_ANCESTRY_SOURCES"   # a comma list of sources to try, in order ("none": none); diagnostics and tests
ANCESTRY_SOURCES = ("proc", "libproc", "ps")


class Ancestry(list):
    """(tty, command line) of this process's ancestors, nearest first, as ``_ancestors`` read them, plus what a reader of the mode
    needs to know about the reading: ``source`` (which reader produced it), and ``complete`` (the walk reached the top, or its
    depth limit, without a read failing or the time budget ending). A plain ``list`` handed to ``detect_mode`` is taken as a
    complete chain; an empty or truncated ``Ancestry`` in which the harness is not found says nothing about the harness, and the
    mode is then "unknown", never "headless"."""

    def __init__(self, items=(), source: str = "", complete: bool = False, why: str = "") -> None:
        super().__init__(items)
        self.source, self.complete, self.why = source, complete, why


# One reader per source: pid -> (ppid, tty, command line), or None when that process cannot be read.
def _read_proc(pid: int, root: str = "/proc") -> tuple[int, str, str] | None:
    """Linux: ``/proc/<pid>/stat`` (parent, controlling terminal) and ``/proc/<pid>/cmdline``. No process is spawned."""
    try:
        with open(f"{root}/{pid}/stat", "rb") as handle:
            stat = handle.read().decode("utf-8", "replace")
        rest = stat[stat.rindex(")") + 2:].split()          # after "pid (comm) ": state ppid pgrp session tty_nr ...
        ppid, tty_nr = int(rest[1]), int(rest[4])
        with open(f"{root}/{pid}/cmdline", "rb") as handle:
            words = [w for w in handle.read().decode("utf-8", "replace").split("\0") if w]
        if not words:                                         # a zombie or kernel thread has no arguments
            words = [stat[stat.index("(") + 1:stat.rindex(")")]]
    except (OSError, ValueError, IndexError):
        return None
    tty = "?" if tty_nr == 0 else f"{(tty_nr >> 8) & 0xfff}:{(tty_nr & 0xff) | ((tty_nr >> 12) & 0xfff00)}"
    return ppid, tty, " ".join(words)


_PROC_BSDINFO, _PROC_BSDINFO_SIZE = 3, 136   # PROC_PIDTBSDINFO and sizeof(struct proc_bsdinfo), <sys/proc_info.h>
_NODEV = 0xFFFFFFFF   # e_tdev of a session with no controlling terminal
_libproc_state: dict[str, Any] = {}


def _libproc():
    if "lib" not in _libproc_state:
        try:
            lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
            lib.proc_pidinfo.restype = ctypes.c_int
            libc = ctypes.CDLL(None, use_errno=True)
            libc.sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
                                    ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
            libc.sysctl.restype = ctypes.c_int
            _libproc_state["lib"] = (lib, libc)
        except (OSError, AttributeError):
            _libproc_state["lib"] = None
    return _libproc_state["lib"]


def _procargs(libc, pid: int) -> list[str] | None:
    """The argument vector of ``pid`` from ``sysctl kern.procargs2`` (what ``ps`` prints as the command), None when unreadable."""
    mib = (ctypes.c_int * 3)(1, 49, pid)                       # CTL_KERN, KERN_PROCARGS2
    size = ctypes.c_size_t(0)
    if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0 or not 4 < size.value < 4 << 20:
        return None
    buf = ctypes.create_string_buffer(size.value)
    if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0) != 0:
        return None
    return _parse_procargs(buf.raw[:size.value])


def _parse_procargs(data: bytes) -> list[str] | None:
    """``[argc: int32][exec path\\0][\\0 padding][argv[0]\\0 ... argv[argc-1]\\0][environment]``."""
    if len(data) < 5:
        return None
    argc = struct.unpack_from("=i", data, 0)[0]
    pos = data.find(b"\0", 4)
    if argc < 0 or pos < 0:
        return None
    while pos < len(data) and data[pos] == 0:
        pos += 1
    if pos >= len(data):
        return None
    words = data[pos:].split(b"\0")[:argc]
    return [w.decode("utf-8", "replace") for w in words] if len(words) == argc else None


def _read_libproc(pid: int) -> tuple[int, str, str] | None:
    """macOS: ``proc_pidinfo(PROC_PIDTBSDINFO)`` (parent, controlling terminal) and ``sysctl kern.procargs2`` (arguments), through
    ctypes and the system's own libraries. No process is spawned, so it works where the setuid ``ps`` cannot run (under
    ``sandbox-exec``, or a container without procps). A process whose arguments cannot be read is named by its kernel name."""
    handles = _libproc()
    if handles is None:
        return None
    lib, libc = handles
    buf = ctypes.create_string_buffer(_PROC_BSDINFO_SIZE)
    if lib.proc_pidinfo(pid, _PROC_BSDINFO, 0, buf, _PROC_BSDINFO_SIZE) != _PROC_BSDINFO_SIZE:
        return None
    raw = buf.raw
    got, ppid = struct.unpack_from("=2I", raw, 12)               # pbi_pid, pbi_ppid
    tdev = struct.unpack_from("=I", raw, 108)[0]                # e_tdev; pbi_comm is at 48, pbi_name at 64
    if got != pid:
        return None
    tty = "?" if tdev == _NODEV else f"ttys{tdev & 0xFFFFFF:03d}"
    words = _procargs(libc, pid)
    if not words:
        name = raw[64:96].split(b"\0")[0] or raw[48:64].split(b"\0")[0]
        words = [name.decode("utf-8", "replace")]
    return ppid, tty, " ".join(words)


def _libproc_agrees() -> bool:
    """The layout check, once per process: libproc's answer for this very process must name the parent the OS API names."""
    if "agrees" not in _libproc_state:
        own = _read_libproc(os.getpid())
        _libproc_state["agrees"] = bool(own) and own[0] == os.getppid()
    return _libproc_state["agrees"]


def _read_ps(pid: int, timeout: float = 1.0) -> tuple[int, str, str] | None:
    try:
        line = subprocess.run(["ps", "-o", "ppid=,tty=,command=", "-p", str(pid)], capture_output=True, text=True,
                              timeout=timeout, stdin=subprocess.DEVNULL).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    parts = line.split(None, 2)
    if len(parts) < 3 or not parts[0].isdigit():
        return None
    return int(parts[0]), parts[1], parts[2]


def _walk(read, source: str, depth: int, end: float, top: int | None = None) -> Ancestry:
    """Read the parents from here up. ``top`` is the parent pid that ends the walk once the process holding it has been read: on
    Linux 0 (so PID 1 is read, because in a container it can be the harness itself: ``docker run -it image claude``); on macOS 1
    or less, because pid 1 is ``launchd`` and is never the harness."""
    if top is None:
        top = 0 if sys.platform.startswith("linux") else 1
    out = Ancestry(source=source)
    pid = os.getppid()
    for _ in range(depth):
        if end - time.monotonic() <= 0:
            out.why = "time budget"
            return out
        found = read(pid)
        if found is None:
            out.why = f"could not read process {pid}"
            return out
        out.append((found[1], found[2]))
        if found[0] <= top:
            out.complete = True
            return out
        pid = found[0]
    out.complete = True     # the depth limit: everything this reader meant to read was read
    return out


def _sources() -> list[str]:
    wanted = os.environ.get(ANCESTRY_ENV)
    if wanted is not None:
        return [name for name in (w.strip() for w in wanted.split(",")) if name in ANCESTRY_SOURCES]
    if sys.platform.startswith("linux"):
        return ["proc", "ps"]
    if sys.platform == "darwin":
        return ["libproc", "ps"]
    return ["ps"]


def _ancestors(depth: int = 8, budget: float = ANCESTOR_BUDGET_S) -> Ancestry:
    """The ancestors of this process, nearest first, for the mode detector: from ``/proc`` on Linux and ``libproc`` on macOS
    (no process is spawned, so a missing or unrunnable ``ps`` does not blind it), else from ``ps``. The first source
    that reads the
    whole walk wins; a source that fails part way is replaced by the next, and when none reads a whole walk the longest
    partial one is
    returned, marked incomplete. Read only when a verdict is an ask, because an ask is the one reply whose meaning depends on the
    mode. At most ``budget`` seconds in all."""
    end = time.monotonic() + budget
    best = Ancestry(source="none", why="no source could read the parent process")
    tried: list[str] = []
    for source in _sources():
        if source == "proc":
            result = (_walk(_read_proc, "proc", depth, end) if os.path.isdir("/proc/self")
                      else Ancestry(source="proc", why="no /proc"))
        elif source == "libproc":
            result = (_walk(_read_libproc, "libproc", depth, end) if sys.platform == "darwin" and _libproc_agrees()
                      else Ancestry(source="libproc", why="libproc unavailable or disagrees with the OS"))
        else:
            result = _walk(lambda pid: _read_ps(pid, max(0.05, min(1.0, end - time.monotonic()))), "ps", depth, end)
        if result and result.complete:
            return result
        tried.append(f"{source}: {result.why or 'empty'}")
        if len(result) > len(best):
            best = result
    best.why = "; ".join(tried) or best.why
    return best


# Headless markers, matched against the harness's own arguments (``_leading_args``) and never against a prompt written after them:
# ``claude explain what tar -p does`` and ``codex fix bug e foo`` are interactive sessions whose prompt text holds a flag-like or
# subcommand-like word. Gemini keeps the whole-line match: a positional prompt may itself make a run one-shot, and a wrongly
# headless ask only becomes a refusal.
_HEADLESS_ARGS = {"claude": ("-p", "--print"), "codex": ("exec", "e", "review"), "cursor": ("-p", "--print")}
_GEMINI_HEADLESS = re.compile(r"(?:^|\s)(?:-p|--prompt)(?:\s|=|$)")
_YOLO_FLAG = {"claude": re.compile(r"--dangerously-skip-permissions|--permission-mode[ =]bypassPermissions"),
              "codex": re.compile(r"--dangerously-bypass-approvals-and-sandbox|--yolo"),
              "gemini": re.compile(r"--approval-mode[ =]yolo|(?:^|\s)(?:-y|--yolo)(?:\s|$)"),
              "cursor": re.compile(r"--force|--yolo")}
_PROCESS = {"claude": "claude", "codex": "codex", "gemini": "gemini", "cursor": "cursor-agent"}


def _leading_args(command: str, program_words: int) -> list[str]:
    """The harness's own arguments: those after the program (and its script, for a node launcher), up to the first word that is
    certainly a positional, meaning a word that follows another word and not a ``-flag`` (the prompt, or a subcommand's operand).
    The word right after the program, or right after a flag, may be a subcommand or the flag's value, so it does not end the
    list; it is the one after that."""
    out: list[str] = []
    previous_is_word = False
    for word in command.split()[program_words:]:
        out.append(word)
        if word.startswith("-"):
            previous_is_word = False
        elif previous_is_word:
            break
        else:
            previous_is_word = True
    return out


def _is_headless(harness: str, cmd: str, words: int) -> bool:
    if harness == "gemini":
        return bool(_GEMINI_HEADLESS.search(cmd))
    marks = _HEADLESS_ARGS.get(harness, ())
    args = _leading_args(cmd, words)
    if harness == "codex":   # a subcommand word, which a flag's value may precede
        return any(a in marks for a in args)
    return any(a in marks for a in args if a.startswith("-"))


def running_binary(harness: str, chain: list[tuple[str, str]]) -> str:
    """The path of the harness process among the ancestors when its command starts with an absolute path to it, else "". For a
    node-launched harness the first word is ``node``: not known, and the record is not checked against it."""
    named = re.compile(rf"(?:^|/){re.escape(_PROCESS.get(harness, harness))}$")
    for _tty, cmd in chain:
        first = cmd.split()[0] if cmd.split() else ""
        if first.startswith("/") and named.search(first):
            return first
    return ""


def detect_mode(harness: str, event: dict[str, Any], env: dict[str, str] | None = None,
                ancestors: list[tuple[str, str]] | None = None) -> tuple[str, str]:
    """(mode, how): "interactive", "headless", "yolo", or "unknown". "headless" unless a person is positively evidenced, because
    a wrongly headless ask only becomes a refusal, while a wrongly interactive one can run the call or wait for ever. Interactive
    needs all of: the harness process is found among the ancestors by name, it has a terminal, and its own arguments have no
    headless flag (``-p``, ``exec``) and, for Claude Code, its hook environment does not say the session is unattended. Yolo: the
    harness's own flag, or Claude Code's ``permission_mode`` of ``bypassPermissions`` in the event. ``INTENTSHIELD_HARNESS_MODE``
    overrides (the hook says so on stderr). ``how`` names the ancestry source that decided (``proc``, ``libproc``, ``ps``) when
    the chain came from ``_ancestors``.

    "unknown" is for one case: the ancestry could not be read (no source worked) or was cut short before the harness was found.
    That says nothing about the session, so it is not read as headless (the round 6 pty lane: a hook with no runnable
    ``ps`` turned
    every interactive ask into a refusal with no prompt); ``Semantics.ask_reply`` decides what an ask means then, from what the
    harness build does with it. A complete chain without the harness in it is still headless. Known losses, all in the refusing
    direction: an IDE or desktop embedding with no controlling terminal is read as headless (``CLAUDE_CODE_SESSION_ATTENDED=1`` is
    not taken as evidence of a person, because no run with it set and no terminal was measured), and so is any wrapper that
    renames the process."""
    env = os.environ if env is None else env
    forced = env.get("INTENTSHIELD_HARNESS_MODE", "").strip().lower()
    if forced in MODES:
        return forced, "INTENTSHIELD_HARNESS_MODE"
    if harness == "claude" and event.get("permission_mode") == "bypassPermissions":
        return "yolo", "event permission_mode bypassPermissions"
    chain = _ancestors() if ancestors is None else ancestors
    via = f" [ancestry: {chain.source}]" if isinstance(chain, Ancestry) and chain.source else ""
    name = _PROCESS.get(harness, harness)
    named = re.compile(rf"(?:^|/){re.escape(name)}(?:\.js)?$")   # the program, or the script a node launcher runs
    found = [(tty, cmd, 1 + next(i for i, w in enumerate(cmd.split()[:2]) if named.search(w))) for tty, cmd in chain
             if any(named.search(w) for w in cmd.split()[:2])]
    if not found:
        if isinstance(chain, Ancestry) and not chain.complete:
            return "unknown", f"the ancestors could not be read ({chain.why or 'no reader worked'}): the mode is not assumed{via}"
        return "headless", f"the harness process was not found among the ancestors: assumed headless{via}"
    tty, cmd, words = found[0]
    if harness in _YOLO_FLAG and _YOLO_FLAG[harness].search(cmd):
        return "yolo", f"harness command line has its yolo flag{via}"
    if _is_headless(harness, cmd, words):
        return "headless", f"harness command line has its headless flag{via}"
    if harness == "claude" and env.get("CLAUDE_CODE_SESSION_ATTENDED") == "0":
        return "headless", f"CLAUDE_CODE_SESSION_ATTENDED=0{via}"
    if tty in ("", "?", "??"):
        return "headless", f"the harness has no terminal{via}"
    return "interactive", f"harness process with a terminal and no headless flag{via}"


@dataclass
class Semantics:
    """What one harness build is measured to do with a hook's reply, in one mode. The mode is read on first use."""
    harness: str
    version: Version | None
    event: dict[str, Any] = field(default_factory=dict)
    version_note: str = ""
    classes: dict[str, str] = field(default_factory=dict)  # feature -> class, for the version
    home: Path | None = None
    _mode: tuple[str, str] | None = field(default=None, repr=False)
    _chain: list[tuple[str, str]] | None = field(default=None, repr=False)
    _checked: bool = field(default=False, repr=False)

    @property
    def mode(self) -> str:
        return self.mode_and_source[0]

    @property
    def chain(self) -> list[tuple[str, str]]:
        if self._chain is None:
            self._chain = _ancestors()
        return self._chain

    @property
    def mode_and_source(self) -> tuple[str, str]:
        if self._mode is None:
            self._mode = detect_mode(self.harness, self.event, ancestors=self.chain)
        return self._mode

    def overrides(self) -> list[str]:
        """The environment variables that replace what the hook would otherwise find out; the hook says so on stderr, because a
        project's settings can set them for a session."""
        return [f"{name}={os.environ[name]}" for name in ("INTENTSHIELD_HARNESS_MODE", "INTENTSHIELD_HARNESS_VERSION",
        ANCESTRY_ENV)
                if os.environ.get(name) is not None and (name != ANCESTRY_ENV or os.environ[name])]

    def _verify_version(self) -> None:
        """In a positively interactive session, before an ask is sent as one: make sure the version is that of the harness that is
        running. A record that is missing or stale (an update, or a second install) is refreshed by asking the running binary
        (the ancestor's path, else the one on PATH) for its version, five seconds at most; when that fails, the ask is a
        refusal."""
        if self._checked or os.environ.get("INTENTSHIELD_HARNESS_VERSION"):
            return
        self._checked = True
        running = running_binary(self.harness, self.chain)
        stale = self.version is None
        if not stale and running:
            try:
                entry = json.loads(_cache(self.home).read_text())[self.harness]
                stale = os.path.realpath(running) != entry.get("binary")
            except (OSError, ValueError, KeyError, TypeError):
                stale = True
        if not stale:
            return
        version = probe_and_record(self.harness, self.home, timeout=5.0, program=running or None)
        if version is not None:
            self.version, self.version_note = version, ""
            self.classes = {feature: lookup(self.harness, feature, version) for feature in RANGES.get(self.harness, {})}
        elif self.version is not None:   # the record named another build than the one running, and the running one is unreadable
            self.version, self.classes = None, {feature: "unmeasured" for feature in RANGES.get(self.harness, {})}
            self.version_note = "the running harness is not the build whose version was recorded"

    def ask_reply(self, kind: str, gemini_ask: bool = False) -> tuple[str, str]:
        """("ask" or "deny", why). An ask is sent as an ask only where a person can answer it and the harness is measured (or, for
        Claude Code, documented) to read it; every other case is a refusal that says what was wanted."""
        if self.mode == "unknown":
            return self._ask_unknown(kind)
        if self.mode != "interactive":
            return "deny", f"no one can answer a prompt in a {self.mode} run"
        self._verify_version()
        ask = self.classes.get("ask", "unmeasured")
        note = f" ({self.version_note})" if self.version_note else ""
        if self.harness == "claude":
            if ask == "denied":  # the ask is read and enforced (as a refusal where no one answers); documented to prompt
                return "ask", ""
            return "deny", f"Claude Code {_show(self.version)}: a hook's ask is not measured to be enforced (class {ask}){note}"
        if self.harness == "gemini":
            if kind == "shell" and ask == "hangs" and gemini_ask:
                return "ask", ""
            if kind != "shell":
                return "deny", "Gemini CLI drops an ask for a trusted MCP tool, so an ask is not a guard there"
            return "deny", f"Gemini CLI {_show(self.version)}: an ask is {ask}{note}; --gemini-ask is the opt-in"
        if self.harness == "codex":
            return "deny", "Codex CLI does not support a hook's ask (the call runs)"
        if self.harness == "cursor":
            return ("ask", "") if kind == "shell" else ("deny", "Cursor ran an ask on an allowlisted MCP tool")
        return "deny", "unknown harness"


    def _ask_unknown(self, kind: str) -> tuple[str, str]:
        """An ask when the session's mode could not be read. Not "headless": that costs an interactive user the prompt.
        The table's
        own fate for the build decides, and the choice is named in the reply:

        * Claude Code 2.1.85 and later (class "denied") refuses a hook's ask itself where no one can answer, so the ask
        is passed on
          unchanged: a person gets the prompt, an unattended run gets the refusal it would get from IntentShield's own
          deny. Where the
          build is older, or unmeasured, an ask is not measured to be enforced, so it is a refusal.
        * Gemini CLI waits for an answer in a headless run (a stall of 90 s or more, then the call does not run), and a
        refusal costs
          an interactive user one prompt: the refusal is the lesser harm, and ``INTENTSHIELD_HARNESS_MODE=interactive``
          restores the
          prompt for a session known to have a person.
        * Codex CLI runs a call whose hook asked, in any mode, and Cursor is not measured: a refusal."""
        ask = self.classes.get("ask", "unmeasured")
        note = f" ({self.version_note})" if self.version_note else ""
        if self.harness == "claude":
            if ask == "denied":
                return "ask", (f"mode unknown: Claude Code {_show(self.version)} itself refuses a hook's ask that no one answers "
                               "(measured, 2.1.85 and later), so the ask is passed on unchanged")
            return "deny", (f"the session's mode could not be read, and Claude Code {_show(self.version)} is not measured to "
                            f"enforce a hook's ask (class {ask}){note}")
        if self.harness == "gemini":
            return "deny", ("the session's mode could not be read, and Gemini CLI would wait for an answer in a headless run "
                            "(a stall) where a refusal costs an interactive user one prompt; "
                            "INTENTSHIELD_HARNESS_MODE=interactive restores the prompt")
        if self.harness == "codex":
            return "deny", "Codex CLI does not support a hook's ask (the call runs)"
        return "deny", f"the session's mode could not be read, and {self.harness}'s handling of a hook's ask is not measured"

    def mode_note(self) -> str:
        """What the detector read, in the reply's reason text, so that a run's evidence shows which source decided."""
        mode, how = self.mode_and_source
        return f"[IntentShield read this session as {mode}: {how}]"


def _show(version: Version | None) -> str:
    return ".".join(map(str, version)) if version else "(unknown version)"


def resolve(harness: str, event: dict[str, Any] | None = None, home: Path | None = None,
            env: dict[str, str] | None = None) -> Semantics:
    version, note = recorded_version(harness, home)
    classes = {feature: lookup(harness, feature, version) for feature in RANGES.get(harness, {})}
    sem = Semantics(harness, version, event or {}, note, classes, home)
    if env is not None:  # tests: no process lookup
        sem._mode = detect_mode(harness, event or {}, env, [])
        sem._chain, sem._checked = [], True
    return sem


def ask_refusal(reason: str, why: str) -> str:
    """The reason of an ask sent as a refusal: what the guard wanted, and why the user was not asked."""
    return (f"{reason.rstrip()} (IntentShield wanted the user to confirm this call, but {why}; so it is refused and the user "
            "can allow it.)")


# ---------------------------------------------------------------------------------------------------- fail-closed hook
LAUNCHER = ('|| { rc=$?; [ "$rc" -eq 2 ] || echo "IntentShield hook did not run (exit code $rc); this call is refused." >&2; '
            "exit 2; }")


def launcher(command: str) -> str:
    """``command`` followed by a shell suffix that turns any exit code but 0 into exit 2 with a reason on stderr. Measured: Claude
    Code, Codex CLI and Gemini CLI before 0.30.0 run a call whose hook exited 126, 127 or 1; exit 2 with a reason on stderr is
    a refusal in all of them. The suffix is for the hooks that check a call, and runs in the shell that starts the hook, so a
    dead interpreter (exit 126) is caught too. POSIX shells only: on Windows the command is unchanged."""
    if os.name == "nt" or LAUNCHER in command:
        return command
    return f"{command} {LAUNCHER}"


# ---------------------------------------------------------------------------------------------------- harness-native replies
def native_reply(harness: str, decision: str, reason: str) -> dict[str, Any]:
    """The reply a harness reads as ``decision`` ("deny" or "ask") with ``reason``, exit code 0, in its own shape (the shapes the
    hook-fidelity study measured: Claude Code and Codex ``hookSpecificOutput.permissionDecision``, Gemini CLI ``decision`` and
    ``reason``, Cursor ``permission`` with its two messages). A refusal sent this way is honoured on every build measured, which
    an exit-2 refusal with an empty stderr is not (Codex 0.166.0 ran that call)."""
    reason = reason.strip() or "IntentShield refused this call."
    if harness == "gemini":
        return {"decision": decision, "reason": reason}
    if harness == "cursor":
        return {"permission": decision, "user_message": reason, "agent_message": reason}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                   "permissionDecisionReason": reason}}


# ---------------------------------------------------------------------------------------------------- findings for doctor
def findings(harness: str, version: Version | None, gemini_ask: bool = False) -> list[tuple[str, str]]:
    """(level, message) for the fail-open conditions measured for ``version`` of ``harness``; level is "warn" or "FAIL"."""
    out: list[tuple[str, str]] = []
    shown = _show(version)
    if version is None:
        out.append(("warn", f"{harness}: version unknown, so no measured behaviour applies; run `intentshield doctor` with "
                            f"{harness} on PATH to record it. Until then asks are sent as refusals"))
    if harness == "codex":
        bypass = lookup("codex", "bypass", version)
        if bypass in ("hook-skipped", "uncertain"):
            out.append(("warn", f"Codex CLI {shown}: `codex exec --dangerously-bypass-hook-trust` is measured to NOT run hooks "
                                "through 0.140.0 (it runs them from 0.141.0, the next release). Trust the hooks in "
                                "`codex` once instead"))
        out.append(("warn", f"Codex CLI {shown}: a hook's ask, an empty reply, malformed JSON, exit 1, 126, 127 and a timeout "
                            "all let the call run, and a hook nobody trusted is skipped without a word in `codex exec`. "
                            "IntentShield sends refusals only as a reasoned deny or exit 2 with stderr"))
    elif harness == "claude":
        ask = lookup("claude", "ask", version)
        if ask in ("dropped", "uncertain"):
            between = " (this version lies between the measured releases 2.1.84 and 2.1.85)" if ask == "uncertain" else ""
            out.append(("warn", f"Claude Code {shown}: a hook's ask did not stop a pre-approved Bash call through 2.1.84"
                                f"{between}; IntentShield sends a deny instead"))
        if version is None or version < (2, 1, 295):
            out.append(("warn", f"Claude Code {shown}: `onFailure: block` is documented from 2.1.295 on and was measured to be "
                                "ignored on 2.1.281 (honoured on 2.1.316); before it a hook that fails or times out lets the "
                                "call run. The launcher turns a hook that cannot start into exit 2; the hook's own deadline "
                                "keeps it under its timeout"))
        out.append(("warn", f"Claude Code {shown}: a hook that prints nothing or malformed JSON allows the call, with or without "
                            "`onFailure: block` (measured on 2.1.316)"))
    elif harness == "gemini":
        ask = lookup("gemini", "ask", version)
        if ask in ("dropped", "uncertain"):
            out.append(("warn", f"Gemini CLI {shown}: a hook's ask runs the shell call in yolo mode (0.24.5 to 0.37.2); "
                                "IntentShield sends a deny instead"))
        if ask in ("hangs", "uncertain", "unmeasured") and gemini_ask:
            out.append(("warn", f"Gemini CLI {shown}: --gemini-ask is on, and a headless yolo run (gemini -p) waits for an "
                                "answer that never comes (0.38.0 to 0.66.0, and with the shell allow-listed instead of yolo); "
                                "the hook sends a deny there when it can tell the mode"))
        dead = lookup("gemini", "dead", version)
        if dead == "runs":
            out.append(("warn", f"Gemini CLI {shown}: a hook that cannot start (exit 126, a dead interpreter) lets "
                                                     "the call run before 0.30.0; the launcher refuses it"))
        elif dead == "uncertain":
            out.append(("warn", f"Gemini CLI {shown}: lies between measured releases 0.29.7 (a hook that cannot start lets the "
                                "call run) and 0.30.0 (it blocks the call); the launcher refuses it either way"))
        out.append(("warn", f"Gemini CLI {shown}: a trusted MCP server (trust: true) drops a hook's ask; a hook that exits 2 "
                            "with no text, or exits 126 or 127 with no output, allows the call"))
    return out
