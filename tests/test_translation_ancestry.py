"""Round 7: the mode detector no longer needs a runnable ``ps`` (src/intentshield/translation.py).

Round 6's pty lane found that with no runnable ``ps`` (``sandbox-exec`` blocks the setuid binary; a container may have
no procps) the
detector read "harness process not found: assumed headless" for an interactive session, and an ask became a refusal
with no prompt.
Now: ps-free ancestry readers (``/proc`` on Linux, ``libproc`` and ``sysctl`` on macOS), and when no reader works the mode is
"unknown", for which an ask is decided by what the harness build does with it. Tests here launch no harness."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from intentshield import translation
from intentshield.harness import HarnessGuard, Verdict, handle

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmarks" / "hook_fidelity"
DARWIN = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")


# ------------------------------------------------------------------------------------------------ the /proc reader
def _fake_proc(root: Path, pid: int, ppid: int, comm: str, cmdline: list[str], tty_nr: int = 0) -> None:
    d = root / str(pid)
    d.mkdir(parents=True)
    # pid (comm) state ppid pgrp session tty_nr ...: a comm may hold spaces and parentheses, so only the LAST ")" ends it
    (d / "stat").write_text(f"{pid} ({comm}) S {ppid} {pid} {pid} {tty_nr} 0 4194304 100 0 0 0\n")
    (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in cmdline) + (b"\0" if cmdline else b""))


def test_the_proc_reader_reads_parent_terminal_and_arguments(tmp_path):
    _fake_proc(tmp_path, 40, 30, "claude", ["/home/u/.local/bin/claude", "--model", "x"], tty_nr=34816)   # /dev/pts/0: 136:0
    _fake_proc(tmp_path, 41, 40, "bash", ["bash", "-c", "hook"])
    assert translation._read_proc(40, str(tmp_path)) == (30, "136:0", "/home/u/.local/bin/claude --model x")
    assert translation._read_proc(41, str(tmp_path)) == (40, "?", "bash -c hook")      # tty_nr 0: no controlling terminal


def test_the_proc_reader_survives_a_comm_with_parentheses_and_a_zombie(tmp_path):
    _fake_proc(tmp_path, 50, 7, "evil) S 1 (x", ["prog"], tty_nr=0)
    assert translation._read_proc(50, str(tmp_path)) == (7, "?", "prog")
    _fake_proc(tmp_path, 51, 7, "defunct one", [])                                     # no arguments: named by its comm
    assert translation._read_proc(51, str(tmp_path)) == (7, "?", "defunct one")


def test_the_proc_reader_returns_none_for_a_missing_or_garbled_process(tmp_path):
    assert translation._read_proc(99, str(tmp_path)) is None
    (tmp_path / "98").mkdir()
    (tmp_path / "98" / "stat").write_text("98 no parenthesis here")
    assert translation._read_proc(98, str(tmp_path)) is None


def _proc_walk(tmp_path, monkeypatch, start, platform):
    monkeypatch.setattr(os, "getppid", lambda: start)
    monkeypatch.setattr(translation.sys, "platform", platform)
    return translation._walk(lambda pid: translation._read_proc(pid, str(tmp_path)), "proc", 8, translation.time.monotonic() + 5)


def test_a_walk_on_linux_reads_init_and_stops_at_parent_zero(tmp_path, monkeypatch):
    _fake_proc(tmp_path, 30, 20, "claude", ["/u/bin/claude"], tty_nr=34816)
    _fake_proc(tmp_path, 20, 1, "sh", ["sh"], tty_nr=34816)
    _fake_proc(tmp_path, 1, 0, "init", ["/sbin/init"])
    chain = _proc_walk(tmp_path, monkeypatch, 30, "linux")
    assert [cmd for _, cmd in chain] == ["/u/bin/claude", "sh", "/sbin/init"] and chain.complete and chain.source == "proc"
    assert translation.detect_mode("claude", {}, {}, chain)[0] == "interactive"


def test_a_harness_that_is_pid_1_is_found_on_linux(tmp_path, monkeypatch):
    # docker run -it image claude: the hook's parent is sh (pid 20), whose parent is the harness, pid 1, whose parent is 0
    _fake_proc(tmp_path, 20, 1, "sh", ["sh", "-c", "hook"])
    _fake_proc(tmp_path, 1, 0, "claude", ["claude"], tty_nr=34816)
    chain = _proc_walk(tmp_path, monkeypatch, 20, "linux")
    assert [cmd for _, cmd in chain] == ["sh -c hook", "claude"] and chain.complete
    assert translation.detect_mode("claude", {}, {}, chain)[0] == "interactive"
    _fake_proc(tmp_path, 21, 1, "sh", ["sh"])
    (tmp_path / "1" / "cmdline").write_bytes(b"claude\0-p\0")
    assert translation.detect_mode("claude", {}, {}, _proc_walk(tmp_path, monkeypatch, 21, "linux"))[0] == "headless"


def test_a_walk_on_linux_whose_pid_1_is_unreadable_is_incomplete(tmp_path, monkeypatch):
    _fake_proc(tmp_path, 20, 1, "sh", ["sh"])
    chain = _proc_walk(tmp_path, monkeypatch, 20, "linux")
    assert len(chain) == 1 and not chain.complete and "process 1" in chain.why


def test_a_walk_on_macos_stops_at_launchd_without_reading_it(tmp_path, monkeypatch):
    _fake_proc(tmp_path, 30, 20, "claude", ["/u/bin/claude"], tty_nr=34816)
    _fake_proc(tmp_path, 20, 1, "sh", ["sh"], tty_nr=34816)
    chain = _proc_walk(tmp_path, monkeypatch, 30, "darwin")      # no pid 1 on disk: reading it would fail the walk
    assert [cmd for _, cmd in chain] == ["/u/bin/claude", "sh"] and chain.complete and chain.source == "proc"
    assert translation.detect_mode("claude", {}, {}, chain)[0] == "interactive"


def test_an_explicit_top_overrides_the_platform(tmp_path, monkeypatch):
    _fake_proc(tmp_path, 20, 1, "sh", ["sh"])
    monkeypatch.setattr(os, "getppid", lambda: 20)
    end = translation.time.monotonic() + 5
    chain = translation._walk(lambda pid: translation._read_proc(pid, str(tmp_path)), "proc", 8, end, top=1)
    assert len(chain) == 1 and chain.complete


def test_a_walk_that_cannot_read_a_parent_is_incomplete_and_says_which(tmp_path, monkeypatch):
    _fake_proc(tmp_path, 30, 20, "sh", ["sh"])                                         # its parent, 20, is not readable
    monkeypatch.setattr(os, "getppid", lambda: 30)
    chain = translation._walk(lambda pid: translation._read_proc(pid, str(tmp_path)), "proc", 8, translation.time.monotonic() + 5)
    assert len(chain) == 1 and not chain.complete and "process 20" in chain.why


# ------------------------------------------------------------------------------------------------ the macOS reader
def test_procargs_parsing():
    blob = (3).to_bytes(4, "little") + b"/bin/zsh\0\0\0\0" + b"zsh\0-c\0echo hi\0" + b"HOME=/x\0PATH=/y\0"
    assert translation._parse_procargs(blob) == ["zsh", "-c", "echo hi"]
    assert translation._parse_procargs(b"\1\0\0\0/bin/x\0\0") is None                     # argc says 1, nothing follows
    assert translation._parse_procargs(b"\0") is None


@pytest.mark.skipif(not DARWIN, reason="libproc is macOS")
def test_libproc_agrees_with_the_os_and_with_ps_on_this_process():
    own = translation._read_libproc(os.getpid())
    assert own is not None and own[0] == os.getppid() and Path(own[2].split()[0]).name.lower().startswith("python")
    assert translation._libproc_agrees()
    try:
        ps = subprocess.run(["ps", "-o", "ppid=,tty=,command=", "-p", str(os.getpid())], capture_output=True, text=True,
                            timeout=5).stdout.split(None, 2)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("ps cannot run here")
    assert int(ps[0]) == own[0]
    assert (ps[1] in ("?", "??")) == (own[1] == "?")                                      # terminal or none, as ps says
    assert ps[2].split()[0] == own[2].split()[0]


@pytest.mark.skipif(not DARWIN, reason="libproc is macOS")
def test_libproc_reads_the_terminal_of_a_process_on_a_pty():
    """A real pty: the reader must say the process has a terminal, the property the detector depends on."""
    import pty
    import select
    master, slave = pty.openpty()
    src = str(ROOT / "src")
    code = (f"import sys, os; sys.path.insert(0, {src!r}); from intentshield import translation as t; "
            "print('TTY=' + t._read_libproc(os.getpid())[1])")
    boot = ("import os,sys,fcntl,termios\nos.setsid()\nfcntl.ioctl(0,termios.TIOCSCTTY,0)\n"
            "os.execvp(sys.argv[1],sys.argv[1:])\n")
    proc = subprocess.Popen([sys.executable, "-c", boot, sys.executable, "-c", code], stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    out = b""
    while select.select([master], [], [], 10)[0]:
        try:
            chunk = os.read(master, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    proc.wait(timeout=10)
    os.close(master)
    assert b"TTY=ttys" in out, out


@pytest.mark.skipif(not LINUX, reason="/proc is Linux")
def test_the_real_proc_reader_agrees_with_the_os():
    own = translation._read_proc(os.getpid())
    assert own is not None and own[0] == os.getppid()


# ------------------------------------------------------------------------------------------------ the orchestrator
@pytest.mark.skipif(not (DARWIN or LINUX), reason="a ps-free reader exists for macOS and Linux")
def test_the_ancestry_is_read_with_no_runnable_ps(monkeypatch):
    if os.getppid() <= 0:
        pytest.skip("this test process is PID 1 (docker run without --init): it has no ancestors to read")
    if DARWIN and os.getppid() == 1:
        pytest.skip("pytest is an orphaned nohup job: its parent is launchd, which libproc cannot read, so no ancestors")

    def no_ps(*args, **kwargs):
        raise PermissionError("Operation not permitted")      # what sandbox-exec says to the setuid ps

    monkeypatch.setattr(translation.subprocess, "run", no_ps)
    monkeypatch.delenv(translation.ANCESTRY_ENV, raising=False)
    chain = translation._ancestors()
    assert chain and chain.complete and chain.source in ("proc", "libproc")
    assert chain[0][1].split()[0]            # the nearest ancestor has a command line


def test_the_order_of_sources_and_the_environment_restriction(monkeypatch):
    monkeypatch.setenv(translation.ANCESTRY_ENV, "ps")
    assert translation._sources() == ["ps"]
    monkeypatch.setenv(translation.ANCESTRY_ENV, "none")
    assert translation._sources() == []
    monkeypatch.setenv(translation.ANCESTRY_ENV, "bogus, libproc")
    assert translation._sources() == ["libproc"]
    monkeypatch.delenv(translation.ANCESTRY_ENV)
    monkeypatch.setattr(sys, "platform", "linux")
    assert translation._sources() == ["proc", "ps"]
    monkeypatch.setattr(sys, "platform", "darwin")
    assert translation._sources() == ["libproc", "ps"]
    monkeypatch.setattr(sys, "platform", "win32")
    assert translation._sources() == ["ps"]


def test_a_failed_source_falls_through_to_ps_and_names_it(monkeypatch):
    monkeypatch.setenv(translation.ANCESTRY_ENV, "proc,ps")
    monkeypatch.setattr(translation.os.path, "isdir", lambda p: False)               # no /proc here

    def fake_ps(argv, **kwargs):
        pid = int(argv[-1])
        line = {os.getppid(): "55 ttys001 /u/bin/claude --model x", 55: "0 ttys001 /bin/zsh"}[pid]   # parent 0 ends every walk
        return subprocess.CompletedProcess(argv, 0, stdout=line + "\n", stderr="")

    monkeypatch.setattr(translation.subprocess, "run", fake_ps)
    chain = translation._ancestors()
    assert chain.source == "ps" and chain.complete and chain[0] == ("ttys001", "/u/bin/claude --model x")
    mode, how = translation.detect_mode("claude", {}, {}, chain)
    assert mode == "interactive" and "[ancestry: ps]" in how


def test_every_source_failing_gives_an_empty_incomplete_ancestry_with_each_reason(monkeypatch):
    monkeypatch.setenv(translation.ANCESTRY_ENV, "proc,libproc,ps")
    monkeypatch.setattr(translation.os.path, "isdir", lambda p: False)
    monkeypatch.setattr(translation, "_libproc_agrees", lambda: False)

    def no_ps(*a, **k):
        raise FileNotFoundError("ps")

    monkeypatch.setattr(translation.subprocess, "run", no_ps)
    chain = translation._ancestors()
    assert list(chain) == [] and not chain.complete
    assert "proc: no /proc" in chain.why and "libproc:" in chain.why and "ps: could not read process" in chain.why


def test_a_partial_source_is_kept_when_no_other_completes(monkeypatch):
    monkeypatch.setenv(translation.ANCESTRY_ENV, "ps")
    calls = []

    def one_then_gone(argv, **kwargs):
        calls.append(argv)
        if len(calls) == 1:
            return subprocess.CompletedProcess(argv, 0, stdout="77 ttys001 /bin/zsh\n", stderr="")
        raise PermissionError("blocked")

    monkeypatch.setattr(translation.subprocess, "run", one_then_gone)
    chain = translation._ancestors()
    assert len(chain) == 1 and not chain.complete and chain.source == "ps"


# ------------------------------------------------------------------------------------------------ the detector's "unknown"
def test_unreadable_ancestry_is_unknown_never_headless():
    blind = translation.Ancestry(source="none", why="no source could read the parent process")
    mode, how = translation.detect_mode("claude", {}, {}, blind)
    assert mode == "unknown" and "not assumed" in how
    cut = translation.Ancestry([("ttys001", "/bin/zsh")], source="ps", complete=False, why="could not read process 9")
    assert translation.detect_mode("claude", {}, {}, cut)[0] == "unknown"             # cut short before the harness was found


def test_a_complete_chain_without_the_harness_is_still_headless():
    chain = translation.Ancestry([("ttys001", "/bin/zsh"), ("??", "/sbin/launchd")], source="libproc", complete=True)
    mode, how = translation.detect_mode("claude", {}, {}, chain)
    assert mode == "headless" and "assumed headless" in how and "[ancestry: libproc]" in how
    assert translation.detect_mode("claude", {}, {}, [])[0] == "headless"             # a plain list is taken as a whole chain


def test_a_partial_chain_that_does_contain_the_harness_is_read_normally():
    cut = translation.Ancestry([("ttys001", "/u/bin/claude")], source="proc", complete=False)
    assert translation.detect_mode("claude", {}, {}, cut)[0] == "interactive"
    cut_p = translation.Ancestry([("ttys001", "/u/bin/claude -p hi")], source="proc", complete=False)
    assert translation.detect_mode("claude", {}, {}, cut_p)[0] == "headless"


def test_overrides_and_the_event_still_beat_a_blind_ancestry():
    blind = translation.Ancestry(source="none")
    assert translation.detect_mode("claude", {}, {"INTENTSHIELD_HARNESS_MODE": "interactive"}, blind)[0] == "interactive"
    assert translation.detect_mode("claude", {"permission_mode": "bypassPermissions"}, {}, blind)[0] == "yolo"


def test_the_ancestry_restriction_is_reported_like_the_other_overrides(monkeypatch):
    sem = translation.Semantics("claude", (2, 1, 316))
    for name in ("INTENTSHIELD_HARNESS_MODE", "INTENTSHIELD_HARNESS_VERSION", translation.ANCESTRY_ENV):
        monkeypatch.delenv(name, raising=False)
    assert sem.overrides() == []
    monkeypatch.setenv(translation.ANCESTRY_ENV, "none")
    assert sem.overrides() == [f"{translation.ANCESTRY_ENV}=none"]


# ------------------------------------------------------------------------ the ask when the mode is unknown
def _unknown(harness_name: str, version: str | None) -> translation.Semantics:
    parsed = translation.parse_version(version) if version else None
    sem = translation.Semantics(harness_name, parsed, classes={f: translation.lookup(harness_name, f, parsed)
                                                               for f in translation.RANGES.get(harness_name, {})})
    sem._mode = ("unknown", "the ancestors could not be read (test): the mode is not assumed")
    sem._chain, sem._checked = translation.Ancestry(source="none"), True
    return sem


@pytest.mark.parametrize("version,expected", [("2.1.316", "ask"), ("2.1.85", "ask"), ("2.1.300", "ask"), ("2.1.84", "deny"),
                                              ("2.0.41", "deny"), ("2.0.10", "deny"), (None, "deny")])
def test_claude_unknown_mode_passes_the_ask_where_the_harness_itself_refuses_an_unanswered_one(version, expected):
    decision, why = _unknown("claude", version).ask_reply("shell")
    assert decision == expected and why
    if decision == "ask":
        assert "itself refuses a hook's ask that no one answers" in why


@pytest.mark.parametrize("harness_name,version,kind", [("gemini", "0.66.0", "shell"), ("gemini", "0.38.0", "shell"),
                                                        ("gemini", "0.37.1", "shell"), ("gemini", "0.66.0", "mcp"),
                                                        ("codex", "0.166.0", "shell"), ("cursor", None, "shell")])
def test_every_other_harness_refuses_an_ask_when_the_mode_is_unknown(harness_name, version, kind):
    decision, why = _unknown(harness_name, version).ask_reply(kind, gemini_ask=True)
    assert decision == "deny" and why


def test_the_gemini_choice_is_named_with_its_reason_and_its_way_out():
    _, why = _unknown("gemini", "0.66.0").ask_reply("shell", gemini_ask=True)
    assert "stall" in why and "INTENTSHIELD_HARNESS_MODE=interactive" in why


def test_unknown_does_not_probe_a_harness_binary(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("an unknown mode must not run `<harness> --version`")

    monkeypatch.setattr(translation, "probe_and_record", boom)
    assert _unknown("claude", None).ask_reply("shell")[0] == "deny"


# ------------------------------------------------------------------------------------------------ the reply carries what was read
def _guard(tmp_path: Path, sem) -> HarnessGuard:
    g = HarnessGuard(tmp_path / "h.db", builtin_tools=True)
    g.translation = sem
    return g


def _force_ask(monkeypatch):
    verdict = lambda self, *a, **k: Verdict("ask", "because", user_reason="shown to the user")
    for name in ("shell", "call", "file", "fetch"):
        monkeypatch.setattr(HarnessGuard, name, verdict)


def _pre():
    return {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": "touch x"}}


def test_a_claude_ask_with_an_unreadable_session_is_sent_as_an_ask_that_names_why(tmp_path, monkeypatch):
    _force_ask(monkeypatch)
    reply = handle("claude", _pre(), _guard(tmp_path, _unknown("claude", "2.1.316")))["hookSpecificOutput"]
    text = reply["permissionDecisionReason"]
    assert reply["permissionDecision"] == "ask" and text.startswith("shown to the user")
    assert "read this session as unknown" in text and "the ask is passed on unchanged" in text


def test_a_refused_ask_carries_the_reading_too(tmp_path, monkeypatch):
    _force_ask(monkeypatch)
    reply = handle("claude", _pre(), _guard(tmp_path, _unknown("claude", "2.1.84")))["hookSpecificOutput"]
    assert reply["permissionDecision"] == "deny" and "read this session as unknown" in reply["permissionDecisionReason"]
    event = {"hook_event_name": "BeforeTool", "session_id": "s", "tool_name": "run_shell_command", "tool_input": {"command": "x"}}
    gem = handle("gemini", event, _guard(tmp_path, _unknown("gemini", "0.66.0")))
    assert gem["decision"] == "deny" and "read this session as unknown" in gem["reason"]


def test_a_known_reading_names_its_source_in_the_reply(tmp_path, monkeypatch):
    _force_ask(monkeypatch)
    sem = _unknown("claude", "2.1.316")
    sem._mode = translation.detect_mode("claude", {}, {}, translation.Ancestry([("ttys002", "/u/bin/claude")], "libproc", True))
    reply = handle("claude", _pre(), _guard(tmp_path, sem))["hookSpecificOutput"]
    assert reply["permissionDecision"] == "ask" and "read this session as interactive" in reply["permissionDecisionReason"]
    assert "[ancestry: libproc]" in reply["permissionDecisionReason"]


# ---------------------------------------------------------------- the whole hook, no readable ancestry

def test_the_hook_process_with_every_source_off_keeps_a_claude_ask(tmp_path):
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "s3", "tool_input": {"command": "touch x"},
             "cwd": str(tmp_path)}
    env = {**os.environ, "INTENTSHIELD_HARNESS_VERSION": "2.1.316", translation.ANCESTRY_ENV: "none",
           "INTENTSHIELD_HOOK_DB": str(tmp_path / "h.db"), "INTENTSHIELD_THREAT_MEMORY": "0"}
    env.pop("INTENTSHIELD_HARNESS_MODE", None)
    argv = [sys.executable, str(BENCH / "mitigation_hook.py"), "claude", "--builtin-tools", "--eval-verdict", "ask",
            "--eval-translate", "on"]
    done = subprocess.run(argv, input=json.dumps(event), capture_output=True, text=True, env=env)
    out = json.loads(done.stdout)["hookSpecificOutput"]
    assert out["permissionDecision"] == "ask" and "read this session as unknown" in out["permissionDecisionReason"]
    assert f"{translation.ANCESTRY_ENV}=none replaces what the hook would detect" in done.stderr
