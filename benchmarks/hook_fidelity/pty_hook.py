"""The hook the interactive pty lane installs: ``mitigation_hook`` (IntentShield's real hook entry point with the guard's
decision fixed)
plus an observer that writes, per hook event, what the mode detector said and what the hook sent back.

Nothing here changes what the hook decides. It adds, around the unchanged ``mitigation_hook.main``:

* ``probe``: ``translation.detect_mode`` called on its own for every call event, from the same process and so from the same
ancestors the
  real lookup uses (the ancestor ``ps`` walk has a 2 s budget, so the evaluation's handler timeout is long);
* ``ask_reply``: ``translation.Semantics.ask_reply`` wrapped so that the decision the shipped code took on an ask (mode, why,
version
  class, the reply kind) is written down; the wrapper returns exactly what the original returns;
* ``reply``: the bytes the hook wrote to stdout and its exit code.

Extra arguments (stripped before the hook runs): ``--pty-log PATH``, one JSON line per event, written when the hook finishes (and
a first
line when it starts, so a hook killed by the harness still leaves a trace); ``--ancestry-sources LIST`` (round 7), which sets
``INTENTSHIELD_ANCESTRY_SOURCES`` in this process (``none``: no ancestry reader may run, the case of a host where ``/proc``,
``libproc`` and ``ps`` are all unreadable) because a harness may scrub the hook's environment.

Round 7 adds three facts to the start row that do not come from the detector, so that its reading can be checked against something
other than how the run was launched: ``has_ctty`` (the hook process can open ``/dev/tty``), ``stdout_isatty``, and
``ps_check`` (whether
this process can run ``ps`` at all: ``ok`` or the error).
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "src"))
sys.path.insert(0, str(HERE))


def _pop(argv: list[str], flag: str, default: str = "") -> str:
    if flag in argv:
        at = argv.index(flag)
        value = argv[at + 1]
        del argv[at : at + 2]
        return value
    return default


def _has_ctty() -> bool:
    """Whether this process has a controlling terminal (it can open /dev/tty): the fact the detector's tty column stands for."""
    try:
        os.close(os.open("/dev/tty", os.O_RDWR))
        return True
    except OSError:
        return False


def _ps_check() -> str:
    """``ok`` when ``ps`` runs from this process, else the error (the sandbox blocks the setuid binary: ``PermissionError``)."""
    import subprocess

    try:
        done = subprocess.run(["ps", "-o", "pid=", "-p", str(os.getpid())], capture_output=True, text=True, timeout=3,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"{type(exc).__name__}: {exc}"[:120]
    return "ok" if done.returncode == 0 and done.stdout.strip() else f"exit {done.returncode}: {done.stderr.strip()[:80]}"


def _append(path: str, row: dict) -> None:
    if path:
        with open(path, "a") as handle:
            handle.write(json.dumps(row) + "\n")


class _Tee(io.StringIO):
    """Collects what the hook prints and passes it on."""

    def __init__(self, real) -> None:
        super().__init__()
        self.real = real

    def write(self, text: str) -> int:
        super().write(text)
        return self.real.write(text)

    def flush(self) -> None:
        self.real.flush()


def main() -> None:
    argv = sys.argv
    log = _pop(argv, "--pty-log")
    sources = _pop(argv, "--ancestry-sources")
    if sources:
        os.environ["INTENTSHIELD_ANCESTRY_SOURCES"] = sources
    harness = argv[argv.index("--harness") + 1] if "--harness" in argv else (argv[1] if len(argv) > 1 else "")
    raw = sys.stdin.read()
    try:
        event = json.loads(raw)
    except ValueError:
        event = {}
    name = event.get("hook_event_name") if isinstance(event, dict) else None
    from intentshield import translation

    is_call = name in translation.CALL_EVENTS
    row: dict = {
        "ts": time.time(),
        "pid": os.getpid(),
        "phase": "start",
        "event": name,
        "harness": harness,
        "env_attended": os.environ.get("CLAUDE_CODE_SESSION_ATTENDED"),
        "env_entrypoint": os.environ.get("CLAUDE_CODE_ENTRYPOINT"),
        "stdin_isatty": os.isatty(0),
        "stdout_isatty": os.isatty(1),
        "has_ctty": _has_ctty(),
        "ancestry_sources_env": os.environ.get("INTENTSHIELD_ANCESTRY_SOURCES"),
    }
    if is_call:
        row["ps_check"] = _ps_check()
        t0 = time.monotonic()
        try:
            chain = translation._ancestors()
            mode, source = translation.detect_mode(harness, event, ancestors=chain)
            row["probe_mode"], row["probe_source"] = mode, source
            row["probe_chain"] = [[tty, " ".join(cmd.split()[:3])[:160]] for tty, cmd in chain]
            row["probe_ancestry"] = {"source": getattr(chain, "source", "given"), "complete": getattr(chain, "complete", True),
                                     "why": getattr(chain, "why", "")}
        except Exception as exc:  # an observer must not stop the hook
            row["probe_error"] = f"{type(exc).__name__}: {exc}"
        row["probe_s"] = round(time.monotonic() - t0, 3)
    _append(log, row)

    decisions: list[dict] = []
    original = translation.Semantics.ask_reply

    def ask_reply(self, kind, gemini_ask=False):
        result = original(self, kind, gemini_ask)
        decisions.append(
            {
                "kind": kind,
                "gemini_ask": gemini_ask,
                "mode": self.mode,
                "mode_source": self.mode_and_source[1],
                "mode_note": self.mode_note(),
                "version": ".".join(map(str, self.version)) if self.version else None,
                "ask_class": self.classes.get("ask"),
                "version_note": self.version_note,
                "sent": result[0],
                "why": result[1][:200],
            }
        )
        return result

    translation.Semantics.ask_reply = ask_reply
    sys.stdin = io.StringIO(raw)
    tee = _Tee(sys.stdout)
    sys.stdout = tee
    code: object = 0
    try:
        import mitigation_hook

        mitigation_hook.main()
    except SystemExit as exc:
        code = exc.code
        raise
    finally:
        sys.stdout = tee.real
        _append(
            log,
            {
                "ts": time.time(),
                "pid": os.getpid(),
                "phase": "end",
                "event": name,
                "exit_code": code,
                "reply_stdout": tee.getvalue()[:600],
                "ask_decisions": decisions,
            },
        )


if __name__ == "__main__":
    main()
