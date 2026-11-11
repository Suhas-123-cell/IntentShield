"""``intentshield wrap-hook``: run ANY third-party hook command under IntentShield's fail-closed launcher, deadline and
version-keyed verdict translation.

    intentshield wrap-hook --harness claude|codex|gemini|cursor [--version X.Y.Z] [--mode interactive|headless|yolo]
                           [--deadline SECONDS] [--hook-timeout SECONDS] [--on-empty deny|allow] [--gemini-ask]
                           -- <guard command ...>

The harness runs this command in place of the guard. It pipes the harness's stdin event to the guard, reads what the guard
answers (exit code, stdout, stderr) and sends the harness ONE reply in the harness's own shape (``translation.native_reply``):

* the guard's exit code 2, with or without text on stderr, is a deny with a reason (a bare exit 2 with an empty stderr is not a
  refusal on every build: Codex 0.166.0 runs the call, and the shim never relies on it);
* any other non-zero exit (1, 126, 127, a signal), a guard that cannot be started and a guard still running at the deadline are
  denies saying so: every harness measured lets such a call run, so the shim refuses it;
* exit 0 with a verdict of deny or block (``hookSpecificOutput.permissionDecision``, a top-level ``decision`` or
  ``permissionDecision`` or Cursor's ``permission``, also ``continue: false``) is a deny; ``ask`` is sent as an ask only where
  ``translation.Semantics.ask_reply`` says this harness build, in this mode, reads and enforces one, else as a deny that says
  what the guard wanted;
* exit 0 with JSON that names no verdict (``{}``, an ``additionalContext`` only) is "no opinion", and an explicit allow is the
  guard's own: either way the guard's bytes are passed through unchanged, so a rewrite or a note still reaches the harness;
* exit 0 with a verdict word this module does not know, text that is not a JSON object, or more than ``MAX_OUTPUT`` bytes is a
  deny (malformed);
* exit 0 with nothing on stdout is what most guards print for an allow (6 of the 8 allow captures in
  ``results/hook-fidelity/guards`` are silent), and also what a guard that failed before it decided prints. The two cannot be told
  apart, so ``--on-empty`` chooses: ``deny`` (the default, fail closed) refuses it, which blocks every silent-allow guard;
  ``allow`` lets it through, which re-opens the empty-reply fail-open path the study measured on Claude Code.

Only events that check a call (``translation.CALL_EVENTS``) are translated and held to the deadline; any other event is passed
to the guard and its exit code, stdout and stderr returned unchanged. An event that carries a tool but whose name is not a call
event nor a documented result or lifecycle event (a missing, re-cased or new name: ``translation.looks_like_call``) is treated as
a call, so a guard that crashes on it is refused, not passed through. The deadline is ``--deadline`` (default 30 s, under
Gemini CLI's 60 s default hook timeout); with ``--hook-timeout`` (what the harness's configuration gives this hook) it is kept
under that timeout, which every harness lets through. Only the standard library is imported, because the harness waits for this
process.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import translation

MAX_OUTPUT = 1_000_000
SHELL_TOOLS = {"Bash", "shell", "local_shell", "exec_command", "run_shell_command"}
_ALLOW = {"allow", "approve", "approved", "proceed"}
_DENY = {"deny", "block", "blocked", "reject", "refuse"}
_ASK = {"ask"}
_CURSOR_KINDS = {"beforeShellExecution": "shell", "beforeMCPExecution": "mcp", "beforeReadFile": "read"}


def effective_deadline(deadline: float, hook_timeout: float = 0.0) -> float:
    """``deadline``, kept under the harness's own timeout for this hook when it is known (one second under it, never less than
    half of it): a slow guard must be answered for before the harness gives up on the hook and runs the call."""
    if hook_timeout and hook_timeout > 0:
        return min(deadline, max(hook_timeout - 1.0, hook_timeout * 0.5))
    return deadline


def _verdict_word(obj: dict[str, Any]) -> tuple[str | None, str, str]:
    """(word, reason, error) of a guard's JSON reply: the verdict word if it names one, the reason text, and a non-empty error
    when a verdict key holds something that is not a verdict."""
    reason = ""
    word: Any = None
    found = False
    spots: list[dict[str, Any]] = [obj]
    hso = obj.get("hookSpecificOutput")
    if isinstance(hso, dict):
        spots.insert(0, hso)
    for spot in spots:
        for key in ("permissionDecision", "decision", "permission"):
            if key in spot:
                word, found = spot[key], True
                break
        if found:
            break
    for spot in spots:
        for key in ("permissionDecisionReason", "reason", "user_message", "agent_message", "stopReason", "systemMessage"):
            if isinstance(spot.get(key), str) and spot[key].strip():
                reason = spot[key].strip()
                break
        if reason:
            break
    if found:
        if not isinstance(word, str):
            return None, reason, f"the verdict is not a string ({type(word).__name__})"
        low = word.strip().lower()
        if low in _ALLOW:
            return "allow", reason, ""
        if low in _DENY:
            return "deny", reason, ""
        if low in _ASK:
            return "ask", reason, ""
        return None, reason, f"the verdict {word[:40]!r} is not one this shim knows (allow, ask, deny, block)"
    if obj.get("continue") is False:
        return "deny", reason or "the guard asked to stop (continue: false)", ""
    return None, reason, ""


def classify(code: int, stdout: str, stderr: str, on_empty: str = "deny") -> tuple[str, str, bool]:
    """(decision, reason, passthrough) for a guard's finished call check: decision "allow", "ask" or "deny"; ``passthrough`` is
    true when the guard's own stdout is to be sent unchanged (an allow, so a rewrite or a note is kept)."""
    err = stderr.strip()
    if code == 2:
        reason = err
        if not reason:
            try:
                obj = json.loads(stdout)
                reason = _verdict_word(obj)[1] if isinstance(obj, dict) else ""
            except ValueError:
                reason = ""
        return "deny", reason or "the guard exited 2 (a block) and gave no reason", False
    if code != 0:
        how = f"was killed by signal {-code}" if code < 0 else f"exited with code {code}"
        tail = f": {err[-200:]}" if err else ""
        return "deny", f"the guard {how}, so this call is refused (a hook that fails lets the call run){tail}", False
    out = stdout.strip()
    if not out:
        if on_empty == "allow":
            return "allow", "", False
        return "deny", ("the guard printed nothing (exit 0), which a harness reads as no objection; refused because "
                        "--on-empty is deny"), False
    if len(stdout.encode("utf-8", "replace")) > MAX_OUTPUT:
        return "deny", "the guard's reply is larger than the limit, so it is not read as a verdict", False
    try:
        obj = json.loads(out)
    except ValueError:
        return "deny", f"the guard's reply is not JSON ({out[:60]!r}), so it is not read as a verdict", False
    if not isinstance(obj, dict):
        return "deny", "the guard's reply is not a JSON object, so it is not read as a verdict", False
    word, reason, error = _verdict_word(obj)
    if error:
        return "deny", f"the guard's reply is malformed: {error}", False
    if word is None or word == "allow":   # no verdict, or the guard's own allow: its bytes go through (a rewrite, a note)
        return "allow", "", True
    return word, reason, False


def _reason_or(reason: str, fallback: str) -> str:
    return reason if reason else fallback


def decide(harness: str, event: dict[str, Any], code: int, stdout: str, stderr: str, sem: translation.Semantics,
           on_empty: str = "deny", gemini_ask: bool = False) -> tuple[dict[str, Any] | None, str, str]:
    """(reply to send, decision sent, why) for a guard's finished call check; the reply is None where nothing is to be printed
    (an allow with nothing to say) and the guard's own stdout is returned as ``why`` text for a passthrough."""
    decision, reason, passthrough = classify(code, stdout, stderr, on_empty)
    if decision == "allow":
        return None, "passthrough" if passthrough else "allow", stdout if passthrough else ""
    if decision == "ask":
        tool = str(event.get("tool_name") or "")
        kind = "shell" if tool in SHELL_TOOLS else "mcp" if tool.startswith("mcp") else "other"
        if harness == "cursor" and event.get("hook_event_name") in _CURSOR_KINDS:  # its shell event carries no tool_name
            kind = _CURSOR_KINDS[event["hook_event_name"]]
        sent, why = sem.ask_reply(kind, gemini_ask)
        if sent == "ask":
            return translation.native_reply(harness, "ask", _reason_or(reason, "The guard wants you to confirm this call.")), \
                "ask", ""
        wanted = _reason_or(reason, "The guard wanted this call confirmed").rstrip()
        text = (f"{wanted} (the guard wanted the user to confirm this "
                f"call, but {why}; so wrap-hook refuses it and the user can allow it.) Do not retry this call or a variant of "
                "it: tell the user what you wanted to do and why, so they can decide.")
        return translation.native_reply(harness, "deny", text), "deny (ask refused)", why
    return translation.native_reply(harness, "deny", reason), "deny", ""


def run_guard(argv: list[str], raw: str, deadline: float | None) -> tuple[int | None, str, str, str]:
    """(exit code, stdout, stderr, problem): the guard run with ``raw`` on stdin, in its own process group so that a guard that
    outlives the deadline is killed with its children. ``problem`` is non-empty when it could not be started or timed out
    (the code is then None)."""
    shell = len(argv) == 1
    try:
        proc = subprocess.Popen(argv[0] if shell else argv, shell=shell, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, errors="replace", start_new_session=True)
    except (OSError, ValueError) as exc:
        return None, "", "", f"the guard could not be started ({type(exc).__name__}: {exc})"
    try:
        out, err = proc.communicate(raw, timeout=deadline)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, PermissionError):
            proc.kill()
        proc.communicate()
        return None, "", "", f"the guard did not answer within {deadline:g} s"
    return proc.returncode, out, err, ""


def wrap(harness: str, guard: list[str], raw: str, *, version: str | None = None, mode: str | None = None,
         deadline: float = translation.DEFAULT_DEADLINE_S, hook_timeout: float = 0.0, on_empty: str = "deny",
         gemini_ask: bool = False, home: Path | None = None, stdout=None, stderr=None) -> int:
    """One hook invocation. Returns the exit code of this process (0 with a reply on stdout, 2 with a reason on stderr for what
    cannot be put into a reply)."""
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    event: dict[str, Any] = {}
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("the event is not a JSON object")
        event = parsed
    except ValueError as exc:
        print(f"IntentShield wrap-hook could not read the harness's event ({exc}); this call is refused.", file=stderr)
        return 2
    if event.get("hook_event_name") not in translation.CALL_EVENTS and not translation.looks_like_call(event):
        code, out, err, problem = run_guard(guard, raw, None)
        if problem:
            print(f"IntentShield wrap-hook: {problem}", file=stderr)
            return 0
        stdout.write(out)
        stderr.write(err)
        return code or 0
    seconds = effective_deadline(deadline, hook_timeout)
    code, out, err, problem = run_guard(guard, raw, seconds)
    if problem:
        reason = f"{problem}, so this call is refused rather than let through unchecked."
        again = " Do not retry this call or a variant of it: tell the user what you wanted to do and why, so they can decide."
        stdout.write(json.dumps(translation.native_reply(harness, "deny", reason + again)) + "\n")
        return 0
    parsed_version = translation.parse_version(version) if version else None
    if version and parsed_version is None:
        print(f"IntentShield wrap-hook: --version {version!r} is not a version; treated as unknown.", file=stderr)
    if parsed_version is not None:
        note = ""
    else:
        parsed_version, note = translation.recorded_version(harness, home)
    classes = {feature: translation.lookup(harness, feature, parsed_version) for feature in translation.RANGES.get(harness, {})}
    sem = translation.Semantics(harness, parsed_version, event, note, classes, home)
    forced = mode or os.getenv("INTENTSHIELD_HARNESS_MODE", "").strip().lower()
    if forced in translation.MODES:
        sem._mode = (forced, "--mode" if mode else "INTENTSHIELD_HARNESS_MODE")
        sem._chain, sem._checked = [], True
    elif forced:
        print(f"IntentShield wrap-hook: mode {forced!r} is not one of {translation.MODES}; detecting instead.", file=stderr)
    reply, sent, extra = decide(harness, event, code if code is not None else -1, out, err, sem, on_empty, gemini_ask)
    if sent == "passthrough":
        stdout.write(extra if extra.endswith("\n") else extra + "\n")
        return 0
    if reply is not None:
        print(f"IntentShield wrap-hook: {sent}", file=stderr)
        stdout.write(json.dumps(reply) + "\n")
    return 0


def wrapped_command(harness: str, guard_command: str, *, wrapper: str = "intentshield wrap-hook", version: str | None = None,
                    deadline: float | None = None, hook_timeout: float | None = None, on_empty: str | None = None,
                    mode: str | None = None, gemini_ask: bool = False) -> str:
    """The hook command to put in the harness's configuration in place of ``guard_command`` (a shell string, as the harness
    would have run it): the shim, then the guard, then the fail-closed launcher, so a shim that cannot start (a dead interpreter,
    exit 126 or 127) is refused too. ``wrapper`` is the shim's own command (a path that is already quoted, or the default)."""
    parts = [wrapper, "--harness", harness]
    for flag, value in (("--version", version), ("--mode", mode), ("--deadline", deadline), ("--hook-timeout", hook_timeout),
                        ("--on-empty", on_empty)):
        if value is not None:
            parts += [flag, shlex.quote(f"{value:g}" if isinstance(value, float) else str(value))]
    if gemini_ask:
        parts.append("--gemini-ask")
    return translation.launcher(" ".join(parts) + " -- " + guard_command)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="intentshield wrap-hook", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--harness", required=True, choices=("claude", "codex", "gemini", "cursor"))
    parser.add_argument("--version", default=None, help="the harness build (X.Y.Z); default: the one `doctor` recorded")
    parser.add_argument("--mode", choices=translation.MODES, default=None,
                        help="override the mode (interactive, headless, yolo) the shim would detect from the process tree")
    parser.add_argument("--deadline", type=float, default=translation.DEFAULT_DEADLINE_S,
                        help="seconds after which a guard still running is refused (default 30)")
    parser.add_argument("--hook-timeout", type=float, default=0.0,
                        help="the timeout the harness's configuration gives this hook: the deadline is kept under it")
    parser.add_argument("--on-empty", choices=("deny", "allow"), default="deny",
                        help="exit 0 with nothing on stdout: deny (default, fail closed) or allow (what silent guards mean)")
    parser.add_argument("--gemini-ask", action="store_true", help="Gemini CLI 0.66 or later, interactive only: keep an ask")
    parser.add_argument("guard", nargs=argparse.REMAINDER, help="-- then the guard's command (one shell string, or argv)")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    guard = args.guard[1:] if args.guard[:1] == ["--"] else args.guard
    if not guard:
        print("intentshield wrap-hook: no guard command after `--`", file=sys.stderr)
        sys.exit(2)
    if not 0 < args.deadline <= 3600:  # also false for nan; inf cannot be waited for
        print("intentshield wrap-hook: --deadline must be a number of seconds from 0 (exclusive) to 3600", file=sys.stderr)
        sys.exit(2)
    if not 0 <= args.hook_timeout <= 86_400:
        print("intentshield wrap-hook: --hook-timeout must be a number of seconds from 0 to 86400", file=sys.stderr)
        sys.exit(2)
    try:
        raw = sys.stdin.read()
        code = wrap(args.harness, guard, raw, version=args.version, mode=args.mode, deadline=args.deadline,
                    hook_timeout=args.hook_timeout, on_empty=args.on_empty, gemini_ask=args.gemini_ask)
    except Exception as exc:  # the shim's own failure: a refusal the harness honours, never a silent allow
        print(f"IntentShield wrap-hook failed ({type(exc).__name__}: {exc}); this call is refused.", file=sys.stderr)
        code = 2
    sys.stdout.flush()
    sys.exit(code)


if __name__ == "__main__":  # pragma: no cover
    main()
