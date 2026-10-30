"""Does a Gemini CLI BeforeTool hook's "ask" decision stop a shell command, prompt the user, or let it run?

    gemini_ask_probe.py run <mode> <outdir>   # mode: yolo | default | interactive-yolo | interactive-default
    gemini_ask_probe.py hook <log>            # the stub hook it installs: "ask" for every run_shell_command

The agent is told to run `touch ran.txt` in a fresh directory; whether ran.txt exists is the answer. The
interactive modes run Gemini CLI in a pseudo-terminal, save the screen text, and answer a prompt with Escape
(PROBE_ANSWER=approve sends Enter instead). PROBE_HOOK=intentshield installs the real hook instead of the stub
(`--builtin-tools --review always --gemini-ask`, so it asks before any command that changes something).
Auto-update is switched off in the probe's settings: an earlier interactive run without that let Gemini CLI
update itself. Uses GEMINI_API_KEY from .env (free tier).
"""
import json
import os
import pty
import re
import select
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROMPT = "Run exactly this shell command and nothing else: touch ran.txt   Then reply with the single word done."
# Screen text that means Gemini CLI is waiting for the user: its own dialogs, or a hook's message above one.
PROMPTED = r"Allow execution|Do you want to proceed|Apply this change|PROBE: confirm|IntentShield asks|IntentShield:"


def hook(log: str) -> int:
    event = json.loads(sys.stdin.read() or "{}")
    reply = {}
    if event.get("hook_event_name") == "BeforeTool" and event.get("tool_name") == "run_shell_command":
        reply = {"decision": "ask", "reason": "stub ask from the probe", "systemMessage": "PROBE: confirm this command?"}
    with open(log, "a") as handle:
        handle.write(json.dumps({"event": event.get("hook_event_name"), "tool": event.get("tool_name"),
                                 "reply": reply}) + "\n")
    print(json.dumps(reply))
    return 0


def tap(log: str, command: list[str]) -> int:
    """Runs the real hook on the event and logs its reply."""
    event = sys.stdin.read()
    done = subprocess.run(command, input=event, capture_output=True, text=True)
    reply = json.loads(done.stdout) if done.stdout.strip() else {}
    with open(log, "a") as handle:
        handle.write(json.dumps({"event": json.loads(event).get("hook_event_name"),
                                 "tool": json.loads(event).get("tool_name"), "reply": reply}) + "\n")
    sys.stdout.write(done.stdout)
    sys.stderr.write(done.stderr)
    return done.returncode


def setup(out: Path) -> tuple[Path, dict]:
    from dotenv import dotenv_values
    out.mkdir(parents=True, exist_ok=True)
    home, work = out / "home", out / "work"
    (home / ".gemini").mkdir(parents=True, exist_ok=True)
    work.mkdir(exist_ok=True)
    cmd = f"{sys.executable} {Path(__file__).resolve()} hook {out / 'hook.jsonl'}"
    if os.environ.get("PROBE_HOOK") == "intentshield":  # the real hook, which asks before any change here
        cmd = (f"env INTENTSHIELD_HOOK_DB={out / 'hooks.db'} INTENTSHIELD_THREAT_MEMORY=off PYTHONPATH={ROOT / 'src'} "
               f"{sys.executable} {Path(__file__).resolve()} tap {out / 'hook.jsonl'} {sys.executable} -m "
               "intentshield.harness gemini --builtin-tools --review always --gemini-ask")
    hooks = {"BeforeTool": [{"matcher": "*", "hooks": [{"type": "command", "command": cmd}]}]}
    (home / ".gemini" / "settings.json").write_text(json.dumps(
        {"security": {"auth": {"selectedType": "gemini-api-key"}},
         "general": {"disableAutoUpdate": True, "disableUpdateNag": True, "enableAutoUpdate": False,
                     "enableAutoUpdateNotification": False},
         "hooks": hooks}))
    (home / ".gemini" / "trustedFolders.json").write_text(json.dumps({str(work.resolve()): "TRUST_FOLDER"}))
    env = {**os.environ, "HOME": str(home), "GEMINI_API_KEY": dotenv_values(ROOT / ".env").get("GEMINI_API_KEY") or ""}
    return work, env


def headless(out: Path, approval: str) -> None:
    work, env = setup(out)
    done = subprocess.run(["gemini", "-p", PROMPT, "-m", "gemini-3.1-flash-lite", "--approval-mode", approval,
                           "-o", "json"], cwd=work, env=env, capture_output=True, text=True, timeout=300,
                          stdin=subprocess.DEVNULL)
    (out / "stdout.txt").write_text(done.stdout)
    (out / "stderr.txt").write_text(done.stderr[-20000:])


def interactive(out: Path, approval: str) -> None:
    work, env = setup(out)
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(work)
        os.execvpe("gemini", ["gemini", "-i", PROMPT, "-m", "gemini-3.1-flash-lite", "--approval-mode", approval], env)
    screen, answered, start = b"", False, time.time()
    while time.time() - start < 120:
        ready, _, _ = select.select([fd], [], [], 1)
        if ready:
            try:
                screen += os.read(fd, 65536)
            except OSError:
                break
        text = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", screen).decode("utf-8", "replace")
        if not answered and re.search(PROMPTED, text):
            time.sleep(2)
            os.write(fd, b"\r" if os.environ.get("PROBE_ANSWER") == "approve" else b"\x1b")  # Enter approves, Escape refuses
            answered = True
            start = time.time() - 90  # leave 30 s for the agent to wrap up
        if (work / "ran.txt").exists() and not answered:
            break
    os.write(fd, b"\x03\x03")
    time.sleep(1)
    (out / "screen.txt").write_text(re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", screen).decode("utf-8", "replace"))
    (out / "answered.txt").write_text(str(answered))


def main() -> int:
    if sys.argv[1] == "hook":
        return hook(sys.argv[2])
    if sys.argv[1] == "tap":
        return tap(sys.argv[2], sys.argv[3:])
    mode, out = sys.argv[2], Path(sys.argv[3]).resolve()
    if mode.startswith("interactive-"):
        interactive(out, mode.split("-", 1)[1])
    else:
        headless(out, mode)
    ran = (out / "work" / "ran.txt").exists()
    events = [json.loads(line) for line in (out / "hook.jsonl").read_text().splitlines()] \
        if (out / "hook.jsonl").exists() else []
    asks = sum(1 for e in events if (e["reply"] or {}).get("decision") == "ask")
    print(f"{mode}: ran.txt created = {ran}; hook asked {asks} time(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
