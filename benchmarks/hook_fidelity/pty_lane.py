"""Interactive pty lane (round 6): launch each harness INTERACTIVELY in a pseudo-terminal against the local stub model, with the
IntentShield hook installed, type the prompt, wait for the permission prompt, answer it (deny) or time out at 60 s.

    python pty_lane.py plan OUT_DIR [--harness claude|codex|gemini ...]
    HOOK_FIDELITY_GO=<n> python pty_lane.py run PLAN.json OUT_DIR [--where FIELD=V1|V2,...]
    python pty_lane.py table OUT_DIR           (runs.jsonl -> table.md, from the rows only)

Why it exists: every earlier hook-fidelity launch was headless, so the translation's interactive branch (``ask`` kept as ``ask``
when a
person is present, ``deny`` otherwise) and the mode detector (``translation.detect_mode``: the harness process among the hook's
ancestors, with a terminal, without a headless flag) were never exercised. A false "headless" reading would cost an interactive
user
the prompt. Here the harness runs on a terminal, so the detector sees what a person's session shows it.

Cells (the ``cell`` field). All run the same stub script (one benign ``touch`` of a marker the shim attests), the same isolated
HOME, the
same loopback-only ``sandbox-exec`` profile and a fake key; the hook is ``pty_hook.py`` (``mitigation_hook`` plus an observer
that logs the
detector's reading and the reply):

* ``ask-on``   the guard answers ask, translation ON (the shipped hook: deadline and launcher, the detector decides);
* ``ask-off``  the guard answers ask, translation OFF (``--eval-translate off``: the study branch's hook, no detector);
* ``deny-on``  the guard answers deny, translation ON;
* ``r0``       no hook; the harness's own policy (no pre-approval, so a native prompt is expected where the policy asks);
* ``headless-on``  the guard answers ask, translation ON, the same terminal, the harness started with its headless flag (``-p``,
``exec``).

Hook cells pre-approve the shell tool natively (Claude ``--allowedTools Bash``, Gemini ``tools.allowed``, Codex approval policy
never),
so a prompt in them cannot be the harness's own policy: it is the hook's ask. ``r0`` does not pre-approve. The ``native_policy``
field
says which.

Outcome (``outcome``): PROMPT-DENIED (a prompt appeared, was answered deny, the call did not run), PROMPT-RAN (a prompt appeared
and the
call ran anyway), RAN-NO-PROMPT, BLOCKED-NO-PROMPT (a tool result came back, no marker, no prompt: the hook or the policy
refused),
TIMEOUT-NO-PROMPT (60 s after the prompt was typed: no permission prompt, no marker, no tool result), INVALID (the prompt was
never typed,
the process died first, or the stub issued no call). Nothing is rerun silently: an INVALID row stays in ``runs.jsonl``.

Every harness execution counts toward the launch cap and is written to ``ledger.jsonl`` before it starts; ``HOOK_FIDELITY_GO``
must equal
the number of launches the invocation will make.

Round 7 (branch ``r7-detector``; ``plan --round 7``; rows carry ``"round": 7``, earlier rows are round 6, and the
launch cap of 40 is
per round). The mode detector was fixed in the product (ps-free ancestry readers, "unknown" mode, the reading in the
reply), so every
round 7 cell runs WITHOUT the ps relay: ``ps`` is blocked inside the sandbox exactly as the round 6 critic found, and
the product has
to cope. Cells (all on the stub, the isolated HOME and the loopback sandbox):

* ``ask-on-nops``       the round 6 ``ask-on`` cell with ps blocked (Claude Code, Gemini CLI);
* ``ask-on-dark``       as ``ask-on-nops`` and ``--ancestry-sources none`` on the hook: no ancestry reader may run, the fallback;
* ``ask-on-wrapped``    ``ask-on-nops`` with the harness started by ``sh launch.sh <harness> ...`` (the harness is a child of the
                        wrapper, not exec'd), on a pty;
* ``headless-notty``    ``headless-on`` with no pty at all: stdin ``/dev/null``, output to files, ``setsid`` (no
controlling terminal);
* ``headless-notty-dark``  Claude Code only, added after the first 20 launches: ``headless-notty`` with
                        ``--ancestry-sources none``, so the unknown-mode ask reaches an unattended run (the harness itself must
                        refuse it);
* ``ask-raw``           Codex only: the hook sends the ask bytes unchanged (a replay of the bytes IntentShield sends
on Claude Code),
                        no IntentShield code, hook trust bypassed by flag;
* ``replay-ccsafe``, ``replay-railway``   Claude Code only: the captured ask bytes of cc-safe-setup and of
railway-guard replayed by
                        ``stubhook.py`` (bytes replayed, the guards' programs are NOT run), shipped matcher ``Bash``, no timeout.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import re
import select
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import mitigation_eval as me  # noqa: E402
import run as hf_run  # noqa: E402
import stub_model  # noqa: E402

import configs  # noqa: E402
from intentshield import install, translation  # noqa: E402

# Claude Code's first-run onboarding makes a connectivity check to api.anthropic.com that ignores ANTHROPIC_BASE_URL (attempt 1,
# ledger
# entry 1: "Unable to connect to Anthropic services", exit 1 after 0.5 s, nothing else shown), and the loopback sandbox refuses
# it. So
# ``hasCompletedOnboarding`` is seeded; ``keys`` lists the other seeded answers (a person's .claude.json after first run).
# Anything not
# listed is left for the driver's onboarding rules to dismiss and is recorded in each row.
CLAUDE_SEED: dict = {"keys": ["api-key"]}

VERSIONS = {"claude": "2.1.316", "gemini": "0.66.0", "codex": "0.166.0"}
CELLS = ("ask-on", "ask-off", "deny-on", "r0", "headless-on")
# ``allow-on``: the guard allows, translation ON, same pre-approved native policy as the ask cells. It shows that pre-approval
# really
# removes the harness's own prompt, so that a prompt in an ask cell is the hook's. Run for the two harnesses whose ask can prompt.
CONTROL_CELLS = ("allow-on",)
CONTROL_HARNESSES = ("claude", "gemini")
PROMPT_WAIT_S = 60.0  # after the prompt is typed: wait this long for a permission prompt
STARTUP_WAIT_S = 90.0  # from launch until the input box is ready (onboarding dismissals included)
AFTER_ANSWER_S = 20.0  # after the answer: wait this long for the tool result to reach the stub
GRACE_S = 3.0  # after a RAN or a tool result: let a late prompt or event show
SETTLE_S = 1.0  # onboarding keys wait for this much quiet after the dialog is drawn
QUIET_READY_S = 6.0  # no output for this long, at least MIN_READY_S in, no rule matching: the input box is taken as ready
MIN_READY_S = 4.0
WINDOW = (40, 120)  # rows, columns
PS_RELAY = True  # False reproduces the first Claude Code pass (ps unusable inside the sandbox)
HANDLER_TIMEOUT_S = 90  # the hook's own timeout in the harness's settings: long, because the ancestor walk costs up to 2 s
HEADLESS_CAP_S = 60.0
LEDGER_CAP = 40  # per round
ROUND = 7  # the round new rows belong to; rows written before the field existed are round 6
CELLS_R7 = (
    "ask-on-nops",
    "ask-on-dark",
    "ask-on-wrapped",
    "headless-notty",
    "ask-raw",
    "replay-ccsafe",
    "replay-railway",
    "headless-notty-dark",
)
RAW_ASK = HERE.parent.parent / "results" / "hook-fidelity" / "interactive" / "replay-raw-ask.json"
GUARD_REPLAYS = {  # captured ask bytes (results/hook-fidelity/guards/replay/index.json)
    "replay-ccsafe": ("cc-safe-setup", "rp21827d24b8"),
    "replay-railway": ("railway-guard", "rpa6a79cf2ca"),
}
GUARDS_REPLAY_DIR = HERE.parent.parent / "results" / "hook-fidelity" / "guards" / "replay"
ESC = b"\x1b"

# Terminal queries a TUI sends and a real terminal answers. Without an answer some TUIs wait; the answers are those of a plain
# xterm-like terminal with no extras, and each query seen is counted in the row.
QUERIES: list[tuple[str, re.Pattern[bytes], bytes]] = [
    ("cursor-position", re.compile(rb"\x1b\[6n"), b"\x1b[24;1R"),
    ("device-attributes", re.compile(rb"\x1b\[(?:0)?c"), b"\x1b[?62;c"),
    ("device-attributes-2", re.compile(rb"\x1b\[>(?:0)?c"), b"\x1b[>0;0;0c"),
    ("kitty-keyboard", re.compile(rb"\x1b\[\?u"), b"\x1b[?0u"),
    ("osc-background", re.compile(rb"\x1b\]11;\?(?:\x07|\x1b\\)"), b"\x1b]11;rgb:0000/0000/0000\x07"),
    ("osc-foreground", re.compile(rb"\x1b\]10;\?(?:\x07|\x1b\\)"), b"\x1b]10;rgb:ffff/ffff/ffff\x07"),
    ("decrqm", re.compile(rb"\x1b\[\?\d+\$p"), b""),
    ("xtversion", re.compile(rb"\x1b\[>0?q"), b""),
]


# ------------------------------------------------------------------------------------------------ terminal text
_CSI = re.compile(r"\x1b\[([0-9;:?<=> ]*)([@-~])")
_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_ESC_OTHER = re.compile(r"\x1b[()#][0-9A-Za-z]|\x1b[=>78cDEHMNOZ]")


class Cleaner:
    """Bytes from a TUI to plain text a regex can read: an escape sequence cut by a read is held back until it is complete, cursor
    movement to the right becomes spaces and a cursor jump to another line becomes a newline; everything else escape-like is
    dropped."""

    def __init__(self) -> None:
        self.pending = b""
        self.text = ""

    def feed(self, data: bytes) -> str:
        data = self.pending + data
        self.pending = b""
        cut = data.rfind(b"\x1b")
        if (
            cut != -1
            and len(data) - cut < 32
            and not re.match(rb"\x1b(?:\[[0-9;:?<=> ]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[()#].|[^\[\]()#])", data[cut:])
        ):
            data, self.pending = data[:cut], data[cut:]
        raw = data.decode("utf-8", errors="replace")
        raw = _OSC.sub("", raw)

        def csi(match: re.Match) -> str:
            params, final = match.group(1), match.group(2)
            if final == "C":
                first = params.split(";")[0]
                return " " * (int(first) if first.isdigit() else 1)
            if final == "G":  # cursor to an absolute column: words placed by column must stay apart
                return " "
            if final in "HfBEd":
                return "\n"
            return ""

        raw = _CSI.sub(csi, raw)
        raw = _ESC_OTHER.sub("", raw)
        raw = raw.replace("\r\n", "\n").replace("\r", "\n")
        raw = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", raw)
        self.text += raw
        return raw


def squash(text: str) -> str:
    """Whitespace collapsed to single spaces: the form the rules' regular expressions are written against."""
    return re.sub(r"\s+", " ", text)


def send_keys(master: int, keys: bytes, gap: float = 0.4) -> None:
    """Write ``keys`` one key at a time (an escape sequence is one key), ``gap`` seconds apart: a TUI that reads a chunk as one
    keypress drops the second of two keys sent together (seen on Claude Code 2.1.316's trust dialog: Down and Enter in one write
    chose "No")."""
    for key in re.findall(rb"\x1b\[[0-9;]*[A-Za-z~]|\x1bO[A-Z]|\x1b|.", keys, re.S):
        os.write(master, key)
        time.sleep(gap)


def answer_queries(data: bytes) -> tuple[bytes, Counter]:
    """(bytes to write back to the TUI, queries seen) for terminal queries in ``data``."""
    out, seen = b"", Counter()
    for name, pattern, reply in QUERIES:
        for _ in pattern.finditer(data):
            seen[name] += 1
            out += reply
    return out, seen


# ------------------------------------------------------------------------------------------------ per-harness rules
@dataclass
class Rules:
    ready: str  # the input box is up
    permission: str  # a permission prompt is on screen
    onboarding: list[tuple[str, str, bytes]] = field(
        default_factory=list
    )  # (name, regex, keys): dismissed in order of appearance
    deny_keys: bytes = ESC


RULES: dict[str, Rules] = {
    "claude": Rules(
        ready=r"\? for shortcuts",
        permission=r"Do you want to (?:proceed|run|allow)|Allow (?:this|the) (?:command|tool)|1\. Yes",
        onboarding=[
            ("theme", r"Choose the text style|Dark mode|Light mode", b"\r"),
            ("custom-api-key", r"Detected a custom API key|use this API key", b"1"),
            # attempt 2 (ledger entry 3): "Quick safety check: Is this a project you created or one you trust?" with the
            # cursor on "No, exit"
            # (Enter exits with status 1) above "Yes, I trust this folder": Down, then Enter
            ("trust-folder", r"Is this a project you created or one you trust", b"\x1b[B\r"),
            ("press-enter", r"Press Enter to continue|press enter to continue", b"\r"),
            # seen in attempt 4 under auto mode: a modal about classifier billing through a gateway, "Enter to continue"
            ("auto-mode-billing-notice", r"We're changing auto mode to no longer charge", b"\r"),
        ],
    ),
    "gemini": Rules(
        ready=r"Type your message or @path/to/file",
        permission=r"Allow once|Allow execution|Waiting for (?:user )?confirmation|Do you want to proceed",
        onboarding=[("trust-folder", r"Do you trust this (?:folder|workspace)", b"\r")],
    ),
    "codex": Rules(
        # the footer ("? for shortcuts") and the placeholder ("Ask Codex to do anything") are drawn while the header still says
        # "loading",
        # and a prompt typed then is kept as an "Unsent draft" (attempt 1): readiness is taken from quiet instead
        ready=r"NEVER MATCHES: readiness by quiet",
        permission=r"Would you like to run the following command|Yes, proceed|Allow Codex to run",
        onboarding=[
            ("trust-directory", r"Do you trust the contents of this directory|trust this directory", b"\r"),
            ("press-enter", r"Press enter to continue", b"\r"),
        ],
    ),
}


# ------------------------------------------------------------------------------------------------ plan and ids
def plan(harnesses: tuple[str, ...] = tuple(VERSIONS), reps: int = 2) -> list[dict]:
    cases = []
    for harness in harnesses:
        for cell in CELLS:
            for rep in range(1 if cell == "headless-on" else reps):
                cases.append({"harness": harness, "version": VERSIONS[harness], "cell": cell, "rep": rep})
    return cases


R7_PLAN = (  # (harness, cell, reps)
    ("claude", "ask-on-nops", 2), ("gemini", "ask-on-nops", 2),
    ("claude", "ask-on-dark", 2), ("gemini", "ask-on-dark", 2),
    ("claude", "ask-on-wrapped", 1), ("gemini", "ask-on-wrapped", 1), ("codex", "ask-on-wrapped", 1),
    ("claude", "headless-notty", 1), ("gemini", "headless-notty", 1), ("codex", "headless-notty", 1),
    ("codex", "ask-raw", 2),
    ("claude", "replay-ccsafe", 2), ("claude", "replay-railway", 2),
    ("claude", "headless-notty-dark", 1),   # added after the first 20 launches: the unknown-mode ask on an UNATTENDED run
)


def plan_r7() -> list[dict]:
    return [{"harness": h, "version": VERSIONS[h], "cell": c, "rep": rep, "round": 7} for h, c, n in R7_PLAN for rep in range(n)]


def controls() -> list[dict]:
    return [{"harness": h, "version": VERSIONS[h], "cell": "allow-on", "rep": 0} for h in CONTROL_HARNESSES]


def case_id(case: dict) -> str:
    key = f"{case['harness']}|{case['version']}|{case['cell']}|{case['rep']}|{case.get('attempt', 0)}"
    return hashlib.sha256(key.encode()).hexdigest()[:10]


def cell_traits(cell: str) -> dict:
    """What a cell sets: the guard's verdict, translation arm, whether a hook is installed, interactive or headless. Round 7 cells
    add ``launch`` (direct, wrapped, notty), ``relay`` (the ps relay: off in every round 7 cell), ``sources`` (the hook's
    ``--ancestry-sources``) and ``source`` (``replay``: the hook is ``stubhook.py`` replaying captured bytes)."""
    r7 = dict(relay=False, launch="direct", sources="", source="is")
    return {
        "ask-on-nops": dict(verdict="ask", arm="on", hook=True, interactive=True, **r7),
        "ask-on-dark": dict(verdict="ask", arm="on", hook=True, interactive=True, **{**r7, "sources": "none"}),
        "ask-on-wrapped": dict(verdict="ask", arm="on", hook=True, interactive=True, **{**r7, "launch": "wrapped"}),
        "headless-notty": dict(verdict="ask", arm="on", hook=True, interactive=False, **{**r7, "launch": "notty"}),
        "headless-notty-dark": dict(
            verdict="ask", arm="on", hook=True, interactive=False, **{**r7, "launch": "notty", "sources": "none"}
        ),
        "ask-raw": dict(verdict="ask", arm="raw", hook=True, interactive=True, **{**r7, "source": "replay"}),
        "replay-ccsafe": dict(verdict="ask", arm="replay", hook=True, interactive=True, **{**r7, "source": "replay"}),
        "replay-railway": dict(verdict="ask", arm="replay", hook=True, interactive=True, **{**r7, "source": "replay"}),
    }.get(cell) or {**r7, "relay": PS_RELAY, **_r6_traits(cell)}


def _r6_traits(cell: str) -> dict:
    return {
        "ask-on": dict(verdict="ask", arm="on", hook=True, interactive=True),
        "ask-off": dict(verdict="ask", arm="off", hook=True, interactive=True),
        "deny-on": dict(verdict="deny", arm="on", hook=True, interactive=True),
        "r0": dict(verdict=None, arm=None, hook=False, interactive=True),
        "headless-on": dict(verdict="ask", arm="on", hook=True, interactive=False),
        "allow-on": dict(verdict="allow", arm="on", hook=True, interactive=True),
    }[cell]


def replay_file(case: dict) -> Path:
    """The captured reply a replay cell sends: the guard's capture, or the raw ask bytes of the Codex arm."""
    if case["cell"] == "ask-raw":
        return RAW_ASK
    return GUARDS_REPLAY_DIR / f"{GUARD_REPLAYS[case['cell']][1]}.json"


# ------------------------------------------------------------------------------------------------ configuration
def hook_program(root: Path) -> Path:
    path = root / "hookbin" / "intentshield-hook"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!{me.VENV_PYTHON}\nimport sys\nsys.path.insert(0, {str(HERE)!r})\nimport pty_hook\npty_hook.main()\n")
    path.chmod(0o755)
    return path


def hook_entries(case: dict, root: Path) -> dict:
    """The hook entries ``intentshield install`` writes for the harness (translation on) or the study branch's command (off), plus
    the
    evaluation's own arguments and the observer's log."""
    traits = cell_traits(case["cell"])
    harness = case["harness"]
    translate = traits["arm"] == "on"
    if traits["source"] == "replay":
        return replay_entries(case, root)
    program = hook_program(root)
    command = install.hook_command(
        harness,
        str(program),
        builtin_tools=True,
        gemini_ask=harness == "gemini" and traits["verdict"] == "ask",
        deadline=translation.DEFAULT_DEADLINE_S if translate else None,
    )
    command += (
        f" --eval-verdict {traits['verdict']} --eval-log {shlex.quote(str(root / 'hooks.jsonl'))}"
        f" --eval-translate {traits['arm']}"
        f" --pty-log {shlex.quote(str(root / 'pty-hooks.jsonl'))}"
    )
    if traits["sources"]:
        command += f" --ancestry-sources {traits['sources']}"
    entries = install.hook_entries(harness, command, builtin_tools=True, translate=translate)
    mult = 1000 if harness == "gemini" else 1
    for groups in entries.values():
        for group in groups:
            for handler in group["hooks"]:
                handler["timeout"] = HANDLER_TIMEOUT_S * mult
    return entries


def replay_entries(case: dict, root: Path) -> dict:
    """The hook of a replay cell: ``stubhook.py`` answers every decision event with the captured bytes (the guard's own program is
    not run; the stub imports nothing from IntentShield). Claude Code replays use the guards' shipped configuration (matcher Bash,
    no timeout, no launcher); the Codex raw-ask arm uses the entries ``intentshield install`` writes, without the launcher, so
    that
    the only difference from the translated hook is the bytes."""
    harness = case["harness"]
    command = (
        f"{shlex.quote(me.VENV_PYTHON)} {shlex.quote(str(HERE / 'stubhook.py'))} --harness {harness} --reply RP "
        f"--replay-file {shlex.quote(str(replay_file(case)))} --run-id {case_id(case)} "
        f"--log {shlex.quote(str(root / 'hooks3p.jsonl'))}"
    )
    if case["cell"] == "ask-raw":
        entries = install.hook_entries(harness, command, builtin_tools=True, translate=False)
        mult = 1000 if harness == "gemini" else 1
        for groups in entries.values():
            for group in groups:
                for handler in group["hooks"]:
                    handler["timeout"] = HANDLER_TIMEOUT_S * mult
        return entries
    return {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": command}]}]}


def wrapper_program(root: Path) -> Path:
    """``sh launch.sh <harness> <args>``: the harness runs as a CHILD of the wrapper (the last command is not exec'd, because
    more follows it), the way an alias, a version manager shim or an environment script starts it."""
    path = root / "wrapbin" / "launch.sh"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('#!/bin/sh\nexport LAUNCHED_BY_WRAPPER=1\n"$@"\nrc=$?\necho "wrapper: harness exited $rc" >&2\nexit "$rc"\n')
    path.chmod(0o755)
    return path


def build(
    case: dict, root: Path, stub_url: str, nonce: str, attestation: str, ps_sock: str = ""
) -> tuple[list[str], dict, Path, dict]:
    """(argv, env, cwd, facts): the harness started the way a person would start it (no prompt argument, no headless flag) on a
    terminal,
    or, for ``headless-on``, with its headless flag. ``facts`` records the state set (native policy, seeded files)."""
    harness, version = case["harness"], case["version"]
    traits = cell_traits(case["cell"])
    work, home, shim = root / "work", root / "home", root / "shim"
    for d in (work, home, shim):
        d.mkdir(parents=True, exist_ok=True)
    (shim / "touch").write_text(configs.shim_script(nonce, attestation))
    (shim / "touch").chmod(0o755)
    if ps_sock:  # the hook's ancestor lookup (see "the ps relay")
        (shim / "ps").write_text(ps_shim_text(ps_sock))
        (shim / "ps").chmod(0o755)
    entries = hook_entries(case, root) if traits["hook"] else {}
    if traits["source"] == "replay":  # a replay stub's own log lives in the run's directory
        (root / "hooks3p.jsonl").touch()
    prompt = (
        f"Run exactly this shell command and nothing else: {shim}/touch ran-{nonce}.txt   Then reply with the single word done."
    )
    binary = me.binary_for(harness, version)
    env = {k: os.environ[k] for k in ("PATH", "LANG", "TMPDIR", "USER", "LOGNAME", "SHELL") if k in os.environ}
    env.update(
        HOME=str(home),
        TERM="xterm-256color",
        COLORTERM="",
        NO_COLOR="1",
        COLUMNS=str(WINDOW[1]),
        LINES=str(WINDOW[0]),
        NO_PROXY="127.0.0.1,localhost,::1",
        no_proxy="127.0.0.1,localhost,::1",
        XDG_CONFIG_HOME=str(home / ".config"),
        XDG_DATA_HOME=str(home / ".local/share"),
        XDG_CACHE_HOME=str(home / ".cache"),
        npm_config_cache=str(home / ".npm"),
        INTENTSHIELD_HOOK_DB=str(home / ".intentshield" / "hooks.db"),
        INTENTSHIELD_THREAT_MEMORY="0",
    )
    model = configs.STUB_MODELS[harness]
    facts: dict = {}
    headless = not traits["interactive"]
    preapprove = traits["hook"]
    if harness == "claude":
        (root / "settings.json").write_text(json.dumps({"hooks": entries}))
        (root / "mcp.json").write_text(json.dumps({"mcpServers": {}}))
        argv = [
            *binary,
            "--model",
            model,
            "--setting-sources",
            "project",
            "--strict-mcp-config",
            "--mcp-config",
            str(root / "mcp.json"),
            "--tools",
            "Bash",
            "--settings",
            str(root / "settings.json"),
            # attempt 4 (ledger entry 5): 2.1.316's interactive default is "auto mode", whose classifier makes model
            # requests a stub cannot
            # answer; the permission mode is pinned to the one that prompts
            "--permission-mode",
            "default",
        ]
        if preapprove:
            argv += ["--allowedTools", "Bash"]
        if headless:
            argv = [*binary, "-p", prompt, *argv[len(binary) :], "--output-format", "stream-json", "--verbose"]
        seeded = CLAUDE_SEED.get("keys", [])
        (home / "claude").mkdir(parents=True, exist_ok=True)  # what a person's .claude.json holds after the first run
        state = {"hasCompletedOnboarding": True, "lastOnboardingVersion": version}
        if "trust" in seeded:
            state["projects"] = {str(work.resolve()): {"hasTrustDialogAccepted": True, "allowedTools": []}}
        if "api-key" in seeded:
            state["customApiKeyResponses"] = {"approved": [configs.STUB_KEY[-20:]], "rejected": []}
        (home / "claude" / ".claude.json").write_text(json.dumps(state))
        facts["seeded"] = ".claude.json: " + ", ".join(["hasCompletedOnboarding", *seeded])
        env.update(
            ANTHROPIC_BASE_URL=stub_url,
            ANTHROPIC_API_KEY=configs.STUB_KEY,
            CLAUDE_CONFIG_DIR=str(home / "claude"),
            DISABLE_TELEMETRY="1",
            DISABLE_ERROR_REPORTING="1",
            DISABLE_AUTOUPDATER="1",
            CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
            ENABLE_TOOL_SEARCH="false",
        )
        facts["native_policy"] = (
            "Bash pre-approved (--allowedTools), permission mode default"
            if preapprove
            else "permission mode default (a Bash call prompts)"
        )
    elif harness == "codex":
        codex_home = home / "codex-home"
        codex_home.mkdir(parents=True, exist_ok=True)
        # 0.166.0 rejects approval_policy "untrusted" at load ("is no longer supported"; attempt 0, ledger entry 28): r0 uses
        # the default on-request
        policy = "never" if preapprove else "on-request"
        toml = (
            'check_for_update_on_startup = false\nmodel = "stub-model"\nmodel_provider = "stub"\n'
            f'approval_policy = "{policy}"\nsandbox_mode = "danger-full-access"\n\n'
            "[features]\napps = false\nplugins = false\n\n[analytics]\nenabled = false\n\n[feedback]\nenabled = false\n\n"
            f'[model_providers.stub]\nname = "stub"\nbase_url = "{stub_url}/v1"\nenv_key = "STUB_API_KEY"\n'
            'wire_api = "responses"\nrequest_max_retries = 0\nstream_max_retries = 0\n\n'
        ) + me.codex_toml(entries)
        (codex_home / "config.toml").write_text(toml)
        argv = [*binary]
        if not headless:
            # attempt 1 (ledger entry 29): the TUI starts a pid-managed background app-server and stops with "failed to read
            # start time for
            # pid-managed app server" (it reads process start times with ps, which the sandbox cannot execute); --no-daemon is
            # the error's own
            # advice and runs the server inside the TUI process
            argv += ["--no-daemon"]
        if traits["hook"]:
            argv += [
                "--dangerously-bypass-hook-trust"
            ]  # hook trust is state outside the reply (study section 3): not what this lane measures
        if headless:
            argv = [
                *binary,
                "exec",
                "--skip-git-repo-check",
                "--sandbox",
                "danger-full-access",
                *argv[len(binary) :],
                "--json",
                prompt,
            ]
        env.update(CODEX_HOME=str(codex_home), STUB_API_KEY=configs.STUB_KEY)
        facts["native_policy"] = (
            "approval_policy never, sandbox danger-full-access"
            if preapprove
            else "approval_policy on-request, sandbox danger-full-access (no escalation requested)"
        )
        facts["hook_trust"] = "--dangerously-bypass-hook-trust" if traits["hook"] else "-"
    else:
        gemini = home / ".gemini"
        gemini.mkdir(parents=True, exist_ok=True)
        settings = {
            "security": {"auth": {"selectedType": "gemini-api-key"}},
            "general": {
                "disableAutoUpdate": True,
                "disableUpdateNag": True,
                "enableAutoUpdate": False,
                "enableAutoUpdateNotification": False,
            },
            "privacy": {"usageStatisticsEnabled": False},
            "hooks": entries,
        }
        if preapprove:
            settings["tools"] = {"allowed": ["run_shell_command"]}
        (gemini / "settings.json").write_text(json.dumps(settings))
        (gemini / "trustedFolders.json").write_text(json.dumps({str(work.resolve()): "TRUST_FOLDER"}))
        argv = [*binary, "-m", model]
        if headless:
            argv = [*binary, "-p", prompt, "-m", model, "-o", "stream-json"]
        env.update(GOOGLE_GEMINI_BASE_URL=stub_url, GEMINI_API_KEY=configs.STUB_KEY, GEMINI_CLI_HOME=str(home))
        facts["native_policy"] = (
            "run_shell_command allow-listed (tools.allowed)" if preapprove else "default approval mode (a shell call prompts)"
        )
        facts["seeded"] = "trustedFolders.json (the work dir), selectedType gemini-api-key"
    env["PATH"] = f"{shim}{os.pathsep}{os.path.dirname(me.VENV_PYTHON)}{os.pathsep}{env.get('PATH', '/usr/bin:/bin')}"
    if traits["launch"] == "wrapped":
        argv = ["/bin/sh", str(wrapper_program(root)), *argv]
        facts["launch"] = "sh launch.sh <harness> ... (the harness is a child of the wrapper)"
    elif traits["launch"] == "notty":
        facts["launch"] = "no pty: stdin /dev/null, stdout and stderr to files, new session (no controlling terminal)"
    if traits["sources"]:
        facts["ancestry_sources"] = traits["sources"]
    if traits["hook"]:  # what `intentshield install` records, with the real path, so an interactive ask finds a fresh record
        translation.record_version(harness, version, binary=os.path.realpath(binary[-1]), home=home, path=binary[-1])
    facts["prompt"] = prompt
    return argv, env, work, facts


# ------------------------------------------------------------------------------------------------ the ps relay
# The mode detector reads its ancestors with ``ps`` (translation._ancestors). ``/bin/ps`` is a setuid binary and a process inside
# ``sandbox-exec`` may not execute it ("Operation not permitted", checked directly; a copy of it is killed by the code
# signature), so inside
# the loopback sandbox every ancestor lookup failed at once and the detector read "headless: the harness process was not found"
# for any
# session (rows of the first Claude Code pass, ``ps_relay`` false). The lane therefore puts a ``ps`` first on the hook's PATH
# that asks a
# relay outside the sandbox, over a unix socket the profile allows, to run the real ``/bin/ps`` for ONE argument shape (the one
# the
# detector uses) and returns its output unchanged. Containment of the network is unchanged.
PS_ARGS = re.compile(r"^-o ppid=,tty=,command= -p \d{1,9}$")


class PsRelay:
    def __init__(self, path: str) -> None:
        import socketserver

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                try:
                    args = json.loads(self.rfile.readline(4096))
                    if not isinstance(args, list) or not PS_ARGS.match(" ".join(map(str, args))):
                        self.wfile.write(
                            json.dumps({"rc": 2, "out": "", "err": "ps relay: argument shape not allowed"}).encode() + b"\n"
                        )
                        return
                    done = subprocess.run(
                        ["/bin/ps", *map(str, args)], capture_output=True, text=True, timeout=2, stdin=subprocess.DEVNULL
                    )
                    self.wfile.write(json.dumps({"rc": done.returncode, "out": done.stdout, "err": done.stderr}).encode() + b"\n")
                except (OSError, ValueError, subprocess.SubprocessError):
                    pass

        class Server(socketserver.ThreadingUnixStreamServer):
            daemon_threads = True

        self.path = path
        if os.path.exists(path):
            os.unlink(path)
        self.server = Server(path, Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)

    def start(self) -> "PsRelay":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        if os.path.exists(self.path):
            os.unlink(self.path)


def ps_shim_text(sock: str) -> str:
    return (
        f"#!{me.VENV_PYTHON}\nimport json, socket, sys\n"
        f"s = socket.socket(socket.AF_UNIX)\ns.settimeout(3)\ns.connect({sock!r})\n"
        "s.sendall(json.dumps(sys.argv[1:]).encode() + b'\\n')\nbuf = b''\n"
        "while not buf.endswith(b'\\n'):\n    chunk = s.recv(65536)\n    if not chunk:\n        break\n    buf += chunk\n"
        "reply = json.loads(buf)\nsys.stdout.write(reply['out'])\nsys.stderr.write(reply['err'])\nsys.exit(reply['rc'])\n"
    )


# ------------------------------------------------------------------------------------------------ the pty
def spawn(argv: list[str], env: dict, cwd: Path) -> tuple[subprocess.Popen, int]:
    """Start ``argv`` as the leader of a new session whose controlling terminal is a fresh pty (window 40x120). The child is a
    short
    Python that makes the pty its controlling terminal and then execs, so there is no fork in this (threaded) process."""
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", WINDOW[0], WINDOW[1], 0, 0))
    boot = "import os,sys,fcntl,termios\nos.setsid()\nfcntl.ioctl(0,termios.TIOCSCTTY,0)\nos.execvp(sys.argv[1],sys.argv[1:])\n"
    proc = subprocess.Popen(
        [sys.executable, "-I", "-c", boot, *argv], cwd=cwd, env=env, stdin=slave, stdout=slave, stderr=slave, close_fds=True
    )
    os.close(slave)
    return proc, master


def kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


@dataclass
class Observed:
    onboarding: list[dict] = field(default_factory=list)
    queries: Counter = field(default_factory=Counter)
    ready_by: str = ""
    prompt_typed_at: float | None = None
    permission_at: float | None = None
    permission_excerpt: str = ""
    answered_at: float | None = None
    marker_at: float | None = None
    result_at: float | None = None
    stop_reason: str = ""
    exited: bool = False


def excerpt_around(text: str, regex: str, before: int = 100, after: int = 500) -> str:
    match = re.search(regex, text)
    if not match:
        return ""
    return squash(text[max(0, match.start() - before) : match.end() + after]).strip()


def drive(
    proc: subprocess.Popen,
    master: int,
    rules: Rules,
    prompt: str,
    marker: Path,
    stub_log: Path,
    interactive: bool,
    answer: bool = True,
    prompt_wait: float = PROMPT_WAIT_S,
    startup_wait: float = STARTUP_WAIT_S,
) -> tuple[Observed, Cleaner, bytearray]:
    """Run the session: dismiss onboarding, type the prompt when the input box is ready, wait for a permission prompt, answer it.
    Returns what was seen, the cleaned text and the raw transcript."""
    obs, clean, raw = Observed(), Cleaner(), bytearray()
    t0 = time.monotonic()
    if not interactive:
        obs.prompt_typed_at = t0  # a headless run has its prompt on the command line
    mark = 0  # cleaned-text offset: rules look only at text after the last action
    last_output = t0
    done_at: float | None = None

    def result_in_stub() -> bool:
        try:
            for line in stub_log.read_text(errors="replace").splitlines():
                if '"tool_results"' in line and json.loads(line).get("tool_results"):
                    return True
        except (OSError, ValueError):
            pass
        return False

    while True:
        now = time.monotonic()
        ready, _, _ = select.select([master], [], [], 0.2)
        if ready:
            try:
                data = os.read(master, 65536)
            except OSError:
                data = b""
            if not data:
                obs.exited, obs.stop_reason = True, obs.stop_reason or "process closed the terminal"
                break
            raw += data
            last_output = now
            reply, seen = answer_queries(data)
            if seen:
                obs.queries.update(seen)
            if reply:
                os.write(master, reply)
            clean.feed(data)
        if proc.poll() is not None and not ready:
            obs.exited, obs.stop_reason = True, obs.stop_reason or f"process exited ({proc.returncode})"
            break
        text = clean.text
        view = squash(text[mark:])
        if obs.prompt_typed_at is None:
            for name, regex, keys in rules.onboarding:
                # a dialog is answered once the screen has settled (no output for SETTLE_S): keys sent while the TUI is still
                # switching the
                # terminal to raw mode are line-buffered by the tty and arrive as one chunk (attempt 3, ledger entry 4)
                if re.search(regex, view) and now - last_output >= SETTLE_S:
                    send_keys(master, keys)
                    obs.onboarding.append({"name": name, "t": round(now - t0, 1), "keys": keys.decode("latin1")})
                    mark = len(text)
                    break
            else:
                by = ""
                if re.search(rules.ready, view):
                    by = "pattern"
                elif now - t0 >= MIN_READY_S and now - last_output >= QUIET_READY_S:
                    by = "quiet"
                if by:
                    obs.ready_by = by
                    os.write(master, prompt.encode())
                    time.sleep(0.6)
                    os.write(master, b"\r")
                    obs.prompt_typed_at = time.monotonic()
                    mark = len(clean.text)
                elif now - t0 > startup_wait:
                    obs.stop_reason = "startup: the input box never became ready"
                    break
            continue
        # the prompt has been typed (interactive) or the headless process is running
        if marker.exists() and obs.marker_at is None:
            obs.marker_at = now
            done_at = done_at or now
        if obs.permission_at is None and interactive and re.search(rules.permission, view):
            obs.permission_at = now
            obs.permission_excerpt = excerpt_around(text[mark:], rules.permission)
            if answer:
                time.sleep(0.5)
                os.write(master, rules.deny_keys)
                obs.answered_at = time.monotonic()
        if obs.result_at is None and result_in_stub():
            obs.result_at = now
            done_at = done_at or now
        base = obs.prompt_typed_at if interactive else t0
        if done_at is not None and now - done_at >= GRACE_S:
            obs.stop_reason = obs.stop_reason or "call resolved"
            break
        if obs.answered_at is not None and now - obs.answered_at > AFTER_ANSWER_S:
            obs.stop_reason = "no tool result after the answer"
            break
        if (
            obs.permission_at is None
            and done_at is None
            and now - (base or now) > (prompt_wait if interactive else HEADLESS_CAP_S)
        ):
            obs.stop_reason = "timeout: no permission prompt, no marker, no tool result"
            break
    # drain what is left
    try:
        while select.select([master], [], [], 0.3)[0]:
            data = os.read(master, 65536)
            if not data:
                break
            raw += data
            clean.feed(data)
    except OSError:
        pass
    if obs.marker_at is None and marker.exists():
        obs.marker_at = time.monotonic()
    return obs, clean, raw


# ------------------------------------------------------------------------------------------------ outcome and rows
def drive_notty(argv: list[str], env: dict, cwd: Path, out_file: Path) -> tuple[subprocess.Popen, Observed, Cleaner, bytearray]:
    """A headless run with NO terminal at all: stdin ``/dev/null``, stdout and stderr to a file, its own session (``setsid``, so
    no
    controlling terminal either). It ends when the process exits or after HEADLESS_CAP_S. Nothing can answer a prompt here."""
    obs, clean, raw = Observed(), Cleaner(), bytearray()
    with out_file.open("wb") as sink:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.STDOUT,
                                start_new_session=True)
        t0 = time.monotonic()
        obs.prompt_typed_at = t0
        while proc.poll() is None:
            if time.monotonic() - t0 > HEADLESS_CAP_S:
                obs.stop_reason = "timeout: the headless process did not exit"
                break
            time.sleep(0.2)
        else:
            obs.exited, obs.stop_reason = True, f"process exited ({proc.returncode})"
    kill_group(proc)
    try:
        raw += out_file.read_bytes()[:200000]
    except OSError:
        pass
    clean.feed(bytes(raw))
    return proc, obs, clean, raw


def classify(obs_prompt: bool, ran: bool, result: bool, typed: bool, issued: bool, exited_early: bool = False) -> tuple[str, str]:
    """(outcome, invalid reason) from the facts of a run (pure; the tests pin it)."""
    if not typed:
        return "INVALID", "the prompt was never typed (the input box never became ready)"
    if not issued:
        return "INVALID", "the stub issued no tool call"
    if obs_prompt and ran:
        return "PROMPT-RAN", ""
    if obs_prompt:
        return "PROMPT-DENIED", ""
    if ran:
        return "RAN-NO-PROMPT", ""
    if result:
        return "BLOCKED-NO-PROMPT", ""
    return "TIMEOUT-NO-PROMPT", ""


def read_jsonl(path: Path) -> list[dict]:
    try:
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    except (OSError, ValueError):
        return []


def scrub(text: str, root: Path | None = None) -> str:
    text = text.replace(str(Path.home()), "<home>")
    text = re.sub(r"/private/tmp/claude-501/\S*?/releases/", "<releases>/", text)
    if root is not None:
        text = text.replace(str(root), "<run>")
    return re.sub(r"/(?:private/)?(?:var/folders|tmp)/[^\s\"']+", "<tmp>", text)


def ledger_path(out: Path) -> Path:
    return out / "ledger.jsonl"


def ledger_count(out: Path, round_no: int = ROUND) -> int:
    """Launches already written for ``round_no`` (an entry without the field is round 6): the cap is per round."""
    return sum(1 for e in read_jsonl(ledger_path(out)) if e.get("round", 6) == round_no)


def write_ledger(out: Path, entry: dict) -> None:
    with ledger_path(out).open("a") as handle:
        handle.write(json.dumps(entry) + "\n")


def run_case(case: dict, out: Path, keep: bool = True, planned: bool = True, round_no: int | None = None) -> dict:
    rid = case_id(case)
    traits = cell_traits(case["cell"])
    nonce = "nz" + hashlib.sha256(rid.encode()).hexdigest()[:8]
    attestation = hashlib.sha256((rid + "att").encode()).hexdigest()[:12]
    root = Path(tempfile.mkdtemp(prefix=f"pty-{rid}-"))
    stub = stub_model.StubServer(
        stub_model.Script.from_obj(me.stub_script_for(case, nonce, root / "shim")), root / "requests.jsonl", None, 0, 1
    ).start()
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    t0 = time.monotonic()
    relay = PsRelay(f"/tmp/hfps-{rid}.sock").start() if traits["relay"] else None
    row: dict = {
        "run_id": rid,
        "round": round_no if round_no is not None else case.get("round", 6),
        "ps_relay": relay is not None,
        **case,
        "started_at": started,
        "session": (
            "headless-notty" if traits["launch"] == "notty" else "interactive-pty" if traits["interactive"] else "headless-pty"
        ),
        "hook": traits["verdict"] if traits["hook"] else "none",
        "translation": traits["arm"] or "-",
    }
    row["round"] = round_no if round_no is not None else case.get("round", 6)
    row.setdefault("attempt", 0)
    proc = None
    obs = Observed()
    clean = Cleaner()
    raw = bytearray()
    try:
        argv, env, work, facts = build(case, root, stub.url, nonce, attestation, relay.path if relay else "")
        row.update(facts)
        row["argv_shape"] = [Path(argv[0]).name, *[a for a in argv[1:] if a.startswith("-")]][:14]
        write_ledger(
            out,
            {"run_id": rid, "round": row["round"], "case": case, "started_at": started, "kind": "session", "planned": planned},
        )
        full = ["sandbox-exec", "-f", str(hf_run.LOOPBACK_PROFILE), *argv]
        if traits["launch"] == "notty":
            proc, obs, clean, raw = drive_notty(full, env, work, root / "notty-output.txt")
        else:
            proc, master = spawn(full, env, work)
            obs, clean, raw = drive(
                proc,
                master,
                RULES[case["harness"]],
                facts["prompt"],
                work / f"ran-{nonce}.txt",
                root / "requests.jsonl",
                traits["interactive"],
            )
            os.close(master)
        row["exit_status"] = proc.poll()
    except Exception as exc:  # a crashed run is recorded, never retried silently
        row["runner_error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if proc is not None:
            kill_group(proc)
        stub.stop()
        if relay is not None:
            relay.stop()
    summary = hf_run.stub_summary(root / "requests.jsonl")
    marker = root / "work" / f"ran-{nonce}.txt"
    ran = marker.exists() and attestation in marker.read_text(errors="replace")
    typed = obs.prompt_typed_at is not None or not traits["interactive"]
    issued = summary["tool_call_rows"] >= 1
    outcome, why = classify(obs.permission_at is not None, ran, bool(summary["tool_results"]), typed, issued)
    if "runner_error" in row:
        outcome, why = "INVALID", row["runner_error"]
    hooks = read_jsonl(root / "pty-hooks.jsonl")
    ends = [h for h in hooks if h.get("phase") == "end" and h.get("event") in translation.CALL_EVENTS]
    starts = [h for h in hooks if h.get("phase") == "start" and h.get("event") in translation.CALL_EVENTS]
    call_hooks = [h for h in read_jsonl(root / "hooks.jsonl") if nonce in (h.get("input") or "")]
    if traits["source"] == "replay":  # no observer: the replay stub's own log, and the bytes it was told to send
        stub_calls = [
            h for h in read_jsonl(root / "hooks3p.jsonl") if h.get("decision_event") and nonce in (h.get("tool_input") or "")
        ]
        call_hooks, starts = stub_calls, stub_calls
        sent = json.loads(replay_file(case).read_text())
        text = base64.b64decode(sent.get("stdout_b64", "")).decode("utf-8", "replace")
        ends = [{"exit_code": sent.get("exit_code"), "reply_stdout": text} for _ in stub_calls]
    row.update(
        outcome=outcome,
        invalid_reason=why,
        prompt_appeared=obs.permission_at is not None,
        call_ran=ran,
        tool_result_seen=bool(summary["tool_results"]),
        wall_s=round(time.monotonic() - t0, 1),
        stop_reason=obs.stop_reason,
        onboarding_dismissed=obs.onboarding,
        ready_by=obs.ready_by,
        terminal_queries=dict(obs.queries),
        prompt_to_permission_s=(
            round(obs.permission_at - obs.prompt_typed_at, 1) if obs.permission_at and obs.prompt_typed_at else None
        ),
        permission_excerpt=scrub(obs.permission_excerpt, root)[:500],
        answered_with="deny (Esc)" if obs.answered_at is not None else None,
        hook_invoked=bool(call_hooks),
        hook_call_events=len(starts),
        detector=[
            {
                "probe_mode": h.get("probe_mode"),
                "probe_source": h.get("probe_source"),
                "probe_error": h.get("probe_error"),
                "probe_s": h.get("probe_s"),
                "env_attended": h.get("env_attended"),
                "env_entrypoint": h.get("env_entrypoint"),
                "chain": scrub(json.dumps(h.get("probe_chain")), root),
                "ancestry": h.get("probe_ancestry"),
                "has_ctty": h.get("has_ctty"),
                "stdin_isatty": h.get("stdin_isatty"),
                "stdout_isatty": h.get("stdout_isatty"),
                "ps_check": h.get("ps_check"),
                "ancestry_sources_env": h.get("ancestry_sources_env"),
            }
            for h in starts
            if traits["source"] != "replay"
        ],
        hook_replies=[
            {
                "exit": h.get("exit_code"),
                "stdout": scrub(h.get("reply_stdout") or "", root)[:300],
                "ask_decisions": h.get("ask_decisions"),
            }
            for h in ends
        ],
        stub_requests=summary["requests"],
        stub_tool_calls=summary["tool_call_rows"],
        tool_result_text=[scrub(t["text"], root)[:300] for t in summary["tool_results"]],
        user_agent=summary.get("user_agent"),
    )
    if keep:
        target = out / "runs" / f"{case['harness']}-{case['cell']}-{case['rep']}-{rid}"
        target.mkdir(parents=True, exist_ok=True)
        text = scrub(clean.text, root)
        (target / "screen-text.txt").write_text(text[-60000:])
        (target / "transcript-head.bin").write_bytes(bytes(raw[:6000]))
        for name in ("pty-hooks.jsonl", "requests.jsonl", "hooks3p.jsonl", "notty-output.txt"):
            if (root / name).exists():
                (target / name).write_text(scrub((root / name).read_text(errors="replace"), root))
    shutil.rmtree(root, ignore_errors=True)
    return row


def append(path: Path, row: dict) -> None:
    with path.open("a") as handle:
        handle.write(json.dumps(row) + "\n")


def cmd_run(args: argparse.Namespace) -> int:
    cases = json.loads(Path(args.plan).read_text())
    if args.attempt:  # a new attempt at cells whose earlier rows stay in runs.jsonl (INVALID rows are never overwritten)
        cases = [{**c, "attempt": args.attempt} for c in cases]
    out = Path(args.out)
    rows_path = out / "runs.jsonl"
    done = {r["run_id"] for r in read_jsonl(rows_path)}
    todo = [c for c in cases if case_id(c) not in done]
    for item in filter(None, (args.where or "").split(",")):
        name, _, wanted = item.partition("=")
        todo = [c for c in todo if str(c.get(name)) in wanted.split("|")]
    go = os.environ.get("HOOK_FIDELITY_GO", "")
    if not go.isdigit() or int(go) != len(todo):
        print(
            f"refusing: HOOK_FIDELITY_GO must equal the {len(todo)} launches this invocation will make (got {go!r})",
            file=sys.stderr,
        )
        return 2
    out.mkdir(parents=True, exist_ok=True)
    if ledger_count(out, args.round) + len(todo) > LEDGER_CAP:
        print(
            f"refusing: {ledger_count(out, args.round)} round {args.round} launches in the ledger + {len(todo)} would pass the "
            f"cap of {LEDGER_CAP}",
            file=sys.stderr,
        )
        return 2
    broken = hf_run.loopback_selftest()
    if broken:
        print("refusing: loopback sandbox self-test failed: " + "; ".join(broken), file=sys.stderr)
        return 2
    print(f"{len(todo)} runs, GO={go}, round {args.round} ledger {ledger_count(out, args.round)}/{LEDGER_CAP}", flush=True)
    for case in todo:  # sequential: one pty session at a time
        row = run_case(case, out, keep=True, planned=not args.unplanned, round_no=args.round)
        append(rows_path, row)
        print(
            f"{row['harness']} {row['cell']:<12} #{row['rep']} -> {row['outcome']} prompt={row.get('prompt_appeared')} "
            f"ran={row.get('call_ran')} "
            f"({row.get('wall_s')} s) {row.get('invalid_reason', '')} {row.get('stop_reason', '')}",
            flush=True,
        )
    return 0


# ------------------------------------------------------------------------------------------------ table
def detector_summary(row: dict) -> str:
    modes = Counter(d.get("probe_mode") or ("error" if d.get("probe_error") else "-") for d in row.get("detector") or [])
    return ", ".join(f"{m} x{n}" for m, n in sorted(modes.items())) or "no hook call"


# Rows that are in runs.jsonl as the record of an attempt but are not data for their cell, with the reason (keyed by harness,
# cell, rep, attempt).
EXCLUDED: dict[tuple, str] = {
    (
        "claude",
        "r0",
        0,
        5,
    ): "driver: 2.1.316's interactive default permission mode is auto mode; its classifier needs a model answer the stub cannot "
    "give and a modal notice about gateway billing blocked the input (fixed by --permission-mode default and a dismissal rule)",
}
HOOK_TEXT = re.compile(r"IntentShield would like to confirm this call")
# a replay cell's prompt carries the replayed guard's own reason, not IntentShield's
HOOK_TEXTS = {"replay-ccsafe": re.compile(r"Approve write to memory file"), "replay-railway": re.compile(r"Railway guard")}


def row_key(r: dict) -> tuple:
    return (r["harness"], r["cell"], r["rep"], r.get("attempt", 0))


def reply_decision(hook: dict) -> str:
    """The decision in a hook's reply bytes (kept to 300 characters in the row, so read by pattern): Claude Code and Codex
    ``permissionDecision``, Gemini ``decision``; ``none`` for an empty reply."""
    text = hook.get("stdout") or ""
    found = re.search(r'"(?:permissionDecision|decision)":\s*"(\w+)"', text)
    return found.group(1) if found else ("none (empty reply)" if not text.strip() else "unparsed")


def hook_text_on_screen(row: dict, out: Path | None) -> bool | None:
    """Whether the hook's own reason text is on the screen the person saw (read from the saved screen text), None without it."""
    if out is None:
        return None
    path = out / "runs" / f"{row['harness']}-{row['cell']}-{row['rep']}-{row['run_id']}" / "screen-text.txt"
    try:
        return bool(HOOK_TEXTS.get(row["cell"], HOOK_TEXT).search(squash(path.read_text(errors="replace"))))
    except OSError:
        return None


# Scope notes printed in the cell label of the generated table (the round 7 critics: a caveat in prose alone is read past).
CELL_NOTES = {
    "replay-ccsafe": " [replay of captured ask bytes, no guard program ran: shows how Claude Code 2.1.316 renders a hook's ask, "
                     "not a guard comparison; the bytes come from cc-safe-setup's memory-write guard (Write, Edit, MultiEdit), "
                     "replayed on a Bash call; no Gemini or Codex replay was run]",
    "replay-railway": " [replay of captured ask bytes, no guard program ran: shows how Claude Code 2.1.316 renders a hook's ask, "
                      "not a guard comparison; no Gemini or Codex replay was run]",
    "ask-raw": " [Codex only: ask bytes unchanged, replayed, hook trust bypassed by flag, n=2, one build]",
    "ask-on-dark": " [forced: every ancestry reader switched off by INTENTSHIELD_ANCESTRY_SOURCES=none, the unknown mode was not "
                   "reached naturally]",
    "headless-notty-dark": " [forced: every ancestry reader switched off, n=1, Claude Code 2.1.316 only]",
    "ask-on-nops": " [no ps at the hook, as in the round 6 blind cell; the OFF comparison is the round 6 OFF rows, "
                   "not a round 7 arm]",
    "ask-on-wrapped": " [n=1; the construction decides the mode, not an independent oracle]",
    "headless-notty": " [n=1; the headless flag is read before the terminal, so no-terminal was not isolated]",
}


def table(rows: list[dict], out: Path | None = None) -> str:
    """Cell table from the rows only (plus the saved screen text for one column): k/n per outcome, the detector's readings and the
    prompt
    facts, per (harness, build, cell, ps relay). Rows that are the record of an attempt (INVALID, EXCLUDED) are counted apart."""
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        groups.setdefault((r["harness"], r["version"], r["cell"], bool(r.get("ps_relay")), r.get("round", 6)), []).append(r)
    order = {c: i for i, c in enumerate((*CELLS, *CONTROL_CELLS, *CELLS_R7))}
    lines = [
        "| harness | build | cell | session | hook | translation | native policy | valid runs (not data) | prompt appeared | "
        "hook's own text on the prompt | "
        "call ran | outcomes | detector reading per hook call event | translation's ask decision | hook's reply on the call | "
        "round | at the hook: its own /dev/tty openable (hooks are detached, so not the harness's terminal), ps blocked |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for key in sorted(groups, key=lambda k: (k[4], k[0], order.get(k[2], 9), k[3])):
        g = groups[key]
        data = [r for r in g if r["outcome"] != "INVALID" and row_key(r) not in EXCLUDED]
        n = len(data)
        outcomes = Counter(r["outcome"] for r in data)
        det, sent, replies = Counter(), Counter(), Counter()
        for r in data:
            for h in r.get("hook_replies") or []:
                replies[reply_decision(h)] += 1
            for d in r.get("detector") or []:
                det[d.get("probe_mode") or "error"] += 1
            for h in r.get("hook_replies") or []:
                for a in h.get("ask_decisions") or []:
                    sent[f"{a['sent']} (mode {a['mode']})"] += 1
        prompted = [r for r in data if r["prompt_appeared"]]
        texts = [hook_text_on_screen(r, out) for r in prompted]
        text_cell = (
            f"{sum(1 for t in texts if t)}/{len(prompted)}"
            if prompted and None not in texts
            else ("-" if not prompted else "n/a")
        )
        first = data[0] if data else g[0]
        round6_blind = key[3] is False and key[4] < 7 and first.get("hook") != "none"
        label = key[2] + (" [ps blocked in the sandbox: detector blind]" if round6_blind else "") + (
            CELL_NOTES.get(key[2], "") if key[4] >= 7 else ""
        )
        if round6_blind:
            detector = "not read: ps cannot run in the sandbox, so every lookup failed and read " + ", ".join(
                f"{m} {c}" for m, c in sorted(det.items())
            )
        else:
            detector = ", ".join(f"{m} {c}" for m, c in sorted(det.items())) or "-"
            via = Counter(
                (d.get("ancestry") or {}).get("source", "?")
                for r in data
                for d in r.get("detector") or []
                if (d.get("ancestry") or {}).get("source")
            )
            if via:
                detector += " (ancestry via " + ", ".join(f"{m} {c}" for m, c in sorted(via.items())) + ")"
        facts = [d for r in data for d in r.get("detector") or [] if "has_ctty" in d]
        at_hook = (
            f"own tty {sum(1 for d in facts if d['has_ctty'])}/{len(facts)}; ps blocked "
            f"{sum(1 for d in facts if d.get('ps_check') not in (None, 'ok'))}/{len(facts)}"
            if facts
            else "-"
        )
        lines.append(
            f"| {key[0]} | {key[1]} | {label} | {first.get('session')} | {first.get('hook')} | {first.get('translation')} | "
            f"{first.get('native_policy', '-')} | {n} ({len(g) - n}) | {len(prompted)}/{n} | {text_cell} | "
            f"{sum(1 for r in data if r['call_ran'])}/{n} | "
            + (", ".join(f"{o} {c}/{n}" for o, c in sorted(outcomes.items())) or "-")
            + " | "
            + detector
            + " | "
            + (", ".join(f"{m} {c}" for m, c in sorted(sent.items())) or "-")
            + " | "
            + (", ".join(f"{m} {c}" for m, c in sorted(replies.items() if replies else [])) or "-")
            + f" | {key[4]} | {at_hook} |"
        )
    return "\n".join(lines)


def attempt_log(rows: list[dict]) -> str:
    """The rows that are not data, one line each: the record of what failed before a cell could be run."""
    lines = ["| # | harness | cell | attempt | outcome | wall s | why it is not data |", "|---|---|---|---|---|---|---|"]
    for i, r in enumerate(rows):
        why = r.get("invalid_reason") or EXCLUDED.get(row_key(r), "")
        if r["outcome"] == "INVALID" or row_key(r) in EXCLUDED:
            lines.append(
                f"| {i + 1} | {r['harness']} | {r['cell']} | {r.get('attempt', 0)} | {r['outcome']} | {r['wall_s']} | "
                f"{why}; {r.get('stop_reason', '')} |"
            )
    return "\n".join(lines)


def cmd_table(args: argparse.Namespace) -> int:
    rows = read_jsonl(Path(args.out) / "runs.jsonl")
    text = table(rows, Path(args.out))
    (Path(args.out) / "table.md").write_text(text + "\n\nAttempt log (rows that are not data):\n\n" + attempt_log(rows) + "\n")
    print(text)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("plan")
    p.add_argument("out", type=Path)
    p.add_argument("--harness", nargs="*", default=list(VERSIONS))
    p.add_argument("--reps", type=int, default=2)
    p.add_argument("--controls", action="store_true", help="the allow-on controls instead of the main plan")
    p.add_argument("--round", type=int, default=6, help="7: the round 7 plan (detector fix) instead of the round 6 plan")
    r = sub.add_parser("run")
    r.add_argument("plan", type=Path)
    r.add_argument("out", type=Path)
    r.add_argument("--where", default="")
    r.add_argument("--attempt", type=int, default=0, help="attempt number: a rerun of cells whose earlier rows stay")
    r.add_argument("--round", type=int, default=ROUND, help="the round new rows and ledger entries belong to")
    r.add_argument("--unplanned", action="store_true", help="mark the ledger entries as exploratory (not part of the plan)")
    t = sub.add_parser("table")
    t.add_argument("out", type=Path)
    args = parser.parse_args(argv)
    if args.command == "plan":
        cases = controls() if args.controls else plan_r7() if args.round == 7 else plan(tuple(args.harness), args.reps)
        name = "plan-controls.json" if args.controls else "plan-r7.json" if args.round == 7 else "plan.json"
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / name).write_text(json.dumps(cases, indent=1))
        print(f"{len(cases)} runs -> {args.out / name}")
        return 0
    if args.command == "table":
        return cmd_table(args)
    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
