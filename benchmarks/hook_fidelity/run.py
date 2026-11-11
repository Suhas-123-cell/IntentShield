"""The hook-fidelity matrix runner. It plans without launching anything; launching needs explicit steps.

    run.py plan [--max-tier N] [--harness H] [--arm S|M] [--sweep N]      # the matrix, run counts, quota estimate; no launch
    run.py run OUT --dry-run [same filters]                               # the plan plus the commands it WOULD run
    run.py run OUT --execute --bin claude=/path ... [filters]             # launches harnesses (see below)
    run.py summarize OUT/runs.jsonl                                       # k/n with Wilson bounds, liveness, classes
    run.py pilot {claude|codex|gemini} [--out DIR] [--port N]             # writes the stub-only pilot script; launches nothing

``run --execute`` is the only path that starts a harness CLI. It refuses unless ALL of these hold, in code:
  * HOOK_FIDELITY_GO=<n> is in the environment with n a positive integer: the person's go-ahead AND a hard budget of
    n launches (reruns included); a script computed this, an agent must not set it;
  * arm S (the loopback stub model endpoint, stub_model.py, one stub process per run, fake key) or arm M (real model); arm S
    cells are not counted against the real-model caps and --cells-json replaces the generated matrix with an explicit list;
  * the selection is within every harness's real-model cap, counting the runs already launched into OUT
    (cap-ledger.json), unless --allow-over-cap;
  * no cell is a no-prompt mode (yolo, --force, bypass flags, a pre-approved Bash) unless it targets a loopback stub
    endpoint (arm S) or --attended says the person is present (containment_refusals, check_containment);
  * every unverified matcher, timeout key, flag set and config-format claim of the selected harnesses has a VALID sign-off
    (signoffs.json, --signoffs): a reader who is not the committer, an ISO retrieval date, and an archived vendor document
    that is a file in the repository whose sha256 matches the entry; the set's hash goes into every row. None is signed off
    today;
  * Claude arm M is a paid path (API key): refused unless --allow-paid claude, which only the person's explicit approval of
    the number of runs justifies;
  * every selected harness can run under an isolated HOME (configs.home_refusal): Claude Code and Cursor need a
    credential passed by name with --pass-env, the real HOME is never used.
Per run it also: uses its own throwaway directory outside the repository and the home directory and its own process
group (killed at the wall-clock cap, survivors checked); checks that no user-level hook or MCP config, managed
settings file or config-dir variable merges in (configs.user_level_leaks) and lints the generated hook config; records
provenance per row (version reported by the harness, binary hash, model, normalised config hash, sandbox mode);
refuses a row missing a field; scrubs home and temp paths from the copied stream and from the row; deletes the run
directory unless the run was INVALID (or --keep-dirs); reruns INVALID runs up to --max-reruns (never rate-limit or login
errors); stops if a harness reports a rate limit twice in a row or its version changes between runs.
It never reads .env or prints a key: a key is passed through only if its name is given with --pass-env.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import json
import os
import random
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from hook_fidelity import cells, claude_lane, codex_matrix, codex_trust, configs, scoring, stub_model, summarize  # noqa: E402

CAP_SECONDS = 120
GEMINI_HANG_CAP_SECONDS = 300
SIGNOFF_FILE = HERE / "signoffs.json"
MAX_RERUNS = 2
VERSION_RECHECK_EVERY = 20  # runs between version probes of the same harness and version
NO_RERUN_REASONS = ("rate_limit", "auth")  # stop and report, never retry
# Reasons that cannot change on a rerun (the shim, the matcher or the config is at fault, not the model): never rerun, and
# stop the whole block after the first one, so a login shell that reorders PATH does not burn three launches per run.
DETERMINISTIC_PREFIXES = ("marker present without", "unhooked tool path")
ARGV_NOPROMPT = ("--dangerously", "--force", "yolo", "skip-permissions", "bypass")
CONFIG_NOPROMPT = (re.compile(r'approval_policy\s*=\s*"never"'), re.compile(r"network_access\s*=\s*true"))
PAID_ARMS = {"claude": "arm M needs ANTHROPIC_API_KEY (or a subscription token) under an isolated HOME: a paid path"}
ACTIVITY_POLL_S = 0.25
BYPASS_MARKERS = ("--dangerously", "--force", "yolo", "skip-permissions", "bypass")
LOOPBACK = ("127.0.0.1", "localhost", "::1")
ARM_S_READY = ("claude", "codex", "gemini")   # harnesses whose arm S path is wired (r3-claude, r3-codex, r3-gemini lanes)
LOOPBACK_SANDBOX_HARNESSES = ("claude", "gemini")   # arm S runs of these go under the loopback sandbox; Codex cannot nest it
LOOPBACK_PROFILE = HERE / "loopback.sb"   # macOS sandbox-exec: outbound network only to loopback and unix sockets


class ContainmentError(RuntimeError):
    """A no-prompt cell that is neither aimed at a loopback stub endpoint nor declared attended."""


class PreflightError(RuntimeError):
    """The run's own configuration failed a check before launch (user-level leak, lint)."""


# ----------------------------------------------------------------------------------------------------------------
# Plan
def _seconds(cell: cells.Cell) -> float:
    prediction = cells.predict(cell)
    if prediction is not None and prediction.outcome == "HUNG":
        return GEMINI_HANG_CAP_SECONDS if cell.harness == "gemini" else CAP_SECONDS
    return cells.ASSUMED_SECONDS[cell.arm]


def plan_data(selection: list[cells.Cell], sweep: int = 0) -> dict:
    data: dict = {"harness": {}, "tiers": {}, "unverified": [], "sweep": None}
    for harness in cells.HARNESSES:
        mine = [c for c in selection if c.harness == harness]
        row = {"cells": len(mine), "controls": sum(1 for c in mine if c.reply in ("R0", "R1")),
               "runs": sum(c.reps for c in mine), "by_arm": {}, "by_tier": {}}
        for arm in ("S", "M"):
            arm_cells = [c for c in mine if c.arm == arm]
            typical, worst = cells.MODEL_REQUESTS[harness]
            row["by_arm"][arm] = {"cells": len(arm_cells), "runs": sum(c.reps for c in arm_cells),
                                  "hours": sum(c.reps * _seconds(c) for c in arm_cells) / 3600,
                                  "requests_typical": sum(c.reps for c in arm_cells) * typical if arm == "M" else 0,
                                  "requests_worst": sum(c.reps for c in arm_cells) * worst if arm == "M" and worst else None}
        for tier in range(4):
            row["by_tier"][tier] = {"cells": sum(1 for c in mine if c.tier == tier),
                                    "runs": sum(c.reps for c in mine if c.tier == tier),
                                    "m_runs": sum(c.reps for c in mine if c.tier == tier and c.arm == "M")}
        cumulative, over = 0, None
        for tier in range(4):
            cumulative += row["by_tier"][tier]["m_runs"]
            if over is None and cumulative > cells.CAPS[harness]:
                over = tier
        row["cap"], row["over_cap_at_tier"] = cells.CAPS[harness], over
        data["harness"][harness] = row
    for tier in range(4):
        data["tiers"][tier] = {"cells": sum(1 for c in selection if c.tier == tier),
                               "runs": sum(c.reps for c in selection if c.tier == tier)}
    data["unverified"] = [text for _, text in configs.unverified_items()]
    if sweep:
        releases = {h: [f"release-{i + 1:02d}" for i in range(sweep)] for h in ("codex", "gemini")}
        swept = cells.sweep_cells(releases)
        data["sweep"] = {"releases": sweep, "cells": len(swept), "runs": sum(c.reps for c in swept)}
    return data


def _cap_note(row: dict) -> str:
    over = row["over_cap_at_tier"]
    return f"{row['cap']}" + (f" EXCEEDED at tier {over}" if over is not None else "")


def format_plan(selection: list[cells.Cell], sweep: int = 0) -> str:
    data = plan_data(selection, sweep)
    total_runs, total_cells = sum(c.reps for c in selection), len(selection)
    lines = [f"hook-fidelity matrix: {total_cells} cells, {total_runs} runs "
             "(R0/R1 controls included; this command launches nothing)",
             "",
             "tier 0 = confirmatory cells and their controls; 1 = essential replies on MCP and shell, current version;",
             "2 = failure settings, writes, slower replies, the real-model validation arm; 3 = optional replies, variants,",
             "other versions. Cut order when a quota says stop: highest tier first. Tier 0 is never cut; tier 1 only by a",
             "quota hard stop.",
             "",
             f"{'harness':8} {'cells':>6} {'ctrl':>5} {'runs':>6} | {'S runs':>7} {'S hours':>8} | {'M runs':>7} {'M hours':>8} "
             f"{'requests typ/worst':>19} | M cap"]
    for harness, row in data["harness"].items():
        s, m = row["by_arm"]["S"], row["by_arm"]["M"]
        worst = "?" if m["requests_worst"] is None and m["runs"] else m["requests_worst"]
        requests = f"{m['requests_typical']}/{worst}"
        lines.append(f"{harness:8} {row['cells']:>6} {row['controls']:>5} {row['runs']:>6} | {s['runs']:>7} {s['hours']:>8.1f} | "
                     f"{m['runs']:>7} {m['hours']:>8.1f} {requests:>19} | {_cap_note(row)}")
    lines += ["", "runs per tier: " + ", ".join(f"{t}: {v['runs']} ({v['cells']} cells)" for t, v in data["tiers"].items())]
    runnable = sum(c.reps for c in selection if c.arm == "M")
    stub = sum(c.reps for c in selection if c.arm == "S")
    lines += [f"runnable today: arm M {runnable} runs; arm S {stub} runs (wired for {', '.join(ARM_S_READY)}: the stub endpoint",
              "stub_model.py runs in-process per run under a loopback-only sandbox; `run.py pilot` still writes the 10-run",
              "pilot script for the other harnesses, whose `run --execute` arm S path is refused).",
              "Hours are ASSUMPTIONS (arm S 20 s, arm M 45 s per run, 120 s or 300 s for a predicted hang): replace them with",
              "the 10-run pilot. Requests per run are assumed too; Gemini's worst (75) is the highest seen in the pilot.",
              "Cursor failure replies, variants and any second version are the first cuts. Cursor's confirmatory cells run at",
              "n=10 and are extended to n=20 only if the pilot shows quota headroom and the person agrees."]
    if data["sweep"]:
        sw = data["sweep"]
        replies = ", ".join(cells.SWEEP_REPLIES)
        lines.append(f"version sweep (Codex and Gemini, {sw['releases']} releases, replies R0 and {replies}, "
                     f"MCP and shell, both modes): {sw['cells']} cells, {sw['runs']} runs on arm S (tier 4, not in the totals "
                     "above; the release list comes from `npm view`, not from this plan)")
    lines.append("scripted interactive experiment (M3, separate from the matrix, not generated here): R3 and R4 x MCP and shell "
                 "x responder no/yes x n=5 = 40 runs per harness, with a deterministic pty responder and a fixed delay")
    lines += ["", "confirmatory cells (written down before the runs, according to the author) and their predictions:"]
    for cid in cells.CONFIRMATORY:
        match = [c for c in selection if c.confirmatory == cid]
        if not match:
            lines.append(f"  {cid}: not in this selection")
            continue
        c = match[0]
        p = cells.predict(c)
        guess = f"predicted {p.outcome} ({p.basis}), P_doc {p.p_doc}" if p else "no prediction"
        lines.append(f"  {cid}: {c.harness} {c.version} {c.mode} {c.kind} state={c.state} {c.reply} "
                     f"({cells.REPLY_NAMES[c.reply]}): {guess}; n={c.reps}, arm {c.arm}")
    lines += ["", "paid arms (refused without --allow-paid <harness>, which needs the person's explicit approval of the "
                  "number of runs): " + "; ".join(f"{h}: {why}" for h, why in PAID_ARMS.items()),
              "", "unverified, each gates `run --execute` until signed off with an archived vendor document "
                  "(signoffs.json; ids in configs.unverified_items):"]
    lines += [f"  {item}" for item in data["unverified"]]
    lines += ["", "not built: the interactive pty",
              "responder, the real IntentShield adapter arm, vendor hook-loader validation of the generated configs (only a",
              "structural lint runs), per-harness transcript parsers (transcript evidence is a nonce heuristic; the stub's",
              "nonce-bound hook events and the witness hook are the primary attempt evidence)."]
    return "\n".join(lines)


# ----------------------------------------------------------------------------------------------------------------
# Run
def _sha256(path: str | None) -> str:
    if not path or not os.path.isfile(path):
        return "unavailable"
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _binary(harness: str, version: str, bins: dict[str, str]) -> tuple[list[str], str]:
    """The command prefix for a harness at a version, and the file to hash. Codex runs through npx pinned to a version."""
    given = bins.get(f"{harness}:{version}") or bins.get(harness)
    if harness == "codex" and not given:
        return ["npx", "-y", f"@openai/codex@{version}"], ""
    if not given:
        given = {"claude": "claude", "gemini": "gemini", "cursor": str(Path.home() / ".local/bin/cursor-agent")}[harness]
    words = shlex.split(given)
    if len(words) > 1 and os.path.isfile(words[-1]):   # an interpreter plus a script (node cli.js): hash the script
        return words, words[-1]
    return words, shutil.which(words[0]) or words[0]


def _version_text(binary: list[str], env: dict[str, str]) -> str:
    done = subprocess.run([*binary, "--version"], capture_output=True, text=True, timeout=120, env=env, stdin=subprocess.DEVNULL)
    return (done.stdout or done.stderr).strip()[:200]


def probe_version(binary: list[str], passthrough: tuple[str, ...]) -> str:
    """The harness's own version string, probed with a throwaway isolated HOME (deleted afterwards)."""
    root = Path(tempfile.mkdtemp(prefix="hf-ver-"))
    try:
        env = configs._env(configs.make_paths(root), True, {}, passthrough)
        return _version_text(binary, env)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _kill_group(pgid: int, proc: subprocess.Popen | None = None) -> bool:
    """Kill the whole process group; True when no live member survives. ``proc`` (the group leader, our child) is reaped
    first: on macOS ``killpg(pgid, 0)`` answers EPERM while an unreaped zombie is the only member left, which is not a
    survivor (found in round 3: it crashed the runner on the first run that hit the wall-clock cap)."""
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    except PermissionError:
        return True        # nothing left that we may signal
    if proc is not None:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    time.sleep(0.5)
    try:
        os.killpg(pgid, 0)
        return False
    except ProcessLookupError:
        return True
    except PermissionError:
        return True        # only zombies of other processes remain (macOS answers EPERM for an unreaped zombie)


# ----------------------------------------------------------------------------------------------------------------
# Containment, sign-off, isolation: enforced here, not only described in the protocol
def noprompt_reasons(cell: cells.Cell, spec: configs.RunSpec | None = None) -> list[str]:
    """Why this cell removes every prompt (empty = the harness can still stop an unapproved call). Without a spec the
    reasons come from the declared mode and the static facts of the config writers (Codex always writes
    ``approval_policy = "never"``); with a spec the command line and the generated config text are scanned too, so a
    flag or setting that the mode table does not list cannot slip through."""
    mode = cells.MODES[cell.harness][cell.mode]
    reasons = []
    if mode.klass == "human-declared-absent":
        reasons.append(f"mode {cell.mode} declares the human absent")
    reasons += [f"flag {flag}" for flag in mode.flags if any(m in flag.lower() for m in BYPASS_MARKERS)]
    if cell.harness == "claude" and cell.mode in ("M1", "M1h") and cell.kind == "shell":
        reasons.append("Bash is pre-approved with --allowedTools")
    if cell.harness == "codex":
        reasons.append('approval_policy = "never" and network_access = true in the generated config.toml')
        if cell.state == "trusted-bypass":
            reasons.append("flag --dangerously-bypass-hook-trust")
    if spec is not None:
        prompts = ("Run exactly", "Call the", "Create a", "Read the")   # the task text is not a flag
        reasons += [f"command-line word {word}" for word in spec.argv
                    if any(m in word.lower() for m in ARGV_NOPROMPT) and not word.startswith(prompts)]
        for path in spec.files:
            try:
                text = Path(path).read_text(errors="replace")
            except OSError:
                continue
            reasons += [f"{pattern.pattern} in {Path(path).name}" for pattern in CONFIG_NOPROMPT if pattern.search(text)]
    return list(dict.fromkeys(reasons))


def targets_local_stub(spec: configs.RunSpec) -> bool:
    """Every URL in the command line and environment is loopback and there is at least one (the stub model endpoint).
    Nothing else counts as local: a hostname, a proxy or a vendor URL makes this False."""
    words = [a for a in spec.argv if a != spec.prompt]   # the task text may hold a URI such as notes://plan: not an endpoint
    text = " ".join(words) + " " + " ".join(f"{k}={v}" for k, v in spec.env.items())
    urls = re.findall(r"[a-z]+://[^\s'\"]+", text)
    return bool(urls) and all(urlparse(u).hostname in LOOPBACK for u in urls)


def containment_refusals(selection: list[cells.Cell], attended: bool) -> dict[str, int]:
    """Runs per reason that this selection would launch a no-prompt cell against a real model without the person
    present. Arm S cells are checked again against their actual endpoint by check_containment. Empty = fine."""
    if attended:
        return {}
    out: dict[str, int] = defaultdict(int)
    for cell in selection:
        if cell.arm != "S":
            for reason in noprompt_reasons(cell):
                out[f"{cell.harness} {cell.mode} {cell.kind}: {reason}"] += cell.reps
    return dict(out)


def check_containment(cell: cells.Cell, spec: configs.RunSpec, attended: bool) -> None:
    reasons = noprompt_reasons(cell, spec)
    if not reasons or attended:
        return
    if cell.arm == "S" and targets_local_stub(spec):
        return
    raise ContainmentError(f"{cell.key}: no-prompt cell ({'; '.join(reasons)}) is not aimed at a loopback stub endpoint "
                           "and --attended was not given")


def _committer() -> str:
    """Who commits here (HOOK_FIDELITY_COMMITTER, else git's user.name): a sign-off reader must be someone else."""
    given = os.environ.get("HOOK_FIDELITY_COMMITTER")
    if given:
        return given
    try:
        done = subprocess.run(["git", "config", "user.name"], capture_output=True, text=True, timeout=10, cwd=configs.ROOT)
        return done.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def signoff_problems(entry: object, committer: str, root: Path = configs.ROOT) -> list[str]:
    """What is wrong with one sign-off entry. Valid = a reader who is not the committer, an ISO retrieval date that is not
    in the future, and an archived vendor document that is a file inside the repository whose sha256 matches the one
    recorded in the entry."""
    if not isinstance(entry, dict):
        return ["no entry"]
    problems = []
    reader = entry.get("reader")
    if not isinstance(reader, str) or not reader.strip():
        problems.append("no reader")
    elif committer and reader.strip().casefold() == committer.strip().casefold():
        problems.append("the reader is the committer")
    try:
        when = datetime.date.fromisoformat(str(entry.get("retrieved")))
        if when > datetime.date.today():
            problems.append("retrieval date is in the future")
    except ValueError:
        problems.append("retrieval date is not an ISO date")
    if str(entry.get("note", "")).lstrip().upper().startswith("NOT SUPPORTED"):
        problems.append("the note says the claim is NOT SUPPORTED")
    if entry.get("kind") == "measured":   # no vendor document says it; a preflight proves it before every run
        evidence = entry.get("evidence")
        resolved = (root / evidence).resolve() if isinstance(evidence, str) and evidence else None
        if resolved is None or root.resolve() not in resolved.parents or not resolved.is_file():
            problems.append("measured entry: the evidence is not a file inside the repository")
        return problems
    archive = entry.get("archive")
    if not isinstance(archive, str) or not archive:
        problems.append("no archive path")
    else:
        resolved = (root / archive).resolve()
        if root.resolve() not in resolved.parents:
            problems.append("archive is not a file inside the repository")
        elif not resolved.is_file():
            # A vendor page with no licence to redistribute is not committed: the README of its directory records the
            # source and the hash of the file the reader read, and the entry must carry that same hash.
            record = resolved.parent / "README.md"
            listed = record.read_text() if record.is_file() else ""
            if not any(resolved.name in line and str(entry.get("sha256")) in line for line in listed.splitlines()):
                problems.append("archive is not a file inside the repository")
        elif hashlib.sha256(resolved.read_bytes()).hexdigest() != entry.get("sha256"):
            problems.append("archive sha256 does not match the entry")
    return problems


def signoff_hash(path: Path = SIGNOFF_FILE) -> str:
    """Short hash of the sign-off set in force; stored in every row and printed in the summary."""
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return "none"
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]


def signoff_gaps(selection: list[cells.Cell], path: Path = SIGNOFF_FILE, committer: str | None = None,
                 root: Path = configs.ROOT) -> list[str]:
    """Unverified items relevant to this selection whose sign-off is missing or invalid (signoff_problems)."""
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        data = {}
    who = _committer() if committer is None else committer
    harnesses = tuple(sorted({c.harness for c in selection}))
    kinds = {(c.harness, c.kind) for c in selection}
    modes = {(c.harness, c.mode) for c in selection}
    gaps = []
    for item_id, text in configs.unverified_items(harnesses):
        parts = item_id.split(":")
        if parts[0] == "matcher" and (parts[1], parts[2]) not in kinds:
            continue
        if parts[0] == "mode" and (parts[1], parts[2]) not in modes:
            continue
        entry = data.get(item_id)
        if isinstance(entry, dict) and isinstance(entry.get("by_harness"), dict):   # an 'all:' item signed per harness
            for harness in harnesses:
                problems = signoff_problems(entry["by_harness"].get(harness), who, root)
                if problems:
                    gaps.append(f"{item_id} [{harness}]: {text} [{'; '.join(problems)}]")
            continue
        problems = signoff_problems(entry, who, root)
        if problems:
            gaps.append(f"{item_id}: {text} [{'; '.join(problems)}]")
    return gaps


def scrub(text: str, paths: configs.RunPaths | None = None) -> str:
    """Home directory, run directory and temp paths replaced by placeholders (rows and copied streams are committed)."""
    pairs: list[tuple[str, str]] = []
    if paths is not None:
        pairs += [(str(paths.root), "<run>"), (str(paths.root.resolve()), "<run>")]
    pairs += [(str(Path.home()), "<home>"), (os.path.expanduser("~"), "<home>"),
              (str(Path(tempfile.gettempdir()).resolve()), "<tmp>"), (tempfile.gettempdir(), "<tmp>")]
    for old, new in sorted(set(pairs), key=lambda p: -len(p[0])):
        if old and old not in ("/", "<home>"):
            text = text.replace(old, new)
    return re.sub(r"/(?:Users|home)/[^/\s\"']+", "/<user>", text)


def normalized_config_hash(paths: configs.RunPaths, run_id: str, nonce: str, attestation: str) -> str:
    """Hash of the written configuration with paths, run id, nonce and attestation replaced by placeholders, so two runs
    of one cell hash alike and a changed config is visible."""
    digest = hashlib.sha256()
    swaps = [(str(paths.root.resolve()), "<RUN>"), (str(paths.root), "<RUN>"), (str(Path.home()), "<HOME>"),
             (run_id, "<ID>"), (nonce, "<NONCE>"), (attestation, "<ATTEST>")]
    for path in sorted(paths.written, key=lambda p: str(p.relative_to(paths.root))):
        text = path.read_text(errors="replace")
        for old, new in swaps:
            text = text.replace(old, new)
        text = re.sub(r"sha256:[0-9a-f]{64}", "sha256:<HASH>", text)   # Codex's per-hook trust hash differs per run
        digest.update(f"{path.relative_to(paths.root)}\0{text}\0".encode())
    return digest.hexdigest()


def deterministic(reason: str) -> bool:
    """An INVALID reason a rerun cannot change (the config is at fault, not the model)."""
    return reason.startswith(DETERMINISTIC_PREFIXES)


def pending_runs(runs: list[tuple[cells.Cell, int]], rows: list[dict], max_reruns: int) -> list[tuple[cells.Cell, int, int]]:
    """(cell, rep, attempt) still to launch. A run key with a non-INVALID row is done; one whose attempts were all INVALID
    is rerun until max_reruns reruns were made, except after a rate limit or a login error, which are never retried."""
    by_key: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_key[row.get("run_key", "")].append(row)
    out = []
    for cell, rep in runs:
        prior = by_key.get(f"{cell.key}|{rep}", [])
        if any(r["outcome"] != "INVALID" for r in prior):
            continue
        if prior and (prior[-1]["invalid_reason"] in NO_RERUN_REASONS or deterministic(prior[-1]["invalid_reason"])
                      or len(prior) > max_reruns):
            continue
        out.append((cell, rep, len(prior)))
    return out


def watch(proc: subprocess.Popen, cap: float, files: list[Path], poll: float = ACTIVITY_POLL_S) -> tuple[bool, int, int]:
    """Wait for ``proc`` for at most ``cap`` seconds while polling the sizes of ``files`` (the harness's output streams
    and the run's logs). Returns (cap hit, kill time ns, time ns of the last growth seen), so that "quiet" is measured
    over the whole run and not from one stat of the final mtime. Output the harness buffers until exit looks quiet:
    HUNG additionally needs a target hook event, and the limitation is stated in the protocol."""
    sizes: dict[Path, int] = {}
    last = time.time_ns()
    deadline = time.monotonic() + cap
    while True:
        try:
            proc.wait(timeout=poll)
            return False, time.time_ns(), last
        except subprocess.TimeoutExpired:
            pass
        now = time.time_ns()
        for path in files:
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            if sizes.get(path, 0) != size:
                last = now
            sizes[path] = size
        if time.monotonic() >= deadline:
            return True, now, last


def shim_smoke(paths: configs.RunPaths, nonce: str, attestation: str, login: bool = False, absolute: bool = False) -> list[str]:
    """Run the PATH shim through ``sh -c`` (and, with ``login``, a login ``bash -lc``); no harness is involved. The marker it
    writes must carry the attestation, or every shell run of the block would be INVALID ("unattested marker"). Empty = fine.
    A login shell can reorder PATH (on macOS ``path_helper`` puts /usr/bin first, so the shim is skipped: observed in the
    committed tests' environment), which matters only if a harness runs its shell tool as a login shell; ``login=True``
    reports it, and the first unattested run stops the block anyway (deterministic reason). ``absolute``: the scripted command
    calls the shim by its absolute path (the Codex stub arm, because Codex runs ``zsh -lc``), so PATH does not matter."""
    problems = []
    for shell in ([["/bin/sh", "-c"], ["/bin/bash", "-lc"]] if login else [["/bin/sh", "-c"]]):
        if not Path(shell[0]).exists():
            continue
        probe = paths.work / f"ran-{nonce}.txt"
        probe.unlink(missing_ok=True)
        env = {"PATH": str(paths.shim_dir) + os.pathsep + "/usr/bin:/bin", "HOME": str(paths.home)}
        try:
            command = f"{paths.shim_dir}/touch ran-{nonce}.txt" if absolute else f"touch ran-{nonce}.txt"
            subprocess.run([*shell, command], cwd=paths.work, env=env, capture_output=True, timeout=30,
                           stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError) as exc:
            problems.append(f"{' '.join(shell)}: {exc!r}")
            continue
        if not (probe.is_file() and attestation in probe.read_text(errors="replace")):
            problems.append(f"{' '.join(shell)}: the touch shim did not attest the marker (PATH reordered?)")
        probe.unlink(missing_ok=True)
    return problems


def loopback_selftest() -> list[str]:
    """Check that the loopback sandbox profile really cuts outbound network: a connect to a public address must fail and a
    connect to a local listener must work, both from inside ``sandbox-exec``. Empty list = the profile works. If the
    sandbox did NOT work the probe would reach a public address once (a TCP handshake, no data): the cost of proving it."""
    if sys.platform != "darwin" or not shutil.which("sandbox-exec"):
        return ["sandbox-exec is not available on this platform"]
    probe = ("import socket,sys\n"
             "srv=socket.socket(); srv.bind(('127.0.0.1',0)); srv.listen(1); port=srv.getsockname()[1]\n"
             "socket.create_connection(('127.0.0.1',port),timeout=3).close()\n"
             "try:\n    socket.create_connection(('1.1.1.1',443),timeout=3).close(); print('OUTBOUND-OPEN'); sys.exit(3)\n"
             "except OSError:\n    print('outbound-closed')\n")
    try:
        done = subprocess.run(["sandbox-exec", "-f", str(LOOPBACK_PROFILE), sys.executable, "-I", "-c", probe],
                              capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        return [f"loopback sandbox self-test could not run: {exc!r}"]
    if done.returncode != 0 or "outbound-closed" not in done.stdout:
        return [f"loopback sandbox self-test failed (exit {done.returncode}): {(done.stdout + done.stderr).strip()[:200]}"]
    return []


STUB_START_S = 15.0
EGRESS_EXIT = 7


def egress_lines(log: Path | None) -> list[str]:
    """Lines of the egress logging proxy's log (empty without one). The proxy refuses every request and logs what the harness
    asked for; the runs are sequential, so what a run adds to the log is that run's attempts."""
    if log is None:
        return []
    try:
        return [ln for ln in log.read_text().splitlines() if ln.strip()]
    except OSError:
        return []


def stream_events(stream: str) -> list[dict]:
    """A compact view of a harness's JSONL event stream (Codex ``--json``): event type, item type, status, exit code and the
    first 160 characters of any message or command. It keeps what a hook failure or a block leaves in the stream (the
    harness's own words) and drops usage and ids, so that a row can say what the harness itself reported."""
    out: list[dict] = []
    for line in stream.splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if not isinstance(obj, dict):
            continue
        item = obj.get("item") if isinstance(obj.get("item"), dict) else {}
        text = item.get("message") or item.get("text") or item.get("command") or obj.get("message") or ""
        entry = {"t": obj.get("type"), "i": item.get("type"), "s": item.get("status"), "x": item.get("exit_code"),
                 "m": str(text)[:160]}
        out.append({k: v for k, v in entry.items() if v not in (None, "")})
    return out


def stub_summary(log: Path) -> dict:
    """What the stub saw in one run (arm S): the request sequence (counts per path), the tool-less side calls, the tools
    offered with the scripted call and whether the scripted tool was among them, the tool results the harness sent back
    (a hook's block reason, a permission denial or the command's output) and the version banner. Empty fields when the
    log is missing."""
    rows: list[dict] = []
    try:
        for line in log.read_text(errors="replace").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    except OSError:
        pass
    by_path: dict[str, int] = defaultdict(int)
    for row in rows:
        by_path[f"{row.get('method')} {row.get('path')}"] += 1
    called = [r for r in rows if r.get("decision") == "tool_call"]
    with_results = [r for r in rows if r.get("tool_results")]
    results = [t for r in rows for t in r.get("tool_results") or []]
    result_text = " ".join(str(t.get("text", "")) for t in with_results[0]["tool_results"])[:300] if with_results else ""
    first = (called or rows or [{}])[0]
    return {"requests": len(rows), "by_path": dict(by_path),
            "generate": sum(1 for r in rows if r.get("kind") == "generate"),
            "count_tokens": sum(1 for r in rows if r.get("kind") == "count"),
            "tool_less_calls": [str(r.get("side_call_head") or "")[:160] for r in rows
                                if r.get("decision") == "text:no-tools-offered"],
            "tool_call_rows": len(called), "tool_calls_issued": len(called),
            "call_index_max": max([r.get("call_index") or 0 for r in rows] or [0]),
            "scripted_tool_offered": bool(called) and all(r.get("scripted_tool_offered") for r in called),
            "offered_tools": first.get("offered_tools") or [],
            "tool_results": [{"is_error": t.get("is_error"), "text": str(t.get("text", ""))[:200]} for t in results],
            "result_seen": bool(with_results), "result_text": result_text, "model": first.get("model", ""),
            "side_calls": [str(r.get("side_call_head") or "") for r in rows if r.get("decision") == "text:no-tools-offered"],
            "decisions": [r.get("decision") for r in rows], "statuses": [r.get("status") for r in rows],
            "user_agent": (rows[0].get("headers", {}).get("user-agent") if rows else None)}


def loopback_prefix() -> list[str]:
    """The sandbox-exec prefix that refuses every outbound connection except loopback and unix sockets (loopback.sb); a
    harness aimed at the stub that ignores the base URL, or phones home, cannot reach a real host. Checked with nc and curl by
    the Gemini lane (an external address is refused, a loopback server answers) and by ``loopback_selftest``."""
    if sys.platform != "darwin" or not shutil.which("sandbox-exec"):
        raise PreflightError("the loopback sandbox needs macOS sandbox-exec")
    return ["sandbox-exec", "-f", str(LOOPBACK_PROFILE)]


def stub_fields(log: Path) -> dict:
    """The flat stub fields of the Gemini lane's rows: request count, request kinds and the tool names offered on the first
    request that listed any. (The nested ``stub`` object of a row holds the richer ``stub_summary``.)"""
    records = []
    try:
        records = [json.loads(line) for line in log.read_text(errors="replace").splitlines() if line.strip()]
    except (OSError, ValueError):
        pass
    return {"stub_requests": len(records), "stub_request_kinds": [str(r.get("kind", "")) for r in records],
            "stub_offered_tools": next((r.get("offered_tools") for r in records if r.get("offered_tools")), None)}


def start_stub(cell: cells.Cell, paths: configs.RunPaths, run_id: str, dump: bool = False) -> stub_model.StubServer:
    """The run's own stub model endpoint on a random loopback port, one scripted call, ``--max-calls 1`` (a re-sample after a
    block must not run the call twice). The request log is the run's requests.jsonl; a request dump is off unless asked.
    Codex's shell command calls the touch shim by absolute path (it runs ``zsh -lc``): the stub script gets the shim dir."""
    nonce = configs.nonce_for(run_id)
    script = stub_model.Script.from_obj(configs.stub_script(cell, nonce, paths.work,
                                                            paths.shim_dir if cell.harness == "codex" else None))
    return stub_model.StubServer(script, paths.root / "requests.jsonl", paths.root / "dump" if dump else None, 0, 1).start()


def execute_one(cell: cells.Cell, rep: int, order: int, out: Path, bins: dict[str, str], model: str,
                passthrough: tuple[str, ...], attempt: int = 0, attended: bool = False, version_reported: str = "",
                keep_dirs: bool = False, shared_cache: Path | None = None, signoff: str = "none",
                loopback_sandbox: bool = True, stub_dump: bool = False, egress_proxy: str = "",
                egress_log: Path | None = None, cap_s: float | None = None, loopback_only: bool = False) -> dict:
    run_id = configs.run_id_for(cell, rep, order, attempt)
    paths = configs.make_paths(Path(tempfile.mkdtemp(prefix=f"hf-{run_id}-")))
    stub: stub_model.StubServer | None = None
    try:
        if cell.arm == "S":
            if cell.harness not in ARM_S_READY:
                raise NotImplementedError(f"arm S is not wired for {cell.harness}")
            stub = start_stub(cell, paths, run_id, stub_dump)
        binary, binary_file = _binary(cell.harness, cell.version, bins)
        spec = configs.build(cell, paths, run_id, binary, model, passthrough, shared_cache, stub_url=stub.url if stub else "")
        if egress_proxy:   # any non-loopback request of the harness goes to a proxy that refuses and logs it
            for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
                spec.env[name] = egress_proxy
        check_containment(cell, spec, attended)
        problems = (configs.user_level_leaks(cell.harness, paths, spec.env, argv=spec.argv)
                    + configs.lint_config(cell, paths, spec))
        if not spec.isolated_home:
            problems.append("the run is not under an isolated HOME")
        if cell.kind == "shell":
            problems += shim_smoke(paths, spec.nonce, spec.attestation, absolute=cell.arm == "S" and cell.harness == "codex")
        if problems:
            raise PreflightError(f"{cell.key}: " + "; ".join(problems))
    except BaseException:
        if stub:
            stub.stop()
        shutil.rmtree(paths.root, ignore_errors=True)
        raise
    trust_entries: list[dict] = []
    if cell.harness == "codex" and cell.state == "trusted-persisted" and cell.reply != "R0":
        try:
            with (out / "launches.jsonl").open("a") as ledger_file:   # the app-server is a launch of the harness binary too
                ledger_file.write(json.dumps({"run_id": run_id, "key": f"{cell.key}|{rep}|hooks/list", "attempt": attempt,
                                              "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}) + "\n")
            trust_entries = codex_trust.list_hooks(binary, spec.env, spec.cwd)
            if not trust_entries:
                raise PreflightError(f"{cell.key}: the vendor loader (hooks/list) returned no hook to trust")
            config = Path(spec.env["CODEX_HOME"]) / "config.toml"
            config.write_text(config.read_text() + codex_trust.trust_toml(trust_entries))
        except BaseException:
            if stub:
                stub.stop()
            shutil.rmtree(paths.root, ignore_errors=True)
            raise
    argv = list(spec.argv)
    sandboxed = bool(stub) and ((loopback_sandbox and cell.harness in LOOPBACK_SANDBOX_HARNESSES) or loopback_only)
    if sandboxed:
        # hard guarantee that a stub-arm harness cannot reach anything but loopback (Codex cannot nest its own seatbelt in
        # sandbox-exec: its arm S runs rely on the egress proxy and its generated config instead)
        argv = [*loopback_prefix(), *argv]
    config_hash = normalized_config_hash(paths, run_id, spec.nonce, spec.attestation)
    cap = cap_s or (GEMINI_HANG_CAP_SECONDS if cell.harness == "gemini" else CAP_SECONDS)
    started, t0 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), time.monotonic()
    stdout_path, stderr_path = paths.root / "stdout.txt", paths.root / "stderr.txt"
    capped, survivors = False, True
    egress_before = len(egress_lines(egress_log))
    with (out / "launches.jsonl").open("a") as ledger_file:   # one line per harness launch, written BEFORE it starts
        ledger_file.write(json.dumps({"run_id": run_id, "key": f"{cell.key}|{rep}", "attempt": attempt,
                                      "ts": started}) + "\n")
    try:
        with stdout_path.open("w") as so, stderr_path.open("w") as se:
            proc = subprocess.Popen(argv, cwd=spec.cwd, env=spec.env, stdin=subprocess.DEVNULL, stdout=so, stderr=se,
                                    start_new_session=True)
            capped, kill_ns, last_activity_ns = watch(
                proc, cap, [stdout_path, stderr_path, paths.hooks_log, paths.calls_log, paths.witness])
            survivors = _kill_group(proc.pid, proc)  # also reaps children that outlive the harness
    finally:
        if stub:
            stub.stop()
    wall = time.monotonic() - t0
    stub_log = paths.root / "requests.jsonl"
    stream = stdout_path.read_text(errors="replace")
    errors = stderr_path.read_text(errors="replace")[-20000:]
    hook_events = scoring.read_events(paths.hooks_log, paths.witness, run_id=run_id)
    target_ts = [e.get("ts_ns", 0) for e in hook_events if scoring.tool_matches(cell.kind, e, spec.nonce)]
    quiet = scoring.quiet_seconds(kill_ns, [last_activity_ns], target_ts) if capped else None
    error_kind, error_text = scoring.classify_errors(errors, stream)
    hooked_kind_calls = [n for n in scoring.tool_calls_with_nonce(stream, spec.nonce) if scoring.name_kind(n) == cell.kind]
    evidence = scoring.Evidence(
        kind=cell.kind, reply=cell.reply, nonce=spec.nonce, wall_cap_hit=capped, quiet_before_kill_s=quiet,
        harness=cell.harness, variant=cell.variant, call_names=hooked_kind_calls,
        oracle_hits=scoring.oracle_hits(cell.kind, paths.work, paths.calls_log, spec.nonce, spec.attestation),
        unattested_hits=scoring.unattested_hits(cell.kind, paths.work, spec.nonce, spec.attestation),
        wrong_tool_hits=scoring.wrong_tool_calls(cell.kind, stream, spec.nonce),
        hook_events=hook_events,
        attempt_events=scoring.read_events(paths.attempt_log, paths.attempt_witness, run_id=run_id),
        transcript_attempts=scoring.transcript_attempts(stream, spec.nonce, cell.kind),
        error_kind=error_kind, error_text=scrub(error_text, paths))
    scored = scoring.score(evidence)
    mode = cells.MODES[cell.harness][cell.mode]
    row = {"run_id": run_id, "run_key": f"{cell.key}|{rep}", "harness": cell.harness, "version": cell.version, "mode": cell.mode,
           "mode_class": mode.klass, "kind": cell.kind, "reply": cell.reply, "state": cell.state, "failcfg": cell.failcfg,
           "variant": cell.variant, "arm": cell.arm, "rep": rep, "order": order, "started_at": started, "wall_s": round(wall, 2),
           "exit_status": proc.returncode, "binary_sha256": _sha256(binary_file),
           "model": model or (configs.STUB_MODELS[cell.harness] if stub else configs.DEFAULT_MODELS[cell.harness]),
           "attempt": attempt,
           "version_reported": scrub(version_reported), "home_isolated": spec.isolated_home,
           "config_hash": config_hash, "sandbox": mode.name, "tier": cell.tier, "confirmatory": cell.confirmatory,
           "survivors_killed": not survivors, "run_dir": paths.root.name, "signoff_hash": signoff, "cap_s": cap, **scored}
    if stub:
        row["containment"] = "loopback-sandbox" if sandboxed else "egress-proxy" if egress_proxy else "none"
        row["network_sandbox"] = "sandbox-exec: outbound network denied except loopback" if sandboxed else "none"
        row["egress_attempts"] = [ln.split('"line": ')[-1].strip('"}')[:80] for ln in egress_lines(egress_log)[egress_before:]]
        row["egress_proxy"] = bool(egress_proxy)
        if cell.state == "trusted-persisted":
            row["trust_record"] = [{"status_before": e.get("trustStatus"), "enabled": e.get("enabled")} for e in trust_entries]
        summary = stub_summary(stub_log)
        summary["offered_tools_sha256"] = hashlib.sha256("\n".join(summary.get("offered_tools") or []).encode()).hexdigest()[:16]
        row["stub"] = json.loads(scrub(json.dumps(summary), paths))   # rows are committed
        row.update(stub_fields(stub_log))   # the Gemini lane's flat fields: stub_requests, stub_request_kinds, stub_offered_tools
        row["hook_stderr_lines"] = [scrub(ln, paths)[:200] for ln in errors.splitlines() if ln.strip()][-3:]
        row["stream_events"] = scrub(json.dumps(stream_events(stream)), paths)[:1500]
    if (out / "streams").is_dir():
        (out / "streams" / f"{run_id}.stdout.txt").write_text(scrub(stream, paths))
        if cell.arm == "S" and stub_log.is_file():
            (out / "streams" / f"{run_id}.stub-requests.jsonl").write_text(scrub(stub_log.read_text(errors="replace"), paths))
    if not keep_dirs and row["outcome"] != "INVALID":
        shutil.rmtree(paths.root, ignore_errors=True)
        row["run_dir"] = ""
    return row


PILOT_BINARIES = {"claude": "claude", "codex": "npx -y @openai/codex@{version}", "gemini": "npx -y @google/gemini-cli@{version}"}
PILOT_CAP_S = 120


def pilot_script(harness: str, out: Path, port: int, bins: dict[str, str]) -> Path:
    """Write the 10-run pilot of ``harness`` against the stub endpoint as a bash script and its run directories under ``out``
    (outside the repository and the home directory). NOTHING is launched: the script is for the person to read and run. Every
    run: its own stub process on 127.0.0.1:<port> with --max-calls 1, an isolated HOME, a fake key, a wall-clock cap, the
    stub's request log and a copy of the harness output kept next to the run."""
    out = configs.check_root(out)
    out.mkdir(parents=True, exist_ok=True)
    url = f"http://127.0.0.1:{port}"
    version = cells.VERSIONS[harness][0]
    words = shlex.split(bins.get(harness) or PILOT_BINARIES[harness].format(version=version))
    stub = configs.HERE / "stub_model.py"
    lines = ["#!/bin/bash",
             f"# Hook-fidelity pilot, {harness} {version}, arm S: harness -> local stub endpoint ONLY. Generated; not run.",
             "# Needs: python3 and node/npx on PATH. No real key, no model, no network call is intended; a harness that tries",
             "# a non-loopback host is a stop condition (see the study document).", "set -u",
             f"CAP={PILOT_CAP_S}", "cap() { perl -e 'alarm shift; exec @ARGV' \"$@\"; }", ""]
    for order, cell in enumerate(cells.pilot_cells(harness)):
        run_id = configs.run_id_for(cell, 0, order)
        paths = configs.make_paths(out / f"run-{order:02d}-{cell.reply}-{cell.kind}")
        spec = configs.build(cell, paths, run_id, words, stub_url=url)
        script = paths.root / "stub-script.json"
        script.write_text(json.dumps(configs.stub_script(cell, spec.nonce, paths.work)))
        env = " ".join(f"{k}={shlex.quote(v)}" for k, v in sorted(spec.env.items()))
        log, dump = shlex.quote(str(paths.root / "requests.jsonl")), shlex.quote(str(paths.root / "dump"))
        stub_cmd = (f"python3 -I {shlex.quote(str(stub))} --script {shlex.quote(str(script))} --log {log} "
                    f"--port {port} --max-calls 1 --dump-dir {dump}")
        lines += [f"# run {order + 1}/10: {cell.reply} ({cells.REPLY_NAMES[cell.reply]}) on {cell.kind}, mode {cell.mode}"
                  + (", repeat of run 2" if order == 9 else ""),
                  f"{stub_cmd} >/dev/null 2>&1 & STUB=$!", "sleep 1",
                  f"(cd {shlex.quote(str(spec.cwd))} && cap $CAP env -i {env} {shlex.join(spec.argv)} "
                  f">{shlex.quote(str(paths.root / 'stdout.txt'))} 2>{shlex.quote(str(paths.root / 'stderr.txt'))} </dev/null)",
                  f"echo \"run {order + 1}: harness exit $?\"", "kill $STUB 2>/dev/null; wait $STUB 2>/dev/null",
                  f"echo \"  stub requests: $(wc -l < {shlex.quote(str(paths.root / 'requests.jsonl'))})  marker: "
                  f"$(ls {shlex.quote(str(paths.work))} | grep -c '^\\(ran\\|written\\)-')  hook events: "
                  f"$(cat {shlex.quote(str(paths.hooks_log))} 2>/dev/null | wc -l)\"", ""]
    path = out / f"pilot-{harness}.sh"
    path.write_text("\n".join(lines) + "\n")
    return path


def cmd_pilot(args: argparse.Namespace) -> int:
    out = args.out or Path(tempfile.mkdtemp(prefix=f"hf-pilot-{args.harness}-"))
    bins = dict(item.split("=", 1) for item in args.bin)
    try:
        path = pilot_script(args.harness, out, args.port, bins)
    except NotImplementedError as exc:
        return _refuse(str(exc))
    print(f"wrote {path} (not run). Read it, then run it yourself: bash {path}")
    return 0


def cells_from_json(path: Path) -> list[cells.Cell]:
    """An explicit cell list (a JSON array of objects with the fields of cells.Cell; version, mode, kind and reply are
    required, arm defaults to S, reps to the arm's default). It replaces the generated matrix, so a lane can run exactly the
    cells it planned. Unknown fields and unknown modes or replies are refused."""
    raw = json.loads(path.read_text())
    if not isinstance(raw, list):
        raise ValueError("--cells-json must hold a JSON array")
    fields = set(cells.Cell.__dataclass_fields__)
    out = []
    for entry in raw:
        unknown = set(entry) - fields
        if unknown:
            raise ValueError(f"unknown cell fields {sorted(unknown)}")
        entry = {"arm": "S", **entry}
        entry.setdefault("reps", cells.REPS[entry["arm"]])
        cell = cells.Cell(**entry)
        if (cell.harness not in cells.HARNESSES or cell.mode not in cells.MODES[cell.harness]
                or cell.reply not in cells.REPLY_NAMES):
            raise ValueError(f"bad cell {entry}")
        out.append(cell)
    return out


def selection_from(args: argparse.Namespace) -> list[cells.Cell]:
    if getattr(args, "cells_json", None):
        return cells_from_json(args.cells_json)
    lane = getattr(args, "lane", "")
    named = getattr(args, "matrix", "") or ""
    if named:   # a named, hand-listed selection (codex_matrix.py); the filters do not apply to it
        return codex_matrix.select(named)
    if lane:
        chosen = [c for c in claude_lane.selection(lane) if c.tier <= args.max_tier]
        for item in filter(None, (getattr(args, "where", "") or "").split(",")):   # --where mode=M1h,kind=resource,reply=R1|R4
            field, _, wanted = item.partition("=")
            chosen = [c for c in chosen if str(getattr(c, field)) in wanted.split("|")]
        reps = getattr(args, "reps", 0)
        return [dataclasses.replace(c, reps=reps) for c in chosen] if reps else chosen
    return cells.select(cells.generate(), args.max_tier, args.harness or "", args.arm or "")


def _refuse(message: str, code: int = 2) -> int:
    print(f"refusing: {message}", file=sys.stderr)
    return code


def _load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def cmd_run(args: argparse.Namespace) -> int:
    selection = selection_from(args)
    if args.dry_run or not args.execute:
        print(format_plan(selection, args.sweep))
        tmp = Path(tempfile.mkdtemp(prefix="hf-dryrun-"))
        shown = 0
        print("\ncommands that would run (first repetition of the first cells, prompts shortened;")
        print("built in a temp dir that is removed after):")
        try:
            for cell in selection:
                if cell.arm != "M" or shown >= 6:
                    continue
                try:
                    paths = configs.make_paths(tmp / f"d{shown}")
                    binary, _ = _binary(cell.harness, cell.version, {})
                    spec = configs.build(cell, paths, "dry", binary)
                except NotImplementedError as exc:
                    print(f"  {cell.key}: {exc}")
                    continue
                argv = [a if len(a) < 80 else a[:77] + "..." for a in spec.argv]
                print(f"  [{cell.key}] cwd={spec.cwd.name} {' '.join(argv)}")
                shown += 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return 0
    go = os.environ.get("HOOK_FIDELITY_GO", "")
    if not go.isdigit() or int(go) < 1:
        return _refuse("set HOOK_FIDELITY_GO=<n> (a positive integer: the number of launches the person agreed to, "
                       "reruns included)")
    if not selection:
        return _refuse("the selection is empty (with --lane, a --where field or a stage above --max-tier removed every cell; "
                       "some lane stages need --max-tier 4)")
    unwired = sorted({c.harness for c in selection if c.arm == "S"} - set(ARM_S_READY))
    if unwired:
        return _refuse(f"arm S has no `run --execute` path for {', '.join(unwired)} yet (wired: {', '.join(ARM_S_READY)}); "
                       "run the pilot script from `run.py pilot` for the others")
    if any(c.arm == "S" and c.harness in LOOPBACK_SANDBOX_HARNESSES for c in selection) and not args.no_loopback_sandbox:
        broken = loopback_selftest()
        if broken:
            return _refuse("arm S needs the loopback sandbox (or --no-loopback-sandbox, which the person must approve): "
                           + "; ".join(broken))
    runs_by_harness: dict[str, int] = defaultdict(int)   # real-model runs only: the caps are for arm M (arm S costs nothing)
    for cell in selection:
        if cell.arm == "M":
            runs_by_harness[cell.harness] += cell.reps
    real_model_runs = runs_by_harness
    total_runs = sum(c.reps for c in selection)
    out = args.out.resolve()
    ledger_path = out / "cap-ledger.json"
    ledger = {h: int(n) for h, n in _load_json(ledger_path).items()}
    over = {h: ledger.get(h, 0) + n for h, n in real_model_runs.items() if ledger.get(h, 0) + n > cells.CAPS[h]}
    if over and not args.allow_over_cap:
        return _refuse(f"over the real-model run cap {over} (caps {cells.CAPS}, counting runs already launched into "
                       f"{out.name}); lower --max-tier or pass --allow-over-cap")
    rows_path = out / "runs.jsonl"
    rows = scoring.read_rows(rows_path) if rows_path.exists() else []
    runs = [(c, rep) for c in selection for rep in range(c.reps)]
    random.Random(args.seed).shuffle(runs)  # interleaves each block's controls and replies
    outstanding = len(pending_runs(runs, rows, args.max_reruns))   # a resumed run only needs launches for what is not done
    if outstanding > int(go):
        return _refuse(f"{outstanding} runs are outstanding in this selection ({total_runs} selected) but HOOK_FIDELITY_GO={go}")
    contained = containment_refusals(selection, args.attended)
    if contained:
        return _refuse("no-prompt cells against a real model without --attended (a live model would get unprompted shell or "
                       "file access): " + "; ".join(f"{k} x{n}" for k, n in sorted(contained.items())))
    paid = sorted({c.harness for c in selection if c.arm == "M" and c.harness in PAID_ARMS} - set(args.allow_paid))
    if paid:
        return _refuse("; ".join(f"{h}: {PAID_ARMS[h]}" for h in paid) + ". Needs the person's explicit approval of the number "
                       "of runs: pass --allow-paid <harness> only after it is given (the study's default is the stub arm)")
    gaps = signoff_gaps(selection, args.signoffs, root=args.signoff_root)
    if gaps:
        return _refuse(f"{len(gaps)} unverified item(s) without a sign-off (reader, archived vendor document, retrieval "
                       f"date) in {args.signoffs.name}: " + "; ".join(gaps[:6]) + ("; ..." if len(gaps) > 6 else ""))
    sign = signoff_hash(args.signoffs)
    print(f"sign-off set {sign} ({args.signoffs.name})", flush=True)
    passthrough = tuple(args.pass_env)
    cannot = [msg for h in sorted({c.harness for c in selection}) if (msg := configs.home_refusal(h, passthrough))]
    if cannot:
        return _refuse(" | ".join(cannot))
    out.mkdir(parents=True, exist_ok=True)
    (out / "streams").mkdir(exist_ok=True)
    bins = dict(item.split("=", 1) for item in args.bin)
    if args.codex_manifest:
        bins = {**codex_matrix.manifest_binaries(args.codex_manifest), **bins}

    shared_cache = out / ".npm-cache"
    versions: dict[tuple[str, str], tuple[str, int]] = {}  # (harness, planned version) -> (reported, runs since probe)
    rate_limited, launched, order = 0, 0, len(rows)   # order continues across resumed invocations (run ids stay unique)
    skipped: set[str] = set()
    while True:
        todo = pending_runs(runs, rows, args.max_reruns)
        if not todo:
            return 0
        for cell, rep, attempt in todo:
            if cell.key in skipped:
                continue
            if launched >= int(go):
                return _refuse(f"HOOK_FIDELITY_GO={go} launches used", 6)
            if cell.arm == "M" and ledger.get(cell.harness, 0) >= cells.CAPS[cell.harness] and not args.allow_over_cap:
                return _refuse(f"{cell.harness} reached its real-model cap {cells.CAPS[cell.harness]} (cap-ledger.json)", 6)
            binary, _ = _binary(cell.harness, cell.version, bins)
            vkey = (cell.harness, cell.version)
            reported, since = versions.get(vkey, ("", VERSION_RECHECK_EVERY))
            if since >= VERSION_RECHECK_EVERY:
                stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                with (out / "probes.jsonl").open("a") as handle:   # a --version call launches the binary (no model): counted
                    handle.write(json.dumps({"binary": binary[-1][-60:], "ts": stamp}) + "\n")
                probed = probe_version(binary, passthrough)
                if cell.version not in probed and not (cell.harness == "codex" and binary[0] == "npx"):
                    print(f"stopping: {cell.harness} reports {probed!r}, the plan expected {cell.version}", file=sys.stderr)
                    return 3
                if reported and probed != reported:
                    print(f"stopping: {cell.harness} changed version during the run ({reported!r} -> {probed!r})",
                          file=sys.stderr)
                    return 3
                reported, since = probed, 0
                print(f"version probe (a --version launch): {cell.harness} {probed!r}", flush=True)
            versions[vkey] = (reported, since + 1)
            try:
                row = execute_one(cell, rep, order, out, bins, args.model, passthrough, attempt, args.attended, reported,
                                  args.keep_dirs, shared_cache, sign, loopback_sandbox=not args.no_loopback_sandbox,
                                  stub_dump=args.stub_dump, egress_proxy=args.egress_proxy, egress_log=args.egress_log,
                                  cap_s=args.cap_s, loopback_only=args.loopback_only)
            except NotImplementedError as exc:
                print(f"skipped {cell.key}: {exc}")
                skipped.add(cell.key)
                runs = [r for r in runs if r[0].key != cell.key]
                continue
            except (ContainmentError, PreflightError) as exc:
                print(f"stopping: {exc}", file=sys.stderr)
                return 5
            order += 1
            launched += 1
            ledger_key = cell.harness if cell.arm != "S" else f"{cell.harness}-stub"   # arm S launches are counted, not capped
            ledger[ledger_key] = ledger.get(ledger_key, 0) + 1
            ledger_path.write_text(json.dumps(ledger))
            scoring.append_row(rows_path, row)
            rows.append(row)
            print(f"{row['run_id']} {cell.key} -> {row['outcome']} hook_invoked={row['hook_invoked']} "
                  f"attempt={attempt} ({row['wall_s']} s)", flush=True)
            if row["outcome"] == "INVALID" and deterministic(row["invalid_reason"]):
                blocked = {c.key for c in selection if c.block == cell.block}
                skipped |= blocked
                runs = [r for r in runs if r[0].key not in blocked]   # nothing of this block is launched again
                print(f"stopping block {' '.join(map(str, cell.block))}: {row['invalid_reason']} (a rerun cannot change this; "
                      "fix the config or the matcher, then resume)", file=sys.stderr)
            if row.get("egress_attempts"):
                print(f"stopping: the harness tried a non-loopback connection {row['egress_attempts']} (stop condition 1 of the "
                      "stub-arm pilot): fix the configuration before any further launch", file=sys.stderr)
                return EGRESS_EXIT
            rate_limited = rate_limited + 1 if row["invalid_reason"] == "rate_limit" else 0
            if rate_limited >= 2:
                print("stopping: two rate-limit errors in a row; stop and report, do not retry", file=sys.stderr)
                return 4


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def filters(p: argparse.ArgumentParser) -> None:
        p.add_argument("--max-tier", type=int, default=3)
        p.add_argument("--harness", choices=cells.HARNESSES)
        p.add_argument("--arm", choices=["S", "M"])
        p.add_argument("--sweep", type=int, default=0, help="also count a version sweep over this many Codex and Gemini releases")
        p.add_argument("--reps", type=int, default=0, help="with --lane: override the repetitions of every selected cell")
        p.add_argument("--where", default="", metavar="FIELD=V1|V2,...",
                       help="with --lane: keep the cells whose fields match, e.g. mode=M1h,kind=resource,reply=R1|R4")
        p.add_argument("--lane", default="", metavar="claude-STAGE",
                       help="a lane instead of the generated matrix: claude-pilot|core|fail|sweep|all (claude_lane.py)")

    plan = sub.add_parser("plan")
    filters(plan)
    run = sub.add_parser("run")
    run.add_argument("out", type=Path)
    filters(run)
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--execute", action="store_true")
    run.add_argument("--allow-over-cap", action="store_true")
    run.add_argument("--attended", action="store_true",
                     help="the person is present: allows no-prompt cells (yolo, --force, bypass) against a real model")
    run.add_argument("--allow-paid", action="append", default=[], metavar="HARNESS",
                     help="the person approved a paid arm for this harness (Claude arm M uses an API key)")
    run.add_argument("--signoffs", type=Path, default=SIGNOFF_FILE, help="sign-off file for the unverified config items")
    run.add_argument("--signoff-root", type=Path, default=configs.ROOT,
                     help="directory that sign-off archive paths are relative to and must stay inside (the repository)")
    run.add_argument("--max-reruns", type=int, default=MAX_RERUNS, help="reruns of an INVALID run (not rate limit or login)")
    run.add_argument("--keep-dirs", action="store_true", help="keep every run directory (INVALID runs are always kept)")
    run.add_argument("--bin", action="append", default=[], metavar="HARNESS[:VERSION]=PATH")
    run.add_argument("--model", default="")
    run.add_argument("--no-loopback-sandbox", action="store_true",
                     help="arm S without the sandbox-exec loopback profile (needs the person's approval)")
    run.add_argument("--stub-dump", "--dump-stub", dest="stub_dump", action="store_true",
                     help="arm S: keep the scrubbed request bodies in each run directory")
    run.add_argument("--matrix", default="", choices=["", *codex_matrix.MATRICES],
                     help="a named hand-listed selection of the Codex lane (arm S); the tier and harness filters are ignored")
    run.add_argument("--codex-manifest", type=Path, help="releases manifest.json: binary paths for codex:<version>")
    run.add_argument("--egress-proxy", default="", metavar="URL",
                     help="loopback URL of a logging proxy that refuses every request; set as HTTP(S)_PROXY of the harness, "
                          "with --egress-log (its log file). A run that adds a line to the log stops the whole invocation")
    run.add_argument("--egress-log", type=Path, default=None)
    run.add_argument("--cells-json", type=Path,
                     help="run exactly these cells (a JSON array of cells.Cell fields) instead of the matrix")
    run.add_argument("--cap-s", type=float, help="wall-clock cap per run in seconds (default 120, 300 for Gemini)")
    run.add_argument("--loopback-only", action="store_true",
                     help="kept for the Gemini lane's scripts: the loopback sandbox is now the default for Claude Code and "
                          "Gemini arm S runs (--no-loopback-sandbox turns it off)")
    run.add_argument("--seed", type=int, default=20261031)
    run.add_argument("--pass-env", action="append", default=[], metavar="NAME",
                     help="environment variable to pass through (a key)")
    pilot = sub.add_parser("pilot", help="write the 10-run stub-only pilot of one harness as a script; launches nothing")
    pilot.add_argument("harness", choices=("claude", "codex", "gemini"))
    pilot.add_argument("--out", type=Path, help="directory for the run directories and the script (outside repo and HOME)")
    pilot.add_argument("--port", type=int, default=18080, help="loopback port of the stub (one stub per run, sequential)")
    pilot.add_argument("--bin", action="append", default=[], metavar="HARNESS=COMMAND")
    summ = sub.add_parser("summarize")
    summ.add_argument("rows", type=Path)
    summ.add_argument("--wilson-all", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "plan":
        print(format_plan(selection_from(args), args.sweep))
        return 0
    if args.command == "pilot":
        return cmd_pilot(args)
    if args.command == "summarize":
        print(summarize.format_report(summarize.summarize(scoring.read_rows(args.rows)), args.wilson_all))
        return 0
    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
