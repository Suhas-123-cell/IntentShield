# Interactive pty lane (round 6, branch `r6-pty`; round 7 section below, branch `r7-detector`)

Question (the round 4 mitigation critic's fatal objection): every earlier evaluation launch was headless, so the version-keyed, mode-aware
translation (`ask` kept as `ask` when a person is present, `deny` otherwise) and the mode detector (`translation.detect_mode`) were never
exercised. A false "headless" reading would cost an interactive user the prompt. This lane launches each harness **interactively on a
pseudo-terminal** against the local stub model, with the hook installed, types the prompt, waits for the permission prompt, answers it
(deny, by Esc) or times out at 60 s, and logs what the detector read and what the hook sent.

Scope in one sentence: a deterministic stub model that issues one benign `touch`, macOS, one build per harness (Claude Code 2.1.316, Gemini
CLI 0.66.0, Codex CLI 0.166.0), n=2 per cell, the "person" is a script that presses Esc. It says nothing about a real model, a real
person, other builds, other platforms or Cursor (not run).

Files: `runs.jsonl` (one row per launch, 40, including the failed attempts), `table.md` (derived by `pty_lane.py table`, from the rows and the
saved screen text), `ledger.jsonl` (one line per harness execution, written before it starts), `plan.json` and `plan-controls.json`,
`runs/<harness>-<cell>-<rep>-<id>/` (the screen text the driver saw, the hook observer's log and the stub's request log; paths scrubbed.
The runner also wrote the first 6000 raw terminal bytes of each run as `transcript-head.bin`; those 61 files are **not committed**, so a run
directory holds no raw bytes, and `table.md` regenerates from the rows and the saved screen text alone). Driver: `benchmarks/hook_fidelity/pty_lane.py`, observer: `pty_hook.py`, tests:
`tests/test_hook_fidelity_pty.py` (38 tests, none launches a harness).

## Result (k/n; build, mode, reply and evidence on every line)

"Prompt" = a permission prompt appeared on the terminal after the prompt was typed. "Hook text" = the prompt screen carries the hook's own
reason ("IntentShield would like to confirm this call (ask)"), which is what attributes a prompt to the hook and not to the harness. Hook
cells pre-approve the shell tool natively, so a native prompt is not expected in them (the `allow-on` control checks that). Evidence for
every row: `runs.jsonl` (filter `harness`, `cell`), screens in `runs/`.

| harness, build | cell (mode, hook reply) | prompt | hook text | call ran | outcome | detector read | translation sent |
|---|---|---|---|---|---|---|---|
| Claude Code 2.1.316 | **ask-on** (interactive pty; hook ask, translation ON) | 2/2 | 2/2 | 0/2 | PROMPT-DENIED 2/2 | interactive 2/2 | ask 2/2 |
| Claude Code 2.1.316 | ask-off (interactive; hook ask, translation OFF) | 2/2 | 2/2 | 0/2 | PROMPT-DENIED 2/2 | not read (see "ps defect") | n/a, OFF sends the ask |
| Claude Code 2.1.316 | deny-on (interactive; hook deny) | 0/2 | n/a | 0/2 | BLOCKED-NO-PROMPT 2/2 | not read (see "ps defect") | n/a |
| Claude Code 2.1.316 | r0 (interactive; no hook, permission mode default) | 2/2 | 0/2 | 0/2 | PROMPT-DENIED 2/2 (native prompt) | n/a | n/a |
| Claude Code 2.1.316 | headless-on (`-p` on the same pty; hook ask, ON) | 0/1 | n/a | 0/1 | BLOCKED-NO-PROMPT 1/1 | headless 1/1 (by the `-p` flag) | deny 1/1 |
| Claude Code 2.1.316 | allow-on control (interactive; hook allow, ON) | 0/1 | n/a | 1/1 | RAN-NO-PROMPT 1/1 | interactive 1/1 | n/a |
| Gemini CLI 0.66.0 | **ask-on** (interactive; hook ask + `--gemini-ask`, ON) | 2/2 | 2/2 | 0/2 | PROMPT-DENIED 2/2 | interactive 2/2 | ask 2/2 |
| Gemini CLI 0.66.0 | ask-off (interactive; hook ask + `--gemini-ask`, OFF) | 2/2 | 2/2 | 0/2 | PROMPT-DENIED 2/2 | interactive 2/2 | n/a |
| Gemini CLI 0.66.0 | deny-on (interactive; hook deny) | 0/2 | n/a | 0/2 | BLOCKED-NO-PROMPT 2/2 | interactive 2/2 | n/a |
| Gemini CLI 0.66.0 | r0 (interactive; no hook, default approval mode) | 2/2 | 0/2 | 0/2 | PROMPT-DENIED 2/2 (native prompt) | n/a | n/a |
| Gemini CLI 0.66.0 | headless-on (`-p` on the pty; hook ask, ON) | 0/1 | n/a | 0/1 | BLOCKED-NO-PROMPT 1/1 | headless 1/1 (by the `-p` flag) | deny 1/1 |
| Gemini CLI 0.66.0 | allow-on control (interactive; hook allow, ON) | 0/1 | n/a | 1/1 | RAN-NO-PROMPT 1/1 | interactive 1/1 | n/a |
| Codex CLI 0.166.0 | **ask-on** (interactive; hook ask, ON) | 0/2 | n/a | 0/2 | BLOCKED-NO-PROMPT 2/2 | interactive 2/2 | deny 2/2 ("Codex CLI does not support a hook's ask") |
| Codex CLI 0.166.0 | ask-off (interactive; hook ask, OFF) | 0/2 | n/a | 0/2 | BLOCKED-NO-PROMPT 2/2 | interactive 2/2 | n/a (the old hook hand-maps ask to deny on Codex) |
| Codex CLI 0.166.0 | deny-on (interactive; hook deny) | 0/2 | n/a | 0/2 | BLOCKED-NO-PROMPT 2/2 | interactive 2/2 | n/a |
| Codex CLI 0.166.0 | r0 (interactive; no hook, on-request, danger-full-access) | 0/2 | n/a | 2/2 | RAN-NO-PROMPT 2/2 | n/a | n/a |
| Codex CLI 0.166.0 | headless-on (`exec` on the pty; hook ask, ON) | 0/1 | n/a | 0/1 | BLOCKED-NO-PROMPT 1/1 | headless 1/1 (by the `exec` word) | deny 1/1 |

**Mode detector against known mode** (the one reading per run at the first call event, rows with a working `ps`): interactive sessions read
interactive **16 of 16** (Claude Code 3, Gemini 7, Codex 6), headless-flag runs on the same terminal read headless **3 of 3**. The known mode
is how I launched each run, so this is agreement with construction, not an independent oracle. The lookup took 0.15 s (Claude Code, Gemini)
to 0.8 s (Codex) against its 2 s budget.

### What this shows

1. **Where `ps` works, the translation did not cost an interactive user the prompt.** On Claude Code 2.1.316 and Gemini CLI 0.66.0 the
   translated hook (ON) kept the `ask` as an `ask` and the prompt appeared 2/2 on each, carrying the hook's own text, the same as with the
   translation OFF (2/2 on each). The detector's reading was interactive in every one of those runs. This is the cell the round 4 critic said
   was never run; it is now run once per build with n=2 on a deterministic stub. The `allow-on` control (1/1 each) shows the pre-approval
   removes the harness's own prompt, so the prompt in an ask cell is the hook's.
2. **Headless readings flip as designed**: the same terminal with `-p` (Claude Code, Gemini) or `exec` (Codex) read headless 3/3 and the
   ask became a deny 3/3 (a reasoned deny that says no one could answer; the screen shows no prompt).
3. **Codex never prompts for a hook ask**: ON denies it (interactive 2/2 and headless 1/1), OFF denies it (2/2, hand-mapped); no
   Codex prompt appeared in any hook cell. This matches the translation table (`Codex CLI does not support a hook's ask`), so for Codex the
   interactive branch is a no-op by design. The interactive `deny` was enforced 2/2 on every harness, with no prompt.
4. **Native prompts exist and are separable from the hook's**: Claude Code 2.1.316 (permission mode default) 2/2 and Gemini CLI 0.66.0 2/2
   prompt for the shell call with no hook; their text has none of the hook's words (hook text 0/2 each). Codex with
   `approval_policy = "on-request"` and `danger-full-access` ran the call with no prompt, 2/2 (see "not measured": a Codex native prompt was not
   produced).

### The `ps` defect: a false headless reading, found by this lane (fixed in the product in round 7, see above)

The first pass of the Claude Code cells (rows with `ps_relay` absent: attempt 6 of `ask-on`, `ask-off`, `deny-on`, `r0`, `headless-on`) ran
with the harness inside the study's loopback `sandbox-exec` profile. **`/bin/ps` cannot be executed inside `sandbox-exec`** (it is a setuid
binary: `Operation not permitted`, checked directly with the profile; a copy of it is killed by its code signature). The detector reads its
ancestors with `ps`, so every lookup failed at once (`probe_s` about 0.002 s, empty chain) and the detector read "headless: the harness
process was not found among the ancestors" for an interactive session. Result on those rows: the translated `ask-on` hook sent a **deny** and
the user got **no prompt, 2/2** (BLOCKED-NO-PROMPT, `runs.jsonl` rows 8 and 9), where the same cell with a working `ps` gave a prompt 2/2.
That is exactly the failure the critic predicted, reached by an environment where `ps` is not runnable. **Inferred, not verified**
(round 6 integration): the earlier headless mitigation runs used the same sandbox profile, so their detector was probably blind too, but those
rows did not record the detector's reading and no one re-checked them. A headless ask never consults the table, so their outcomes do not
depend on it.

How the lane handles it: from attempt 7 on, a `ps` first on the hook's PATH asks a relay outside the sandbox, over a unix socket the profile
allows, to run the real `/bin/ps` for the one argument shape the detector uses (`-o ppid=,tty=,command= -p <pid>`), and returns its output
unchanged. Network containment is unchanged (the profile is the same, `loopback_selftest` ran before every invocation). Gemini and Codex
ran with the relay from their first launch. The 4 Claude Code rows without the relay that do not depend on the detector's reading
(`ask-off` 2, `deny-on` 2) are kept as data for their outcomes, and their detector column says "not read". `ask-on` (2) and `headless-on`
(1) were rerun with the relay (attempt 7); the blind rows stay in `runs.jsonl` and `table.md` as a separate line labelled
"ps blocked in the sandbox". **Not shown by this lane**: how often a real user has no runnable `ps` (a container without procps, a Windows
host, a hardened sandbox). Only the consequence is shown, on one build, under the sandbox profile used here for containment:
the ask degrades to a deny and the prompt is lost. The detector's own documentation lists a renamed process as a known loss in the
refusing direction; an absent `ps` is another, and is not listed.

## Round 7 (branch `r7-detector`): the `ps` defect fixed in the product, and what the pty lane shows now

Scope in one sentence: the same deterministic stub (one benign `touch`), macOS, one build per harness (Claude Code 2.1.316, Gemini CLI 0.66.0,
Codex CLI 0.166.0), the same isolated homes and loopback `sandbox-exec` profile, **no ps relay in any round 7 cell** (so `ps` is blocked at the hook, as
in the round 6 critic's finding), n=1 or n=2 per cell, the "person" is a script that presses Esc. 21 launches (cap 40 per round; the first 20 were the plan,
the 21st, `headless-notty-dark`, was added after them, and is marked so in the `R7_PLAN` comment of `pty_lane.py` and here; the ledger marks every entry `planned`). Round 7 rows carry `"round": 7`; rows without the
field are round 6. Nothing is rerun or dropped: 21 launches, 21 data rows, 0 INVALID. Round 7 ran on commit `c83ad35` (the product fix) plus lane
code that only affects the table; the round 6 rows ran on `d0f9ace`.

**What changed in the product** (`src/intentshield/translation.py`, `harness.py`, 34 new unit tests in `tests/test_translation_ancestry.py`, 12 more for the lane in `tests/test_hook_fidelity_pty_plan_and_observer.py`):

1. A ps-free ancestry source: `libproc` (`proc_pidinfo` for parent and controlling terminal, `sysctl kern.procargs2` for the command line) through ctypes on
   macOS, `/proc` on Linux, then `ps`; the first source that reads the whole walk wins. No new dependency, no process spawned. A layout check runs once
   per process (libproc's answer for the hook's own pid must name the parent the OS names).
2. When no source can read the ancestry, or the walk is cut short before the harness is found, the mode is **unknown**, no longer "assumed headless". For an
   ask the table's own fate for the build decides: Claude Code 2.1.85 and later (class `denied`): the ask is passed on **unchanged**, because the harness
   itself refuses an ask nobody answers; Claude Code before 2.1.85 or unmeasured, Codex (it runs the call), Cursor (unmeasured) and **Gemini**: refused. The
   Gemini choice is a judgement, not a measurement of lesser harm: an interactive user loses one prompt, against the headless hang measured in earlier lanes
   (HUNG 2/2 on 15 releases, 0.38.0 to 0.66.0); `INTENTSHIELD_HARNESS_MODE=interactive` restores the prompt. A complete chain without the harness in it is
   still headless (a renamed process).
3. Every reply that came from an ask now ends with `[IntentShield read this session as <mode>: <how> [ancestry: <source>]]` (and, for an ask passed on in unknown
   mode, the reason), so the evidence shows which source decided. `INTENTSHIELD_ANCESTRY_SOURCES` (`proc`, `libproc`, `ps`, `none`) restricts the sources
   (diagnostics and the `dark` cells; reported on stderr like the other overrides).

### Result (k/n; build, mode, reply and evidence on every line)

"Prompt" = a permission prompt appeared. "Hook text" = the prompt carries the hook's own reason text. Evidence for every row: `runs.jsonl` (filter `round` = 7,
`harness`, `cell`), screens and hook logs in `runs/`, derived table in `table.md`. `ps` was blocked inside the sandbox in all 21 launches (no relay, by construction). The 15 launches whose hook ran the observer recorded `ps_check` from the hook
process itself, `PermissionError: Operation not permitted: 'ps'` in 15 of 15 (`table.md`, "ps blocked" column); the 6 replay launches have no observer, so no `ps_check`.

| harness, build | cell | prompt | hook text | call ran | outcome | detector read (source) | reply sent |
|---|---|---|---|---|---|---|---|
| Claude Code 2.1.316 | **ask-on-nops** (ps blocked, translation ON) | 2/2 | 2/2 | 0/2 | PROMPT-DENIED 2/2 | interactive 2/2 (libproc 2/2) | ask 2/2 |
| Gemini CLI 0.66.0 | **ask-on-nops** (ps blocked, ON, `--gemini-ask`) | 2/2 | 2/2 | 0/2 | PROMPT-DENIED 2/2 | interactive 2/2 (libproc 2/2) | ask 2/2 |
| Claude Code 2.1.316 | ask-on-dark (no ancestry reader allowed) | 2/2 | 2/2 | 0/2 | PROMPT-DENIED 2/2 | **unknown 2/2** | ask 2/2 (passed on unchanged) |
| Gemini CLI 0.66.0 | ask-on-dark | 0/2 | n/a | 0/2 | BLOCKED-NO-PROMPT 2/2 | **unknown 2/2** | deny 2/2 (the designed refusal) |
| Claude Code 2.1.316 | ask-on-wrapped (`sh launch.sh claude ...`, harness a child) | 1/1 | 1/1 | 0/1 | PROMPT-DENIED 1/1 | interactive 1/1 (libproc) | ask 1/1 |
| Gemini CLI 0.66.0 | ask-on-wrapped | 1/1 | 1/1 | 0/1 | PROMPT-DENIED 1/1 | interactive 1/1 (libproc) | ask 1/1 |
| Codex CLI 0.166.0 | ask-on-wrapped | 0/1 | n/a | 0/1 | BLOCKED-NO-PROMPT 1/1 | interactive 1/1 (libproc) | deny 1/1 (Codex never gets an ask) |
| Claude Code 2.1.316 | headless-notty (no pty, `setsid`, stdin `/dev/null`, `-p`) | 0/1 | n/a | 0/1 | BLOCKED-NO-PROMPT 1/1 | headless 1/1 (libproc, by `-p`) | deny 1/1 |
| Gemini CLI 0.66.0 | headless-notty (`-p`) | 0/1 | n/a | 0/1 | BLOCKED-NO-PROMPT 1/1 | headless 1/1 (libproc, by `-p`) | deny 1/1 |
| Codex CLI 0.166.0 | headless-notty (`exec`) | 0/1 | n/a | 0/1 | BLOCKED-NO-PROMPT 1/1 | headless 1/1 (libproc, by `exec`) | deny 1/1 |
| Claude Code 2.1.316 | headless-notty-dark (the unknown-mode ask on an unattended run) | 0/1 | n/a | 0/1 | BLOCKED-NO-PROMPT 1/1 | unknown 1/1 | ask 1/1, then **Claude itself refused it** (its tool result carries the hook's reason) |
| Codex CLI 0.166.0 | **ask-raw** (the ask bytes unchanged, stub replay, no IntentShield code, hook trust bypassed by flag) | 0/2 | n/a | **2/2** | **RAN-NO-PROMPT 2/2** | n/a | ask 2/2 (bytes replayed) |
| Claude Code 2.1.316 | replay-ccsafe (captured ask bytes of cc-safe-setup, shipped matcher `Bash`, no timeout) | 2/2 | 2/2 | 0/2 | PROMPT-DENIED 2/2 | n/a | ask 2/2 (bytes replayed) |
| Claude Code 2.1.316 | replay-railway (captured ask bytes of railway-guard, same config) | 2/2 | 2/2 | 0/2 | PROMPT-DENIED 2/2 | n/a | ask 2/2 (bytes replayed) |

Comparison cells in the same table, round 6, same stub: Claude Code `ask-on` with `ps` blocked and the old code **0/2 prompts** (BLOCKED-NO-PROMPT 2/2, the
defect); with the ps relay 2/2; translation OFF with `ps` blocked 2/2 (the old hook sends the ask without reading the mode). Codex `ask-on` and `ask-off` BLOCKED 2/2 (both deny).

### What this shows, and what it does not

1. **The defect is fixed for the case that produced it.** With `ps` blocked, Claude Code 2.1.316 ask-on gave the prompt 2/2 (round 6, old code: 0/2) and
   Gemini CLI 0.66.0 gave it 2/2, the detector reading interactive through `libproc` every time. ON is no longer worse than OFF with `ps` blocked (2/2 and 2/2 on Claude
   Code); it is **equal**, not better: the translation's benefit stays the headless refusal measured in earlier lanes.
2. **`libproc` worked under `sandbox-exec`, so the unknown-mode path was never reached naturally.** It ran only where I switched every reader off with
   `INTENTSHIELD_ANCESTRY_SOURCES=none` (the `dark` cells, 5 launches). Those cells show what the fallback does (Claude Code: prompt 2/2 interactive and a
   refusal by the harness on an unattended run, 1/1; Gemini: refusal with no prompt 2/2), not how often a real host has no readable ancestry. A container without
   procps would still have `/proc` on Linux; that reader is unit-tested against a fake `/proc` tree but **was not run on a Linux host** (none here).
3. **The detector was exercised beyond agreement with construction only in two ways, both modest.** A wrapper script between the sandbox and the harness did not
   confuse it (interactive 3/3, nearest harness match, wrapper ancestors recorded in the chain), and a run with no pty at all read headless 3/3, **but by the
   `-p` or `exec` flag, which is checked before the terminal**, so the "no terminal" branch was not isolated. The ground truth is still how I launched each run.
   The "own tty" column in `table.md` is the hook process's own `/dev/tty`: Claude Code and Codex detach their hooks from the terminal (0/n) and Gemini does not, so
   it says nothing about the harness's terminal.
4. **Codex, raw ask (the critic's missing arm): Codex does not prompt and does not block, it runs the call, 2/2.** Its screen says
   `Hook failed: PreToolUse hook returned unsupported permissionDecision:ask` and then the `touch` ran (marker attested). Under the translation the same
   ask is a deny and the call is blocked (round 6, 2/2; and the OFF arm, IntentShield's old hook, also denies), so the Codex translation cell is now backed by a
   raw-ask control, on one build, with hook trust bypassed by flag.
5. **Captured third-party ask bytes through the same pty cell: no difference from IntentShield's ask.** cc-safe-setup's and railway-guard's captured ask bytes
   each gave a prompt 2/2 on Claude Code 2.1.316 with their own reason text on the prompt, the call not run 0/2, exactly the IntentShield ask-on cells (2/2, 2/2). On
   this build and mode **there is nothing to compare in IntentShield's favour**, and nothing against it. Caveats: only two of the six captured guards emit an ask at
   all; cc-safe-setup's bytes come from its memory-write guard, whose shipped matcher is `Write|Edit|MultiEdit`, so replaying them on a Bash call is a cross-matcher
   replay its own configuration would not reach (the same `NO_ASK_ON_SHELL` caveat as the head-to-head lane); the guards' programs were not run, only the bytes. The
   Gemini and Codex replays the critic also named were not run (no captured guard emits an ask in those shapes that a shell call reaches).

### Not done, plainly (round 7)

* **Claude Code auto mode and yolo (`--dangerously-skip-permissions`) interactive sessions: NOT MEASURED.** The stub cannot answer auto mode's classifier; the lane
  stays pinned to `--permission-mode default`, so the critic's "hook ask in auto mode" question is open. Same for Gemini without `--gemini-ask`, Codex hook trust
  interactively (the flag bypasses it), MCP asks, other builds, Windows (no reader besides `ps`, so unknown mode there), Linux, other terminals, an IDE embedding.
* **Natural failure of the ps-free readers** (libproc blocked by a stricter sandbox, `hidepid` on `/proc`) was not observed; the `dark` cells simulate it with the environment switch.
* The unknown-mode behaviour for Claude Code before 2.1.85, Gemini 0.37.x and older, and Cursor is covered by unit tests only (the table's classes), not by a launch.
* n=1 or 2 per cell on a deterministic stub is a demonstration, not a rate. The reason text for `none` says "no source could read the parent process" (it does not say that
  the sources were switched off); the `ancestry_sources_env` field in each row does.
* Home directories: mtimes of `~/.claude ~/.codex ~/.gemini ~/.cursor` before and after: `~/.codex`, `~/.gemini`, `~/.cursor` **no change**; `~/.claude` 33 differing
  lines, all in the orchestrating session's own files (project transcripts and subagent journals under `projects/`, `.claude.json` backups, `skills/synced`), none under a
  path a lane run uses (each run has its own `HOME` and `CLAUDE_CONFIG_DIR`); the live session writes there too, so this cannot prove the negative. Lists: scratchpad
  `r7/mtime-{before,after}.txt` (not committed).
* A Gemini 0.41.2 headless process from an earlier round was found still running (pid 91704, elapsed about 4 h 53 min when noticed, a hung `-p` run). It is not
  from this lane and I did not kill it.

### Reproduce (round 7)

```
cd benchmarks/hook_fidelity
python pty_lane.py plan --round 7 ../../results/hook-fidelity/interactive     # 21 cells, plan-r7.json
HOOK_FIDELITY_GO=<n> python pty_lane.py run <plan-r7.json> <out> --where cell=ask-on-nops --round 7
python pty_lane.py table <out>
```

Launch ledger, round 7: `ledger.jsonl` entries with `"round": 7`, 21 of the cap 40; `HOOK_FIDELITY_GO` equalled the exact launch count of each invocation (2, 6, 6, 6, 1); no
paid API, no DeepSeek, no Cursor; harness CLIs only against the local stub on 127.0.0.1 with a fake key, inside the loopback `sandbox-exec` profile, versions from the
installed releases under the session scratch directory.

## Round 6 critic: how far this lane's result reaches (applied at integration)

The critic recomputed every k/n and found them correct, and found the arms matched. The objections, all accepted:

* **Fatal: no third-party guard is in this lane.** Every arm is IntentShield ON, IntentShield OFF, deny, none or allow. Nothing here compares IntentShield with another
  guard, and only two captured guards (cc-safe-setup, railway-guard) ever emit an ask at all. **Do not read any "better than existing guards" from this lane.** The cells it
  would take: replay the captured ask bytes of cc-safe-setup and railway-guard through the same pty cells on Claude Code, Gemini and Codex (bytes replayed, program not
  run) and count prompt, ran and blocked against IntentShield's reply. **Not run.**
* **Major: ON equals OFF in every interactive cell** (Claude 2/2 vs 2/2, Gemini 2/2 vs 2/2, Codex 2/2 vs 2/2 blocked). The finding is a **non-regression where `ps` works**,
  and the cost is a dependency on `ps` and process names: with `ps` blocked, ON loses the prompt that OFF keeps (ON 0/2 vs OFF 2/2 in this lane's rows; the critic's forced-blind
  rerun, ON 0/1 vs OFF 1/1). The translation's benefit is the headless refusal measured in earlier lanes, not here. A headless-off arm on the same pty was not run.
* **Major: configuration was chosen by the lane.** Every sentence is scoped to Claude Code 2.1.316 under `--permission-mode default` plus `--allowedTools Bash` (the real
  interactive default, auto mode, was not run), Gemini 0.66.0 with `--gemini-ask` in both arms, Codex 0.166.0 with hook trust bypassed by flag. **NOT MEASURED** next to the
  claim: auto mode, yolo, Gemini without `--gemini-ask`, Codex hook trust interactively.
* **Major: the Codex OFF arm is IntentShield's own old hook, which already maps ask to deny**, so Codex ON versus OFF is IntentShield against itself and cannot show an effect;
  no Codex cell sends a raw ask, and "Codex drops an ask" rests on the headless lanes (RAN 5/5 per build). A raw-ask Codex arm in the pty was not run.
* **Minor:** the detector's "known mode" is how each run was launched (agreement with construction; headless was `-p` or `exec` on a pty, not a no-tty CI run; the
  orchestrating session's `claude` was an ancestor and the nearest match won; no wrapped, renamed or nested launch was varied). n=2 per cell, n=1 for headless and the
  controls, no intervals and no rate. The "earlier headless rows were blind" sentence is now marked inferred (above), and the attempt-log narrative is reconciled with
  the screens (launch ledger).

The statement the critic supports: under permission mode default and a stub, the mode-aware translation kept a hook's ask as a prompt for an interactive user when `ps`
worked, the same as with the translation off, and turned an ask into a reasoned deny under `-p` or `exec`; against other guards the lane supports nothing.

## Method

* **Harness start.** `pty_lane.py spawn`: a child Python makes a fresh pty (window 40x120) its controlling terminal (`setsid`, `TIOCSCTTY`)
  and execs `sandbox-exec -f loopback.sb <harness>`; the harness runs as a person would start it (no prompt argument, no headless flag) on
  `TERM=xterm-256color`, `NO_COLOR=1`. The driver answers the terminal queries a TUI sends (cursor position, device attributes, kitty keyboard,
  OSC colours; counted in each row as `terminal_queries`), cleans the byte stream to text, dismisses onboarding by rules, waits for the input box
  (by pattern, else by 6 s of quiet; `ready_by` in each row), types the prompt (0.6 s before Enter), waits up to 60 s for a permission
  prompt, answers it with Esc, then waits up to 8 s for a tool result to reach the stub, or stops 3 s after a marker or a tool result.
* **Stub, isolation, containment.** `stub_model.py` in-process on 127.0.0.1 with one scripted `touch` of a shim that attests the marker, fake
  key, isolated HOME and per-harness config dirs per run, the loopback-only `sandbox-exec` profile, no proxy. Hook: `pty_hook.py` =
  `mitigation_hook.main` (IntentShield's real hook entry point with the guard's verdict fixed) plus an observer that, per hook call event, logs
  the detector's own reading (`translation.detect_mode` from the hook process, so from the same ancestors), the ancestor chain, the decision
  `Semantics.ask_reply` took, and the reply bytes. A test pins that the wrapper does not change the reply. Translation ON is the command
  `intentshield install` writes (deadline 30 s, launcher); OFF is the study branch's command.
* **Native policy** (the `native_policy` field). Hook cells: Claude Code `--allowedTools Bash` with `--permission-mode default`; Gemini CLI
  `tools.allowed = ["run_shell_command"]`; Codex `approval_policy = "never"` with `danger-full-access` and
  `--dangerously-bypass-hook-trust`. R0: no pre-approval (Claude Code, Gemini); Codex `on-request` with `danger-full-access`.
* **Detector probe vs real lookup.** The observer's probe is the same function on the same chain; for ON asks the hook's own lookup is the
  `ask_decisions` record (mode, source, version class, what was sent), which agreed with the probe on every ask row.

### Seeded state and onboarding (recorded exactly)

* **Claude Code 2.1.316.** Attempt 0 (no seeding): welcome splash then "Unable to connect to Anthropic services / Failed to connect to
  api.anthropic.com: ECONNREFUSED", exit 1 after 0.5 s: the first-run connectivity check ignores `ANTHROPIC_BASE_URL` and the sandbox refuses
  it. Seeded since: `.claude.json` with `hasCompletedOnboarding` and `lastOnboardingVersion`, and `customApiKeyResponses.approved` for the
  fake key (the API-key dialog was therefore never shown and its dismissal is untested). Then one dialog remained and was dismissed by the
  driver every run: "Quick safety check: Is this a project you created or one you trust?" with the cursor on "No, exit" (Enter exits with
  status 1; the keys that work are Down, then Enter, sent as separate keystrokes 0.4 s apart after the screen settled; sent together, or while
  the TUI was still switching to raw mode, they chose "No"). Under the default permission mode of 2.1.316 ("auto mode", whose classifier
  makes model requests a stub cannot answer, plus a modal notice about classifier billing through a gateway), the call was not decided
  (attempt 5, excluded); `--permission-mode default` is therefore pinned, and the interactive default a person gets on this build is **not
  what these cells ran under** (see not measured).
* **Gemini CLI 0.66.0.** No onboarding screen: `trustedFolders.json` for the work directory and `selectedType = gemini-api-key` are seeded as in
  the lane runs. Gemini starts a child node process (`--max-old-space-size=8192`) under the launcher; the detector found the harness by the
  `node .../gemini` ancestor.
* **Codex CLI 0.166.0.** No onboarding screen appeared (no trust-directory dialog). Two start-up findings: `approval_policy = "untrusted"` is
  rejected at load by this build ("no longer supported"), so R0 uses `on-request`; and the TUI's pid-managed background app-server dies in the
  sandbox ("failed to read start time for pid-managed app server"; it uses `ps` too), so the interactive Codex launches use `--no-daemon`
  (the error's own advice). Hook trust is bypassed with `--dangerously-bypass-hook-trust` (documented to work from 0.141.0), which is state
  outside the hook's reply and not what this lane measures; **Codex hook trust in an interactive session was not tested**.
* In every harness the real harness config directories are not read: each run has its own HOME and config dir.

## Launch ledger (cap 40, used 40, no paid API, no DeepSeek, no Cursor)

`HOOK_FIDELITY_GO` equalled the exact number of launches of each invocation. 40 harness executions (`ledger.jsonl`), all sessions on the stub
(no `--version` or `--help` execution was needed: versions come from the install directory, flags from the vendors' own error text or the
bundle). Not data (8): Claude Code `r0` attempts 0 to 5 (attempts 0 and 1: the connectivity check, the screens of both show the ECONNREFUSED
message; attempts 2, 3 and 4: the trust dialog was answered "No", the saved screens of all three end at the dialog, whatever the driver's
automatic "why" column in `table.md` says for 2 and 3 ("the stub issued no tool call"); attempt 5: auto mode). The earlier text counted
"one seeding slip of mine" as a seventh attempt; no separate row or screen shows one, so it is dropped here (it was probably one of the two
connectivity attempts). Codex `r0` attempts 0 and 1 (unsupported policy, daemon). These are the attempt log in `table.md` and were
never silently overwritten. Data (32): Claude Code 13 (ask-on 4 of which 2 blind, ask-off 2, deny-on 2, r0 2, headless-on 2 of which 1 blind,
allow-on 1), Gemini 10 (r0 2, ask-on 2, ask-off 2, deny-on 2, headless-on 1, allow-on 1), Codex 9 (r0 2, ask-on 2, ask-off 2, deny-on 2,
headless-on 1). 40 = 27 planned cells + 2 controls + 3 blind Claude rows that the relay reruns superseded + 8 attempt rows.

Home directories: mtimes of `~/.claude ~/.codex ~/.gemini ~/.cursor` snapshotted before and after: `~/.codex`, `~/.gemini`, `~/.cursor`: **no
change**. `~/.claude`: 38 differing lines, all in the orchestrating session's own files (its project transcripts, `remote-settings.json*`,
`policy-limits.json*`, `skills/synced`, two `.claude.json` backups), none under a path a lane run uses; the lane runs set `HOME` and
`CLAUDE_CONFIG_DIR` to a per-run directory. That is consistent with no lane run touching it but cannot prove it, because the live session
writes there too. Lists: scratchpad `r6pty/mtime-{before,after}-*.txt` (not committed).

## Not done, plainly

* **A real person and a real model.** The answerer is Esc from a script; the model is a stub issuing one call. Retries, a model that tries
  another tool after a refusal, and human timing are not measured.
* **The interactive default of Claude Code 2.1.316 (auto mode)** was not run: with it the hook's ask may or may not prompt, and the stub
  cannot answer the classifier. **NOT MEASURED.** Same for `--dangerously-skip-permissions` or yolo interactive sessions (the detector would
  read yolo and deny).
* **Claude Code `ask-off` and `deny-on` detector readings**: 4 rows without a working `ps`, not rerun (cap). The detector was read correctly
  on all 19 rows that had one; the 6 blind interactive rows read headless 6/6, the blind headless row read headless 1/1 (right for the wrong
  reason).
* **Codex interactive native prompt**: not produced. 0.166.0 rejects `untrusted`, `on-request` with `danger-full-access` never prompts, and
  Codex's seatbelt cannot nest inside the loopback sandbox, so the `workspace-write` plus escalation-request route was not run.
  **NOT MEASURED.**
* **Codex hook trust interactively** (the bypass flag was used), **Gemini without `--gemini-ask`** (both arms had it; without it the ON arm
  denies by design and was not run), **MCP asks**, **a missing or stale version record in an interactive ask** (the record was fresh in every
  run), **builds other than the three**, **Windows and Linux**, **other terminals**, **an IDE embedding with no controlling terminal**, **a
  wrapper that renames the process**, **Cursor**.
* **n=2 on a deterministic stub is a demonstration per cell, not a rate.** Two repeats of one scripted call cannot show a flaky detector.
* Ground truth for the detector is how the run was launched; it is agreement with construction, not an external oracle. The real
  orchestrating session's own `claude` process was an ancestor of the hook in the Claude Code runs (further up than the stub build); the
  detector takes the nearest match, which was the right one in every run, but a nested or wrapped launch is a case this lane did not vary.

## Reproduce

```
cd benchmarks/hook_fidelity
python pty_lane.py plan ../../results/hook-fidelity/interactive            # 27 cells; --controls for the two allow-on controls
HOOK_FIDELITY_GO=<n> python pty_lane.py run <plan.json> <out> [--where harness=gemini] [--attempt N]
python pty_lane.py table <out>                                              # rows -> table.md
```

The harness installs live in the session scratch directory (`HF_RELEASES`) and are not committed; `table` and the tests need only the branch.

**Round 7 critic corrections (written at integration; rows unchanged, the cell labels in `table.md` now carry each cell's scope note).** The `ps` defect was produced by this lane's own `sandbox-exec` profile, so "fixed" means "no longer depends on a runnable `ps`"; unknown mode was reached only by
`INTENTSHIELD_ANCESTRY_SOURCES=none`; the replay cells show how Claude Code 2.1.316 renders any hook's ask and are not a guard comparison (cc-safe-setup's bytes are from a `Write|Edit|MultiEdit` guard replayed on a Bash call; no Gemini or Codex replay was run); the OFF figures are round-6 rows
from older code; the wrapped and no-tty rows are n=1 and do not isolate the detector. The test file count for the detector is 38 (`tests/test_translation_ancestry.py`). Integrated account: [hook-fidelity-study.md](https://github.com/Suhas-123-cell/IntentShield/blob/research-notes/docs/research-notes/hook-fidelity/hook-fidelity-study.md) section 6b.1.
