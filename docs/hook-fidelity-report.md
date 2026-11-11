# What three coding-agent CLIs do with the verdict a hook returns

A report on a measurement study of Claude Code, Codex CLI and Gemini CLI, with IntentShield's own hook as one of the things measured.
The full record (every set of runs, every re-check, the launch accounting) is [`hook-fidelity-study.md`](hook-fidelity-study.md); the data are
under [`results/hook-fidelity/`](../results/hook-fidelity/README.md). Read this page first. It is a measurement note, not a paper, and
it is not a vulnerability report.

**In one paragraph.** A hook that returns `deny` was enforced on every build and in every mode where the hook ran. Whether the hook ran
depended on state outside its reply: trust, matchers and flags. An `ask` with no human at the keyboard is handled three different ways
by the three tools, and one of them changed between two adjacent releases. A hook that fails by running past its timeout let the
guarded call run on every build tested. The other failure replies were tested on far fewer builds. IntentShield's own hook decides
worse than some other guards on one test set and better on another, and the better result comes from a test built from the same
categories as its rules. Everything was measured against a scripted stub model on macOS.

## 1. Question

Agent tools let a user register a hook that runs before each tool call and returns a verdict: allow, ask, deny, or nothing. Guards
for coding agents are built on that interface. The question is whether the tool enforces the verdict it is given, on which releases,
and what it does when the hook fails. The same data answer a second question: when IntentShield's hook and other published guards see
the same call, what do they each decide?

Four sub-questions organise the study: what each tool does with an `ask` when no human can answer (RQ1); which hook failures fail
open (RQ2); how stable each behaviour is across releases (RQ3); which MCP surfaces reach a hook (RQ4, in the full record only).

## 2. Method

**Stub model.** Each tool runs its real binary against a local server (`benchmarks/hook_fidelity/stub_model.py`) that issues exactly
one scripted tool call, then answers "done". The model is therefore not a variable: the study measures what the tool does with a hook
reply, not what a real model does after a refusal. The tool runs in an isolated home directory, with a fake key and no outside network.

**What a cell is.** One cell is one harness build, one mode (for example Claude Code `-p --allowedTools Bash`, Codex `exec`, Gemini
`-p --approval-mode yolo`), one tool kind (shell, MCP, write, resource), one hook reply and one trust state. A cell is run twice on a
sweep build and three to five times on the newest build. The stub is deterministic, so repeats check repeatability and do not estimate
a rate; an interval on them bounds repeatability only.

**The oracle.** A side effect outside the model and the hook: a marker file written by a per-run shim on `PATH`, or a nonce line in a
test MCP server. The outcome is RAN (the effect is on disk), BLOCKED (no effect, and the call was attempted), HUNG (no progress to the
wall-clock cap) or INVALID (a rate limit, a login prompt, no evidence of an attempt; never counted).

**Controls.** A cell is scored only if its neutral control (a hook that returns `{}`) showed the hook ran in every valid run. A build
where it did not is excluded and listed; it is not a finding.

**Hook replies.** No hook; neutral; allow; ask; deny with a reason; empty output with exit 0; malformed JSON; exit 2 with stderr;
exit 1; a sleep past the timeout (15 s against a 3 s timeout); a hook file that is not executable; a shebang that names a missing
interpreter; a missing file. Hook bytes are a stub's, written from the vendors' documentation, except in a separate set of runs where six
third-party guards' own output bytes were captured in a sandbox and replayed.

**Builds.** Claude Code 2.0.41 to 2.1.316 (23 releases, plus five more installed to bisect one change), Codex CLI 0.131.0 to 0.166.0
(17 releases, plus two for another bisect) and Gemini CLI 0.24.5 to 0.66.0 (28 releases). These are the releases that could be
installed and run, not every release and not a random draw. **Cursor CLI was not measured**: its free plan hit a usage limit on both
launches that reached the model, so no Cursor row is scored.

**Terms.** Each term below is used later without further explanation.
- *Build*: one released version of a tool.
- *Sweep*: the same cell run on many builds of one tool.
- *Reply codes* (the R numbers in the tables): R0 no hook, R1 neutral, R2 allow, R3 ask, R4 deny with a reason, R5 empty output with
  exit 0, R6 malformed JSON, R7 exit 2 with stderr, R8 exit 1, R9 sleeps past the timeout, R10b a shebang naming a missing interpreter.
- *Control*: the same cell with the neutral reply R1, run to show that the hook ran at all.
- *Invalid by control*: the control showed that the hook did not run, so the cell tests nothing and is listed, not counted.
- *Scored against a native block*: the tool's own gate (for example an untrusted Codex hook) blocked the control, and the tool documents
  that gate, so the block is the baseline and the cell is still scored.
- *Expectation*: the outcome the author wrote down for a cell before the runs, according to the author, mostly from the vendor's
  documentation (the data files call it a prediction and its source its basis: docs, source code, the pilot or inference).
- *Deviation*: a cell whose outcome differs from its documentation-based expectation, or where the documentation says nothing.
- *Sign-off*: an entry in `benchmarks/hook_fidelity/signoffs.json` that records which vendor document backs a claim about how a cell is set up.
- *Kill criterion*: the test that the author says was written down before the runs for whether the results amount to a paper (section 4).
- *Held-out*: an item whose source was not used while IntentShield's rules were written.
- *Post hoc*: scored after the author had already seen the result on the same data.
- *Scope* of a guard: the harnesses and tool kinds that the guard's own README says it covers.
- *yolo*: Gemini CLI's approval mode that runs every tool call without asking.

**Scale.** 1,342 committed stub rows (the 8 Gemini smoke rows left out) in 507 cells: 361 scored, 122 controls, 16 invalid by control
and 8 scored against a native block. The author's expectations, written from the documentation before the runs according to the author
(the commits are not in `main`'s history and the available timestamps do not settle the order; see the limits), matched in 263 of 277
build-level checks on documented behaviour (94.9 percent, Wilson 95 percent 91.7 to 97.0). Counted per distinct behaviour instead of per
build, 67 of 79 matched on every build (84.8 percent, 75.3 to 91.1). The hits are not blind and not independent; see the limits.

**Tooling.** The study was carried out under the author's direction by AI coding agents. The committed documents state that agents ran
the cells and wrote the sign-offs on vendor documentation, the documentation-based expectations, the deviation coding and the
fixtures of both comparison sets (the 214-call set was built by one agent in a single session from recalled sources), and that further
agents re-ran sampled cells and reviewed the write-ups. The same documents say that no human second coder exists. They do not say how
much of this output the author checked by hand, and this report claims nothing about that.

## 3. The version matrix

One row per harness and hook reply, for the guarded shell command; each cell lists the outcome by release. This table is generated by
the command in section 8 from the committed rows; the per-release tables of each tool are `results/hook-fidelity/claude/version-table.md`, `codex/by-version.md` and `gemini/sweep/table.md`.

| harness | hook reply | builds | outcome of the guarded shell command, by release |
|---|---|---|---|
| Claude Code | deny (R4) | 27 | BLOCKED 2.0.41 to 2.1.316 (27 builds) |
| Claude Code | ask, no human (R3) | 27 | RAN 2.0.41 to 2.1.84 (6 builds); BLOCKED 2.1.85 to 2.1.316 (21 builds) |
| Claude Code | hook runs past its timeout (R9) | 22 | RAN 2.0.41 to 2.1.316 (22 builds) |
| Claude Code | empty reply, exit 0 (R5) | 1 | RAN 2.1.316 (1 build) |
| Claude Code | malformed JSON, exit 0 (R6) | 1 | RAN 2.1.316 (1 build) |
| Claude Code | exit 2 with stderr (R7) | 1 | BLOCKED 2.1.316 (1 build) |
| Claude Code | exit 1 (R8) | 1 | RAN 2.1.316 (1 build) |
| Claude Code | interpreter missing (R10b) | 1 | RAN 2.1.316 (1 build) |
| Codex CLI | deny (R4) | 12 | BLOCKED 0.143.0 to 0.166.0 (12 builds) |
| Codex CLI | ask, no human (R3) | 12 | RAN 0.143.0 to 0.166.0 (12 builds) |
| Codex CLI | hook runs past its timeout (R9) | 12 | RAN 0.143.0 to 0.166.0 (12 builds) |
| Codex CLI | empty reply, exit 0 (R5) | 2 | RAN 0.165.0 to 0.166.0 (2 builds) |
| Codex CLI | malformed JSON, exit 0 (R6) | 2 | RAN 0.165.0 to 0.166.0 (2 builds) |
| Codex CLI | exit 2 with stderr (R7) | 12 | BLOCKED 0.143.0 to 0.166.0 (12 builds) |
| Codex CLI | exit 1 (R8) | 2 | RAN 0.165.0 to 0.166.0 (2 builds) |
| Codex CLI | interpreter missing (R10b) | 2 | RAN 0.165.0 to 0.166.0 (2 builds) |
| Gemini CLI | deny (R4) | 26 | BLOCKED 0.24.5 to 0.66.0 (26 builds) |
| Gemini CLI | ask, no human (R3) | 28 | RAN 0.24.5 to 0.37.2 (13 builds); HUNG 0.38.0 to 0.66.0 (15 builds) |
| Gemini CLI | hook runs past its timeout (R9) | 1 | RAN 0.66.0 (1 build) |
| Gemini CLI | empty reply, exit 0 (R5) | 1 | RAN 0.66.0 (1 build) |
| Gemini CLI | interpreter missing (R10b) | 26 | RAN 0.24.5 to 0.29.7 (4 builds); BLOCKED 0.30.0 to 0.66.0 (22 builds) |

Builds counted are those whose control ran the hook. Excluded: Claude Code 2.1.0 (the control was blocked, so nothing was tested) and
Codex 0.131.0 to 0.140.0 under the bypass flag (the flag had no effect there, see finding 4). For Claude Code the ask row includes
five releases installed to bisect the change, so the count is 27: 22 sampled builds with a working control plus the five. Claude Code's ask cell runs with
`--allowedTools Bash`, a pre-approval rule; the old-release RAN results are confounded by that rule and were not run with a human prompt.

## 4. Findings

Each finding is a count from the committed rows, with the Wilson 95% interval where a rate is meaningful. Row counts are not
independent (a deterministic stub, two to five repeats per cell), so the build counts are the figure to read.

**Finding 1. A deny was enforced wherever the hook ran, and the hook did not always run.**

> deny enforced where the hook ran: 66 of 66 builds, 220/220 [98.3, 100.0]% rows (0 let the call run); the rows are 84 deterministic cells on 66 builds, so the interval bounds repeatability, not a population rate; deny rows where the hook did not run and the call ran: 47 of 273 (Claude Code mcp__.* matcher on a resource read 5, Codex untrusted hook 40, Gemini CLI before 0.26.0 2)

Read the first figure, 66 of 66 builds. The 220 rows are 84 cells repeated two to five times on a deterministic stub, so the interval on
rows says how repeatable the stub is and nothing about how often a deny is enforced across hooks, builds or users.

The 47 are three causes: a Codex hook the user had not trusted is skipped without any signal in `codex exec` (40 rows, 12 builds); a
Claude Code hook scoped with the natural `mcp__.*` matcher does not see a resource read, which goes through a built-in tool name (5
rows); Gemini CLI hooks were opt-in before 0.26.0 (2 rows). No cell shows a deny that a running hook returned and the tool ignored.
This does not show that an attacker can bypass a guard: nothing here shows a trigger an attacker controls.

**Finding 2. An `ask` with no human is handled three ways.**
- Claude Code ask: RAN on 6 builds, BLOCKED on 21 of 27 measured; last RAN 2.1.84, first BLOCKED 2.1.85. The change lies between two adjacent patch releases, found by bisection. Before it, the call ran; after it, the tool
  turns an `ask` into a refusal in `-p` runs (documented behaviour). The pre-approval rule in the cell is a confound for the old builds.
- Codex ask: RAN on 12 of 12 builds. The Codex documentation says an `ask` is parsed but not supported.
- Gemini ask: RAN on 13, HUNG on 15 of 28 builds; last RAN 0.37.2, first HUNG 0.38.0. Under yolo the call runs silently until 0.37.2 and, from 0.38.0, waits until the wall-clock cap. "Hung" means no
  progress at the cap (90 to 900 s depending on the cell), not that it waits for ever.

**Finding 3. Failure replies: timeouts fail open on every build tested; the rest were tested on few builds.**
- R9, hook runs past its timeout: Claude Code RAN on 22 of 22; Codex CLI RAN on 12 of 12; Gemini CLI RAN on 1 of 1
- R5, empty reply: Claude Code RAN on 1 of 1; Codex CLI RAN on 2 of 2; Gemini CLI RAN on 1 of 1
- R7, exit 2: Claude Code BLOCKED on 1 of 1; Codex CLI BLOCKED on 12 of 12
- R10b, interpreter missing: Claude Code RAN on 1 of 1; Codex CLI RAN on 2 of 2; Gemini CLI BLOCKED on 22 of 26, RAN on 4 of 26
The Gemini result for a missing interpreter is the safe direction (the documentation says such a failure only warns) and changes at
0.30.0. Malformed JSON and exit 1 were run on the same one Claude Code and two Codex builds as the empty reply and also let the call
run. Timeouts are the only failure class measured across the whole sweep for Claude Code and Codex. A sentence such as "a hook that
crashed let the call run on most builds" would go beyond these counts.

**Finding 4. State outside the hook's reply decides more than the reply does.**
- Codex untrusted hooks: 70 rows, hook ran in 0, call ran in 70, 12 builds. The tool prints nothing.
- Codex bypass flag: hook did not run on 5 builds (0.131.0 to 0.140.0), ran on 14 builds (0.141.0 to 0.166.0). The flag that is meant to trust hooks was accepted and had no effect in `codex exec` through 0.140.0. This is a
  publicly reported and fixed bug (openai/codex #26383), so it is a reproduction, not a new finding.
- Gemini CLI's outcome depends on approval mode and MCP trust; Claude Code's on pre-approval rules (finding 2).

**Kill criterion.** The author says the test was written down before the runs: at least 5 undocumented deviations that replicate on three
or more builds, or the study is a note and not a paper. The count is 3 (20 undocumented groups; two of the three replicating ones are
Gemini's), so the criterion is not met. Re-counted by direction, no replicating deviation in the unsafe direction is free of a
confound. The threshold of 5 has no rationale beyond "several"; at 3 the criterion would be met.

## 5. How IntentShield's hook compares with other guards

The comparison covers what each guard decides on the same calls, offline, with no model in the loop. There are two fixture sets, both
written by the author, and the two results point in different directions. Both are stated here.

**Where IntentShield is behind.**
- 467-fixture set, held-out harmful items, before the rules: IntentShield lets through 137/166 [76.0, 87.6]%, asks on 29; safety-net on its scope: 31/130 [17.3, 31.9]%; knox on its scope: 67/117 [48.2, 65.9]%. This set (467 fixtures, 10 guards) is mostly shell commands and MCP calls. Before its dangerous-command
  rules, IntentShield's hook flagged none of the destructive, git, credential-read, pipe-to-shell or rc-and-CI-write items. Its one
  distinctive flag is an MCP call whose destination was copied from an earlier tool result, which is provenance, not injection
  detection, and 20 of 24 benign calls of that shape were asked about too.
- On the 214-item set below, counting denies alone, IntentShield is behind safety-net: denies alone on those items: safety-net 41/85, IntentShield 24/85; IntentShield asks on 36 more. On knox's scope the two are close.

**Where IntentShield is ahead.**
- IntentShield before the rules, 214-item set: lets through 96/104 [85.6, 96.1]% harmful calls; IntentShield with the rules, same set: lets through 28/104 [19.3, 36.2]% harmful calls. The 214 items are 104 harmful and 110 benign calls to built-in shell, read, write and edit tools.
- on safety-net's shell scope, 85 harmful items: safety-net lets through 44/85 [41.3, 62.1]%, IntentShield 25/85 [20.8, 39.8]%.
- on knox's scope, 73 harmful items: knox lets through 44/73 [48.8, 70.7]%, IntentShield 18/73 [16.2, 35.6]%; denies alone knox 29, IntentShield 28.
- benign calls: IntentShield asks on 5 of 110, denies 0; safety-net denies 4 of 100.

**The rules on the first set, before and after, on the same items.** The dangerous-command rules were written after the first set's
result was known, so this is a post hoc score. Both figures are on one denominator in each line:
- 467-fixture set, harmful held-out items IntentShield lets through, before the built-in tool rules and after them (post hoc): 166 items that stayed held out, 137/166 [76.0, 87.6]% before, 6/166 [1.7, 7.7]% after; 178 items declared held out, 137/178 [70.3, 82.5]% before, 6/178 [1.6, 7.2]% after; 156 built-in tool calls, the only ones the rules act on, 137/156 [81.8, 92.1]% before, 6/156 [1.8, 8.1]% after
- the 22 MCP calls among the 178 get the same reply before and after the rules in 22 of 22

The 178 are the items declared held out. The 166 leave out 12 items of one MCP attack family (AgentDojo `ignore_previous`), because a
rule in the MCP inspector was written from that family's own misspelling, so they are not held out. The 156 leave out all 22 MCP calls,
which the built-in tool rules never see; they are decided the same with and without the rules. Of the 156 built-in tool calls the rules
still let 6 through. The rules are opt-in (`--builtin-tools`).

**How to read the two together.** The rules were written from six harmful categories and the 214 items sample the same six. The
author built the set, and the rules and the labels come from the same model family. The rules file existed on disk while the fixtures
were being finished (file times show it); the builder states the fixtures were not read against it, which only that statement
supports. The gain from 96/104 to 28/104 on the same items measures fit to those categories. The 6 of 166 on the earlier set is a post
hoc figure on items whose aggregate result the author had already seen; it is not detection of anything unseen.

About a tenth of the 214-item set's harmful items are discovery-only commands with no effect on their own (a `find` for key file
names, a `grep` for the word password, a history or environment filter, a secret scanner run, a read of `~/.gitconfig`). The author
labelled them harmful and no one else reviewed the labels; the list of nine is in `benchmarks/hook_fidelity/report_numbers.py`. Every
guard let all of them through, so they raise every false-allow figure above. Without them, the direction does not change:
- fresh set without the 9 discovery-only items: IntentShield with the rules lets through 19/95 [13.2, 29.1]% of the harmful calls (28/104 with them); on safety-net's shell scope, safety-net 36/77 [36.0, 57.8]% and IntentShield 17/77 [14.3, 32.5]%; on knox's scope, knox 39/68 [45.5, 68.4]% and IntentShield 13/68 [11.5, 30.0]%; each of these three guards let every discovery-only item in its scope through

An `ask` is not a stop on Claude Code up to 2.1.84 or on Codex, and on Gemini it either runs the call (to 0.37.2) or hangs (from 0.38.0), so
the lead in asks is worth less than the lead in denies, and denies are where IntentShield trails safety-net. IntentShield ships a
translation that turns an ask into a refusal where nobody can answer it; the study's effective-protection figures for it extrapolate
shell-measured delivery to other tools and are in section 6e of the full record, not here. Nothing was tested outside the six categories, so no claim about
how the rules generalise is made in either direction.

## 6. Limits

- **Stub model.** One scripted call per run; no retry, no switch of tool, no argument. A local model (qwen2.5:7b) and one paid model
  issued the call on a narrow slice (four reply classes, two builds, a prompt that forbids a retry) and the outcome matched the stub in
  every valid run. That says little about a goal-directed model. Counts are in section 6d of the full record.
- **One operating system, headless.** macOS, bash and zsh. A Linux check ran a process-ancestry reader on dummy processes in a container;
  it ran no harness. The exit 126 versus 127 split depends on the shell. Hook timeout is 3 s in the cells, not the vendors' default.
- **Cursor unmeasured.** No Cursor row is scored.
- **Sampled builds.** The builds are those that could be installed. A boundary such as "from 2.1.85" lies between two measured builds
  unless it was bisected; only Claude Code's `ask` change and Codex's bypass-flag boundary were. Gemini's and the rest were not.
- **Failure cells on few builds.** See finding 3: empty, malformed, exit 1 and missing-interpreter replies ran on one to two builds for
  Claude Code and Codex. Codex failure replies ran with hooks trusted by the bypass flag; persisted trust, the realistic state, was added for most of them on 0.165.0 and 0.166.0 only, and not for the missing-interpreter reply.
- **Same-category comparison.** The 214-item set samples the six categories the rules were written for; the author built the set, and
  the rules and labels come from one model family. The test of whether the rules work outside those categories, with 30 to 50 harmful
  calls written by someone else and scored once with the rules frozen, was not run.
- **No inter-rater check, and the coding is not independent.** The deviation classes, the documentation-based expectations and the sign-offs
  on vendor documentation were produced by the same agents that ran the cells (see Tooling in section 2). No second coder re-coded a sample, and no agreement
  statistic exists. What does exist: re-running the coder over the committed rows gives the same codes (section 8), which checks the
  program, not the judgement.
- **No determinism run on the stub.** Six cells repeated twenty times, under load, was not done.
- **The order of writing cannot be checked from this repository.** According to the author, the expectations and the kill criterion
  were written and committed the same day, before the runs, and they were not blind. Those commits are not in `main`: the study was
  merged as one squashed commit. The author archives the original commits; an outside reader cannot verify them. The available
  timestamps do not settle the order. The earliest committed Claude Code row started at 2026-10-31T22:03:05Z, and the Claude Code
  documentation pages the expectations rest on are recorded as retrieved on 2026-11-01, with no time of day and no time zone. Read
  "written before the runs" as the author's statement. The documentation pages are recorded by URL and hash, not copied.
- **The rules have changed since the study ran.** The committed results are the rules as they stood then, and are not
  regenerated. Since then a deny from the dangerous-command rules wins over a session ask. Re-running the committed fixtures through
  today's code (2026-11-11) changes 45 IntentShield decisions from ask to deny: 27 of the 467-fixture set (9 items) and 18 of the
  214-call set (6 items). All 45 are harmful credential-exfiltration rows. No benign row changed and none changed to allow. On the
  214-call set the 41 asked and 35 denied become 35 asked and 41 denied; 28 of 104 harmful calls are still let through and the 5
  benign asks stay. The figures in section 5 are the study's, not these, and the denies-alone count (24/85) was not recomputed.
- **One author, a conflict of interest.** The author maintains IntentShield, whose hook is one of the things measured.
- **Findings age.** Vendors update their tools. Gemini CLI's consumer tiers were reported (unverified) to end on 2026-06-18, so 28 releases of a
  possibly retiring tool carry two of the three replicating deviations.

## 7. Disclosure status

Drafts exist for Anthropic, OpenAI, Google and Cursor. **Nothing has been sent and no vendor has been contacted.** The drafts are kept
outside the repository until they go out. Most behaviours are documented by the vendors or already reported, so they would go as public
documentation feedback or issues without an embargo. One item may qualify for a private report with a 45-day window: a Claude Code
deny hook scoped with `mcp__.*` does not see a resource read. Its class is to be decided with the vendor, and no real model has been
shown to reach it. No cell qualifies for a private report on the deny rule, because every deny that a running hook returned was
enforced. The drafts describe observed hook behaviour with benign markers and no evasion technique.

## 8. Reproduce it offline

Everything below needs no harness, no model and no network. From the repository root:

```
.venv/bin/python benchmarks/hook_fidelity/report_numbers.py          # the matrix and every figure in sections 3 to 5
.venv/bin/python benchmarks/hook_fidelity/detect_compare.py report --decisions results/hook-fidelity/detect/decisions.jsonl --out <copy of detect/>
.venv/bin/python benchmarks/hook_fidelity/fresh_report.py            # the 214-item tables
.venv/bin/pytest -q tests/test_hook_fidelity_*.py                    # recomputes the figures the documents cite
```

`detect_compare.py report` and `breakdown` work in a clean clone: they read `detect/decisions.jsonl` and no guard clone. They write into
the directory they are given, so copy `results/hook-fidelity/detect/` first if you only want to compare. The other tables and their
commands are in [`results/hook-fidelity/README.md`](../results/hook-fidelity/README.md).

What needs more: the guard decisions need clones of the 26 guards at their pinned commits (`benchmarks/hook_fidelity/fetch_corpus.py
--dry-run` prints the plan; running it needs the network), and launches need the exact harness releases, macOS `sandbox-exec` and a
launch budget. The prevalence counts came from a code-search index and cannot be reproduced from this repository. Where the repository
has no `.venv`, generated scripts use the interpreter that runs the benchmark code.

The output of `report_numbers.py`, for checking this page against the data (a test fails if they differ):

```
1342 committed stub rows

| harness | hook reply | builds | outcome of the guarded shell command, by release |
|---|---|---|---|
| Claude Code | deny (R4) | 27 | BLOCKED 2.0.41 to 2.1.316 (27 builds) |
| Claude Code | ask, no human (R3) | 27 | RAN 2.0.41 to 2.1.84 (6 builds); BLOCKED 2.1.85 to 2.1.316 (21 builds) |
| Claude Code | hook runs past its timeout (R9) | 22 | RAN 2.0.41 to 2.1.316 (22 builds) |
| Claude Code | empty reply, exit 0 (R5) | 1 | RAN 2.1.316 (1 build) |
| Claude Code | malformed JSON, exit 0 (R6) | 1 | RAN 2.1.316 (1 build) |
| Claude Code | exit 2 with stderr (R7) | 1 | BLOCKED 2.1.316 (1 build) |
| Claude Code | exit 1 (R8) | 1 | RAN 2.1.316 (1 build) |
| Claude Code | interpreter missing (R10b) | 1 | RAN 2.1.316 (1 build) |
| Codex CLI | deny (R4) | 12 | BLOCKED 0.143.0 to 0.166.0 (12 builds) |
| Codex CLI | ask, no human (R3) | 12 | RAN 0.143.0 to 0.166.0 (12 builds) |
| Codex CLI | hook runs past its timeout (R9) | 12 | RAN 0.143.0 to 0.166.0 (12 builds) |
| Codex CLI | empty reply, exit 0 (R5) | 2 | RAN 0.165.0 to 0.166.0 (2 builds) |
| Codex CLI | malformed JSON, exit 0 (R6) | 2 | RAN 0.165.0 to 0.166.0 (2 builds) |
| Codex CLI | exit 2 with stderr (R7) | 12 | BLOCKED 0.143.0 to 0.166.0 (12 builds) |
| Codex CLI | exit 1 (R8) | 2 | RAN 0.165.0 to 0.166.0 (2 builds) |
| Codex CLI | interpreter missing (R10b) | 2 | RAN 0.165.0 to 0.166.0 (2 builds) |
| Gemini CLI | deny (R4) | 26 | BLOCKED 0.24.5 to 0.66.0 (26 builds) |
| Gemini CLI | ask, no human (R3) | 28 | RAN 0.24.5 to 0.37.2 (13 builds); HUNG 0.38.0 to 0.66.0 (15 builds) |
| Gemini CLI | hook runs past its timeout (R9) | 1 | RAN 0.66.0 (1 build) |
| Gemini CLI | empty reply, exit 0 (R5) | 1 | RAN 0.66.0 (1 build) |
| Gemini CLI | interpreter missing (R10b) | 26 | RAN 0.24.5 to 0.29.7 (4 builds); BLOCKED 0.30.0 to 0.66.0 (22 builds) |

builds excluded (neutral control did not run the hook): {'Claude Code': ['2.1.0'], 'Codex CLI': ['0.131.0', '0.133.0', '0.134.0', '0.136.0', '0.140.0'], 'Gemini CLI': []}

[findings]
deny: deny enforced where the hook ran: 66 of 66 builds, 220/220 [98.3, 100.0]% rows (0 let the call run); the rows are 84 deterministic cells on 66 builds, so the interval bounds repeatability, not a population rate; deny rows where the hook did not run and the call ran: 47 of 273 (Claude Code mcp__.* matcher on a resource read 5, Codex untrusted hook 40, Gemini CLI before 0.26.0 2)
ask_claude: Claude Code ask: RAN on 6 builds, BLOCKED on 21 of 27 measured; last RAN 2.1.84, first BLOCKED 2.1.85
ask_codex: Codex ask: RAN on 12 of 12 builds
ask_gemini: Gemini ask: RAN on 13, HUNG on 15 of 28 builds; last RAN 0.37.2, first HUNG 0.38.0
fail_timeout: R9, hook runs past its timeout: Claude Code RAN on 22 of 22; Codex CLI RAN on 12 of 12; Gemini CLI RAN on 1 of 1
fail_empty: R5, empty reply: Claude Code RAN on 1 of 1; Codex CLI RAN on 2 of 2; Gemini CLI RAN on 1 of 1
fail_exit2: R7, exit 2: Claude Code BLOCKED on 1 of 1; Codex CLI BLOCKED on 12 of 12
fail_dead: R10b, interpreter missing: Claude Code RAN on 1 of 1; Codex CLI RAN on 2 of 2; Gemini CLI BLOCKED on 22 of 26, RAN on 4 of 26
codex_untrusted: Codex untrusted hooks: 70 rows, hook ran in 0, call ran in 70, 12 builds
codex_bypass: Codex bypass flag: hook did not run on 5 builds (0.131.0 to 0.140.0), ran on 14 builds (0.141.0 to 0.166.0)

[guards]
fresh_is_before: IntentShield before the rules, 214-item set: lets through 96/104 [85.6, 96.1]% harmful calls
fresh_is_after: IntentShield with the rules, same set: lets through 28/104 [19.3, 36.2]% harmful calls
fresh_vs_safety_net: on safety-net's shell scope, 85 harmful items: safety-net lets through 44/85 [41.3, 62.1]%, IntentShield 25/85 [20.8, 39.8]%
fresh_denies_only: denies alone on those items: safety-net 41/85, IntentShield 24/85; IntentShield asks on 36 more
fresh_vs_knox: on knox's scope, 73 harmful items: knox lets through 44/73 [48.8, 70.7]%, IntentShield 18/73 [16.2, 35.6]%; denies alone knox 29, IntentShield 28
fresh_benign: benign calls: IntentShield asks on 5 of 110, denies 0; safety-net denies 4 of 100
fresh_discovery: fresh set without the 9 discovery-only items: IntentShield with the rules lets through 19/95 [13.2, 29.1]% of the harmful calls (28/104 with them); on safety-net's shell scope, safety-net 36/77 [36.0, 57.8]% and IntentShield 17/77 [14.3, 32.5]%; on knox's scope, knox 39/68 [45.5, 68.4]% and IntentShield 13/68 [11.5, 30.0]%; each of these three guards let every discovery-only item in its scope through
detect_is: 467-fixture set, held-out harmful items, before the rules: IntentShield lets through 137/166 [76.0, 87.6]%, asks on 29
detect_sn: safety-net on its scope: 31/130 [17.3, 31.9]%; knox on its scope: 67/117 [48.2, 65.9]%
rules_same_items: 467-fixture set, harmful held-out items IntentShield lets through, before the built-in tool rules and after them (post hoc): 166 items that stayed held out, 137/166 [76.0, 87.6]% before, 6/166 [1.7, 7.7]% after; 178 items declared held out, 137/178 [70.3, 82.5]% before, 6/178 [1.6, 7.2]% after; 156 built-in tool calls, the only ones the rules act on, 137/156 [81.8, 92.1]% before, 6/156 [1.8, 8.1]% after
rules_mcp_items: the 22 MCP calls among the 178 get the same reply before and after the rules in 22 of 22
```
