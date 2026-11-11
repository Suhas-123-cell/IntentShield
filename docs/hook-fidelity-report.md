# What three coding-agent CLIs do with the verdict a hook returns

A measurement study of Claude Code, Codex CLI and Gemini CLI, with IntentShield's own hook as one of the things measured. It is a
measurement note, not a paper and not a vulnerability report. Denominator variants, per-build detail and long caveats are in the
[appendix](hook-fidelity-report-appendix.md). The working record is
[`hook-fidelity-study.md`](research-notes/hook-fidelity/hook-fidelity-study.md) and the data are in
[`results/hook-fidelity/`](../results/hook-fidelity/README.md).

**Summary.** A `deny` was enforced on every build where the hook ran, but whether it ran depended on trust, matchers and flags outside its
reply. An `ask` with no human is handled three ways. A hook that runs past its timeout let the call run on every build tested with the
default configuration. In unattended runs, where an ask is not a stop, IntentShield's hook is behind safety-net on denies alone, as scored
in the study and on the current rules (section 5); the attended comparison was not made. All runs used a scripted stub model on macOS.

## 1. Question

An agent tool lets a user register a hook that runs before each tool call and returns allow, ask, deny or nothing. Does the tool enforce
that verdict, on which releases, and what does it do when the hook fails? A second question: when IntentShield's hook and other published
guards see the same call, what does each decide?

## 2. Method

Each tool's real binary runs against a local stub model that issues one scripted tool call and then answers "done", so the model is not
a variable. A cell is one build, mode, tool kind, hook reply and trust state, run two to five times (ten Codex untrusted-state controls, once). The stub is scripted, so repeats
check how repeatable the harness is and estimate no rate; no separate determinism run was made. The oracle is a side effect outside the
model and the hook, such as a marker file. A cell is scored only if its neutral control showed that the hook ran. The author wrote the
expected outcome of each cell from the vendors' documentation (see section 7). The committed data are 1,342 stub rows in 507 cells.

The builds are the releases that could be installed, not a random draw (the sampling frame follows the table of build counts).
**Cursor CLI was not measured**: its free plan hit a usage limit.

| term | meaning |
|---|---|
| R1 | neutral reply `{}`: the control, which shows that the hook ran |
| R3, R4 | ask with no human to answer; deny with a reason |
| R5, R6 | empty output with exit 0; malformed JSON with exit 0 |
| R7, R8 | exit 2 with stderr; exit 1 |
| R9, R10b | the hook sleeps past its timeout; its shebang names a missing interpreter |
| RAN, BLOCKED | the guarded effect is on disk; no effect, and the call was attempted |
| HUNG | no progress until the wall-clock cap (90 to 900 s) |

Build counts, from `benchmarks/hook_fidelity/report_numbers.py`. Installed builds were run at least once, including releases installed
only to bisect one change. Scored builds are those whose control ran the hook; five Codex CLI builds ignored the flag that trusts hooks
and Claude Code 2.1.0 blocked the control.

| harness | installed builds | scored builds | excluded by control |
|---|---|---|---|
| Claude Code | 28 | 27 | 1 |
| Codex CLI | 19 | 14 | 5 |
| Gemini CLI | 28 | 28 | 0 |

**Sampling frame.** No rule for choosing builds was recorded beyond "could be installed and run", plus extra releases around two changes
(Claude Code 2.1.84 and 2.1.85, Codex CLI 0.141.0 and 0.142.0). Stable releases listed by npm between the first and last build installed
(`npm view <package> time`, 2026-11-11; not committed): Claude Code 309 (28 installed), Codex CLI 63 (19), Gemini CLI 78 (28). Adjacent
releases share most of their code, so "N of N builds" is not N independent observations.

## 3. The version matrix

One row per harness and hook reply, for the guarded shell command. The builds column counts builds that ran that reply, at most the
scored count. Claude Code's ask cell uses a pre-approval rule, `--allowedTools Bash`, which confounds the old-release RAN results.

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

## 4. Findings

**Finding 1. A deny was enforced wherever the hook ran, and the hook did not always run.** The figure to read is 65 of 65 builds: those
on which a deny ran the hook in any trust state and for any tool kind (22 Claude Code, 17 Codex CLI, 26 Gemini CLI). It is not the deny rows of
the matrix below, which count the shell command only and also add up to 65. On 47
of 271 deny rows the hook did not run and the call ran: a Codex hook the user had not trusted (40 rows), a Claude Code `mcp__.*` matcher
that does not see a resource read (5), and Gemini CLI before 0.26.0, where hooks were opt-in (2). Six more rows, all Gemini CLI 0.66.0 in its
default approval mode, were blocked without the hook running and are in neither count. No cell shows a running hook's deny
ignored. This is not a finding that an attacker can bypass a guard.

**Finding 2. An `ask` with no human is handled three ways.**
- Claude Code: RAN on 2.0.41 to 2.1.84, BLOCKED from 2.1.85, found by bisection between two adjacent patch releases. This sweep pre-approved
  Bash (`--allowedTools Bash`). The same cell with nothing pre-approved ran on one build, 2.1.316 (BLOCKED in 5 of 5 runs, with the neutral
  reply refused too), and on none before 2.1.85. So the flip at 2.1.85 is measured with the pre-approval only.
- Codex CLI: RAN on 12 of 12 builds. Its documentation says an `ask` is parsed but not supported.
- Gemini CLI: RAN to 0.37.2, then HUNG from 0.38.0 (15 of 28 builds).

**Finding 3. With the default configuration a timeout fails open on every build tested.** The hook's timeout in the cells was 3 s, not the vendors' default. R9 RAN on 22 of 22 Claude Code builds, 12 of 12
Codex CLI builds and 1 of 1 Gemini CLI build. The other failure replies ran on one to two builds of Claude Code and Codex CLI, so nothing
general about "a crashed hook" follows. Claude Code's documented `onFailure: "block"` setting, which IntentShield's `install` writes,
changed RAN to BLOCKED for R8, R9, R10a, R10b and R13 on 2.1.316 (RAN in 3 of 3 runs without the key, BLOCKED in 3 of 3 with it). R7 and R11
were already BLOCKED without it, and R5 and R6 still RAN with it. On 2.1.281 (before that version), R9 RAN 2 of 2 either way and R8 2 of 2 with it.

**Finding 4. State outside the reply decides more than the reply does.** Codex CLI with an untrusted hook ran the hook in 0 of 70 rows and
the call in all 70, on 12 builds, and printed nothing. The flag meant to trust hooks did nothing in `codex exec` through 0.140.0, a
publicly reported and fixed bug (openai/codex #26383).

## 5. How IntentShield's hook compares with other guards

The comparison is offline, with no model. Both fixture sets were written by the author: 467 fixtures, mostly shell commands and MCP calls,
and 214 calls to built-in shell, read, write and edit tools. The results point in different directions. The items are not a random
sample: an interval below is sampling noise on these items only.

**Where IntentShield is behind.**
- 467-fixture set, held-out harmful items, before the dangerous-command rules: IntentShield lets through
  137/166 [76.0, 87.6]%, asks on 29. On their own scopes safety-net lets through 31/130 [17.3, 31.9]% and knox 67/117 [48.2, 65.9]%.
- 214-call set, denies alone, with the rules as they were when scored: safety-net 41/85, IntentShield 24/85, with asks on 36 more. An ask is
  not a stop in an unattended run on Claude Code to 2.1.84, on Codex CLI or on Gemini CLI to 0.37.2, so there denies are what count, and
  IntentShield trails safety-net. With a person at the prompt an ask is a stop; that comparison was not made. Paired on the same 85 items,
  safety-net denied 24 that IntentShield did not and IntentShield denied 7 that safety-net did not (exact sign test, p = 0.0033); on knox's
  73 items the denies split 18 to 17.
- The same items with the rules in the repository now (`fresh_report.py --current-rules`, after 0.4.3): IntentShield denies 29 of the 85 and asks on 31;
  21 items that only safety-net denied and 9 that only IntentShield denied (p = 0.043); on knox's items 16 only knox and 17 only IntentShield. The rules changed after
  the items had been seen, so this is no cleaner than the study's figure.

**Where IntentShield is ahead: only on its own rule categories, and post hoc.** The opt-in rules were written after the first set's result was known. The
214 items sample the same six categories the rules were written from, and the set was built by the same model family. The gain measures
fit to those categories, not detection of anything unseen.
- 214-call set, harmful calls let through: 96/104 [85.6, 96.1]% before the rules, 28/104 [19.3, 36.2]% after. On safety-net's scope
  (85 items): safety-net 44/85 [41.3, 62.1]%, IntentShield 25/85 [20.8, 39.8]%. On knox's scope (73 items): knox 44/73 [48.8, 70.7]%,
  IntentShield 18/73 [16.2, 35.6]%.
- 467-fixture set, 166 held-out harmful items: 137/166 before the rules, 6/166 [1.7, 7.7]% after.
- Some items appear in the rules' unit tests: 33 of the 156 built-in tool items at commit 1979d0e, among them canonical commands such as
  `rm -rf /`, so "held out" was weak for those from the start. Without them the 467-set figures are 104/133 [70.4, 84.4]% before and
  6/133 [2.1, 9.5]% after. `overlap_check.py` names any item the tests have matched since and exits 1: it now names H129, so the
  count on the tree is 34 of 156. The 214-call set has 7 of 104; the appendix rescores its comparison.

**Benign calls: a tie with safety-net and a loss to knox.** On the 214-call set IntentShield asks on 4 of safety-net's 100 shell items and
safety-net denies 4; on knox's 74 items IntentShield asks on 5 and knox flags 0. On the 467-fixture set IntentShield asks on 6 of 234
and denies none; safety-net denies 3 of 160 and knox flags 0 of 168.

Nothing was tested outside the six categories, so no claim about generalisation is made in either direction.

## 6. Limits

- **Stub model, one operating system.** One scripted call per run, on macOS, headless. A real model was tried on a narrow slice only.
- **Sampled builds.** A boundary such as "from 2.1.85" lies between two measured builds unless bisected, and only two were.
- **Same-category comparison.** The author built the set, and the rules and labels come from one model family. A test with 30 to 50
  harmful calls written by someone else, outside those categories and scored once with the rules frozen, was not run.
- **Tooling and no inter-rater check.** The study was carried out under the author's direction by AI coding agents. They ran the cells and
  wrote the sign-offs, the expectations, the deviation coding and the fixtures. No human second coder exists and there is no agreement
  statistic. How much the author checked by hand is not documented here, and this report claims nothing about it.
- **No determinism run on the stub**, one author who maintains the tool being measured, and findings that age as vendors update.

## 7. Status

- **Disclosure.** Drafts exist for Anthropic, OpenAI, Google and Cursor. **Nothing has been sent and no vendor has been contacted.**
- **Order of writing.** According to the author, the expectations and the kill criterion were written and committed before the runs. Those
  commits are not in `main`, because the study was merged as one squashed commit, so an outside reader cannot verify them, and the available
  timestamps do not settle the order. Read "written before the runs" as the author's statement.
- **Kill criterion.** The author's test for whether the results amount to a paper was at least 5 undocumented deviations that replicate on
  three or more builds. The count is 3, so it is not met, but only just: there are 20 undocumented groups, 2 of the 3 that replicate are
  Gemini CLI's, and the threshold of 5 has no rationale beyond "several". At a threshold of 3 the criterion would be met.
- **Standing.** A measurement note and an artifact. [`contribution.md`](contribution.md) says what the work does and does not support.

## 8. Reproduce

Everything cited here regenerates offline from the committed rows:

```
.venv/bin/python benchmarks/hook_fidelity/report_numbers.py   # the builds, matrix and every figure above (prints only)
.venv/bin/python benchmarks/hook_fidelity/overlap_check.py    # the items now in the tests, and the rescored figures (prints only; exit 1 on drift)
.venv/bin/python benchmarks/hook_fidelity/fresh_report.py --out <empty directory> --current-rules   # IntentShield's decisions from this checkout's rules
.venv/bin/pytest -q tests/test_hook_fidelity_*.py             # recomputes the figures the documents cite
```

The [appendix](hook-fidelity-report-appendix.md#reproduce-in-full) lists the other commands and what needs more.
