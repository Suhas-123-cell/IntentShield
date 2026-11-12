# What IntentShield contributes, and what it does not

This page says what the repository supports as a research contribution, as of 2026-11-11. It is kept brief. The longer record
with every earlier verdict, the superseded tables and the day-by-day account of the hook study is in
[contribution-history.md](https://github.com/Suhas-123-cell/IntentShield/blob/research-notes/docs/research-notes/contribution-history.md).

> **Verdict.** Not publishable at a main research track as it stands. The supportable outputs are an artifact (the guard, the
> stub-model runner, the committed rows and the scripts that regenerate every table) and a measurement note or workshop paper about
> what three coding-agent CLIs do with a hook's verdict.

Most of IntentShield is engineering over prior art. The regex rules, argument provenance, quarantine, rug-pull detection and the
rules-plus-judge design each have a published owner (the table is in section 2 of the
[history](https://github.com/Suhas-123-cell/IntentShield/blob/research-notes/docs/research-notes/contribution-history.md#2-every-mechanism-is-prior-art)). The learned detectors gave negative or null results and
are off by default or evidence-only ([detectors.md](detectors.md)).

## What is claimed, and the limit of each claim

1. **A versioned measurement of what Claude Code (27 scored builds), Codex CLI (14) and Gemini CLI (28) do with the verdict a hook returns.**
   - A `deny` was enforced on every build and in every mode where the hook ran. Whether the hook ran depended on state outside its
     reply: trust, matchers and flags.
   - An `ask` with nobody to answer it is handled three different ways, and one of them changed between two adjacent Claude Code
     releases (2.1.84 and 2.1.85). That sweep ran with Bash pre-approved; with nothing pre-approved the cell ran on one build only.
   - A hook that ran past its timeout (3 s in these cells) let the call run on 22 of 22 Claude Code, 12 of 12 Codex CLI and 1 of 1
     Gemini CLI builds. Claude Code's documented `onFailure: "block"` setting, which IntentShield's
     `install` writes, blocked it on one build, 2.1.316 (3 of 3 runs), and had no effect on 2.1.281 (2 of 2 RAN).
   - Account: [hook-fidelity-report.md](hook-fidelity-report.md). Scored builds are those whose neutral control ran the hook; the
     report's table gives installed, scored and excluded builds per harness.
   - *Limits:* a scripted stub model, headless runs, macOS only, one author, sampled builds, Cursor not measured, most behaviours
     already documented by the vendors, no attacker-reachable trigger shown. It measures the tools, not IntentShield. The coding was
     done by the same AI agents that ran the cells, and no second human coder exists (the report's Limits).
2. **Self-disclosure parameter stripping.** A malicious MCP server can ask the agent for its model name or system prompt through a
   tool parameter. IntentShield removes such parameters from the schema.
   - On the 159 distinct tool schemas the four MSB agents saw, it stripped 36 parameters, all on attack-role servers, and none of the
     194 parameters on the clean tools (95% upper bound 1.9%; [results/self-disclosure.md](../results/self-disclosure.md)).
   - *Limits:* this is an in-sample check, not a detection rate. The rule was written for the channel that MSB's attack servers use (a
     parameter such as `llm_model_name`), and it was added on 2026-10-09, after the MSB runner existed and in a commit that also
     changed the runner. So the 36 and the 0 show that the rule fires on MSB's template and not on its 86 clean tools. All 36 stripped
     parameters are of that kind. One benchmark's catalogs, and a renamed parameter with a neutral description would pass the rule.
3. **A trivial structural baseline that matches detector-based guards on MSB's executed harm.** A guard with no detection (withhold
   descriptions, strip self-disclosure fields, hold every mutation for review) also executes 0% harm, so that metric cannot rank guards;
   what detectors add is what reaches the reviewer. Tables: [benchmarks.md](benchmarks.md). *Limits:* an MSB property; it did not
   transfer to AgentDojo.
4. **One rule set behind four harnesses and a protocol proxy**, with a measured split of what each placement sees
   ([coverage-study.md](coverage-study.md)). *Limits:* engineering, not a research result; the mechanisms have prior art.

## What is not claimed

- Novelty of any mechanism, or of the finding that a hook-scoped guard misses some MCP channels (largely a consequence of the hook
  schemas, and a proxy that closes them partly does so by dropping the channel).
- That IntentShield detects more than other guards. On the author's 467 fixtures its hook is behind: it let through 137 of 166
  held-out harmful items before the built-in tool rules. On a second set of 214 calls, built by the same model family from the same
  six categories the rules were written from, it lets through fewer calls than safety-net and knox but trails safety-net on denies
  alone: 24 of 85 against 41 of 85 with the rules as they were when scored, and 29 of 85 with the rules in the repository now (the
  report's section 5). Nothing was tested outside those categories; the gain is post hoc and fits its own categories.
- That IntentShield beats published defences. The surveyed MCP guards publish no detection numbers to compare against, and on
  AgentDojo, the one benchmark where defences do publish, IntentShield's row (a 7B agent, 15.6% residual attack success, 5 of 32, from a
  local run whose rows are not committed) is far behind LlamaFirewall's published 1.75% with GPT-4o. So the claim is not "best performing".
- That any tool lets an attacker bypass a guard, or what a real model or a person at a terminal does at scale.
- That the hook study's expectations were fixed before the runs, beyond the author's statement: the commits that would show the order
  are not in `main`'s history, and the timestamps do not settle it (the report's Limits).

## The route that remains

An artifact or tool paper, plus the hook-fidelity measurement note. A research-track paper would need work that has not been done:

- a test of the built-in tool rules outside their six categories, with 30 to 50 harmful calls written by someone other than the
  author, committed first and scored once with the rules frozen;
- a second human coder on a sample of the deviation classes and documentation-based expectations, with an agreement statistic;
- a determinism run of the stub (six cells, twenty repeats, not under load) and a real-model arm on more than two builds;
- an order of writing that outsiders can check, such as a deposited hash of the expectations and kill criterion with an outside
  timestamp;
- a Linux or second-OS run of a real harness, and Cursor measured on a plan that allows it;
- a completed vendor disclosure (drafts exist; nothing has been sent).

[hook-fidelity-study.md](https://github.com/Suhas-123-cell/IntentShield/blob/research-notes/docs/research-notes/hook-fidelity/hook-fidelity-study.md), section 15, lists these with their costs.

## Where it stands among open-source MCP guards

<a id="121-where-it-stands-among-open-source-mcp-guards"></a>

On 2026-10-29 seven free, open-source MCP guards were compared in a table, and about six more were described from their own READMEs
only. Among the seven, IntentShield is the most broadly scoped keyless guard and the only MCP-specific one found
that publishes benchmark results and false-positive rates. That supports "broadly scoped and measured", not "best". The guards have
things IntentShield lacks: sandboxed server execution, masking of secrets in results, signed server packages and a trace-level
alignment check. A head-to-head run of another guard on IntentShield's corpora was not done. The table, the survey notes and the
architecture review are in the [history](https://github.com/Suhas-123-cell/IntentShield/blob/research-notes/docs/research-notes/contribution-history.md#121-where-it-stands-among-open-source-mcp-guards).

## Authorship and process

IntentShield is the work of one author, a student who wants to study AI at graduate level and work on cheaper, faster and safer AI
models.

What the repository and its documents show:

- The author set the goals and the working rules: security work stays defensive, claims are stated at what the evidence supports, and
  the budget is small. The author made the decisions to release and to merge.
- The code, the tests, the documents, the study runs and the reviews were produced with AI coding agents under the author's direction.
  [hook-fidelity-report.md](hook-fidelity-report.md) already says this for the hook study.
- No second human coder exists, so no agreement between coders can be reported.
- How much of the agents' work the author checked by hand is not documented, and this page claims nothing about it.

## Pointers

- The hook study, in order of length: [hook-fidelity-report.md](hook-fidelity-report.md) (read this), its
  [appendix](hook-fidelity-report-appendix.md) (denominators, per-build detail, caveats), then
  [hook-fidelity-study.md](https://github.com/Suhas-123-cell/IntentShield/blob/research-notes/docs/research-notes/hook-fidelity/hook-fidelity-study.md) (the full working record), and the data in
  [results/hook-fidelity/](../results/hook-fidelity/README.md).
- Numbers and limits of every other benchmark: [benchmarks.md](benchmarks.md).
- Literature and prior art: [related-work.md](related-work.md).
- Old section numbers (§5 why it is not publishable, §7 two routes, §9.5 the AgentDojo kill test, §12.1 the comparison table, §13 the
  hook study as it stood): [contribution-history.md](https://github.com/Suhas-123-cell/IntentShield/blob/research-notes/docs/research-notes/contribution-history.md).
