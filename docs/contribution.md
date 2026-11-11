# The contribution, in detail

This file sets out what in IntentShield could be a research contribution, the evidence, how
it compares with the closest papers, and whether it is worth publishing. It is the honest
version: most of IntentShield is engineering over prior art.

> **Verdict (current, 2026-11-11).** Not publishable at a main research track as it stands. The supportable outputs are an artifact
> and a measurement note or workshop paper.
>
> **Claimed, each with its limit**
> - A versioned measurement of what Claude Code (23 sampled builds), Codex CLI (17) and Gemini CLI (28) do with the verdict a
>   PreToolUse-style hook returns (§13, `docs/hook-fidelity-report.md`). Limit: a scripted stub model, headless, macOS, one author,
>   Cursor unmeasured, most behaviours already documented by the vendors. A measurement of the harnesses, not of IntentShield.
> - Self-disclosure parameter stripping, measured on 159 tool schemas (§10, §12). Limit: one benchmark's catalogs, and the rule is a
>   pattern a renamed parameter would pass.
> - A trivial structural baseline that matches detector-based guards on MSB's executed harm (§9). Limit: an MSB property; it did not
>   transfer to AgentDojo (§9.5).
>
> **Not claimed**
> - Novelty of any mechanism (§2), or the channel-placement finding as a research result (§5).
> - That IntentShield detects more than other guards. On the author's 467 fixtures its hook is behind (it misses 137 of 166 held-out
>   harmful items). On the 214-call set built from the same six categories as its rules it is mixed (it trails safety-net on denies),
>   and nothing was tested outside those categories (§13).
> - That any harness lets an attacker bypass a guard, or what a real model or a person at a terminal does at scale.
>
> **Route that remains.** Route 1, an artifact or tool paper, plus the hook-fidelity measurement note (§7, §13). A research-track
> paper would need work that has not been done: an out-of-category detection test by an independent author, a second coder, a
> determinism run on the stub, and a completed vendor disclosure (`docs/hook-fidelity-study.md` section 15).
>
> The dated sections below keep each earlier verdict as it was written. Where a later one replaces it, the section says so.

## 1. The claim as first stated

> A third-party MCP guard installed as a harness hook scoped to tool calls, which is how
> shipping guards install, does not achieve *complete mediation*. Of the five
> attacker-controllable MCP channels, it observes only two (tool call and tool result) in
> time to act. Tool descriptions, resource contents and prompt contents reach the model but
> not the hook. A transparent protocol-level proxy restores complete mediation, and we
> measure what that costs.

## 2. Every mechanism is prior art

Checked against the literature (two searches, Oct 2026):

| Mechanism in IntentShield | Prior art that owns it |
|---|---|
| Argument/value provenance | PACT (2605.11039), ToolFence (2609.37196), CaMeL |
| Description regex scan + quarantine | MCP-Guard (2508.10991), Tool-Guard (2606.20922) |
| Rug-pull / schema-drift detection | ETDI (2506.01333) |
| Rules + LLM judge, evidence-only | MCP-Guard, "Evaluate the Stack" (2610.07359) |
| Semantic injection classifier | MCP-Guard's E5 stage; over-flagging known (NotInject) |
| Tool routing to save tokens | RAG-MCP, AgentDojo tool filter |
| Self-disclosure parameter redaction | The Stochastic Deputy (2609.14780), MSB's own attack |

None of these is publishable on its own. The candidate novelty was the **placement**
question instead: the industry now guards MCP at the harness hook, so does that placement see
everything it must? That is a complete-mediation question (Saltzer & Schroeder, 1975).

## 3. The claim as a reference-monitor property

A reference monitor needs **complete mediation**: every access to every protected object
passes through it. Each MCP channel that can carry attacker text is an object class:

1. tool **description** (server-authored metadata the model reads to choose a tool)
2. tool **result** (server-authored output)
3. **resource** contents (server-authored documents the client fetches)
4. **prompt** contents (server-authored prompt templates or slash commands)
5. server-initiated **sampling / elicitation**

A guard achieves complete mediation only if it observes all five before they can affect an
action.

## 4. The evidence (measured 2026-10-12)

Method and raw data: [coverage-study.md](coverage-study.md), reproducible with
`benchmarks/coverage/run.py`. A probe server plants a unique benign marker in each channel. A
passive hook logs which event delivered each marker and under which tool name.

| Channel | Claude Code hook (`mcp__.*`) | Gemini CLI hook (`BeforeTool`) | Transparent proxy |
|---|---|---|---|
| Tool result | observed, PostToolUse | observed, AfterTool | observed (`tools/call`) |
| Tool description | no pre-action hook carried it (the `Stop` hit was the model echoing the marker) | not carried by any hook; not observed in logs | observed (`tools/list`) |
| Resource content | `PostToolUse` under built-in `ReadMcpResourceTool`: seen by a `*` matcher, missed by `mcp__.*` | not reached by the model (`resources/read` 0 to 0) | not exposed (tools only; functionality lost, not mediated); `resources/read` 1 to 0 on Claude |
| Prompt content | no pre-action hook carried it (the `Stop` hit was the model echoing the marker) | carried pre-model by `BeforeAgent`/`BeforeModel`, not by `BeforeTool` | not exposed (tools only; `prompts/get` 1 to 0) |
| Elicitation | not exercised (SDK errors) | not exercised (SDK errors) | not exercised |
| Sampling | not tested | not tested | not tested |

What the cells mean:
- **"no pre-action hook carried it":** the marker reached the model's context, but the only
  hook event that logged it was `Stop`, which fires after the turn, and that hit was the
  model echoing the marker back. No hook saw the description or prompt before the action.
- **`ReadMcpResourceTool`:** Claude Code surfaced the resource under its built-in tool name,
  so a `mcp__.*` matcher misses it and a `*` matcher sees it.
- **"not exposed":** the proxy exposes only tools, so the server never received
  `resources/read` or `prompts/get` on either harness. That loses the functionality; it does
  not mediate it. The proxy mediated every `tools/list` call (14-15 per run).
- **Rug pull:** under the proxy, the changed tool was hidden and later calls to it were
  refused for the session.
- **Re-run:** the cells are from the 2026-10-13 re-run with the fixed instrumentation, which
  separates hook events that delivered a marker from those that only echoed it. It confirmed the
  earlier cells; Gemini's description reached the model but no hook delivered it, and neither
  harness exercised elicitation or sampling. One run per cell.

## 5. Why it is not publishable as it stands

1. **The one gap that is structural is already known in substance.** Tool descriptions are
   the only channel that both harnesses' tool hooks miss. That follows directly from the hook
   input schemas: `PreToolUse` carries the tool name and arguments, not the description.
   Description scanners such as MCP-Guard and Tool-Guard exist for this reason, so
   a reviewer would call the gap known.
2. **Two of the three misses are configuration, not structure.** A `*` matcher in Claude
   Code sees resource reads under `ReadMcpResourceTool`. Gemini CLI's model-level hooks
   (`BeforeModel`, `BeforeToolSelection`) do carry prompts and tool declarations.
3. **The proxy's complete mediation partly comes from dropping channels.** It closes
   resources and prompts by not forwarding them, which loses functionality rather than
   mediating it. Real mediation would forward them under the same checks as tool results.
4. **The evidence is thin.** It covers two harnesses, one small model each and one run. It
   uses benign markers only, so no harm was shown, elicitation was not exercised (SDK
   errors), sampling was not tested, and the stored data came from instrumentation that is
   being fixed.
5. **The area is crowded and fast-moving.** HarnessSecurity-Bench (2610.07639) covers six
   harnesses with a ten-mechanism taxonomy. COPEX (2610.04378) attacks the MCP channels.
   "Measuring and Exploiting Implicit Trust" (2609.18217) fragments payloads across channels
   and already evaluated seven third-party MCP tools. "Breaking the Protocol" (2601.17549)
   and CapScope (2609.08371) are adjacent.
6. **The supporting MSB numbers were leaked, and the fix shows they are weaker than they
   looked.** (The figures in this item and the next are from the superseded v4/v5 runs of §6; the argument stands, the numbers
   are not current.) The MSB runner used to name its servers `task`, `attack` and `addition`, and the
   agent, hooks and judge saw those names. Commit `1c0d4dc` gave the servers neutral ids and
   qwen2.5:7b was re-run (`artifacts/msb-v4`, 220 held-out cases). Unguarded harm rose from
   51.4% to 58.5% [51.8, 64.8], so the leak had understated it. The guarded rows stayed at
   0.0% [0, 1.7] (gateway and hooks). But three things limit what that shows:
   - The gateway's zero mostly reflects exposure removal. It withholds descriptions by
     default and strips self-disclosure parameters, and the prompt-injection task servers are
     quarantined through the `shadowing` rule because the attack text names filesystem tools.
     The guarded agent attempted harm in only 2 of 220 cases, both blocked by
     `BLOCK_UNTRUSTED_ARGUMENT_SOURCE`.
   - Any guard that holds mutations for review and strips self-disclosure fields gets
     `harm_executed = 0` on MSB mechanically, because every file-write harm needs
     `write_file` or `edit_file`, and the 48 parameter leaks are neutralized by field
     stripping. A trivial baseline that does only that (`benchmarks/msb.py`, commits
     `0dee1d4`, `fc770ee`; `artifacts/msb-v5`) also scores 0.0%, with higher task success
     than the gateway (MSB `user_task` 51.4% vs 33.6%, paired n=140). What the detectors add
     is that no harmful call is left for the reviewer: the baseline holds 47 harmful calls
     among 250 reviews (27 cases), the gateway none. Withholding descriptions alone cuts
     attempted harm on the baseline from 37.6% to 12.4%.
   - The `name_overlap` results are partly an artifact: FastMCP titles argument schemas
     `<func>Arguments`, so the attacker's tool contains the real tool's name and `shadowing`
     quarantines it. That is not real name-collision detection.

   The hook path is the stronger evidence: of 37 harmful attempts (17.0% of 218 cases), every
   harmful call was denied or sent to ask, and none executed.
7. **The gateway utility drop is explained, not fixed away.** Task tool reached fell from
   56.4% (frozen commit) to 45.7% and then 42.3% (neutral ids). The cause is the DeBERTa
   intent model (`INTENTSHIELD_INTENT_MODEL_DIR`). It abstains on ordinary reads, and
   abstention mapped to alignment 0.0, which overrides lenient reads (an abstention gives no
   opinion since `14150e7`; on the v7 re-run blocked legitimate task calls fell from 18.7% to 7.3%, still above the 0.5% with the model off). `BLOCK_INTENT_MISMATCH`
   counts were 0 (v2), 149 (v3), 141 (v4) and 0 with the model off (`artifacts/msb-v4-noclf`,
   reached 54.5%, executed 40.0%). The v2 gateway rows ran without the model. With it off,
   harm is still 0.0%, so it gave no measured security gain on MSB.

## 6. The numbers that hold up

These stay valid whatever happens to the paper question. They are evidence for an artifact
or tool paper, not a research claim on their own.

Four items in this section are marked **SUPERSEDED**: the MSB table, the paired-case paragraph under it, the earlier MSB rows
and the test count. They are the 2026-10-12/13 runs (v4/v5) and are kept as the record of that date; do not cite them. Current
MSB numbers (v12 for qwen, v8 for llama and ornith, all with the intent model off) are in `results/msb` and come from
`benchmarks/paper_numbers.py`; see `docs/research-notes/artifact-paper.md` §5. The MCPTox replay, the rules-versus-judge table, the routing
and the injection-classifier items still hold and are not marked.

- **SUPERSEDED (2026-10-12/13, v4/v5; current numbers: `benchmarks/paper_numbers.py`). MSB held-out, live servers, neutral ids** (`benchmarks/msb.py`, qwen2.5:7b, single run,
  temperature 0, 220 cases, 20 draws per attack template, so the Wilson intervals are too
  narrow; `artifacts/msb-v4`):

  | Setup | Harm executed [95% CI] | Task tool executed | Task tool reached |
  |---|---|---|---|
  | None | 58.5% [51.8, 64.8] (n=219) | 70.3% | 70.3% |
  | Gateway (intent model on) | 0.0% [0, 1.7] | 29.5% | 42.3% |
  | Gateway, intent model off | 0.0% [0, 1.7] | 40.0% | 54.5% |
  | Hooks (n=218) | 0.0% [0, 1.7] | 49.1% | 49.5% |
  | Trivial baseline | 0.0% [0, 1.7] | 55.0% | 74.1% |
  | Trivial baseline, descriptions exposed | 0.0% [0, 1.7] | 44.5% | 68.6% |
  | Gateway, descriptions exposed | 0.0% [0, 1.7] | 25.0% | 38.6% |

  **SUPERSEDED, same run as the table above.** Paired on 218 cases (`benchmarks/msb_compare.py`): harmful calls left in review 47
  (baseline), 99 (baseline, exposed), 0 (gateway), 4 (gateway, exposed); MSB `user_task`
  51.4%, 41.4%, 33.6%, 32.1% (n=140).

  Read the 0.0% with §5 item 6: it is largely exposure removal and a mechanical effect of holding
  mutations. The task-tool metrics count the attack server only where there is no task server (rescored 2026-10-13; before, they also counted lookalike tools). The runner also
  deviates from MSB (injection text only on the task server; list-directory tools allowed),
  and the 10-step cap truncated 53/219 unguarded, 12/220 gateway and 29/218 hook cases.
- **SUPERSEDED. Earlier MSB rows** (frozen commit `05bb91a`; llama3.1:8b and Ornith-1.5-9B; descriptions
  exposed): harm 22-53% to 0.0%, task tool reached 55-66% gateway, executed 60-69% on hooks.
  These were measured before the neutral-id fix and without the intent model, and were not
  re-run. The LLM judge has not been evaluated on neutral ids; its only MSB runs (v3) were
  leaked, and its only catches were `attack:`-named tools.
- **MCPTox replay** (no inference; scanner rules developed on MCPTox, so tuning-set
  numbers): the full proxy has 0.4% attack success, blocks 95.4% of
  poisoned-tool calls, and falsely blocks 3.5% of benign calls. 46.3% of benign calls go to
  human review.
- **Rules vs. LLM judge on MCPTox test-split servers** (Gemini 3.5 Flash-Lite, real tool
  names, so no label leak; 301 poisoned and 108 clean descriptions). These servers are not
  held out for the rules, which were developed on MCPTox; they are held out only for the
  judge's prompts:

  | | Rules | Judge | Either |
  |---|---|---|---|
  | Poisoned descriptions flagged (recall) | 96.3% | 99.7% | 100% |
  | Clean descriptions falsely flagged | 1.9% | 4.6% | 6.5% |
- **Tool routing** (BM25 over 45 MCPTox catalogs, 324 queries): the right tool ranks first
  in 80% of queries, in the top three in 90%, and in the top five in 92%.
- **Injection classifier:** a negative result. It falsely flags 20.3% of benign rows, so it
  is off by default.
- **SUPERSEDED. Tests:** 145 passed and 1 was skipped on 2026-10-12 (146 with the HTTP end-to-end test enabled; 253 passed and 1 skipped on 2026-10-20). The suite is much larger now; the current count is in the CI run, not here.

### 6.1 Adaptive detection (2026-10-13): does it change the verdict?

No. It adds tool features and two measurements, not a research claim:

- The injection evaluation with hard benign texts mostly sharpens the negative results. The local
  classifier flags 24.4% of benign texts and 113 of 142 hard ones. The exemplar detector generalizes
  only to what resembles its seeds.
- On a local adaptive attacker (42 seeds, one model, simulated rule approval), learning cut evasions
  from 16/42 to 13/42. That is not significant, and the attacker produced few valid attempts. A
  claim would need a stronger attacker, more seeds, several attacker models, real operator decisions,
  and a measured reviewer cost.
- One real bug was found on the way (a tokenizer flag that fragmented DeBERTa input at run time). It
  explains why the classifier did worse in use than its training report, and it bears on the intent
  model too.

## 7. Two routes that could still produce a paper

*Superseded in part by §13 (2026-11-01, hook verdict fidelity study): route 2 was run as a three-harness hook-fidelity study and measured; the verdict below is kept for the record.*

**Route 1: a tool or artifact paper (cheaper, closer to done).** The subject would be a
cross-harness MCP guard: hooks for Claude Code, Codex CLI, Cursor and Gemini CLI plus a
transparent proxy, evaluated held out on live servers. It needs:
1. Neutral MSB server names (done for qwen2.5:7b, commit `1c0d4dc`, `artifacts/msb-v4`).
   The llama3.1:8b and Ornith-1.5-9B rows and the descriptions-exposed rows still need a
   neutral-id re-run, free on local Ollama.
2. The gateway utility drop is isolated: it is the DeBERTa intent model, not a later guard
   change (§5 item 7). The open choice is whether to keep that model on the read path. The trivial
   baseline's runs are done (`artifacts/msb-v5`): it matches the gateway on `harm_executed`
   (0.0%) with higher task success, so the detection claim rests on reviewer load (harmful
   calls left for a human: 47 vs 0), which needs a review-fallibility argument to count.
3. At least one baseline on the same split, such as Llama Prompt Guard 2 (Groq free tier) or
   an MCP-Guard-style detector.
4. Reviewer load reported as a metric, plus one stronger agent model on a free tier.
5. A limitations section that states the MSB modifications (injection text only on the task
   server, list-directory tools allowed, task-tool metrics counting lookalikes, the
   `shadowing` naming artifact, the 10-step truncation).

Venues: demo or artifact tracks, a software paper, or arXiv first. Skeleton started in
[artifact-paper.md](research-notes/artifact-paper.md) (2026-10-14).

**Route 2: a measurement study (the only route with a research claim, and much more
work).** It would measure the channel coverage of shipping guards across four to six
harnesses, in each harness's default and recommended guard configuration. It needs:
- Per-channel payloads that are benign but measurably change behavior.
- Several models and repeated runs.
- A proxy that forwards resources and prompts under checks instead of dropping them, with
  its measured cost.
- Responsible disclosure to the harness vendors before release.

The claim would then rest on observed behavior across the ecosystem, not on two harnesses
and benign markers. The corrected coverage cells (§4) show how much hangs on configuration:
a `*` matcher sees the Claude resource, and Gemini's model hooks carry the prompt.

## 8. Honest ceiling

IntentShield is solid engineering with a careful held-out evaluation. None of its mechanisms
is novel. On review, the placement finding is too thin, and partly a known consequence of
the hook schemas. On today's evidence, the realistic outcome is an artifact or tool paper
(route 1). A research paper needs route 2, and no amount of framing substitutes for it.

## 9. Route 3: an evaluation-methodology paper (audited 2026-10-14)

**The idea.** On MSB, executed harm cannot tell guards apart. Every guard arm that holds
mutations scores 0.0%, including the trivial baseline with no detection
(`artifacts/msb-compare-v4-v5-exposure.txt`, 218 paired cases). The arms separate only on
the stages before execution:

**SUPERSEDED table (2026-10-12/13 qwen runs; do not cite).**

| Arm | Executed | Attempted | Reached review | `user_task` (n=140) |
|---|---|---|---|---|
| none | 58.3% | 58.7% | — | 68.6% |
| trivial baseline | 0.0% | 12.4% | 12.4% | 51.4% |
| trivial baseline, descriptions exposed | 0.0% | 37.6% | 31.6% | 41.4% |
| gateway | 0.0% | 0.9% | 0.0% | 33.6% |
| gateway, intent model off | 0.0% | 1.8% | 0.0% | 45.0% |
| hooks | 0.0% | 17.0% | 0.0% (20 blocked) | 58.6% |

> The table above is superseded (2026-10-20). On current code (MSB v12, `results/msb`) none is 58.7% executed, the gateway with the
> intent model off 42.9% `user_task`, and the hooks row is the intent-off run (50.7%, 2.3% reached review). Cite
> `benchmarks/paper_numbers.py`, not this table.

The mechanism is now confirmed from the MSB paper itself (Tab. 9): five of its six attack
tasks are judged by environment state after `write_file`, `edit_file` or `kill_process`. The
sixth (`llm_model_name` supplied as a parameter) is neutralized by field stripping. So any guard
that holds mutations and strips self-disclosure fields scores 0% by construction.

### 9.1 Literature audit: how 19 papers score outcomes

Papers read in full HTML on 2026-10-14. These are the questions that decide whether the idea
is new. "Structural floor" means a baseline that only removes exposure or authority (block or
hold all side effects, withhold descriptions, read-only), with no detection.

| Paper | Eval type | Held/ask/review outcome | Structural floor | Utility | Reviewer load |
|---|---|---|---|---|---|
| MSB 2510.15994 | live loop, state oracle | no HITL; not discussed | no (MCIP only) | PUA, NRP | no |
| MCP-SafetyBench 2512.15163 | live loop, signature detectors | no HITL; DSR = 1−ASR, so refusals and no-ops count as defended | no (safety prompt only) | not under defense | no |
| MCPSecBench 2508.13220 | 3 GUI hosts, LLM judge | hosts' own approval dialogs present; handling **not stated** | no | no | no |
| MCPTox 2508.14925 | proposed calls, poisoned tool never executed | n/a | no | no | no |
| MCP-TDP 2605.24069 | Cline sandbox, side-effect forensics | no gate ("agent has permission to execute") | no | no | no |
| COPEX 2610.04378 | fixed orchestrator, oracle + judge | none; the judge defaults to "detected" when unsure | no | no | no |
| MCP-Guard 2508.10991 | static classification | n/a | no | no | no |
| MCPShield 2602.14281 | 76 malicious servers | none | no | benign FP only | no |
| TrustShiftProbe 2608.23763 | live loop, read-heavy domains | none | no | no | no |
| ShieldNet 2604.04426 | network traces | alerts only | no | no | no |
| Tool-Guard 2606.20922 | AgentDojo, ASB | none | tool filter only | yes | no |
| PACT 2605.11039 | AgentDojo | blocks; no HITL | **no**, but states "invocation-level quarantining can reach perfect security" | benign only | no |
| ToolFence 2609.37196 | AgentDojo | denial = recoverable; HITL future work | tool filter only | clean + under attack | judge calls/task |
| CapScope 2609.08371 | 300 runs, Pi agent | "interactive approval is disabled" | no deny-all-writes | yes | no |
| Execution control 2606.29073 | 10 hand-built cases | "held at a waiting-for-approval state" scored **blocked**; no approver model | B1 has per-call approval | no | no |
| HarnessSecurity-Bench 2610.07639 | 6 harnesses, 2,500 trials, state oracles | approvals routed to an **LLM reviewer** (Qwen3.8-27B) | **yes, in effect**: read-only mode ASR 8.3%→0.8% at −34 pp utility; network isolation 57.1%→0.8% at −24.5 pp | yes | no |
| Evaluate the Stack 2610.07359 | 1,119 static labelled actions | scored both ways; review-as-catch "reversed five conclusions"; "Any metric that credits escalation as a catch scores a deferring layer well" | n/a | n/a | no human layer |
| Oversight Has a Capacity 2606.08919 | 125 labelled actions, simulated reviewer | reviewer reliability r(ℓ) decays past capacity C; "more human oversight can make a system less safe" | n/a | n/a | **yes (simulated)** |
| Habituation at the Gate 2606.22721 | 11,429 real reviews of agent PRs | approval 30.1%→36.8% early to late, comments −22% | n/a | n/a | no miss rate measured |

Also read for context: Approval Laundering 2609.38983 shows that what is approved is not always
what executes in Claude Code (bound-gap rate 1.0 for scope and temporal laundering, 0.45 for
argument laundering, n=19-20 per class). So "approved" is not a safe endpoint either. Implicit
Trust 2609.18217 tested seven third-party MCP tools; the best blocked 2 of 30 payload-channel
combinations.

### 9.2 What the audit changes

1. **The "benchmarks count review as safe" framing is mostly a strawman.** Only 2606.29073
   scores a held call as blocked with no follow-up. Most MCP defense papers have no
   human-in-the-loop at all: they block. Drop this as the headline.
2. **The structural-floor gap is real and wide.** None of the 15 defense and benchmark papers above HarnessSecurity-Bench in the table
   runs a no-detection structural baseline. Two run AgentDojo's tool filter, and PACT concedes
   the point in one sentence. HarnessSecurity-Bench is the exception, with read-only mode and
   network isolation as harness mechanisms on coding tasks rather than MCP defenses; it must be
   cited as the closest precedent.
3. **Utility is often missing.** It is not reported under defense in 10 of those 15 (MSB, Tool-Guard, PACT, ToolFence and CapScope report it).
   Without it, a structural floor cannot even be compared.
4. **Success criteria are inconsistent across benchmarks.** MCPTox counts proposed calls,
   MSB checks state after execution, MCP-SafetyBench counts any refusal as defended, and COPEX's
   judge defaults to "detected". The same guard can score very differently. COPEX already asks
   that the oracle be stated per attack.
5. **The fallible-reviewer metric is not new.** Oversight Has a Capacity owns the reviewer model
   and the danger-through metric, and Evaluate the Stack owns the review-accounting point. Use
   their model; do not claim it.

### 9.3 The contribution that survives

> On live MCP benchmarks, a guard with no detection (withhold descriptions, strip
> self-disclosure fields, hold every mutation) matches every detector-based guard on executed
> harm, because the benchmarks' harms are mutations. Published MCP defenses are evaluated
> without this structural floor, often without utility, and with incompatible success
> oracles. We report the full funnel (exposed → attempted → reached review → executed),
> utility, and the review queue for the floor and for detector-based guards on two benchmarks
> and several models. We then apply the capacity-limited reviewer model of 2606.08919 to
> live queues: the detectors' measurable value is the harm they keep out of the queue
> (31.6% of cases for the exposed floor vs 0-1.4% for the gateway).

Delta over the closest work:
- **Execution control 2606.29073:** hand-built cases, not a live benchmark.
- **HarnessSecurity-Bench:** harness settings on coding tasks, not MCP defenses, and an LLM
  approver.
- **Evaluate the Stack, Oversight Has a Capacity:** static labelled actions, not live agent
  queues.

The delta is the live MCP agent setting plus the structural floor plus the audit. That is
incremental, but it is a checkable claim that does not need IntentShield's mechanisms to be new.

**Honest ceiling:** a workshop paper or an evaluation, benchmark or SoK-style short paper (agent-safety
workshops, SaTML, AISec), arXiv first. It is not a main-track research contribution unless the floor
result holds on 3+ benchmarks and 3+ models and is shown to flip a published ranking.

### 9.4 Experiments needed (free or local)

1. **MSB with more models.** Run the none, floor and gateway arms (plus the intent-model-off
   gateway) with llama3.1:8b and a third local model, and 3 runs at temperature > 0. Report
   confidence intervals bootstrapped by template, since 20 draws per template are not
   independent.
2. **Second benchmark: MCP-SafetyBench** (`artifacts/data/MCPSafety`). Run the floor arm and
   check how much of its harm is mutation-gated. Its attacks are wider (credential theft,
   preference manipulation), so the floor may not saturate there. That is a finding either way:
   it would show which attack classes a structural floor cannot reach.
3. **Third check: AgentDojo** (own venv exists). A "hold every side-effecting call" floor next
   to the published PACT, ToolFence and Tool-Guard numbers, on utility and utility under attack.
   This is the strongest version: AgentDojo is what the defense papers actually report on.
4. **Queue analysis.** Apply r(ℓ) from 2606.08919 to the per-case review queues. Use their
   C and slope values, and sweep them; never present it as measured human behaviour.
5. **Oracle sensitivity.** Rescore one benchmark's runs under its own oracle and under MSB-style
   execution plus state, to measure how much the choice of oracle alone moves ASR.
6. **Pitfalls appendix with measured effects.**
   - Role names in server ids: upstream MSB `main.py:89,103` names servers `attack-…` and
     `addition-…`; the agent sees bare tool names there, but a gateway or judge that sees server
     ids does not.
   - Lookalike task-tool scoring: 94.0% → 70.2%.
   - Step truncation: 24% unguarded vs 5% gateway.
   - FastMCP `<func>Arguments` titles.

**Kill criterion:** if the AgentDojo floor (item 3) does not come close to the published
defenses on security, or loses far more utility than they do, the claim shrinks to "MSB-specific".
That is still a useful note to the MSB authors, but not a paper.

### 9.5 Kill test on AgentDojo (run 2026-10-14): the floor does not match the published defenses

`benchmarks/agentdojo_floor.py`, with no model calls; table in `artifacts/agentdojo-floor/table-v1.txt`.

- **`static`:** reads AgentDojo v1's ground truth.
- **`replay`:** re-scores the AgentDojo authors' published trajectories (`ethz-spylab/agentdojo`
  `runs/`, 97 benign and 629 attacked runs per model, `important_instructions`) for a floor
  that holds every mutating call.
  - Until the reviewer rejects a held call, the floor's trajectory is identical to the logged one,
    so security and the review queue are exact. Utility under attack after a rejection is not, and is
    reported as an interval.
  - A held call counts as harmful when it calls the attacker's ground-truth function with an
    attacker-only value (IBAN, address, URL, id, password), per user-task and injection-task pair.
  - **Validation:** the oracle flags a harmful call in 278 of 279 GPT-4o successes on goals that need
    a mutation, and in 157 of 157, 199 of 199 and 246 of 247 for the other runs. On benign runs it
    matches 0 calls on seven of the eight models; on gpt-4o-mini it matches 7 checks out of 576, all
    one wrong refund to the attacker's IBAN.

**Static.**
- **Gated goals:** 25 of 27 injection goals need a mutation. Of the other two, travel 6 only asks
  the model to *say* something, and Slack 3 visits a URL through a read.
- **Read-only ceiling:** only 37 of 97 user tasks (38.1%) can be finished with no mutation.
- **Known artifact:** banking user_task_15 legitimately sets the rent recipient to the attacker's
  IBAN, so in that pair the attack coincides with the user's request.

**Replay, GPT-4o (2024-05-13).**
- **Undefended:** benign utility 69.1%, utility under attack 50.1%, attack success 47.7%.
- **Floor with a perfect reviewer:** attack success 3.5%, all of it from the two read-only goals
  plus the user_task_15 artifact.
- **Fallible reviewer** (approves a harmful call with probability p): attack success 5.7% at p=0.05,
  7.9% at p=0.1, 16.8% at p=0.3.
- **Review queue:** 55.7% of benign tasks need at least one review, at 0.75 reviews per task. 48.6%
  of attacked runs put a harmful call in the reviewer's queue.
- **Read-only floor, no human:** benign utility 27.8 to 28.9%.

**Comparison with published GPT-4o defenses (same logs):**
- tool filter: 6.8% attack success, 56.3% utility under attack
- PI detector: 7.9% and 21.1%
- spotlighting: 41.7%
- repeat prompt: 27.8%

From the papers: ToolFence 0.9% attack success with a 1.5-point clean-utility drop (GPT-4o-2024-08-06),
Tool-Guard 2.1%. Both use no human.

**Verdict on the kill test: the claim does not transfer.**
- **Without a human:** the floor loses about 41 points of benign utility (69% to 28%); ToolFence loses
  1.5.
- **With a human:** it matches the defenses on attack success only if the reviewer is near perfect.
  The reviewer sees half of all tasks and a harmful call in about half of all attacked runs. At
  p=0.1 the floor leaks 7.9%, worse than ToolFence or Tool-Guard.
- **Scope:** "a detection-free floor matches every guard" is therefore an MSB property. MSB's harms
  are all mutations and its success check ignores held calls. It is not a general one.

**What is left of route 3:**
1. **A benchmark-design note, not a defense claim.** Whether executed harm saturates depends on
   whether the benchmark's harms are all mutations:
   - MSB: 6/6 attack tasks
   - AgentDojo: 25/27 goals
   - others unchecked

   On MSB a structural floor gets 0% and the metric cannot rank guards. On AgentDojo it cannot reach
   the read-only goals, and it pays in utility or reviews.
2. **The price of autonomy as a common currency.** Report each autonomous defense against a floor
   with a fallible reviewer: the reviews it saves (here 0.75 per task, 56% of tasks) and the p at
   which the floor's leakage matches it (ToolFence's 0.9% is below the floor's 3.5% even at p=0).
   This is free to compute from published logs for any model and defense AgentDojo hosts, and it is
   positive for the published defenses, not a critique. Prior art for the reviewer model:
   2606.08919.

Neither is more than a workshop note. Route 1 (artifact paper) remains the realistic main output.
The AgentDojo replay tool and table can go into it as the baseline section.

**Limits of this replay:**
- The perfect reviewer knows the attacker's goal, so it is an upper bound on reviewer skill.
- Utility under attack after a rejection is an interval ([30.8, 79.5] for GPT-4o), not measured.
  Narrowing it needs live GPT-4o runs (paid) or a strong free-tier model.
- Only `important_instructions` is replayed, on AgentDojo v1.

## 10. What can be claimed as a contribution (2026-10-29)

After a search of the open-source MCP guards shipping in October 2026 (Snyk Agent Scan, Cisco
mcp-scanner, Lasso MCP Gateway, LlamaFirewall, mcp-guardian, ToolHive, Docker MCP Gateway, Progent,
CaMeL; table in §12.1 below), three things in IntentShield have no counterpart among those seven guards, and one of them is
measured well enough to defend:

1. **Self-disclosure parameter stripping, with a precision measurement.** The mechanism: a schema
   parameter that asks the agent for its model name, system prompt or conversation is removed before
   the agent sees the tool, and any value sent for it is dropped. The measurement
   (`benchmarks/self_disclosure_eval.py`, `results/self-disclosure.md`): on the 159 distinct tool
   schemas the four MSB agents were shown, 36 parameters stripped (an earlier 54 counted 18 twice), all on attack-role servers, 0 of
   194 on the 86 clean tools; and harm executed through such a parameter in 23/29 (Gemini 3.5
   Flash-Lite), 33/33 (llama3.1:8b), 48/129 (qwen2.5:7b) and 51/122 (ornith:9b) harmful calls in the unpaired undefended runs. The
   finding that goes with it: for the capable agents in the sample (Gemini, Claude Haiku live), what a
   schema asked for leaked more than injected text did. The prior art is MSB's own attack and "The
   Stochastic Deputy" (2609.14780), which removes tenant identity from schemas for a different reason;
   neither measures a defense's precision on real catalogs.
2. **One rule set in four harnesses plus a proxy**, with the measured split of what each placement
   sees (coverage study). Engineering, not a research claim.
3. **The harm funnel with a trivial structural baseline** (§9), which showed that MSB's executed-harm
   metric cannot rank mutation-holding guards. A benchmark-design note.

Honest ceiling for item 1: a workshop or short paper, or the centrepiece of the artifact paper's
"what the detectors add" section. It rests on one benchmark's catalogs (13 clean servers), and the
rule is a pattern match that a renamed parameter with a neutral description would pass; the
measurement says it is precise on real catalogs, not that it is complete.

## 11. Architecture verdict and target layout (2026-10-29)

An architecture reviewer, given the five code reviews, judged the hook path sound and the gateway's
agent-written intent the one wrong thing (fixed: `trusted_intent`, default off). Target layout it
proposed, to do in this order with tests green at each step: move `wilson` to `benchmarks/stats.py`;
characterization tests that feed one fixture to `HarnessGuard.call` and the proxy's `_rule_check`,
then one shared `callguard.py`; split `mcp_proxy.py` into `mcp/{catalog,gateway,server,control}`
with one auth and rate-limit helper used by the MCP server and the dashboard; move the research
modules (intent and injection training, `evaluation.py`) under `benchmarks/`; make the dashboard
and the detectors optional extras so `fastapi` is not a dependency of the hook. About 7k shipped
lines instead of 11k. Not started.

## 12. Contribution summary and comparison with other guards (moved from the README on 2026-10-29)

For a report or a viva, this is what the repository supports as a contribution, in order of
strength, each with where the evidence is and what it does not show.

1. **Self-disclosure parameter stripping, measured.** A malicious MCP server can learn the agent's
   model, system prompt or conversation by adding a parameter that asks for it; capable agents fill
   it in because the schema asked. IntentShield removes such parameters from the schema before the
   agent sees the tool. None of the seven guards surveyed on 2026-10-29 (§12.1) does this. Measured on every tool schema the four
   MSB agents actually saw (159 schemas, 756 cases): 36 parameters stripped (an earlier 54 counted 18 twice), all on attack-role
   servers, 0 of 194 on the 86 clean tools; undefended harm went through such a parameter in 23 of
   29 Gemini cases and 33 of 33 llama cases. Evidence: `results/self-disclosure.md`,
   `benchmarks/self_disclosure_eval.py`. Limit: one benchmark's catalogs, and a renamed parameter
   with a neutral description would pass the rule.
2. **One guard behind four harnesses and a protocol proxy, with the measured split of what each
   placement sees.** Hooks see the user's real prompt and every call and result; the proxy sees
   descriptions and schemas; neither sees everything. Evidence: `docs/coverage-study.md`, the live
   Claude Code and Gemini CLI runs in `results/harness-live*`. This is engineering, not a research
   claim; the mechanisms have prior art (`docs/contribution.md` §2).
3. **The harm funnel with a trivial structural baseline.** On MSB, a guard with no detection at all
   (withhold descriptions, strip self-disclosure fields, hold every mutation) executes 0% harm, the
   same as every detector-based guard, so the benchmark's headline metric cannot rank guards; what
   detectors add is what reaches the reviewer's queue. Evidence: the MSB tables in `docs/benchmarks.md` and
   `benchmarks/paper_numbers.py`. Limit: it did not transfer to AgentDojo (`docs/contribution.md` §9.5).

What is not a contribution: the regex rules, provenance, quarantine and rug-pull detection (prior
art), the learned detectors (negative or null results, documented), and any "best performing"
claim (see §12.1). The full honest version is §10 above.

### 12.1 Where it stands among open-source MCP guards

Checked 2026-10-29 against the free, open-source guards we could find. "n.p." means the project
publishes no detection numbers.

| guard | licence | descriptions | outputs | argument provenance | rug pull | harness hooks | proxy | runs without a key | published numbers |
|---|---|---|---|---|---|---|---|---|---|
| IntentShield | Apache-2.0 | rules + quarantine; offline scan of installed servers (`intentshield scan`) | rules + taint | yes, plus credential egress | yes | Claude Code, Codex, Cursor, Gemini CLI | yes | yes | MSB, MCPTox, InjecAgent, AgentDojo, false-flag rates |
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) (ex-Invariant mcp-scan) | Apache-2.0 | yes, via Snyk's API | - | - | pinning | discovery only | - | no | n.p. |
| [Cisco mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) | Apache-2.0 | YARA + LLM | - | - | - | - | - | YARA only | n.p. |
| [Lasso MCP Gateway](https://github.com/lasso-security/mcp-gateway) | MIT | scan mode | secret/PII masking | - | - | - | yes | masking only | n.p. |
| [LlamaFirewall / Prompt Guard 2](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall) | PurpleLlama | text scanner | local model | - | - | community recipe | - | PG2 yes | AgentDojo: 1.75% ASR with AlignmentCheck (GPT-4o) |
| [mcp-guardian](https://github.com/eqtylab/mcp-guardian) | Apache-2.0 | - | log | - | - | - | approval per call | yes | n.p. |
| [ToolHive](https://github.com/stacklok/toolhive), [Docker MCP Gateway](https://github.com/docker/mcp-gateway) | Apache-2.0 / MIT | filtering | - | - | - | - | containers, secrets | yes | n.p. |
| [Progent](https://github.com/sunblaze-ucb/progent), [CaMeL](https://arxiv.org/abs/2503.18813) | MIT / research | - | capabilities | policy or data flow | - | - | - | needs an LLM | AgentDojo near 0% ASR on frontier models |

Also found on 2026-10-29, described here from their own READMEs and listings only (not installed or
tested): [mcp-context-protector](https://github.com/trailofbits/mcp-context-protector) (Trail of Bits: a
wrapper that pins server configs and descriptions, quarantines tool responses and strips ANSI control
characters), [MCP Defender](https://mcp.so/servers/mcp-defender) (a desktop app proxying MCP traffic for
Cursor and similar clients), [pipelock](https://github.com/pipelab-org/pipelock) (an egress firewall for
HTTP, MCP, A2A and WebSocket traffic: exfiltration, SSRF and prompt injection, with signed action
receipts), [hol-guard](https://github.com/hashgraph-online/hol-guard) (a runtime blocker for risky tools,
secret access and malicious packages), and the offline scanners
[mcprobe](https://github.com/tamish560/mcprobe) and [mcphound](https://github.com/tayler-id/mcphound)
(description injection, shadowing and drift, with SARIF output). Snyk Agent Scan now also reports toxic
flows and hardcoded secrets. None of them was found to publish detection or false-positive rates.

After this comparison IntentShield gained the two features most of them share: an offline scan of the
servers already installed (poisoning, self-disclosure, shadowing, hardcoded credentials, toxic flows,
pinning, SARIF; Snyk's equivalent sends descriptions to its API) and a credential-egress check in the
hooks and the proxy. A head-to-head run of another guard on IntentShield's corpora was not done: the one
candidate that runs offline (Cisco mcp-scanner's YARA mode) was not installed in this session.

Detection, measured against one of them (2026-10-29, `docs/detectors.md`): on InjecAgent, which neither was
tuned on, IntentShield's rules and Prompt Guard 2 are level (50.8% against 50.3% of 2,108 injections); both
miss plain-language injections; the rules lead only on data they were written from.

What that table supports: among the seven guards surveyed on 2026-10-29, IntentShield is the most broadly
scoped keyless open-source MCP guard, and the only MCP-specific one that publishes benchmark results and
false-positive rates. What it
does not support: "best performing". The MCP-specific guards publish nothing to compare against,
and on the one shared benchmark where defenses do publish (AgentDojo), IntentShield's row is a 7B
agent at 15.6% residual attack success against LlamaFirewall's 1.75% and Progent's near 0% on
GPT-4o-class models. Closing that gap needs a frontier-model AgentDojo run, which is paid.

### 12.2 Architecture verdict (2026-10-29)

An independent architecture review after the five code reviews. The hook-plus-proxy split holds:
each side sees what the other cannot (the hook the user's real prompt and the whole session, the
proxy descriptions and schemas before the model does). Three structural findings were fixed the
same day and are tested in `tests/test_review_fixes.py`:

- **The gateway took its trust anchor from the agent it monitors.** `intentshield_create_run` is
  agent-callable, and the intent it carries exempted values from provenance. Now a value the
  intent names that a tool output had already shown earns no exemption unless the operator sets
  `trusted_intent` (for a runner or hook that writes intents). The user-typed prompt in hook mode
  was never affected.
- **The hook decided read-versus-write from a tool name the server chose.** The transparent proxy
  now writes the operator's `read_only_tools` decision into the catalog it shares with the hooks,
  and the hook uses it; the name heuristic applies only to servers no proxy guards.
- **`wrap` lost cross-server shadowing** (one proxy per server). Each proxy now reads the other
  proxies' catalog files for the shadowing check.

Also fixed: the hook database kept every prompt forever (now pruned after 7 days), and PyTorch was
imported at the top of the proxy module. Known and documented, not fixed: gateway taint lives in
process memory (a restart clears it), the stdio gateway has no approval channel (use Streamable
HTTP or the hooks), and the dashboard, the simulated mailbox, the synthetic evaluation harness and
the negative-result classifiers still ship in the core package. The reviewer's target layout
(`callguard` shared by hook and proxy, one control plane, detectors and dashboard as extras, about
7k lines instead of 11k) is in §11 above as the next refactor.

What the other guards have that IntentShield lacks: sandboxed server execution (ToolHive, Docker),
secret and PII masking in results (Lasso, Docker; IntentShield detects credentials leaving in arguments
and written into configs, but does not mask results), signed provenance of server packages (ToolHive),
signed action receipts (pipelock), SSRF checks on outgoing URLs (pipelock), and a trace-level alignment
check (LlamaFirewall). Only the self-disclosure stripping, the
four-harness hook integration and the hooks-plus-proxy split have no counterpart among the seven guards
surveyed on 2026-10-29.

## 13. Hook verdict fidelity study (2026-11-01)

This section supersedes the §7 routes with the measured state; the verdicts above stay as written. Account: `docs/hook-fidelity-study.md`
(one document: measured, refuted, dropped, not done); data: `results/hook-fidelity/`; four rounds, about 2,290 launches through round 3 and 195
more (runs plus app-server starts: 141 in the gap lane, 54 in the integration) in round 4, all against a local stub model, $0, no real model, no DeepSeek.

**What was done.** Route 2 in a narrower form: instead of channel coverage across four to six harnesses with live models, the question "does a
harness enforce the verdict a third-party PreToolUse-style hook returns?" was measured on Claude Code (23 sampled builds), Codex CLI (17 sampled builds)
and Gemini CLI (28 sampled builds), headless, macOS, one scripted call per run, per mode, per hook reply and per trust state, with raw committed rows,
liveness controls, a kill criterion the author registered before the runs (a same-day commit, not blind, and not verifiable from this repository's history) and review re-launches (20 to 28 cells per lane, all reproduced). Cursor CLI could not be
measured (free-plan limit) and is counted nowhere.

**Measured state.**
- A parsed `deny` was enforced wherever the hook ran, on every build and mode tested. No unenforced deny was found. The hook did not run in three
  cases: Codex hooks nobody had trusted (skipped without a signal), a Claude Code hook scoped with the `mcp__.*` matcher on `ReadMcpResourceTool`
  resource reads, and Gemini CLI before 0.26.0 (hooks opt-in). The build counts are sampled releases, so a boundary such as "from 2.1.85" lies
  between two measured builds (bisected to adjacent releases only for Claude Code's `ask` and Codex's trust-flag boundary).
- An `ask` with no human: denied by Claude Code from 2.1.85 (the change lies between the adjacent patch releases 2.1.84 and 2.1.85), ignored by
  Codex (documented as unsupported), silently run (0.24.5 to 0.37.2) or hung to the cap (0.38.0 to 0.66.0) on Gemini, under yolo and with the
  shell allow-listed.
- Failure replies mostly fail open (documented for Claude Code and Codex; by release for Gemini). What changes the outcome most is state outside
  the reply: Codex hook trust, the bypass flag having no effect in `codex exec` through 0.140.0 (exact boundary 0.140.0 to 0.141.0; a publicly reported and fixed bug, openai/codex #26383, per the round-7 novelty check), Gemini
  approval mode and MCP trust, Claude pre-approval.
- The kill criterion (5 undocumented deviations replicating on three or more builds) is **not met**: 3. By direction, the unsafe-direction count that
  replicates and is not confounded is zero.
- A mitigation (verdict translation, deadline, fail-closed launcher) was built and checked as a regression check on 12 stub builds, then given an
  allow control, a deny-everything control, a shipped-deadline cell and a no-version-recorded cell; it is a reference implementation, not a result.

**Reviewers' verdicts** (hostile reviews of the integrated round-3 branch plus the round-4 gap lane):
- Security lens (S&P, USENIX Security, CCS main track): **reject**. The claimed security contribution is unsupported: no adversary, no
  attacker-reachable trigger, no real model; most behaviours are documented (the Codex hooks page says an ask is "parsed but not supported yet ...
  continues the tool call"; Claude Code documents the denial in `-p`) or have prior public reports; the study had no related work. Accepts a workshop
  or measurement note, an experience-report track, an artifact track, documentation feedback and upstream issues.
- Software-engineering lens (ICSE, FSE, ASE research track): **reject**. No stated RQs, stub not agent, one OS, headless only, a near-tautological
  mitigation evaluation, "the novelty is thinner than the effort". Accepts a tool or demonstration track, an MSR or ESEM data showcase, or an
  industry or AIware workshop paper.
- Artifact lens: **minor revision**. The tables regenerate from the committed rows, but guard decisions and launches need the corpus clones and release installs, which are not committed; 20 count and wording errors, fixed in round 4.
- Mitigation critic: the arithmetic reproduces (28 of 28 re-launched outcomes match) but the evaluation could not falsify the design; "a modest
  engineering contribution over the corpus, not a research one".

**Verdict, updated.** Not publishable as a paper at a main research track. Publishable, as it stands after the round-4 fixes, as: a measurement
note or workshop paper whose claim is the versioned stub-model conformance matrix (three harnesses, headless, macOS) and the finding that state
outside the verdict decides more than the verdict does; an artifact submission (runner, stub, committed rows, regeneration scripts, tests); and the
per-vendor documentation-feedback packet (drafts kept out of the repository, nothing sent). The §7 route 1 (artifact) is the supported one; route 2 as written
(a measurement study across four to six harnesses with live models and a disclosure cycle) is still not done and `docs/hook-fidelity-study.md`
section 15 lists what it would need, with costs: an attacker-reachable trigger, model-in-the-loop agreement, interactive controls, a second OS,
bisected boundaries and a determinism test, independent coding, a completed disclosure cycle. The contribution claim of `§5` is unchanged: the
guard's detection layer is not a research result; the hook-fidelity matrix is a measurement of the harnesses, not of IntentShield.

**What the public repository cannot show.** The study cites commits and branches of its development branch (for example `25b62ad`, "fixtures
committed before any guard ran"); that branch was squash-merged, so those hashes are not in `main`'s history. The author archives the original commits; the order in which predictions, kill criterion and fixtures were committed cannot be
checked from the public history alone. Vendor documentation pages are cited by source URL and sha256, not redistributed
(`results/hook-fidelity/vendor-archive/*/README.md`). The fresh detection set's labels come from one model family, the one that wrote the rules. The
pty lane's 61 raw `transcript-head.bin` captures are not committed. See the study's section 10.

**Product effect.** The study's findings changed shipped behaviour (installs write a deadline and a fail-closed launcher by default; an ask that is
not positively interactive becomes a deny with a reason; `doctor` prints the measured fail-open conditions). That needs a human review before a
release, and the author maintains the product evaluated (conflict of interest, stated in the study and in each disclosure draft).

**Round 6 (2026-11-01): head-to-head and interactive cells.** 249 more launches in two lanes plus 42 critic launches, all against the stub, $0. Two critics narrowed both results.
(1) *Head-to-head* (`docs/hook-fidelity-study.md` section 6a): on the 18 (cell, build) pairs where a shipped captured guard's intended verdict did not survive, IntentShield's installed hook
(translation on) delivered a refusal in 18 of 18 and the translation-off hook in 5 of 18 (12 of 12 and 4 of 12 without the regime-A slow cell whose timeouts we set); a regression table of selected pairs,
no interval. The only comparative claim supported in round 6 (superseded by the round-7 wording below) is the critic's: "IntentShield's installed hook delivers its verdict where the captured guards' shipped configurations, replayed from bytes, do not, and
that this comes mainly from configuration the guards could adopt." 9 of the 18 pairs are the fail-closed launcher, 6 are timeouts we set, 2 show no advantage and 1 isolates the ask-to-deny translation.
It says nothing about detection quality (no allow cell, no wrapped-guard arm), so "better than existing guards" is **not** claimed. (2) *Interactive cells* (section 6b): on Claude Code 2.1.316 and
Gemini 0.66.0 the translation kept an ask as a prompt when `ps` worked, the same as with it off (2/2 each); Codex never prompts for a hook ask; with no runnable `ps` the translation lost the prompt that the
old hook kept, a defect in the product found by the measurement. The round-4 critic's fatal objection is answered in part. **The verdict above stands**: neither lane makes the mitigation a research result
or the study publishable at a main track; the venue fit, the kill criterion and route 1 (artifact) are unchanged. Numbers that changed: the mitigation "no comparison" statements, the interactive "never run"
statements, and the launch totals (about 2,290 through round 3, plus 195 in round 4, plus 291 in round 6).

**Round 7 (2026-11-01): wrapped-guard control, `ps`-free detector, novelty check.** About 231 more launches (181 in the wrap lane, 21 in the detector lane, 29 for three critics' re-runs; the novelty critic launched nothing), all against the stub, $0.
Three critics narrowed everything (`docs/hook-fidelity-study.md` sections 3.7, 6a.1, 6b.1, and section 0, which now says whether the round-6 objections are closed: **not all**).
(1) *Wrapped-guard control* (new `intentshield wrap-hook`): the captured bytes of six third-party guards behind IntentShield's launcher, deadline and translation were blocked in **12 of 12** launched (build, cell) failure pairs, tying IntentShield's installed hook (11 of 11)
and a deny-everything hook (11 of 11); a launcher alone reproduced the 9 dead and crash pairs (5 of 5 launched). The default shim blocks every guard that signals allow by printing nothing, and `--on-empty allow` lets a guard's silent fail-open through. The critic's sentence is the only
comparative claim: a measured delivery gap that a thin generic wrapper closes in these 12 pairs, partly by refusing silent allows; **it cannot tell IntentShield from a wrapper, and says nothing about detection quality**. This weakens the round-6 reading of the head-to-head.
(2) *`ps`-free mode detector*: the prompt is kept with `ps` blocked (Claude Code 2.1.316 2/2, Gemini 0.66.0 2/2); a Codex raw ask **runs** the call (2/2, no prompt); two captured guards' ask bytes tie IntentShield's ask on one build. A lane-sandbox defect repaired, not a field defect; no gain over translation off.
(3) *Novelty check*: no wrapper of third-party hooks was found in a limited search, but every mechanism (mode-keyed ask-to-deny, version floors, `|| exit 2`, crash-to-deny) has precedent in guards' own hooks; DefenseClaw (version-keyed hook contracts) and CATP are the closest prior work; the Codex trust-flag finding is a reproduction of
a fixed public bug (openai/codex #26383). The supportable contribution sentence is the hedged measurement-artifact one in the study's section 0. **The verdict above stands**: nothing in round 7 makes the mitigation a research result or the study publishable at a main track; the venue fit and route 1 (artifact) are unchanged.

**Round 8 (2026-11-01): a decision comparison, the wrapped re-run, a narrow real-model arm, a Linux probe.** About 200 more launches (181 in the lanes, 19 for two critics; plus 15 `--version` probes), a stub, a local Ollama model and one paid model (DeepSeek, user-approved, under one cent at the endpoint's resolution), no Groq, no Gemini API, no Cursor (`docs/hook-fidelity-study.md` sections 6a.1, 6b.1, 6c, 6d; the study's total is now about 3,207 launches). Three critics narrowed everything again.
(1) *Decisions* (the first comparison of what IntentShield decides with what other guards decide; an author-built set of 467 fixtures, illustrative, not a benchmark): on the held-out set (166 harmful and 234 benign items after the critic's correction of a tuned family) IntentShield's hook misses **137/166 (83%, Wilson [76, 88])**, asks on 29, denies none, and flags none of the destructive, git, credential-read, pipe-to-shell or rc/CI-write items; `safety-net` misses 31/130 (24%) on its scope and flags 99 of the same 130 shell items against IntentShield's 19 (sign test p 3e-23, descriptive); `knox` misses 67/117 (57%). IntentShield's one distinctive flag is an MCP call whose destination was copied from an earlier tool result: 10/10 held-out items asked with session state, 0/10 without it and for `knox` (whose hook is never given the earlier result), and **20/24 benign calls with a result-sourced destination asked too**, so it is provenance, not injection detection. With the shipped translation its effective protection is 13 to 17% per build against 61 to 76% for `safety-net` (Bash-measured, extrapolated to other tools, validated on 29 shell cells, 29/29, after an INVALID first pass of 30 launches). **This is the opposite of an advantage: on decisions the detection layer is behind the guards it was compared with, outside the injection case it was built for**, which is consistent with section 5 above.
(2) *Wrapped re-run and `--on-empty allow`*: 36 launches on the merged code, no outcome changed (12/12 pairs, 12/12 asks; a regression check, every run non-interactive); only exit 0 with empty stdout runs under `--on-empty allow` (3/3, by definition; 0/12 of the failures that leave a signal); the default shim refuses 12/17 benign captures that silent-allow guards would let through. (3) *Real model*: qwen2.5:7b 61/61 and deepseek-flash 10/10 valid runs equal to the stub outcome on four reply classes and two builds, with a prompt that forbids a retry: "measured on a narrow slice, no divergence seen", not lifted. (4) *Linux*: the `/proc` reader read 27 of 27 constructed trees in Docker (plus a control), `hidepid` 1/1; a PID-1 defect candidate (0/8; fixed afterwards, see the next paragraph) and a node-launched-Claude blindness on macOS are not fixed.
The only comparative claim supported is the detection critic's scoped sentence (section 0 of the study): coverage, not better decisions. **The verdict above stands, and round 8 narrows it**: nothing here makes the mitigation or the detection layer a research result, the final reviewer's blocking gaps are closed, partly closed or open as the study's section 0 table says (a real person is still open), and the supportable outputs remain the measurement note, the artifact and the documentation-feedback packet.

**After round 8 (2026-11-01): fixes and a fresh set** (`docs/hook-fidelity-study.md` section 6e; no launches, $0; a refuting critic of the fresh set and the rules). The first product change the study caused beyond the translation layer: `translation._walk` reads PID 1 on Linux (the Docker rerun reads 37/37 trees, `pid1` 8/8 from 0/8; macOS unchanged), and `dangerous.py` gives `--builtin-tools` deterministic deny and ask rules for shell, read and write calls (off in the default install). Scored on a fresh set of 214 calls (104 harmful, 110 benign; one author, sources recalled, labels not independent, built before the rules were merged **per the builder, not independently verifiable**, same six categories as the rules), IntentShield with the rules lets through **28/104 (27%, [19, 36]; 41 asked, 35 denied)** with 5/110 benign asks and no denials, against 44/85 (52%) for safety-net on its shell scope and 44/73 (60%) for knox on its scope, where IntentShield lets through 25/85 and 18/73 of the same items. **POST HOC** the same rules score 6/178 on round 8's set, which is not detection on unseen attacks. The honest reading, in the critic's words and mine: on denies alone IntentShield **trails safety-net (24/85 against 41/85) and ties knox (28/73 against 29/73)**; its lead is asks, which are not stops on Claude Code 2.1.84, Codex and Gemini and hang Gemini 0.66.0; the benign asks become refusals on headless builds (5/110 against 4/110 and 0/110); the effective-protection figures (71 to 73% as shipped, against 38 to 48% and 41 to 47%) are extrapolated from shell-measured cells and depend on the translation. The critic also caught that the first knox figure (75/104) counted 31 Gemini items it never ran on (44/73 on its scope). This changes the study's comparative sentence from "behind on decisions" (round 8) to a mixed one, and it is **not** "better than existing guards": the set is same-author and same-category, so it shows the rules work on their own categories and nothing about new techniques. **The verdict above stands**: not publishable at a main track; the rules are engineering evidence for the product, not a research contribution, and the study's own ceiling (measurement note or workshop paper plus artifact) is unchanged. What would test generalisation is a second author or model adding 30 to 50 harmful items outside the six categories, scored once with the rules frozen; that was not done.

**Round 9 (2026-11-01): the generalisation test did not run** (`docs/hook-fidelity-study.md` section 6f; no launches, no model or paid call, $0). The test the 6e critic named as the only check of generalisation, a second author or model adding 30 to 50 harmful calls outside the six rule categories, committed first and scored once with the rules frozen, was attempted on the branch `r9-general` and stopped before any fixture was written. The branch has no commits, `results/hook-fidelity/detect/general/` does not exist, and nothing was scored, so there is no k/n and the round-9 critic's verdict is **refuted for lack of evidence**: its five checks and its recomputations could not be run. The critic's sentence on how the round-8 rules generalise: "Nothing: the generalisation test was not run. No fixture set outside the six rule categories was built, committed or scored, so the study has no measurement of how the round-8 rules behave on harmful calls outside the categories they were written from, and no claim about generalisation should be made in either direction." The 6e comparative sentence stands as written with no new evidence for or against, and the study's section 0 now adds the critic's sentence that the comparison was made on categories the rules were written from, has not been tested outside them, and must not be read as showing that IntentShield detects more than safety-net or knox in general. **The verdict above stands and nothing here changes it**: not publishable at a main track; the ceiling is the measurement note or workshop paper plus the artifact; the out-of-category set is still not done and needs a human to name its author.
