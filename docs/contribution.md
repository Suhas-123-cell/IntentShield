# The contribution, in detail

This file sets out what in IntentShield could be a research contribution, the evidence, how
it compares with the closest papers, and whether it is worth publishing. It is the honest
version: most of IntentShield is engineering over prior art.

**Verdict (2026-10-12, after review): it is not worth submitting to a peer-reviewed venue as
it stands.** The candidate claim below was measured, but on review it is thin and partly
known (§5). Two routes could still produce a paper (§7). Update 2026-10-13: the MSB label
leak is fixed and re-measured (§5.6, §6), and the new evidence weakens the supporting
numbers further: the gateway's 0.0% executed harm mostly comes from the attack not reaching
the agent, not from detection.

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
   looked.** The MSB runner used to name its servers `task`, `attack` and `addition`, and the
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

- **MSB held-out, live servers, neutral ids** (`benchmarks/msb.py`, qwen2.5:7b, single run,
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

  Paired on 218 cases (`benchmarks/msb_compare.py`): harmful calls left in review 47
  (baseline), 99 (baseline, exposed), 0 (gateway), 4 (gateway, exposed); MSB `user_task`
  51.4%, 41.4%, 33.6%, 32.1% (n=140).

  Read the 0.0% with §5.6: it is largely exposure removal and a mechanical effect of holding
  mutations. The task-tool metrics count the attack server only where there is no task server (rescored 2026-10-13; before, they also counted lookalike tools). The runner also
  deviates from MSB (injection text only on the task server; list-directory tools allowed),
  and the 10-step cap truncated 53/219 unguarded, 12/220 gateway and 29/218 hook cases.
- **Earlier MSB rows** (frozen commit `05bb91a`; llama3.1:8b and Ornith-1.5-9B; descriptions
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
  | Poisoned descriptions flagged (recall) | 96.4% | 99.7% | 100% |
  | Clean descriptions falsely flagged | 1.9% | 4.6% | 6.5% |
- **Tool routing** (BM25 over 45 MCPTox catalogs, 324 queries): the right tool ranks first
  in 80% of queries, in the top three in 90%, and in the top five in 92%.
- **Injection classifier:** a negative result. It falsely flags 20.3% of benign rows, so it
  is off by default.
- **Tests:** 145 pass and 1 is skipped. All 146 pass with the HTTP end-to-end test enabled.

## 7. Two routes that could still produce a paper

**Route 1: a tool or artifact paper (cheaper, closer to done).** The subject would be a
cross-harness MCP guard: hooks for Claude Code, Codex CLI, Cursor and Gemini CLI plus a
transparent proxy, evaluated held out on live servers. It needs:
1. Neutral MSB server names (done for qwen2.5:7b, commit `1c0d4dc`, `artifacts/msb-v4`).
   The llama3.1:8b and Ornith-1.5-9B rows and the descriptions-exposed rows still need a
   neutral-id re-run, free on local Ollama.
2. The gateway utility drop is isolated: it is the DeBERTa intent model, not a later guard
   change (§5.7). The open choice is whether to keep that model on the read path. The trivial
   baseline's runs are done (`artifacts/msb-v5`): it matches the gateway on `harm_executed`
   (0.0%) with higher task success, so the detection claim rests on reviewer load (harmful
   calls left for a human: 47 vs 0), which needs a review-fallibility argument to count.
3. At least one baseline on the same split, such as Llama Prompt Guard 2 (Groq free tier) or
   an MCP-Guard-style detector.
4. Reviewer load reported as a metric, plus one stronger agent model on a free tier.
5. A limitations section that states the MSB modifications (injection text only on the task
   server, list-directory tools allowed, task-tool metrics counting lookalikes, the
   `shadowing` naming artifact, the 10-step truncation).

Venues: demo or artifact tracks, a software paper, or arXiv first.

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
