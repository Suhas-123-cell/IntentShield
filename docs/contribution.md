# The contribution, in detail

This file sets out what in IntentShield could be a research contribution, the evidence, how
it compares with the closest papers, and whether it is worth publishing. It is the honest
version: most of IntentShield is engineering over prior art.

**Verdict (2026-10-12, after review): it is not worth submitting to a peer-reviewed venue as
it stands.** The candidate claim below was measured, but on review it is thin and partly
known (§5). Two routes could still produce a paper (§7).

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
| Tool description | post-turn only (`Stop`) | model hooks only | observed (`tools/list`) |
| Resource content | non-MCP tool name only | not reached by the model | closed (`resources/read` 1→0) |
| Prompt content | post-turn only (`Stop`) | model hooks only | closed (`prompts/get` 1→0) |
| Elicitation | not observed | not observed | not forwarded |

What the cells mean:
- **"post-turn only (`Stop`)":** the text reached the model's context, but the hook event
  that carried it fires after the turn. That is too late to block the call it influenced.
- **"non-MCP tool name":** Claude Code surfaced the resource under its built-in
  `ReadMcpResourceTool`. A `mcp__.*` matcher misses it; a `*` matcher would not.
- **"closed":** the proxy exposes only tools, so the server never received `resources/read` or
  `prompts/get` on either harness. The proxy mediated every `tools/list` call (14–15 per run).

## 5. Why it is not publishable as it stands

1. **The one gap that is structural is already known in substance.** Tool descriptions are
   the only channel that both harnesses' tool hooks miss. That follows directly from the hook
   input schemas: `PreToolUse` carries the tool name and arguments, not the description.
   Description scanners such as mcp-scan, MCP-Guard and Tool-Guard exist for this reason, so
   a reviewer would call the gap known.
2. **Two of the three misses are configuration, not structure.** A `*` matcher in Claude
   Code sees resource reads under `ReadMcpResourceTool`. Gemini CLI's model-level hooks
   (`BeforeModel`, `BeforeToolSelection`) do carry prompts and tool declarations.
3. **The proxy's complete mediation partly comes from dropping channels.** It closes
   resources and prompts by not forwarding them, which loses functionality rather than
   mediating it. Real mediation would forward them under the same checks as tool results.
4. **The evidence is thin.** It covers two harnesses, one small model each and one run. It
   uses benign markers only, so no harm was shown, and the elicitation row is inconclusive
   because of SDK errors.
5. **The area is crowded and fast-moving.** HarnessSecurity-Bench (2610.07639) covers six
   harnesses with a ten-mechanism taxonomy. COPEX (2610.04378) attacks the MCP channels.
   "Measuring and Exploiting Implicit Trust" (2609.18217) fragments payloads across channels
   and already evaluated seven third-party MCP tools. "Breaking the Protocol" (2601.17549)
   and CapScope (2609.08371) are adjacent.
6. **The supporting MSB numbers carry a known flaw.** The MSB runner names its servers
   `task`, `attack` and `addition`, and the agent model and the LLM judge see those names
   inside tool names. Every MSB number so far was measured that way. On current code, the
   gateway also reaches the task tool less often than at the frozen commit (52.5% vs 63.6%),
   and the cause is not yet isolated.

## 6. The numbers that hold up

These stay valid whatever happens to the paper question. They are evidence for an artifact
or tool paper, not a research claim on their own.

- **MSB held-out, live servers, guard frozen at `05bb91a`** (`benchmarks/msb.py`): executed
  harm went from 22–53% to **0.0%** on qwen2.5:7b, llama3.1:8b and Ornith-1.5-9B. The task
  tool was still reached in 60–67% of cases. Through the hook path, harm was 0.0% and the
  task tool executed in 64–69% of cases. The naming caveat in §5 applies.
- **MSB re-run on current code** (qwen2.5:7b, 2026-10-12):

  | Setup | Harm executed | Task tool executed | Task tool reached |
  |---|---|---|---|
  | Gateway | 0.0% | 34.7% | 52.5% |
  | Gateway + Groq judge | 0.0% | 27.5% | 52.3% |
  | Hooks | 0.0% | 64.2% | 64.2% |
  | Hooks + Groq judge | 0.0% | 62.1% | 64.8% |

  The judge's only catches on MSB were tools named `attack:...`, so they don't count.
- **MCPTox replay** (no inference): the full proxy has 0.4% attack success, blocks 95.4% of
  poisoned-tool calls, and falsely blocks 3.5% of benign calls. 46.3% of benign calls go to
  human review.
- **Rules vs. LLM judge on held-out MCPTox descriptions** (Gemini 3.5 Flash-Lite, real tool
  names, so no label leak):

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
1. Neutral MSB server names, then a re-run of the unguarded, gateway and hooks setups. This
   is free on local Ollama.
2. The gateway utility drop isolated and fixed, by bisecting the commits after `05bb91a`.
3. At least one baseline on the same split, such as Llama Prompt Guard 2 (Groq free tier) or
   an MCP-Guard-style detector.
4. Reviewer load reported as a metric, plus one stronger agent model on a free tier.
5. A limitations section that states the MSB modifications.

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
and benign markers.

## 8. Honest ceiling

IntentShield is solid engineering with a careful held-out evaluation. None of its mechanisms
is novel. On review, the placement finding is too thin, and partly a known consequence of
the hook schemas. On today's evidence, the realistic outcome is an artifact or tool paper
(route 1). A research paper needs route 2, and no amount of framing substitutes for it.
