# The contribution, in detail

This file states precisely what in IntentShield is a research contribution, what is not, the
evidence for the claim, how it differs from each closely related paper, and what remains to be
done before it is publishable. It is the honest version: most of IntentShield is engineering
over prior art, and one measured result is new.

## 1. The one-sentence claim

> A third-party MCP guard installed as a harness hook scoped to tool calls — the way every
> shipping guard installs — does not achieve *complete mediation*: of the five
> attacker-controllable MCP channels, it observes only two (tool call, tool result) in time to
> act; tool descriptions, resource contents, and prompt contents reach the model but not the
> hook. A transparent protocol-level proxy restores complete mediation, and we measure the
> cost of doing so.

Everything below supports, bounds, or qualifies that sentence.

## 2. Why this is a contribution and the rest is not

IntentShield has many parts. Checked against the literature (two searches, Oct 2026), each
*mechanism* is prior art:

| Mechanism in IntentShield | Prior art that owns it |
|---|---|
| Argument/value provenance | PACT (2605.11039), ToolFence (2609.37196), CaMeL |
| Description regex scan + quarantine | MCP-Guard (2508.10991), Tool-Guard (2606.20922) |
| Rug-pull / schema-drift detection | ETDI (2506.01333) |
| Rules + LLM judge, evidence-only | MCP-Guard, "Evaluate the Stack" (2610.07359) |
| Semantic injection classifier | MCP-Guard's E5 stage; over-flagging known (NotInject) |
| Tool routing to save tokens | RAG-MCP, AgentDojo tool filter |
| Self-disclosure parameter redaction | The Stochastic Deputy (2609.14780), MSB's own attack |

So none of these, alone, is publishable. What is *not* in the literature is the **placement**
question: given that the whole industry now guards MCP at the harness hook, does that placement
see everything it must? That is a complete-mediation question (Saltzer & Schroeder, 1975), and
nobody has answered it per channel, across harnesses, for third-party guards.

## 3. The claim stated as a reference-monitor property

A reference monitor must have **complete mediation**: every access to every protected object
passes through it. Treat each MCP channel that can carry attacker text as an object class:

1. tool **description** (server-authored metadata the model reads to choose a tool)
2. tool **result** (server-authored output)
3. **resource** contents (server-authored documents the client fetches)
4. **prompt** contents (server-authored prompt templates / slash commands)
5. server-initiated **sampling / elicitation**

A guard achieves complete mediation iff it observes all five *before* they can affect an
action. The claim: a hook scoped to tool calls mediates {2} fully and {1} only after the
fact; {3,4,5} do not reach it; a proxy mediates {1,2} and closes {3,4,5}.

## 4. The evidence (measured 2026-10-12)

Method and raw data: [coverage-study.md](coverage-study.md), reproducible with
`benchmarks/coverage/run.py`. A probe server plants a unique benign marker in each channel; a
passive hook logs which event delivered each marker and under which tool name.

Per-channel visibility to the guard:

| Channel | Claude Code hook (`mcp__.*`) | Gemini CLI hook (`BeforeTool`) | Transparent proxy |
|---|---|---|---|
| Tool result | observed, PostToolUse | observed, AfterTool | observed (`tools/call`) |
| Tool description | post-turn only (`Stop`) | model hooks only | observed (`tools/list`) |
| Resource content | non-MCP tool name only | not reached by the model | **closed** (`resources/read` 1→0) |
| Prompt content | post-turn only (`Stop`) | model hooks only | **closed** (`prompts/get` 1→0) |
| Elicitation | not observed | not observed | not forwarded |

The proxy drives server-side `resources/read` and `prompts/get` to **zero** on both harnesses
because it exposes only tools; it mediates every `tools/list` (14–15 calls), so descriptions
are gated before the model sees them.

Two consequences stated carefully:
- "post-turn only (`Stop`)" means the text *did* reach the model's context; the hook that
  carried it fires after the turn, too late to block the call it influenced. A guard built on
  `PreToolUse`/`PostToolUse` scoped to `mcp__.*` therefore never gets a chance to act on it.
- "non-MCP tool name" means Claude Code surfaced the resource under the built-in
  `ReadMcpResourceTool`, which a guard matching `mcp__.*` does not match — so the standard
  scoping misses it even though a `*` matcher would not.

## 5. How it differs from the closest papers

- **HarnessSecurity-Bench (2610.07639):** measures the harnesses' *own built-in* mechanisms
  (allowlists, sandbox, read-only) and notes attacks reaching protected ops by alternative
  paths. It does not measure *third-party guard* visibility, and has no per-MCP-channel matrix.
- **COPEX (2610.04378), "Implicit Trust" (2609.18217):** attack the MCP channels and even
  fragment payloads across them, but deliberately *isolate the model* with a fixed stack; they
  evaluate model susceptibility, not guard placement. They are our threat model, not our result.
- **Fail-open studies / vendor docs:** cover what happens when a hook crashes or times out —
  orthogonal. Our point is that three channels never reach the hook even when it runs perfectly.
- **CapScope (2609.08371):** capability-scoped authorization via harness hooks, for
  coding-agent file/command authority, not MCP-channel coverage.

The delta is the matrix in §4 plus the "a proxy closes the resource/prompt channels" result.

## 6. The supporting (not headline) numbers

These are already measured and make the "cost of mediation" argument; they are not themselves
the contribution.

- **MSB held-out, live servers** (`benchmarks/msb.py`): executed harm 22–53% → **0.0%** on
  qwen2.5:7b, llama3.1:8b, Ornith-9B; task tool still reached 60–67%; ~46% of benign calls
  sent to human review. The latest run on current code holds at 0.0% harm.
- **MCPTox replay** (no inference): full proxy 0.4% attack success, 95.4% of poisoned-tool
  calls blocked, 3.5% benign false block.
- **Rules vs. LLM judge** on held-out MCPTox descriptions: recall 96.4% / 99.7% / 100%
  (rules / judge / either); clean false-flag 1.9% / 4.6% / 6.5%.
- **Injection classifier:** a negative result — 20% benign false-flag; off by default.

## 7. What is required before this is publishable

Status: **a measured hypothesis, workshop-strength, not yet submittable.** Required:

1. **Per-channel live attacks (§3.5 of [paper-draft.md](paper-draft.md)):** one benign-looking
   injection per missed channel, run against a hook-only guard, harm measured — turning "the
   guard can't see it" into "the guard doesn't stop it". Then the same under hooks+proxy.
2. **Codex CLI and Cursor** added to the matrix (two harnesses is thin).
3. **One frontier agent model** (Claude in Claude Code, Gemini in Gemini CLI).
4. **An adaptive attacker** (Groq free-tier `gpt-oss-120b`), per the "attacker moves second"
   literature.
5. **Baselines:** Llama Prompt Guard 2 (Groq), an LLM judge (built), and the harnesses' own
   built-in settings.
6. **Responsible disclosure** of any confirmed gap to Anthropic, Google, OpenAI and Cursor
   before release.

All of 1–5 are feasible on a free/local budget. Target venue: a security workshop (AISec,
SaTML, the Agents-in-the-Wild workshop that published COPEX) or arXiv first; a top venue only
after 1–5 and a second harness pair.

## 8. Honest ceiling

If the live per-channel attacks confirm the matrix, this is a solid workshop paper and a real,
citable contribution: *the dominant MCP-guard deployment model is structurally incomplete, and
here is the coverage map and the fix.* It is not, on its own evidence today, a top-tier paper,
and no amount of framing makes the individual mechanisms novel. The value is the placement
finding, not the guard.
