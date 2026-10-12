# Complete Mediation for MCP: Why Hook-Scoped Guards Miss the Description, Resource, and Prompt Channels

> **Status (2026-10-12, after review): not submittable as framed.** The abstract and §3.3
> state the claim as first framed. It does not survive review as it stands, for three
> reasons:
>
> - The description gap follows from the hook input schemas.
> - A `*` matcher sees resources, and Gemini's model hooks see prompts.
> - The proxy "closes" resources and prompts by not forwarding them.
>
> MSB numbers also carry a server-naming label leak. See
> [contribution.md](contribution.md) §5 and §7. This file is kept as the skeleton for
> route 2, the measurement study.

**Draft skeleton, 2026-10-12.** Section-by-section plan with the numbers already in hand and
explicit TODOs for what each section still needs before submission. Numbers marked ✓ are
measured and reproducible in this repo; numbers marked ☐ are not yet collected.

---

## Abstract (draft)

The Model Context Protocol (MCP) lets LLM agents call third-party tools, and a market of
guards has grown to secure those calls. Almost all of them install the same way: a hook the
harness fires around a tool call (Claude Code, Codex CLI, Cursor, Gemini CLI). We ask whether
that placement satisfies *complete mediation* — whether every attacker-controllable MCP
channel passes through the guard. Using a probe server that marks each of the five MCP
channels (tool description, tool result, resource content, prompt content, sampling/
elicitation) and a passive hook that records what each harness delivers, we show across Claude
Code and Gemini CLI that a hook scoped to MCP tool calls observes only the tool-call and
tool-result channels. Tool descriptions, resource contents, and prompt contents reach the
model but never reach the hook in time to block, so three of five channels bypass every
hook-scoped guard. We then show that a transparent protocol-level proxy restores complete
mediation: it gates descriptions at `tools/list` and closes the resource and prompt channels
outright. We measure the cost of mediation on live MCP servers (MSB) and on tool-poisoning
descriptions (MCPTox): executed harm drops to 0.0% ✓, at a cost in task completion and human
review that we report. Our artifact (IntentShield) pairs hooks with a proxy for this reason.

TODO ☐: one sentence of per-channel attack success once §3.5 is run.

## 1. Introduction

- MCP adoption; third-party tool supply chain; the attack surface is now well documented
  (COPEX, MSB, MCPTox, "Implicit Trust", Unit 42 sampling).
- **The deployment reality:** the control point has moved to the harness hook. Name the
  shipping guards (Pillar, Numbat, CrowdStrike Falcon AIDR, HOL Guard, Endor Labs) — all
  hook-based, all scoped to tool calls.
- **The gap we find:** a hook scoped to tool calls is not a complete reference monitor for
  MCP. Three channels never reach it.
- **Contributions:**
  1. A per-channel, cross-harness *coverage matrix* for third-party MCP guards (§3). Prior
     work measures built-in settings (HarnessSecurity-Bench) or isolates the model (COPEX).
     Novelty is contested: "Implicit Trust" (2609.18217) already evaluated third-party MCP
     tools, and the description gap follows from the hook schemas.
  2. The finding that hook-scoped guards miss the description/resource/prompt channels, with
     the harness-specific mechanism for each miss.
  3. A proxy design that restores complete mediation, and the measured cost on live servers.
- Framing note: this is a *systems and measurement* contribution, not a new defense primitive.

## 2. Background and threat model

- **MCP channels (the five):** describe each and who controls it. Cite the protocol spec.
- **Reference monitor / complete mediation** (Saltzer & Schroeder 1975): every access to
  every object checked. State it as the property under test.
- **Two guard placements:** (a) harness hook scoped to tool calls; (b) transparent proxy
  between client and server. Describe how each is configured in practice.
- **Threat model:** a malicious or compromised MCP server that controls its own descriptions,
  results, resources, and prompts; the user and harness are honest; the guard is trusted but
  can only act on what it observes. Out of scope: a compromised harness or OS.
- **Adversary goal:** get attacker-controlled text into the model's context on a channel the
  guard does not mediate.

## 3. Channel coverage study  ✓ (core result, measured)

### 3.1 Method
Probe server (`benchmarks/coverage/probe_server.py`) marks each channel; passive logging hook
(`log_hook.py`) on every event; headless harness, four benign prompts; direct vs. proxy.
Reproducible: `benchmarks/coverage/run.py`. Full description in `docs/coverage-study.md`.

### 3.2 Result (measured 2026-10-12) ✓

| MCP channel | Claude hook (`mcp__.*`) | Gemini hook (`BeforeTool`) | Transparent proxy |
|---|---|---|---|
| Tool result | seen (PostToolUse) | seen (AfterTool) | seen (every `tools/call`) |
| Tool description | post-turn only (`Stop`) | model hooks only | seen (every `tools/list`) |
| Resource content | non-MCP tool name only | not reached | closed (`resources/read` 1→0) |
| Prompt content | post-turn only (`Stop`) | model hooks only | closed (`prompts/get` 1→0) |
| Elicitation | not observed | not observed | not forwarded |

Server-side counts table (from `docs/coverage-study.md`). ✓

### 3.3 Finding
Hook-scoped guard sees 2 of 5 channels in time to block; proxy mediates or closes all 5.

### 3.4 Why each miss happens (per harness)
Claude Code: descriptions/prompts only on post-turn `Stop`; resources under
`ReadMcpResourceTool` (built-in name, not `mcp__.*`). Gemini CLI: descriptions/prompts only on
model-level hooks, not the tool hook; no default MCP-resource tool.

### 3.5 Per-channel attack confirmation ☐ TODO
For each channel the hook misses, one benign-looking injection that uses it, run with a
hook-only guard installed, measured harm. This turns "the guard can't see it" into "the guard
doesn't stop it". Threat model and payload framings from COPEX (2610.04378) and "Implicit
Trust" (2609.18217). **Responsible disclosure before publication.**

## 4. Restoring complete mediation: hooks + proxy

- IntentShield's design: harness hooks for the call/result channels (the user's real prompt,
  argument provenance, output scanning) plus a transparent proxy that mediates `tools/list`
  (description scanning, quarantine, self-disclosure-parameter redaction) and does not forward
  resources/prompts it has not vetted.
- Argue this is why *both* layers are needed; neither alone is complete.
- Note: this section cites IntentShield's own mechanisms but frames them as the instantiation
  of complete mediation, not as the novelty.

## 5. The cost of mediation

- **Live servers (MSB held-out, `benchmarks/msb.py`):** executed harm 22–53% → **0.0%** ✓
  across qwen2.5:7b, llama3.1:8b, Ornith-9B; task tool still reached 60–67%; ~46% of benign
  calls sent to human review. Report as the price of closing the channels. Caveats:
  - The runner's server names (`task`/`attack`/`addition`) are visible to the agent and the
    judge, so every MSB number needs a re-run with neutral names ☐.
  - On current code the gateway reaches the task tool in 52.5% of cases, against 63.6% at the
    frozen commit (qwen2.5:7b); the cause is not isolated ☐.
- **Tool-poisoning descriptions (MCPTox replay):** quarantine+provenance blocks 95.4% of
  poisoned-tool calls, 3.5% benign false block; full proxy 0.4% attack success. ✓
- **Rules vs. LLM judge (held-out MCPTox descriptions):** rules 96.4% / judge 99.7% / either
  100% recall on poisoned; 1.9% / 4.6% / 6.5% clean false-flag. ✓ Judge = evidence-only,
  Groq/Gemini free tier.
- **Latency/overhead** ☐ TODO: proxy round-trip and hook process cost (hook ≈36 ms measured).

## 6. Related work

- **MCP attack surface:** COPEX (2610.04378), MSB (2510.15994), MCPTox (2508.14925), "Implicit
  Trust" cross-channel fragmentation (2609.18217), Unit 42 sampling, "Breaking the Protocol"
  (2601.17549), A2M (2609.26761).
- **Harness security:** HarnessSecurity-Bench (2610.07639), Approval Laundering (2609.38983),
  CapScope (2609.08371), hook-update supply chain (2609.03884), fail-open studies.
- **Guards/defenses:** PACT (2605.11039), ToolFence (2609.37196), CaMeL, MCP-Guard
  (2508.10991), Tool-Guard (2606.20922), ETDI (2506.01333); "Evaluate the Stack" (2610.07359).
- **Our delta (weak as it stands):** a per-channel visibility matrix for third-party guards
  across harnesses. "Implicit Trust" already evaluated third-party MCP tools, and the proxy
  "closes" the resource and prompt channels only by not forwarding them. Route 2 must show
  the gap in shipping guards' recommended configurations, with real mediation, to have a
  delta.

## 7. Limitations and ethics

- Two harnesses, one small model each; benign markers in §3 (live attacks are §3.5 TODO);
  elicitation channel inconclusive (SDK error). From `docs/coverage-study.md`.
- Ethics: responsible disclosure to Anthropic, Google, OpenAI, Cursor before release; benign
  markers only in the measurement; no live exfiltration against third-party servers.

## 8. Experiments still needed before submission (route 2)

1. Each shipping guard's default and recommended configuration on four to six harnesses (Claude
   Code, Gemini CLI, Codex CLI, Cursor, and more). Include `*` matchers and model-level hooks,
   so that the misses that are only configuration are separated out.
2. Per-channel payloads that are benign but measurably change behavior, on several models with
   repeated runs (free: local plus the Gemini/Groq free tiers).
3. A proxy that forwards resources and prompts under checks instead of dropping them, with its
   measured cost.
4. MSB re-run with neutral server names; the gateway utility drop isolated.
5. Baselines: Llama Prompt Guard 2 (Groq), an LLM judge (built), harness built-in settings.
6. Latency/overhead table.
7. Responsible disclosure to the harness vendors before release.

## References (arXiv IDs to pull into BibTeX)

2610.04378 COPEX · 2510.15994 MSB · 2508.14925 MCPTox · 2609.18217 Implicit Trust ·
2601.17549 Breaking the Protocol · 2609.26761 A2M · 2610.07639 HarnessSecurity-Bench ·
2609.38983 Approval Laundering · 2609.08371 CapScope · 2605.11039 PACT · 2609.37196 ToolFence ·
2508.10991 MCP-Guard · 2606.20922 Tool-Guard · 2506.01333 ETDI · 2610.07359 Evaluate the Stack.
Plus Saltzer & Schroeder 1975 (complete mediation); Unit 42 MCP sampling (web).
