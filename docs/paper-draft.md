# Complete Mediation for MCP: Why Hook-Scoped Guards Miss the Description, Resource, and Prompt Channels  (working title; the claim in it is not supported, see the status note)

> **Status (2026-10-13, after review): not submittable as framed.** The claim as first
> framed (a hook-scoped guard misses three channels; a proxy restores complete mediation)
> does not survive review as it stands, for three reasons:
>
> - The description gap follows from the hook input schemas.
> - A `*` matcher sees resources, and Gemini's model hooks see prompts.
> - The proxy "closes" resources and prompts by not forwarding them.
>
> The abstract and §3.3 below were rewritten to what the data supports. MSB numbers had a
> server-naming label leak, now fixed for qwen2.5:7b only (see §5 and
> [contribution.md](contribution.md) §5, §7). The stored coverage data came from instrumentation
> that is being fixed, so §3 is provisional. This file is kept as the skeleton for route 2,
> the measurement study.

**Draft skeleton, 2026-10-12.** Section-by-section plan with the numbers already in hand and
explicit TODOs for what each section still needs before submission. Numbers marked ✓ are
measured and reproducible in this repo and not known to be affected by a flaw; numbers marked ☐
are not yet collected. Provisional or flawed numbers carry no mark.

---

## Abstract (draft)

The Model Context Protocol (MCP) lets LLM agents call third-party tools, and guards for those
calls commonly install as hooks that the harness fires around a tool call (Claude Code, Codex
CLI, Cursor, Gemini CLI). We ask which attacker-controllable MCP channels such a hook
observes. Using a probe server that marks the MCP channels (tool description, tool result,
resource content, prompt content, and sampling/elicitation) and a passive hook that records
what each harness delivers, we measured Claude Code and Gemini CLI with benign markers. A hook
scoped to MCP tool calls observed the tool-call and tool-result channels. No pre-action hook
carried tool descriptions in either harness. Resources and prompts were seen or missed
depending on the matcher and the hook event (a `*` matcher saw Claude's resource read; Gemini's
model-level hooks carried the prompt), so part of the gap is configuration, not structure.
Elicitation was not exercised and sampling was not tested. A transparent protocol-level proxy
gated descriptions at `tools/list`; it exposes tools only, so resources and prompts were not
mediated but lost. We measured the cost of the guard on live MCP servers (MSB, one 7B agent
model, neutral server ids) and on tool-poisoning descriptions (MCPTox replay). Executed harm
fell from 58.5% to 0.0% with the gateway and with hooks, but that zero largely reflects removed
exposure and held mutations: a trivial baseline that withholds descriptions and holds every
mutation also scores 0.0%, with higher task success, but leaves 47 harmful calls for the human
reviewer where the gateway leaves none. Third-party
guards were not tested. Our artifact (IntentShield) pairs hooks with a proxy.

TODO ☐: one sentence of per-channel attack success once §3.5 is run.

## 1. Introduction

- MCP adoption; third-party tool supply chain; the attack surface is now well documented
  (COPEX, MSB, MCPTox, "Implicit Trust", Unit 42 sampling).
- **The deployment reality:** third-party MCP guards commonly install as tool-call-scoped
  hooks in the harness; no vendor product was tested. The project is defensive-only, and any
  finding about a shipping harness goes through responsible disclosure first.
- **The question we ask:** is a hook scoped to tool calls a complete reference monitor for
  MCP? Our provisional answer: not for tool descriptions, and for other channels it depends on
  configuration.
- **Contributions:**
  1. A per-channel, cross-harness *coverage matrix* for hook placements (§3), with benign
     markers. Prior work measures built-in settings (HarnessSecurity-Bench) or isolates the
     model (COPEX). Novelty is contested: "Implicit Trust" (2609.18217) already evaluated
     third-party MCP tools, and the description gap follows from the hook schemas.
  2. The harness-specific mechanism for each miss, separating structural misses (descriptions)
     from configuration (matchers, model-level hooks).
  3. A proxy design that gates descriptions and drops the other non-tool channels, and the
     measured cost on live servers. It does not mediate those channels.
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

## 3. Channel coverage study  (provisional: old instrumentation, fixed re-run pending)

### 3.1 Method
Probe server (`benchmarks/coverage/probe_server.py`) marks each channel; passive logging hook
(`log_hook.py`) on every event; headless harness, four benign prompts; direct vs. proxy.
Reproducible: `benchmarks/coverage/run.py`. Full description in `docs/coverage-study.md`.

### 3.2 Result (measured 2026-10-12; provisional)

| MCP channel | Claude hook (`mcp__.*`) | Gemini hook (`BeforeTool`) | Transparent proxy |
|---|---|---|---|
| Tool result | seen (PostToolUse) | seen (AfterTool) | seen (every `tools/call`) |
| Tool description | no pre-action hook carried it (the `Stop` hit was the model echoing the marker) | not carried by any hook; not observed in logs | seen (every `tools/list`) |
| Resource content | `PostToolUse` under built-in `ReadMcpResourceTool`: seen by a `*` matcher, missed by `mcp__.*` | not reached (`resources/read` 0 to 0) | not exposed (tools only; functionality lost, not mediated); `resources/read` 1 to 0 on Claude |
| Prompt content | no pre-action hook carried it (the `Stop` hit was the model echoing the marker) | carried pre-model by `BeforeAgent`/`BeforeModel`, not by `BeforeTool` | not exposed (tools only; `prompts/get` 1 to 0) |
| Elicitation | not exercised (SDK errors) | not exercised (SDK errors) | not exercised |
| Sampling | not tested | not tested | not tested |

Server-side counts table (from `docs/coverage-study.md`). The stored artifacts came from the
old instrumentation; a fixed re-run is pending.

### 3.3 Finding
A hook scoped to MCP tool calls observed the tool-call and tool-result channels. Descriptions
were not carried by any pre-action hook. For resources and prompts the answer depends on the
matcher (`*` vs `mcp__.*`) and on which event is used (model-level hooks), so those misses are
configuration, not structure. The proxy mediated `tools/list` (descriptions); it did not
mediate resources and prompts, it stopped exposing them. Under the proxy, a rug-pulled tool
was hidden and later calls to it were refused for the session. We do not claim complete
mediation by either placement.

### 3.4 Why each miss happens (per harness)
Claude Code: descriptions and prompts reached no pre-action hook (the `Stop` hit was the model
echoing the marker); resources arrive under the built-in `ReadMcpResourceTool`, which a `*`
matcher sees and `mcp__.*` misses. Gemini CLI: the prompt is carried by `BeforeAgent` and
`BeforeModel`, not `BeforeTool`; the description was not carried by any hook; the resource
channel was not reached by the model.

### 3.5 Per-channel attack confirmation ☐ TODO
For each channel the hook misses, one benign-looking injection that uses it, run with a
hook-only guard installed, measured harm. This turns "the guard can't see it" into "the guard
doesn't stop it". Threat model and payload framings from COPEX (2610.04378) and "Implicit
Trust" (2609.18217). **Responsible disclosure before publication.**

## 4. Restoring complete mediation: hooks + proxy

- IntentShield's design: harness hooks for the call/result channels (the user's real prompt,
  argument provenance, output scanning) plus a transparent proxy that mediates `tools/list`
  (description scanning, quarantine, self-disclosure-parameter redaction). The proxy exposes
  tools only, so resources and prompts are lost, not mediated.
- The hooks cover what the proxy cannot see (the user's prompt, argument provenance), and the
  proxy covers what the tool hook cannot (descriptions). Neither alone is complete.
- Note: this section cites IntentShield's own mechanisms; it is the instantiation, not the
  novelty. Real mediation of resources and prompts (forwarding them under checks) is not built.

## 5. The cost of mediation

- **Live servers (MSB held-out, `benchmarks/msb.py`, qwen2.5:7b, neutral server ids,
  `artifacts/msb-v4`, 220 cases, single run, temperature 0):** executed harm 58.5% [51.8,
  64.8] unguarded; gateway 0.0% [0, 1.7]; hooks 0.0% [0, 1.7]. Task tool reached 94.1% none,
  50.0% gateway, 66.1% hooks (executed 94.1%, 34.5%, 66.1%). Caveats:
  - The zero mostly reflects exposure removal (descriptions withheld, self-disclosure
    parameters stripped, prompt-injection task servers quarantined through `shadowing`); the
    guarded agent attempted harm in 2 of 220 cases. The hook path is the stronger evidence:
    37 harmful attempts, all denied or asked.
  - Any guard that holds mutations for review and strips self-disclosure fields gets
    `harm_executed = 0` mechanically. The trivial baseline does (0.0%, `user_task` 51.4% vs the
    gateway's 33.6%, paired n=140); the difference is 47 harmful calls left in its review
    queue against 0 for the gateway.
  - The gateway's lower utility is the DeBERTa intent model abstaining on ordinary reads
    (`BLOCK_INTENT_MISMATCH` 141 with it, 0 without; reached 50.0% vs 63.6%). It gave no
    measured security gain on MSB.
  - llama3.1:8b, Ornith-1.5-9B and descriptions-exposed rows were measured before the
    neutral-id fix and without the intent model; not re-run ☐. The LLM judge was not
    evaluated on neutral ids ☐.
  - Runner deviations from MSB (injection text only on the task server, list-directory tools
    allowed, task-tool metrics counting lookalikes), the `name_overlap`/`shadowing` naming
    artifact, and the 10-step truncation (53/219 unguarded, 12/220 gateway, 29/218 hooks).
  - Wilson intervals treat the cases as independent; there are 20 draws per template.
- **Reviewer load** comes from the MCPTox replay, not MSB: about 46% of benign calls go to
  human review in the full proxy (46.3%). Report it as the price of the call layer.
- **Tool-poisoning descriptions (MCPTox replay):** quarantine+provenance blocks 95.4% of
  poisoned-tool calls, 3.5% benign false block; full proxy 0.4% attack success. The scanner
  rules were developed on MCPTox, so these are tuning-set numbers. ✓
- **Rules vs. LLM judge (MCPTox test-split servers, not held out for the rules):** rules
  96.4% / judge 99.7% / either 100% recall on 301 poisoned; 1.9% / 4.6% / 6.5% false-flag on
  108 clean. ✓ Judge = evidence-only, Groq/Gemini free tier.
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
  elicitation not exercised (SDK errors), sampling not tested; stored data from the old
  instrumentation. From `docs/coverage-study.md`.
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
4. MSB re-run with neutral server names for the remaining models (the trivial baseline is
   done; the gateway utility drop is isolated: the intent model).
5. Baselines: Llama Prompt Guard 2 (Groq), an LLM judge (built), harness built-in settings.
6. Latency/overhead table.
7. Responsible disclosure to the harness vendors before release.

## References (arXiv IDs to pull into BibTeX)

2610.04378 COPEX · 2510.15994 MSB · 2508.14925 MCPTox · 2609.18217 Implicit Trust ·
2601.17549 Breaking the Protocol · 2609.26761 A2M · 2610.07639 HarnessSecurity-Bench ·
2609.38983 Approval Laundering · 2609.08371 CapScope · 2605.11039 PACT · 2609.37196 ToolFence ·
2508.10991 MCP-Guard · 2606.20922 Tool-Guard · 2506.01333 ETDI · 2610.07359 Evaluate the Stack.
Plus Saltzer & Schroeder 1975 (complete mediation); Unit 42 MCP sampling (web).
