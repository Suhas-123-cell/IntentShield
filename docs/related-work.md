# Related work and adaptivity plan

Search done 2026-10-11 over arXiv (semantic search, papers from 2024-06 onward). Abstracts
only; claims about other systems below come from their abstracts, not from reruns.

## Verdict

The *combination* IntentShield ships is uncommon: one deterministic guard that covers
descriptions, outputs and arguments, plugs into four real harnesses through hooks and a
transparent proxy, and is held out on live MCP servers (MSB). No single paper found does all
of that. But each mechanism on its own has close prior work, and the strongest one,
argument-level provenance, is now the subject of dedicated papers (PACT, ToolFence, the
dual-graph defense) that go further than IntentShield's version. A paper has to be framed as a
systems and evaluation contribution for MCP harnesses, not as a new defense idea, and it has
to fix the weakness below before it is submitted.

## Update 2026-10-12: second search and a stricter verdict

A second search (arXiv, abstracts plus experiment sections where noted) found that the
angles listed below as "new or uncommon" have since been covered or crowded:

| Angle | Close work found |
|---|---|
| Security of coding-agent harnesses | HarnessSecurity-Bench (2610.07639): ten built-in mechanisms, six harnesses incl. Claude Code, Codex CLI, Gemini CLI, 2,500 trials; notes attacks reaching protected operations through alternative execution paths. Approval Laundering (2609.38983): approval-execution binding failures in Claude Code, Codex CLI, Cursor. CapScope (2609.08371): capability-scoped authorization through harness extension hooks. Hook-update supply chain (2609.03884). Red-teaming six coding agents (2509.05755); MCP clients under tool poisoning (2603.21642) |
| Rules versus LLM judges | "Evaluate the Stack, Not the Layer" (2610.07359): one deterministic layer plus four LLM judges on 1,119 labelled actions, measures whether their errors are independent. AgentTrust (2606.08539): rules cannot decide semantic threats by construction |
| Reviewer load | "Oversight Has a Capacity" (2606.08919), "Habituation at the Gate" (2606.22721), agent security as agent-human interaction (2605.24309), MiniScope (2512.11147) |
| Schema-level parameter removal | The Stochastic Deputy (2609.14780) removes tenant identity from MCP schemas; the self-disclosure attack itself is MSB's out-of-scope-parameter attack |
| Tool routing | RAG-MCP and AgentDojo's tool filter; not a contribution |

Verdict: as a defense paper IntentShield is not publishable at a strong venue today.
Every mechanism has prior art, and a reviewer would also cite: no adaptive attacker; only
7-9B local agents; MSB run on a keyless subset with injections moved to where a proxy can
see them; description rules tuned on MCPTox; no baseline defenses run; the hook path
tested live only in Claude Code with three prompts; 46% of benign calls sent to review;
the trained injection classifier is a negative result.

Candidate contributions that survive the search, strongest first:

1. **What third-party hooks cannot see.** A measurement and attack study of hook-based
   MCP guards across harnesses: which MCP channels and execution paths bypass
   pre/post-tool-call hooks (tool descriptions, MCP resources and prompts, sampling and
   elicitation, `list_changed` mid-session, subagent and parallel calls, hook timeouts
   and crashes failing open, argument-rewrite limits); one attack per gap; a hook-only
   guard against each; the transparent proxy as the fix, with utility cost. No paper
   found does this. Nearest: HarnessSecurity-Bench (built-in mechanisms, not third-party
   guards) and CapScope (hooks for coding-agent authority, not MCP channels). Every gap
   above is a hypothesis until tested; Claude Code and Gemini CLI can be tested for free.
   Findings in shipping harnesses need responsible disclosure.
2. **Rules plus an evidence-only LLM judge on held-out live MCP servers, with reviewer
   load.** Incremental over 2610.07359 unless the live execution and harness path add
   something; better as one section of (1).
3. **Hard negatives for output-injection detectors.** Benign tool outputs that contain
   instructions meant for people, which small detectors flag (20% here). Check overlap
   with InjecGuard's NotInject first; needs human-validated labels, not only generated ones.

Needed for any of them: an adaptive attacker (plan item 7), one frontier agent model,
baselines (Llama Prompt Guard 2 and an LLM judge are both on Groq's free tier), and a
limitations section that states the MSB modifications.

## Closest work

| Work | Layer | Mechanism | Overlap with IntentShield | Where it goes further / differs |
|---|---|---|---|---|
| PACT, arXiv 2605.11039 | Arguments | Semantic roles for tool arguments, cross-step value provenance, role-specific trust contracts | Same core idea as `BLOCK_UNTRUSTED_ARGUMENT_SOURCE` | Tracks provenance of *every* untrusted value, not only values from flagged outputs; 100% security on AgentDojo's three strongest models, 8-16 points more utility than CaMeL |
| ToolFence, arXiv 2609.37196 | Arguments | Typed authorization blueprint, deterministic monitor, judge grants capabilities when the blueprint is incomplete | Deterministic monitor, within-tool argument attacks | Provenance-aware per value; near-zero ASR on AgentDojo with a 3.8-point clean-utility drop |
| Dual-graph defense, arXiv 2605.26497 | Arguments | Aligns a provenance graph with an authorization graph | Value checking at call time | Graph-level provenance |
| CaMeL / CaMeLoT (2609.18674), FIDES (2505.23643), APPA (2607.24625) | Plan / data flow | Information-flow control, capabilities, dual-LLM | Out-of-band deterministic enforcement | Formal IFC; APPA adds recovery instead of abort-only |
| Progent, RTBAS, FORGE (via 2606.26479) | Calls | Privilege policies and reference monitors | Policy engine as sole authority | Progent held under a hand-crafted adaptive attack (25.8% to 4.2%) |
| Task Shield (2412.16682), RETA (2606.15441), AttriGuard (2603.10749), CausalArmor (2602.07918) | Calls | Task alignment or causal attribution of each call | Intent grounding | Semantic (LLM or trained); RETA reports under 10% ASR against six adaptive attacks |
| MCP-Guard, arXiv 2508.10991 | Descriptions / prompts | Static scan, then neural detector, fine-tuned E5, then LLM arbiter; 70k-sample benchmark | Static scan as first stage | Adds learned stages for semantic attacks, which IntentShield lacks |
| MCPShield, arXiv 2602.14281 | Server trust | Metadata-guided probing before use, runtime monitoring, post-use reflection | Catalog-level trust | Adapts trust from observed behavior |
| Tool-Guard, arXiv 2606.20922 | Descriptions | Isolated planning: quarantine tools whose influence caused a misaligned call | Quarantine | Quarantines by observed influence, not by text matching; shows prompt-injection defenses transfer poorly to cross-tool description poisoning |
| SHIELD / TrustShiftProbe, arXiv 2608.23763 | Outputs over time | Behavioral baselines learned in a clean window, audit later payloads | Rug-pull fingerprint | Catches temporal defection in *outputs*; IntentShield fingerprints metadata only. SHIELD cuts ASR from 69.5% to 42.7% |
| ETDI, arXiv 2506.01333 | Catalog | Signed, versioned tool definitions, OAuth policies | Rug-pull detection | Cryptographic, needs server cooperation |
| ShieldNet, arXiv 2604.04426 | Network | Network-level guardrail; SC-Inject-Bench (10k+ supply-chain cases) | Proxy placement | Benchmark worth running |

Benchmarks to know: MCPTox (2508.14925) and MSB (2510.15994), both used here;
MCP-SafetyBench (2512.15163); MCPSecBench (2508.13220); MCP-TDP (2605.24069, 32 description
poisoning cases); SC-Inject-Bench (2604.04426); AutoDojo (2606.15057), a generative AgentDojo
for adaptive attacks.

Adaptive-attack work that reviewers will expect: "The Attacker Moves Second" (2510.09023),
"Adaptive Attacks Break Defenses Against IPI" (2503.00061, eight defenses bypassed at over
50%), PISmith (2603.13026, RL attacker), IterInject (2605.24659), AdapTools (2602.20720),
A2M (2609.26761, trace-optimized MCP hijacking), ShareLock (2606.27027, poison split across
tools with Shamir shares). 2606.26479 argues deterministic out-of-band defenses look like a
harder target than in-band detection, but has only one weak data point.

## What is new in IntentShield, and what is not

New or uncommon:
- Harness integration: one guard behind Claude Code, Codex CLI, Cursor and Gemini CLI hooks,
  plus a transparent proxy for the MCP servers they launch. No paper found evaluates a defense
  through real harness hooks.
- Self-disclosure parameter redaction (schemas asking for the agent's model, system prompt or
  conversation). Not found as a named defense.
- Held-out evaluation on live MSB servers through both a gateway and the hook path, three
  backbones, 0.0% executed harm.

Not new:
- Argument provenance (PACT, ToolFence, dual-graph, CaMeL), regex description scanning
  (MCP-Guard stage 1), quarantine (Tool-Guard), rug-pull fingerprints (ETDI), intent grounding
  (Task Shield and successors).

## Probe of new attack types (2026-10-11)

Ten hand-written samples against the current `scan_description` / `scan_output`:

| Attack type (source) | Result |
|---|---|
| Poison split across three tool descriptions (ShareLock) | missed, all three parts |
| Polite description poison, no trigger words | missed |
| Polite output injection (InjecAgent base style) | missed |
| False error naming another tool and `~/.ssh` | missed |
| Schema-valid lie: attacker IBAN in a normal-looking record (TrustShift semantic corruption) | missed |
| Base64-encoded instruction | missed |
| Spanish instruction override | missed |
| Classic "ignore previous instructions" (control) | flagged |

Status after plan items 1 and 2 (2026-10-11): the base64 row is now flagged (decoding).
The polite-output, false-error and schema-valid-lie outputs are still not flagged, but the
recipient, account or path they plant now sends any call that carries it to review
(`REVIEW_UNTRUSTED_ARGUMENT_SOURCE`). The split, polite-description and Spanish rows remain
open (items 3 and 4).

Status after items 3 and 4 (2026-10-11): the split row is flagged by the server-level scan
(`split_*`, every tool on that server quarantined). The polite-description and Spanish rows,
and the polite-output and false-error outputs, are caught by the trained classifier, but at a
20% benign false-flag rate, so it is not usable yet (see the item 4 note below).

The structural reason it matters: run taint, and therefore `BLOCK_UNTRUSTED_ARGUMENT_SOURCE`,
only starts when `scan_output` flags an output. An attack the rules miss never taints the run,
so the attacker's IBAN or address passes provenance. PACT and ToolFence avoid this by treating
every tool output as untrusted by source.

## Plan to make the guard adapt to new attacks

In order of value per effort:

1. **Detection-independent provenance (done 2026-10-11).** Record distinctive values from *every* tool output
   (by source), not only flagged ones. For authority-bearing arguments (recipients, accounts,
   URLs, paths, commands; a small operator-owned role map like PACT's), a value whose only
   source is a tool output goes to REVIEW; a value from a flagged output or another tool's
   description stays BLOCK. Detection becomes evidence that escalates, not the gate. This
   closes the polite-output, false-error and schema-valid-lie rows without any new rule.
   Cost to measure: benign retrieve-then-act flows ("reply to the sender") now need review.
   Implemented as `authority_values` (emails, URLs, IBANs, 9+ digit numbers, paths; generic
   ids left out) recorded from every output; paths and URLs inside one the user named are
   exempt; `review_output_sourced_arguments` turns it off. Not yet measured on MSB benign
   utility, which this lowers.
2. **Decode before scanning (done 2026-10-11).** Base64, hex, URL and HTML-entity decoding of long tokens, then
   rescan. Cheap, deterministic, closes the encoded row.
3. **Server-level description scan (done 2026-10-11).** Also scan the concatenation of all of a server's
   descriptions, and flag description text that refers to other tools' data or to sending
   anything (ShareLock, cross-tool poisoning). Add `sensitive_target` to the output rules.
   Implemented as `scan_server` (findings only in the joined text become `split_<rule>` and
   quarantine the server), the `cross_tool_data` and `external_send` description rules, and
   the `sensitive_request` output rule. On MCPTox: clean tools flagged 3/362 (unchanged),
   clean server catalogs 0/45, poisoned descriptions 1256/1302 (was 1255).
4. **A semantic second stage, local and evidence-only (built 2026-10-11; first artifact not usable).** A small classifier for "this text
   instructs the agent" on descriptions and outputs, run only on what the rules pass, trained
   on MCPTox/MSB/InjecAgent with paraphrases and translations (keep MSB held-out cases out).
   The repo already has a DeBERTa pipeline. This addresses plain-language and non-English
   injections. It must stay evidence: it can escalate to REVIEW, never authorize.
   Implemented as `InjectionClassifier` (`REVIEW_CLASSIFIER_FLAGGED`, off by default), trained
   on MCPTox plus qwen2.5:7b-written outputs and translations (InjecAgent was not available
   locally; MSB unused). On held-out MCPTox servers it caught 716/716 injections and 4/4 new
   attack probes but flagged 20.3% of benign rows, including human-directed instructions
   ("submit your timesheets by Friday"). Consistent with the detector literature; it needs
   many more hard benign rows before it can be enabled.
5. **Behavioral baselines for outputs.** Per tool, learn the output shape (keys, value types,
   which distinctive values recur) over the first N calls; flag a later output that adds
   instruction-like fields or new destination-shaped values (TrustShift).
6. **Task-alignment judge for mutations only.** For calls that would go to REVIEW, an optional
   local LLM check "does this call serve the stored user request?" (Task Shield / RETA style)
   to cut the 46% reviewer load. Off by default; never the sole authority.
7. **Continuous adaptive red-teaming.** An LLM attacker that rewrites MSB and MCPTox attacks
   against the deployed guard until they pass (IterInject / PISmith style), run before each
   release. Misses become regression tests only on a tuning split; report results on cases
   the loop never saw, or the guard overfits again.

## Experiments a paper needs

1. Baselines on the same MSB held-out split: at least one IFC/provenance defense (CaMeL or
   PACT if code is available), one task-alignment defense, one detector (MCP-Guard-style or a
   prompt-injection classifier), and spotlighting/sandwiching.
2. An adaptive attacker against IntentShield itself, following 2510.09023 / 2606.26479.
3. Held-out benchmarks with different templates: MCP-SafetyBench, MCP-TDP, SC-Inject-Bench.
4. Clean utility on a benign MCP workload, and reviewer load as a reported metric.
5. One frontier model as the agent.
6. Ablation of each layer, including item 1 above versus detection-gated taint.
