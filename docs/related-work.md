# Related work

This page places IntentShield next to the ten works closest to it. Literature last checked 2026-11-19. Each entry comes from the
paper's text (method and evaluation), not only its abstract; the end of some appendices and reference lists was not read, and one
entry says so. The numbers are the ones each paper reports. None of these systems was rerun here, and none was compared with
IntentShield on the same cases. Figures for IntentShield are those in the [README](../README.md) and [benchmarks.md](benchmarks.md).

IntentShield is a deterministic, keyless guard. It reads MCP tool calls, tool descriptions and tool results with rules, sends a call
carrying a value that only a tool result supplied to review, and sits behind four harness hooks and a transparent proxy. Most of its
mechanisms have a published owner, and [contribution.md](contribution.md) says what it does and does not claim.

## Hook and harness guards for coding agents

- **CapScope** (arXiv 2609.08371). A reference monitor on the Pi coding agent's pre-dispatch `tool_call` event. A model call that sees
  only the user request and the file names mints read, write and exec capabilities, which are frozen for the session. In 300 runs
  with one model the injected effect ran in 3 of 75 runs, against 33 to 47 of 75 for ambient and global-policy baselines.
  IntentShield mints no per-task capabilities; it covers MCP calls, descriptions and results across four harnesses.
- **HarnessSecurity-Bench** (arXiv 2610.07639). Rates ten built-in security mechanisms across 40 harnesses, then runs 23 tasks on six
  (including Claude Code, Codex CLI and Gemini CLI) with one base model, switching each mechanism on and off. It studies what the
  harnesses ship; IntentShield is a guard added from outside. The
  [hook study](hook-fidelity-report.md) asks a different question: what three CLIs do with the verdict a hook returns.
- **Approval Laundering** (arXiv 2609.38983; a working draft, read to its Section VI, so the discussion and limitations were cut
  off). Defines six ways a harness can run something other than what a person approved, measured on one Claude Code build, and
  proposes an HMAC-bound approval token. IntentShield does not bind an approval to its arguments or session.

## MCP scanners and proxies

- **MCP-Guard** (arXiv 2508.10991). A proxy with three stages: regular expressions, a fine-tuned E5-large detector and an LLM
  arbitrator. On a curated 5,258-sample subset of its 70,448-sample benchmark, the best configuration reaches 95.4% F1 at about 506
  ms per call. IntentShield's regex stage is the counterpart of its first stage. IntentShield's default path has no learned stage and
  calls no model.
- **MCPShield** (arXiv 2602.14281). Probes a server with mock calls built from its metadata, runs calls in a guarded runtime with an
  authorization scope, and scores behavioural drift. On 76 malicious servers and six backbones the defense rate rises from 10.05% to
  95.30%, and its Table 2 shows benign flag rates up to 29.41%. IntentShield neither probes nor sandboxes servers; it hides a tool whose
  description changed after the client connected.
- **Tool-Guard** (arXiv 2606.20922). Against cross-tool description poisoning it plans over "influenced" and other tools separately
  and checks each chosen call with an LLM. On AgentDojo with GPT-4o, attack success falls from 43.30% to 2.06% at about 3.7 times the
  latency. Its MCP extension is not evaluated. IntentShield quarantines a server by rules over its descriptions, with no per-call
  model check, and was run on live MCP servers.

## Benchmarks used here

- **MCPTox** (arXiv 2508.14925). 1,348 poisoned-description cases over 45 or more real servers; average attack success 36.5% across
  20 model settings. It evaluates no defense. IntentShield replays the published responses of 11 models: 0.4% attack success, 3.5%
  benign false block and 46.3% of benign calls sent to review. Its rules were written on MCPTox, so these are tuning-set figures.
- **MSB** (arXiv 2510.15994). 2,000 attack instances and 12 attack types on real MCP servers; it evaluates one detection-based
  defense, which lowered attack success from 40.35% to 28.69% and task performance from 56.50% to 48.91%. IntentShield's runs use a
  modified subset of 220 held-out cases. Executed harm was 0.0% for the gateway and the hooks, and a trivial baseline also scored
  0.0%, so that metric does not rank guards.

## Provenance and information-flow designs

- **PACT** (arXiv 2605.11039). Gives each tool argument a role and tracks every value's provenance across steps against
  role-specific trust contracts. On AgentDojo it reports 100% security on the three strongest of five models at 38.1 to 46.4%
  utility. Its automatic pipeline had 87.1% role accuracy and 77.4% provenance accuracy on 20 real MCP tools. IntentShield records
  addresses, URLs, account numbers and paths from every tool result and sends a call that carries one to review. It matches values
  and has no per-argument roles or contracts, so PACT is the more complete design.
- **ToolFence** (arXiv 2609.37196). A model compiles a per-task blueprint from the user request before any external content is read;
  a deterministic monitor checks each call against it, and a judge grants off-blueprint calls. On AgentDojo with Qwen3-max, attack
  success falls from 21.20% to 0.20% and clean utility from 42.70% to 38.90%. IntentShield has no per-task blueprint and does not
  use a model to authorize. ToolFence was evaluated on AgentDojo only.

## What is left

A head-to-head run of IntentShield and one of these guards on shared cases has not been done. The learned detectors in this repository gave negative or null results and are off by
default ([detectors.md](detectors.md)).
