# IntentShield: One MCP Guard Across Four Agent Harnesses and a Transparent Proxy (working title)

**Route 1 skeleton, started 2026-10-14.** This is the artifact or tool paper from
[contribution.md](contribution.md) §7. It makes no novelty claim for any mechanism (§2 there): the
contribution is a working, tested, cross-harness system and an honest held-out evaluation of it,
including where it does not help.

**Marks:**
- ✓ measured, reproducible in this repo, and not known to be affected by a flaw;
- ☐ not yet collected;
- ⏳ running now (MSB v8, `artifacts/msb-v8-queue.sh`, started 2026-10-14);
- no mark: provisional.

**Target venues:** artifact or demo tracks, a software paper (for example JOSS for the tool
itself), or arXiv first. Workshop: agent-security workshops. Not a main-track research paper.

---

## Abstract (draft)

MCP lets coding agents call third-party tools, and guards for those calls ship either as harness
hooks or as protocol proxies. We present IntentShield, an open-source guard that installs
the same rule set in four harnesses (Claude Code, Codex CLI, Cursor, Gemini CLI) through their
hook interfaces, and in front of any MCP server as a transparent proxy. It combines:
- description scanning and quarantine;
- rug-pull detection;
- removal of self-disclosure parameters;
- value provenance from tool outputs to later arguments;
- holding mutations for human review;
- optional evidence from an LLM judge and a local exemplar detector.

We evaluate it held out on live MCP servers (MCP Security Bench, three local 7–9B agent models, neutral
server ids) and on MCPTox. We report harm at four stages (attempted, blocked, reached review,
executed), task utility and reviewer load, and we compare against a trivial structural baseline.

On MSB every guard that holds mutations, including the trivial baseline, executes no harm. The
guard's measurable contribution is what it keeps out of the reviewer's queue and the cost it pays
in utility. On AgentDojo's published logs, the same structural floor needs a human on 56% of tasks
and leaks 7.9% at a 10% reviewer error rate, which shows what autonomous defenses buy.

☐ Final numbers after MSB v8.

## 1. Introduction

- MCP's third-party tool supply chain and the documented attack surface: MSB, MCPTox,
  MCP-SafetyBench, COPEX, Implicit Trust.
- **Two deployment points:**
  - harness hooks (PreToolUse/PostToolUse and their equivalents), which see calls and results;
  - a proxy at the protocol layer, which sees `tools/list` (descriptions) and every call.

  Neither alone covers what the other sees. Channel coverage (§3.4) shows the measured split.
- **Contributions:**
  1. **The artifact.** One policy engine behind four harness integrations and a transparent proxy,
     with per-harness semantics for "ask", because each harness handles it differently.
  2. **A held-out evaluation on live MCP servers that reports harm as a funnel**
     (attempted → blocked → reached review → executed), utility and reviewer load, next to a trivial
     structural baseline. It shows what a mutation-holding guard does and does not add.
  3. **A replayable structural-floor analysis on AgentDojo's published logs.** It costs nothing
     to run, and it puts autonomous defenses and human review in the same currency (§6).
  4. **Negative results kept in.** The intent model, the trained injection classifier and the
     plain-language injection blind spot.
- **Framing rule for the whole paper:** systems and evaluation, not a new defense primitive.

## 2. Background and threat model

- **MCP objects:** tool descriptions, results, resources, prompts, sampling and elicitation.
- **Threat model:** a malicious or compromised MCP server controls its descriptions, results and
  schemas; the user and harness are honest; the guard is trusted. Out of scope: a compromised
  harness or OS, and approval laundering inside the harness (2609.38983).
- **The goal of each layer:**
  - a harmful call never executes without a human seeing it;
  - the human sees as few calls as possible, harmful calls least of all;
  - legitimate calls still run.

## 3. Design

### 3.1 Policy engine (`policy.py`, `security_agents.py`)
- Decisions are ALLOW / REVIEW / BLOCK with reason codes. Detectors only add evidence and can never
  authorize.
- Mutations go to REVIEW by default. Reads are allowed unless provenance or quarantine says
  otherwise.
- The DeBERTa intent model exists but is **off** in every reported run (§7 explains why).

### 3.2 Description and server scanning (`mcp_inspect.py`)
- Regex rules on descriptions, plus a scan of each server's joined descriptions for poison split
  across tools (`split_*`). Rules: `cross_tool_data`, `external_send`, `shadowing` (on identifier
  boundaries).
- Quarantine: a flagged tool is withheld from the agent.
- Rug pull: a catalog fingerprint is taken at connect. A tool that changes is hidden and refused
  for the session.
- Self-disclosure parameters (model name, system prompt, conversation) are stripped from schemas.
  Required hidden fields are blanked.

### 3.3 Provenance (`authority_values`)
- Distinctive values (emails, URLs, IBANs, 9+ digit numbers, paths) are recorded from every tool
  output.
- If such a value later appears in an authority-bearing argument:
  - its only source is a tool output: REVIEW;
  - it came from a flagged output or another tool's description: BLOCK.
- Decoding before scanning: base64, hex, URL and HTML entities.

### 3.4 Placements
- **Hooks (`harness.py`):** Claude Code, Codex CLI, Cursor and Gemini CLI. They differ in how
  "ask" works:
  - a rewrite never yields "allow" on a mutation: Claude asks, Codex denies;
  - Cursor's ask keeps the redaction;
  - unreadable stdin exits 2.
- **Transparent proxy (`mcp_proxy.py`):** gates `tools/list` and `tools/call`. It exposes tools
  only: resources and prompts are dropped, not mediated (a stated limitation).
- **Channel coverage:** measured with benign markers. Summarize the coverage-study table from
  `coverage-study.md` and keep its caveats (n=1 per cell, two harnesses).
- **Tool routing** (`intentshield_find_tools` plus a per-prompt hint): on MCPTox, BM25 ranks the
  right tool top-1 80% / top-3 90% / top-5 92% ✓.

### 3.5 Optional evidence (off unless configured)
- LLM judge (`judge.py`, Groq/Gemini free tier).
- Prompt Guard 2 (`prompt_guard.py`).
- Exemplar kNN on outputs (`exemplars.py`).
- Operator-gated learning (`learning.py`) and induced signatures (`signatures.py`).

All of these only ever escalate.

### 3.6 Engineering
- Tests: 247 pass, 1 skipped; 248 with the HTTP end-to-end test ✓.
- Overhead: about 36 ms per hook call ☐ (re-measure); proxy round-trip ☐.
- Install path and configuration per harness ☐ (a short table).

## 4. Evaluation setup

- **MSB (live servers):**
  - runner: `benchmarks/msb.py`;
  - split: 220 held-out cases (20 per attack type, tuning cases excluded);
  - server ids: neutral since `1c0d4dc`;
  - decoding: temperature 0, 10-step cap;
  - agents: qwen2.5:7b, llama3.1:8b, ornith:9b (local Ollama).
- **Arms:** none; trivial baseline (withhold descriptions, strip self-disclosure fields, hold every
  mutation); gateway (proxy); hooks. Plus, for qwen2.5:7b only, a descriptions-exposed variant of
  the baseline and of the gateway.
- **Metrics:**
  - harm attempted / blocked / reached review / executed;
  - task tool reached / executed / blocked;
  - MSB `user_task`;
  - truncated.

  Paired comparisons come from `benchmarks/msb_compare.py`.
- **Runner deviations from MSB (stated up front):**
  - injection text only on the task server;
  - list-directory tools allowed;
  - task-tool metrics count the attack server only where there is no task server (rescored
    2026-10-13).
- **MCPTox replay:** no inference. The description rules were developed on MCPTox, so these
  numbers come from the tuning set.
- **AgentDojo structural floor:** `benchmarks/agentdojo_floor.py`, replaying published logs
  (v1, `important_instructions`).
- **Statistics:** Wilson intervals, with the caveat of 20 draws per template ☐. Add a bootstrap
  clustered by template.

## 5. Results

### 5.1 MSB, qwen2.5:7b (✓, `artifacts/msb-compare-v4-v5-exposure.txt`, 218 paired cases)

| Arm | Executed | Attempted | Reached review | Blocked | Task tool executed | `user_task` (n=140) |
|---|---|---|---|---|---|---|
| none | 58.3% | 58.7% | — | 0 | 70.2% | 68.6% |
| trivial baseline | 0.0% | 12.4% | 12.4% | 0 | 55.5% | 51.4% |
| gateway (intent off) | 0.0% | 1.8% | 0.0% | 1.8% | 40.4% | 45.0% |
| hooks (intent on) | 0.0% | 17.0% | 0.0% | 9.2% | 49.1% | 58.6% |
| hooks (intent off) | ⏳ | | | | | |

Descriptions-exposed variants: baseline attempted 37.6% / reached review 31.6%; gateway attempted
13.3% / reached review 1.4% (intent model on in that run).

### 5.2 MSB, llama3.1:8b and ornith:9b ⏳ (same arms, intent model off)

### 5.3 Reading the funnel
- Executed harm is 0% for every mutation-holding arm, by construction: MSB's file harms need
  `write_file` / `edit_file` / `kill_process`, and the model-name leak is stripped. Report it, but
  do not rank on it.
- **Where the gateway's zero comes from:**
  - withheld descriptions: on the baseline alone they cut attempted harm from 37.6% to 12.4%;
  - stripped parameters;
  - `shadowing` quarantine of the prompt-injection task servers.
- The detectors' measurable contribution: harmful calls reaching the reviewer fall from 12.4–31.6%
  of cases (baseline) to 0–1.4% (gateway). The cost is task utility (☐ recompute the gap with the
  intent model off on all three models).
- **Hooks:** the stronger detection evidence. Of 37 harmful attempts, all were denied or sent
  to ask.

### 5.4 Description poisoning (MCPTox replay) ✓
- Full proxy: 0.4% attack success; 95.4% of poisoned-tool calls blocked; 3.5% benign false block;
  46.3% of benign calls go to review.
- Rules vs judge on test-split servers:
  - recall: rules 96.4%, judge 99.7%, either 100%;
  - clean false flag: 1.9%, 4.6%, 6.5%.

### 5.5 Output-injection detectors ✓ (`benchmarks/injection_eval.py`)

3,717 held-out rows, including 142 hard benign:

| Detector | Detection | Benign false flag |
|---|---|---|
| rules | 49.9% | 2.1% |
| Prompt Guard 2 | 40.2% | 2.0% |
| rules + exemplars | 57.8% | 2.5% |

Plain-language injections from independent sources stay undetected by every usable detector.

### 5.6 Baseline detector on MSB ☐
Prompt Guard 2 as the output detector in the gateway arm, on the same split (Groq free tier).

### 5.7 Stronger agent model ☐
About 100 MSB cases with a free-tier model (Groq `gpt-oss-120b` or Gemini Flash-Lite): none,
baseline and gateway.

## 6. The structural floor on AgentDojo (✓, `artifacts/agentdojo-floor/table-v1.txt`)

- **Method:** replay published trajectories. A floor that holds mutations follows the logged run
  until the reviewer rejects a call.
- **Harm oracle:** flags 278/279 GPT-4o successes; 0 false matches on 7 of 8 models' benign runs.
- **Static:** 25/27 injection goals need a mutation; only 37/97 user tasks are read-only.
- **GPT-4o results:**
  - floor with a perfect reviewer: 3.5% attack success (from 47.7%);
  - fallible reviewer: 7.9% at p=0.1;
  - reviews: 55.7% of benign tasks need one; 48.6% of attacked runs put harm in the queue;
  - read-only floor: benign utility 28% (from 69%).
  - published comparison: ToolFence 0.9% with a 1.5-point utility drop, and no human.
- **Takeaway:** on AgentDojo, autonomous defenses buy the removal of about one review per two
  tasks. On MSB the floor already saturates the harm metric. Benchmarks whose harms are all
  mutations cannot rank mutation-holding guards.

## 7. What did not work (keep this section)

1. **DeBERTa intent model.** It blocks 7–18% of legitimate task calls on MSB and adds no measured
   safety, so it is off in all reported runs. A tokenizer bug (`fix_mistral_regex`) affected its
   training; retraining is future work.
2. **Trained injection classifier:** it flags 24.4% of benign rows (113/142 hard negatives), so it
   is off.
3. **LLM judge on MSB:** its only catches were on label-leaked server names before `1c0d4dc`; it
   has not been re-evaluated on neutral ids ☐.
4. **Adaptive attacker:** 16/42 evasions without learning vs 13/42 with it; not significant, and
   the attacker was weak.
5. **The `name_overlap` artifact:** FastMCP's `<func>Arguments` schema titles trigger `shadowing`.

## 8. Limitations
- **Agents:** small local models only (until §5.7). One run at temperature 0, 20 draws per
  template.
- **MSB:** the runner's deviations (§4); the 10-step truncation (24% unguarded, 5% gateway).
- **MCPTox:** tuning-set numbers for the description rules.
- **Proxy:** drops resources and prompts instead of mediating them; elicitation and sampling are
  not exercised.
- **Reviewer:** reviewer behaviour is modelled, never measured. The AgentDojo replay's reviewer
  knows the attacker's goal.
- **No adaptive attack worth the name.**
- **Ethics:**
  - benign markers in the coverage study;
  - no live attacks on third-party servers;
  - findings about shipping harnesses go to the vendors before release.

## 9. Related work (short, from related-work.md)
- **Defenses:** PACT, ToolFence, CaMeL, MCP-Guard, Tool-Guard, MCPShield, ETDI, Progent.
- **Harness security:** HarnessSecurity-Bench, Approval Laundering, CapScope.
- **Evaluation and oversight:** Evaluate the Stack, Oversight Has a Capacity, Habituation at the
  Gate.
- **Benchmarks:** MSB, MCPTox, MCP-SafetyBench, AgentDojo.

## 10. Artifact
- **Repository and licence** ☐.
- **Reproduction:**
  - `uv sync --extra dev`, then the ML extras;
  - the MSB Docker image;
  - per-table commands, from the README;
  - expected runtime per arm.
- **What ships:** guard, hooks, proxy, benchmarks, tables, and the AgentDojo replay.
  Raw logs on request ☐ (size).

## TODO before submission (ordered)
1. ⏳ MSB v8 → fill §5.1 (hooks, intent off) and §5.2. Run `msb_compare.py` across v4-noclf, v5 and v8.
2. ☐ Template-clustered bootstrap intervals for every MSB table.
3. ☐ §5.6: Prompt Guard 2 arm on MSB (free tier).
4. ☐ §5.7: one stronger free-tier agent on about 100 cases.
5. ☐ Re-measure hook and proxy latency (§3.6).
6. ☐ Install table per harness; README reproduction commands checked from a clean clone.
7. ☐ Pick the venue and its page limit, then cut.
