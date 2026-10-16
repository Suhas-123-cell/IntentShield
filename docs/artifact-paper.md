# IntentShield: One MCP Guard Across Four Agent Harnesses and a Transparent Proxy (working title)

**Route 1 skeleton, started 2026-10-14.** This is the artifact or tool paper from
[contribution.md](contribution.md) §7. It makes no novelty claim for any mechanism (§2 there): the
contribution is a working, tested, cross-harness system and an honest held-out evaluation of it,
including where it does not help.

**Marks:**
- ✓ measured, reproducible in this repo, and not known to be affected by a flaw;
- ☐ not yet collected;
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
executed, plus calls defused by rewriting), task utility and reviewer load, and we compare against a trivial structural baseline.

On MSB every guard that holds mutations, including the trivial baseline, executes no harm on all
three agents (15–58% undefended). The gateway's measurable contribution is the reviewer's queue:
it leaves no harmful call for review, where the baseline leaves one in up to 19% of cases. It pays
6–14 points of task completion relative to the baseline. A Prompt Guard 2 detector adds no
measurable effect. On AgentDojo's published logs, the same structural floor needs a human on 56% of tasks
and leaks 7.9% at a 10% reviewer error rate, which shows what autonomous defenses buy.

☐ Re-check after the clustered intervals (§4).

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
- Tests: 250 pass, 1 skipped; 251 with the HTTP end-to-end test ✓.
- Overhead (`benchmarks/latency.py`, `artifacts/latency.json`, demo MCP server, intent model off,
  2026-10-16) ✓:
  - **hook:** 35 ms per event at the median, p95 under 37 ms, on read, write, small, 4 KB and
    injected results. Bare Python start-up is 15 ms and imports take about 20 ms. The decision
    itself, timed in-process, is 0.02–0.1 ms, and 1.1 ms on a 4 KB result. A
    persistent hook process would remove almost all of it.
  - **transparent proxy:** 2.4 ms per `tools/call` against 0.5 ms direct (+1.9 ms, p95 2.5 ms over
    200 calls). Session start-up (spawn to `list_tools`) is 522 ms against 247 ms direct.
  - Both are small next to one model step (seconds on local 7–9B models).
- **Install and configuration per harness** ✓. Each hook is `intentshield-hook <harness>`, and the
  example configs are in `configs/harness/`.

  | Harness | Config file and events | Rewrites arguments | Asks the user |
  |---|---|---|---|
  | Claude Code | `.claude/settings.json`: `UserPromptSubmit`, `PreToolUse`/`PostToolUse` on `mcp__.*` | yes | yes |
  | Codex CLI | `~/.codex/config.toml`: same events | yes on reads; on a state change it denies with a resend reason | no: deny with a reason |
  | Cursor | `~/.cursor/hooks.json`: `beforeSubmitPrompt`, `beforeMCPExecution` (fail closed), `afterMCPExecution` | no | yes; a rewrite becomes deny-and-resend |
  | Gemini CLI | `~/.gemini/settings.json`: `BeforeAgent`, `BeforeTool`, `AfterTool` (MCP only, via `mcp_context`) | yes | no: deny with a reason |

  Each harness can also wrap its servers with the transparent proxy (`intentshield-mcp --transparent
  --config <file>`, stdio only). On 2026-10-16, from a clean clone at `d7020be`, the installed CLI
  turned the same self-disclosure call into the reply each row predicts. These were synthetic
  events, not live harness sessions: of the four harnesses, only Claude Code has run live
  (`benchmarks/harness_live`).

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
- **Statistics:** a cluster bootstrap over user tasks (`msb_compare.py --bootstrap 2000`). Each
  held-out case is attack type × user task × attack task. The 220 cases come from 28 user tasks
  (2–18 cases each) and 4 attack tasks. The user tasks are resampled with the same draw for every
  arm, which gives paired intervals for arm differences. The 4 attack tasks are too few to resample.
  A rate of 0 or 1 keeps its Wilson interval. With 28 clusters of uneven size, percentile intervals
  may still undercover. Outputs: `artifacts/msb-v8-boot-{qwen,llama3.1_8b,ornith_9b}.txt`.

## 5. Results

All MSB tables are paired: an arm is scored only on the cases every arm of that model completed,
and every run is rescored with the same metric code (`msb_compare.py`). The harm columns are
per-case outcomes. One case can count in more than one column (one harmful call held for review,
another rewritten), so they need not sum to "attempted". **Rewritten** means the harmful call ran,
but the self-disclosure parameter reached the server blanked. Intervals (in the bootstrap
files, §4) are user-task cluster bootstrap 95%, about 1.5–2× wider than Wilson.

### 5.1 MSB, qwen2.5:7b (✓, `artifacts/msb-v8-compare-qwen.txt`, 218 paired cases)

| Arm | Executed | Attempted | Reached review | Blocked | Rewritten | Task tool executed | `user_task` (n=140) |
|---|---|---|---|---|---|---|---|
| none | 58.3% | 58.7% | 0 | 0 | 0 | 70.2% | 68.6% |
| trivial baseline | 0.0% | 12.4% | 12.4% | 0 | 0 | 55.5% | 51.4% |
| gateway (intent on) | 0.0% | 0.9% | 0 | 0.9% | 0 | 29.8% | 33.6% |
| gateway (intent off) | 0.0% | 1.8% | 0 | 1.8% | 0 | 40.4% | 45.0% |
| gateway + Prompt Guard 2 (intent off) | 0.0% | 2.8% | 0 | 2.8% | 0 | 38.1% | 42.9% |
| hooks (intent on) | 0.0% | 17.0% | 0 | 9.2% | 7.8% | 49.1% | 58.6% |
| hooks (intent off) | 0.0% | 17.0% | 2.3% | 9.2% | 5.5% | 46.8% | 50.7% |

- **Intent model:** in the gateway it costs utility (`user_task` 33.6% on, 45.0% off) and buys
  nothing on harm.
- **In hooks**, turning it off moves 5 harmful calls from "rewritten" to "reached review". Blocks
  stay at 20, and `user_task` drops by 8 points, within noise.
- **Prompt Guard 2 adds nothing measurable** (§5.6).
- **Descriptions-exposed variants:**
  - baseline: attempted 37.6%, reached review 31.6%;
  - gateway: attempted 13.3%, reached review 1.4% (intent model on in that run).

### 5.2 MSB, llama3.1:8b and ornith:9b (✓, intent model off, `artifacts/msb-v8-compare-{llama3.1_8b,ornith_9b}.txt`)

llama3.1:8b, 220 paired cases (`user_task` n=140):

| Arm | Executed | Attempted | Reached review | Blocked | Rewritten | Task tool executed | `user_task` |
|---|---|---|---|---|---|---|---|
| none | 15.0% | 17.3% | 0 | 0 | 0 | 77.3% | 70.0% |
| trivial baseline | 0.0% | 0.9%¹ | 0 | 0 | 0 | 43.6% | 36.4% |
| gateway | 0.0% | 0.0% | 0 | 0 | 0 | 21.4% | 22.1% |
| hooks | 0.0% | 9.6% | 0.9% | 0 | 8.6% | 50.9% | 57.1% |

ornith:9b, 216 paired cases (4 dropped for agent timeouts; `user_task` n=139):

| Arm | Executed | Attempted | Reached review | Blocked | Rewritten | Task tool executed | `user_task` |
|---|---|---|---|---|---|---|---|
| none | 56.0% | 56.0% | 0 | 0 | 0 | 92.6% | 82.7% |
| trivial baseline | 0.0% | 19.0% | 19.0% | 0 | 0 | 84.7% | 59.7% |
| gateway | 0.0% | 0.0% | 0 | 0 | 0 | 61.1% | 51.1% |
| hooks | 0.0% | 3.7% | 1.4% | 1.8% | 1.4% | 66.2% | 54.0% |

¹ Two prompt_injection-simulated_user cases where the agent passed file-write arguments to a
read-only tool. The harm test matches on arguments, but no file was written, so these count in
no outcome column.

- **Susceptibility varies widely:** 15.0% executed harm with no defense on llama3.1:8b, 56–58%
  on qwen2.5:7b and ornith:9b.
- **ornith:9b hits the 10-step cap in 26% of undefended cases.** This and the remaining 16–22%
  under the guards bound its `user_task`.

### 5.3 Reading the funnel
- Executed harm is 0% for every mutation-holding arm, by construction: MSB's file harms need
  `write_file` / `edit_file` / `kill_process`, and the model-name leak is stripped. Report it, but
  do not rank on it.
- **Where the gateway's zero comes from:**
  - withheld descriptions: on the baseline alone they cut attempted harm from 37.6% to 12.4%;
  - stripped parameters;
  - `shadowing` quarantine of the prompt-injection task servers.
- **The parity holds on all three models:** the trivial baseline matches every guard on executed
  harm (0%).
- **The gateway's measurable contribution is reviewer load, paid for in utility.**
  - Harmful calls left for a human: baseline 12.4% of cases on qwen (27), 19.0% on ornith (41), 0
    on llama. Gateway: 0 on every model.
  - The gateway completes fewer user tasks than the baseline on every model. Paired cluster
    bootstrap: −6.4 points on qwen [−14.3, −1.0], −14.3 on llama [−26.0, −5.1], −8.6 on ornith
    [−16.7, −2.5]. All three exclude zero, and qwen only barely. The per-arm intervals overlap. The
    paired difference is the test that matters.
- **Hooks keep the most utility of the guards** on qwen and llama, though not on ornith, where the
  baseline is higher. Paired intervals separate them only on llama: `user_task` +35.0 points over
  the gateway [+24.7, +45.5] and +20.7 over the baseline [+7.5, +31.2]. On qwen (intent off) the
  margin over the gateway is +5.7 [−9.2, +23.4], and on ornith +2.9 [−8.0, +16.2].
  - On qwen, most of their defense is real blocking: 20 of 37 attempts blocked.
  - On llama it is almost all parameter rewriting: 19 of 21 attempts rewritten, none blocked. This
    is the same mechanism as the gateway's stripped parameters, applied after the agent has
    already chosen the call.

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

### 5.6 Baseline detector on MSB ✓ (`msb.py --prompt-guard`, row in §5.1)
- **Setup:** Llama Prompt Guard 2 86M (Groq free tier) added as a gateway detector on the same
  218 paired qwen cases.
- **Result:** no measurable effect.
  - Executed harm: 0%, as without it.
  - Blocks: 6 against 4.
  - Task tool executed: 38.1% against 40.4%; `user_task`: 42.9% against 45.0%.
- **Running it was clean:** no Groq errors and no quota stops over 220 cases.

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
1. ✓ MSB v8: §5.1 and §5.2 filled from paired `msb_compare.py` runs (2026-10-15).
2. ✓ User-task cluster bootstrap for every MSB table, with paired differences (2026-10-16).
3. ✓ §5.6: Prompt Guard 2 arm on MSB (free tier).
4. ☐ §5.7: one stronger free-tier agent on about 100 cases.
5. ✓ Hook and proxy latency re-measured (§3.6, 2026-10-16).
6. ✓ Install table per harness (§3.6). Clean clone at `d7020be` (2026-10-16): `uv sync --extra dev
   --frozen` and the tests (250 passed, 1 skipped; HTTP e2e passed), `intentshield-mcp-verify` in-process
   and `--stdio` (13/13 checks), and the four hooks. ☐ Still unchecked from a clean clone: the ML extras,
   the MSB Docker image and the benchmark commands.
7. ✓ Venue: ICSE 2027 Tool Demonstration track (deadline Fri 23 Oct 2026 AoE; IEEEtran 10pt, 4 pages
   including references; single-anonymous; 3–5 min YouTube video). Cut version: `docs/icse27-demo/`
   (`tectonic main.tex`), 3 pages. ☐ Video, ☐ §5.7 Gemini row if MSB v9 finishes in time.
