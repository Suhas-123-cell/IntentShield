# MCP guardrail plan

Goal: IntentShield guards every place an attack can enter an MCP agent: tool
descriptions (before any call), tool calls and their arguments, and tool outputs.
Each phase ships code, tests, and a measurable benchmark hook. Status is kept here.

## Phase 1: Tool-description layer (poisoning, rug pull, shadowing) - done

- `mcp_inspect.scan_description`: deterministic poisoning rules over each upstream
  tool's description and schema annotation text: instruction override, hidden
  `<IMPORTANT>`-style directives, cross-tool directives ("before calling X, call Y"),
  concealment from the user, sensitive paths, argument overrides, priority claims.
- Quarantine: a flagged tool stays registered for audit, is shown as unavailable
  in the catalog, and any call is blocked (`BLOCK_TOOL_QUARANTINED`).
- Shadowing: a description that names another server's tool is flagged.
- Rug pull: the drift fingerprint covers description, title and annotations,
  not only the input schema; any change fails closed.
- Measure: false-flag rate on MCPTox's 45 real servers' clean descriptions;
  detection rate on its poisoned descriptions.

## Phase 2: Tool-output layer (indirect injection) - done

- `mcp_inspect.scan_output`: injection rules over every upstream result.
- A hit records `MCP_OUTPUT_INJECTION` and taints the run with the output's
  distinctive values (emails, URLs, account numbers, paths, long identifiers).
- The result is still returned, marked `injection_detected` with findings, so
  the agent and operator see it.

## Phase 3: Tool-call layer (argument provenance) - done

- A call whose arguments carry a distinctive value the user never gave is blocked
  (`BLOCK_UNTRUSTED_ARGUMENT_SOURCE`) when that value comes from a tainted output
  in the same run or from another tool's description. This targets
  intent-consistent attacks: the right action with an attacker-chosen argument.
- Wired through two service hooks (`pre_policy_check`, `result_inspector`) so the
  policy engine stays pure and the plain gateway is unchanged.

## Phase 4: Benchmarks on the real layers - done (see README)

- MCPTox: score with the description scanner and provenance check, no new model
  calls (cached generations), poisoned vs withheld.
- InjecAgent: scan the injected tool response, taint, then judge the attacker call.
- README: per-attack-type tables. Provenance is covered by proxy tests
  (`tests/test_mcp_guardrail.py`), not yet by the offline harness.

## Findings that set the next phase

- Description layer: 1.3% attack success, 3.5% benign false block on MCPTox's
  11-model replay (tuning set). Needs a held-out benchmark next.
- Output layer misses plain-request injections (InjecAgent base: 0-4% flagged).
  Next step is a semantic detector, not more regex.
- Intent grounding without operator terms falsely blocked ~40% of benign calls on
  third-party servers. Measured (2026-10-06, MCPTox replay, lenient reads):
  - Most of it was the runner's read/mutation guess (first `_` word only, so
    `codacy_get_*` and `list-recent-contacts` were mutations). Fixed in the runner:
    call-layer false block 38.1% -> 23.9%, full proxy 41.4% -> 27.3%, full-proxy
    attack success unchanged at 0.4%.
  - Grounding terms from clean descriptions: only -0.9 points, and they hand
    untrusted text a say in grounding. Dropped.
  - What is left (1,174 calls) is all ungrounded mutations: 88% have no listed write
    verb ("click", "fill"), 12% no tool term. Dropping the verb requirement would
    send 900 of them to review, along with 252 attacks (review, never allow).
  - Decided: ungrounded mutations go to REVIEW, not BLOCK (an ungrounded recipient,
    negation or hard failure still blocks). Full proxy: 3.5% false block, but 46%
    of benign calls now wait on a reviewer. Reviewer load is the next cost to cut.

## Phase 6: Harness guard - done (live runs pending outside Claude Code)

- `intentshield-hook <claude|codex|cursor|gemini>`: one guard behind each harness's
  prompt / pre-call / post-call hooks. Session intent and taint are kept in SQLite.
  Self-disclosure args are blanked, injected or tainted args are denied, and
  mutations after a tainted output are asked (Codex has no ask, so they are denied).
- `intentshield-mcp --transparent --config ...`: proxy that exposes upstream tools
  under their own names, hides quarantined or drifted tools, redacts schemas, and
  marks injected outputs.
- Live Claude Code (Haiku, `benchmarks/harness_live/`): the model name leaked in 3 of 3
  unguarded runs and in 0 of 3 guarded runs.

## Phase 6: Harness guard - done (live runs pending outside Claude Code)

- `intentshield-hook <claude|codex|cursor|gemini>`: one guard behind each harness's
  prompt / pre-call / post-call hooks. Session intent and taint are kept in SQLite.
  Self-disclosure args are blanked, injected or tainted args are denied, and
  mutations after a tainted output are asked (Codex has no ask, so they are denied).
- `intentshield-mcp --transparent --config ...`: proxy that exposes upstream tools
  under their own names, hides quarantined or drifted tools, redacts schemas, and
  marks injected outputs.
- Live Claude Code (Haiku, `benchmarks/harness_live/`): the model name leaked in 3 of 3
  unguarded runs and in 0 of 3 guarded runs.

## Phase 5: External benchmarks - in progress

Decided 2026-10-06: Gemini + local backbones; live MCP benchmarks in Docker, keyless
servers first.

- MSB - done (2026-10-09/10), tuned then held out. `benchmarks/msb.py` drives MSB's
  real servers in a Docker sandbox through the proxy, each agent-side injection moved
  to the server boundary; keyless subset 960 of 1,600 cases.
  - Tuning sample (236, seed 0): first pass left 6.8% / 3.8% harm (qwen2.5:7b /
    llama3.1:8b) through out-of-scope parameters. Fixed with self-disclosure parameter
    redaction, output rules for impersonation / task hijack / "you must follow", and
    lenient reads in the proxy. Tuning harm 0.0% on both models.
  - Held-out (220 cases outside the tuning sample, code frozen at `05bb91a`): harm
    executed 0.0% [0, 1.7] in all four guarded configs, against 51.4% and 21.8%
    unguarded. Task tool reached 58-66% vs 83-91%; the gap is mostly the three PI
    types, whose task tool is itself poisoned and quarantined.
  - Same templates on both splits: generalization to other wording is AgentDojo
    (important_instructions 0% -> 100% flagged) and InjecAgent (base still 0-3%).
  - Ornith-1.5-9B (third backbone, held-out): 52.7% harm unguarded with 98.6% task
    tool use, 0.0% [0, 1.7] guarded with 67.1% reached (219 scored; one case fails
    in Ollama with a 500 every time).
  - Harness hook path (`--defense hooks`, Claude Code adapter + transparent proxy), same
    held-out cases: 0.0% harm on all three backbones; task tool executed 64-69%.
  - Next: live Codex, Cursor and Gemini CLI runs; plain-language injections (InjecAgent
    base) need a semantic detector.
- Adaptive attacks - first pass done. `benchmarks/adaptive.py`: zero-width and
  look-alike rewrites evaded the description rules (10.4% / 49.8% still flagged)
  until Unicode normalization (100%). Paraphrase keeps 98.6% only via shadowing;
  the rules alone keep 42.7%.
- AgentDojo all suites - partial. 8 user x 4 injection tasks per suite on
  qwen2.5:7b: slack attack success 31.3% -> 15.6% (utility 75% -> 50%); travel and
  workspace are 0% utility even undefended, so they need a stronger model.
  Gemini blocked: the key is free tier (5 requests/min), and AgentDojo's Google
  client drops Gemini 3.x thought signatures. Needs billing or a patched client.
- MCP-SafetyBench - cloned, not run: real GitHub and other servers; needs a test
  GitHub account and keys.
- Backbones: qwen2.5:7b, llama3.1:8b local; Gemini pending quota.
- Published baselines (Task Shield etc.) - not started.
- Benign MCP workload (MCP-Universe / MCP-Bench) - not started; needs keys.
