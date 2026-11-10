# Gemini CLI hook-runner sweep (no model, no network at run time)

`driver.mjs` imports `HookRunner`, `HookAggregator` and `HookEventHandler` from a published `@google/gemini-cli-core` and runs
BeforeTool command hooks for 34 scripted replies (24 single-hook replies, then reply-space gaps, a missing interpreter on PATH,
a grandchild that holds the pipe past the timeout, and four two-hook combinations). Each version is installed into its own empty
npm prefix with `--ignore-scripts`; hook scripts are written by the driver, nothing downloaded is a hook.

* Layer A is `HookRunner.executeHook` + `HookAggregator.aggregateResults`; layer B is `HookEventHandler.fireBeforeToolEvent` with a
  stub planner (the real handler, one or two hook configs) and a stub config. They agreed on every row, but both use the same
  runner and aggregator, so the agreement is a **plumbing check only**, not independent validation.
* The proceed/deny class comes from the aggregated `finalOutput` methods that the scheduler itself calls (`shouldStopExecution`,
  `getBlockingError`, `isAskDecision`); read in 0.20.2, 0.29.7, 0.30.0, 0.35.3 (hook fires in `executeToolWithHooks`) and HEAD
  (`evaluateBeforeToolHook`). The scheduler, the tools, `HookSystem`/`HookRegistry`/`HookPlanner` (matcher selection, trust, enable
  flags, `sequential`, dedupe) are **not** run.
* `ask` is reported as `ask/ask-kept`: the aggregator kept the ask. That is NOT a statement about prompting. The consumer reads it
  afterwards (see "Not covered" in docs/hook-fidelity-study.md section 12).

Not exercised: the 60 s default timeout; stdin payload fields `mcp_context` and `original_request_name`; Windows (the 126/127 split and
the error text come from bash on macOS; Windows runs hooks under PowerShell with an appended exit-code line); environment redaction
(the stub config has it off, which is the core default; the CLI settings may override). Boundaries are exact only between the
SAMPLED releases (25 of them; 0.24.5, 0.33.2 and 0.38.2 were added in round 3 because their hook-runner files differ from their
neighbours', see `results/hook-fidelity/gemini-core/boundary.md`; the other unsampled minors and previews between two samples are
covered only by that file comparison). Hooks are opt-in before 0.26.0: the core default `enableHooks` is false in 0.20.2, 0.22.5 and
0.25.2, and the CLI package of 0.24.5 needs `hooks.enabled: true` (default false; from 0.26.0 `hooksConfig.enabled` defaults true), which
the end-to-end runs in `results/hook-fidelity/gemini` measure (a deny hook with no enable key is not invoked on 0.24.5, 2/2 runs).

Run: `SWEEP_DIR=<empty scratch dir> RESULTS_DIR=results/hook-fidelity/gemini-core ./install_and_run.sh`. `table.py RAW OUT [SWEEP_DIR]`
makes `table.md` (grouped), `table-per-version.txt`, `manifest.json` (npm integrity hash of every installed core package) and a scrubbed
copy of the raw rows in `OUT/raw/`. The per-run stderr logs of the runner (`raw/<version>.stderr.txt`, about 3 kB of the runner's own
log lines each) stay in the scratch directory and are not committed.

## Round 3 additions (no model, no network at run time)

* `layer_c.mjs`: layer C, the **real** `HookSystem` (registry, planner with its matcher, runner, aggregator, event handler) built on a
  real `Config` from a settings-shaped `hooks.BeforeTool` config. It runs the same 34 replies as `driver.mjs` (shared through
  `scenarios.mjs`) and adds multi-group and `sequential` aggregation, dedupe, 16 matcher cases against the tool names a hook sees
  (exact, substring, Claude-style names, `*`, empty, absent, invalid regex), folder trust (`folderTrust` on, folder trusted or not)
  and the Config default of `enableHooks`. `hook-runs` counts the hook processes that actually ran.
* `consumer_probe.mjs`: the consumer side, per release from 0.36.0 (before that the runner turns `ask` into `allow`, so no consumer
  ever sees one). A real `Config` with the real default policies (`createPolicyEngineConfig`), the real `ShellTool`, a real
  `DiscoveredMCPTool` whose server connection is an in-process stub, and the real `Scheduler`. Scenarios: tool (shell, MCP) x approval
  mode (default, yolo) x interactive or headless x hook reply (none, allow, ask, deny) x MCP `trust`; MCP `mcp.allowed`, an in-session
  allowlist, an untrusted folder, an argument-scoped policy DENY, `tools.exclude`; and `direct|...` rows that call the invocation's own
  `shouldConfirmExecute(signal, forcedDecision)`. `PROMPT-WAIT` means the call reached `awaiting_approval` and nothing answered within
  `PROBE_WAIT_MS` (5 s here); it is a bounded wait, not proof of an unbounded one (the end-to-end runs in `results/hook-fidelity/gemini`
  measure that).
* `run_consumer.sh`: runs both for a list of versions in parallel, each under its own isolated `HOME` and `TMPDIR` (the probes never
  read or write the real `~/.gemini`: an early run without that read the user's `GEMINI.md`, which is why it is enforced).
* `boundary_scan.sh`: `npm pack` (no install, no scripts) of every non-nightly release in a range and sha256 of `hookRunner.js`,
  `hookAggregator.js`, `hookEventHandler.js`. `table.py` turns the rows into `boundary.md`: where the files change.
* `registry_integrity.sh`: `npm view @google/gemini-cli-core@<v> dist.integrity` for each release; `table.py` stores it next to the
  integrity of the scratch install in `manifest.json` and says whether they agree.
* `table.py RAW OUT [SWEEP_DIR]`: the grouped table, per-version table, manifest, `table-layer-c.md`, `table-consumer.md` and
  `boundary.md`, all from files under `RAW` (`RAW/*.jsonl`, `RAW/layerc/`, `RAW/consumer/`). Behaviour changes are worded as "between
  sampled releases X and Y".

Limits that apply to all of it: the 126 and 127 exit codes and the error text are bash on macOS (Windows runs hooks under PowerShell
with an appended exit-code line: unmeasured); environment redaction is the core default (off) in the stub config, the CLI settings
may turn it on; the stdin payload fields `mcp_context` and `original_request_name` are not exercised by `driver.mjs` (the scheduler
probe sends them through the real handler); the default 60 s hook timeout is not exercised (a 1.5 s timeout is). Boundaries are exact
only between SAMPLED releases; `boundary.md` shows which unsampled releases carry the same runner files, and says nothing about
files other than the three hashed.

