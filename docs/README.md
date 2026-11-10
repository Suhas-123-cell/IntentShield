# IntentShield documentation

## Using IntentShield

- [guide.md](guide.md): running the dashboard, the Streamable HTTP gateway, the transparent proxy, the harness hooks, threat memory and packs, production settings and the REST API.
- [architecture-and-testing.md](architecture-and-testing.md): module map, entry paths, the full test sequence and failure diagnosis.
- [benchmarks.md](benchmarks.md): every benchmark protocol and table (MSB, MCPTox, InjecAgent, AgentDojo, judge, self-disclosure, live harness checks, replayed incidents) and the limits of each.
- [detectors.md](detectors.md): the optional learned detectors, their training, evaluation, negative results, the adaptive attacker and how the operator teaches them.
- [security-review.md](security-review.md): the 2026-10-30 review of the guard itself, with each finding's severity and status, the measured effect of the fixes and what is still open.
- [hook-fidelity-study.md](hook-fidelity-study.md): what Claude Code, Codex CLI and Gemini CLI do with the verdict a hook returns, measured against a stub model (headless matrix, plus round-6 head-to-head and scripted interactive cells; Cursor unmeasured), with the contribution statement and reviewer verdicts, the kill criterion, critic outcomes, related work and a novelty check (section 3.7), threats to validity, the disclosure plan and what a full paper still needs. Round 7 added a wrapped-guard control with allow and deny-all arms (6a.1) and a `ps`-free mode detector with raw-ask and captured-ask cells (6b.1); section 0 says which round-6 objections are closed. Round 8 added a head-to-head of what IntentShield and ten other guards **decide**, with effective protection per build and a post hoc benign-MCP supplement (6c; IntentShield is behind on decisions, and its one distinctive flag is provenance, not injection detection), a narrow real-model arm with a local model and one paid model (6d), the wrapped re-run, the `--on-empty allow` failure cells and the Linux `/proc` reader run (6a.1, 6b.1); section 0 carries the final reviewer's gaps table and the one supported comparative sentence. The fixes after round 8 (6e) fix the Linux PID 1 reader, add deterministic rules for built-in tool calls and score them on a fresh set of 214 calls (a mixed result: fewer calls let through, but behind safety-net on denies alone; a same-author, same-category set, not evidence of general detection).
- [hook-fidelity-corpus.md](hook-fidelity-corpus.md): inventory of 26 published hook-based guards, the byte captures of 6 and the measured replay cells (read the headline per run, not per cell).
- [hook-fidelity-prevalence.md](hook-fidelity-prevalence.md): how many public repos run an agent headlessly beside a committed hook config.
- [hook-fidelity-stub-feasibility.md](hook-fidelity-stub-feasibility.md): the model-free stub endpoint, how each harness is pointed at it, and (section 8) what the harnesses did with it.
- [hook-fidelity-coverage-rerun.md](hook-fidelity-coverage-rerun.md): which MCP surfaces reach a hook, per harness build, without a model.
- [hook-fidelity-mitigation.md](hook-fidelity-mitigation.md): the verdict-translation layer in IntentShield's hook, its held-out regression check, the round 4 critic's verdict and the round 4 control cells, the round 6 head-to-head and interactive results, and round 7: the `intentshield wrap-hook` shim (usage, the `--on-empty` choice), the `ps`-free detector sources and unknown-mode fallback, and the `ps` finding, and round 8: the `--on-empty` false-deny cost, the detector's PID-1 and node-launched blind spots, and what the hook decides.

## Research notes, not user docs

- [artifact-paper.md](artifact-paper.md): draft of the artifact paper (one guard across four harnesses and a proxy).
- [paper-draft.md](paper-draft.md): the earlier complete-mediation draft; its claim is not supported, see its status note.
- [contribution.md](contribution.md): what the repository does and does not support as a contribution, the routes to a paper, the comparison with other guards and the architecture verdict.
- [related-work.md](related-work.md): literature survey and the adaptivity plan.
- [coverage-study.md](coverage-study.md): which MCP channels a hook-scoped guard sees versus a proxy, measured with benign markers.
- [icse27-demo/](icse27-demo/): demo-track paper source and video script.

## Paths under `artifacts/`

Several of these documents cite files under `artifacts/` (raw run logs, dataset checkouts, trained
models). That directory is local working space and is not in the repository. The evidence the tables
rest on is committed under [`results/`](../results/README.md), which also says how each file was produced.
