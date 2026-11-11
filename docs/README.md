# IntentShield documentation

Start with the [README](../README.md) in the repository root. The files here are the reference behind it.

Where to go next, by what you want:

- **To use the tool:** [guide.md](guide.md) for running it and [layers.md](layers.md) for what each part sees and stops.
- **To judge the research:** [contribution.md](contribution.md) says what the work supports and does not, and
  [hook-fidelity-report.md](hook-fidelity-report.md) is the short report of the one study. The other `hook-fidelity-*`
  files and `research-notes/` are the full record and history behind those two; read them only to audit a number.
- **To change the code:** [CONTRIBUTING.md](../CONTRIBUTING.md), then [architecture-and-testing.md](architecture-and-testing.md).

## Using IntentShield

- [layers.md](layers.md): what each placement of the guard (hooks, transparent proxy, gateway) sees and stops, what `install`, `wrap`, `scan` and the judge options do in full, and the upstream configuration.
- [guide.md](guide.md): guarding Claude Code, Codex CLI, Cursor and Gemini CLI with hooks and the transparent proxy, what to do when the guard blocks something legitimate, wrapping a third-party hook, troubleshooting, threat memory and packs, then the gateway, production settings, the dashboard and the REST API.
- [benchmarks.md](benchmarks.md): every benchmark protocol and table (MSB, MCPTox, InjecAgent, AgentDojo, judge, self-disclosure, live harness checks, replayed incidents) and the limits of each.
- [detectors.md](detectors.md): the optional learned detectors, their training, evaluation, negative results, the adaptive attacker and how the operator teaches them.
- [security-review.md](security-review.md): the 2026-10-30 review of the guard itself, with each finding's severity and status, the measured effect of the fixes and what is still open.

Project files in the repository root: [CHANGELOG.md](../CHANGELOG.md), [CONTRIBUTING.md](../CONTRIBUTING.md), [SECURITY.md](../SECURITY.md) (reporting, scope, and what the guard stores on your machine), [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md), [CITATION.cff](../CITATION.cff).

## For contributors

- [architecture-and-testing.md](architecture-and-testing.md): the module map (every module in `src/intentshield/`), the entry paths, the test inventory by area, setup, manual walkthroughs and failure diagnosis.

## The hook verdict fidelity study

The report is the entry point; the other files are the appendix with the full record.

- [hook-fidelity-report.md](hook-fidelity-report.md): the entry point. What Claude Code, Codex CLI and Gemini CLI do with the verdict a hook returns, what was measured, and the limits of the result.
- [hook-fidelity-study.md](hook-fidelity-study.md): the full study: method, every measurement, the comparison of what IntentShield and ten other guards decide, threats to validity and the disclosure plan. The built-in tool rules scored on a fresh set of 214 calls give a mixed result: fewer calls let through, but behind `safety-net` on denies alone, on a same-author set of the categories the rules were written from, so not evidence of general detection.
- [hook-fidelity-mitigation.md](hook-fidelity-mitigation.md): the verdict-translation layer in IntentShield's hook, its regression check, the `intentshield wrap-hook` shim, the process-ancestry mode detector and what the hook decides.
- [hook-fidelity-corpus.md](hook-fidelity-corpus.md): inventory of 26 published hook-based guards, the byte captures of 6 and the measured replay cells (read the headline per run, not per cell).
- [hook-fidelity-prevalence.md](hook-fidelity-prevalence.md): how many public repos run an agent headlessly beside a committed hook config.
- [hook-fidelity-stub-feasibility.md](hook-fidelity-stub-feasibility.md): the model-free stub endpoint, how each harness is pointed at it, and what the harnesses did with it.
- [hook-fidelity-coverage-rerun.md](hook-fidelity-coverage-rerun.md): which MCP surfaces reach a hook, per harness build, without a model.

## Research notes, not user docs

- [research-notes/](research-notes/README.md): historical drafts, not current claims: the artifact-paper skeleton, the earlier complete-mediation draft (its claim is not supported) and the demo-track paper source.
- [contribution.md](contribution.md): the verdict, what is claimed and not claimed, and the route that remains (two pages). The long earlier version is [research-notes/contribution-history.md](research-notes/contribution-history.md).
- [related-work.md](related-work.md): literature survey and the adaptivity plan.
- [coverage-study.md](coverage-study.md): which MCP channels a hook-scoped guard sees versus a proxy, measured with benign markers.

## Paths under `artifacts/`

Several of these documents cite files under `artifacts/` (raw run logs, dataset checkouts, trained
models). That directory is local working space and is not in the repository. The evidence the tables
rest on is committed under [`results/`](../results/README.md), which also says how each file was produced.
