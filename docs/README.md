# IntentShield documentation

Start with the [README](../README.md) in the repository root. The files here are the reference behind it.

**Which files are which.** Word counts are from `wc -w`.

- **Product documentation** (using, checking and changing the tool), about 68,500 words in all: the [README](../README.md),
  [guide.md](guide.md), [layers.md](layers.md), [gateway.md](gateway.md), [detectors.md](detectors.md), [benchmarks.md](benchmarks.md),
  [security-review.md](security-review.md), [architecture-and-testing.md](architecture-and-testing.md),
  [CONTRIBUTING.md](../CONTRIBUTING.md), [SECURITY.md](../SECURITY.md) and [CHANGELOG.md](../CHANGELOG.md). A user needs only the
  README and the guide, about 12,900 words.
- **Research write-ups** (what the measurements support), about 14,100 words: [contribution.md](contribution.md), the
  [hook study report](hook-fidelity-report.md) and its [appendix](hook-fidelity-report-appendix.md), [related-work.md](related-work.md)
  and [coverage-study.md](coverage-study.md).
- **Working notes** are not in this tree. The study's working record, the earlier long version of the verdict and superseded
  drafts are kept on the [`research-notes` branch](https://github.com/Suhas-123-cell/IntentShield/tree/research-notes/docs/research-notes). You need not read them. They are there so that a number can be
  traced to the runs behind it, and nothing in the product documentation depends on them. The data they refer to is under
  [`results/`](../results/README.md). `hook-fidelity-archive/` here holds copies of vendor documentation pages.

**A reading path** for someone judging the work. Word counts are from `wc -w`; times assume 250 words a minute.

| step | what you get | words | minutes |
|---|---|---|---|
| the [README](../README.md) down to Results | what it does, its threat model, how to install it, what it stops and does not stop, what is stored locally | 1,170 | 5 |
| [contribution.md](contribution.md) | what the work does and does not support as a research contribution | 1,420 | 6 |
| [hook-fidelity-report.md](hook-fidelity-report.md) | the one study: method, version matrix, four findings, the guard comparison, limits | 2,780 | 11 |
| all three | | 5,370 | 22 |

The first two steps alone take 11 minutes. The report's three tables count for about 560 of its words, with their pipe characters,
and its [appendix](hook-fidelity-report-appendix.md) (5,250 words) holds the denominators, the per-build detail and the long caveats. Everything
else is reference to look up a number or a protocol.

Where to go next, by what you want:

- **To use the tool:** [guide.md](guide.md) for running it and [layers.md](layers.md) for what each part sees and stops.
- **To judge the research:** the reading path above, then [Background and research](#background-and-research). The working notes
  on the `research-notes` branch are the full record behind it; read them only to audit a number.
- **To change the code:** [CONTRIBUTING.md](../CONTRIBUTING.md), then [architecture-and-testing.md](architecture-and-testing.md).

## Using IntentShield

- [layers.md](layers.md): what each placement of the guard (hooks, transparent proxy, gateway) sees and stops, what `install`, `wrap`, `scan` and the judge options do in full, and the upstream configuration.
- [guide.md](guide.md): guarding Claude Code, Codex CLI, Cursor and Gemini CLI with hooks and the transparent proxy, what to do when the guard blocks something legitimate, wrapping a third-party hook, scanning the servers you use, troubleshooting, and threat memory and packs.
- [gateway.md](gateway.md): the gateway (an MCP server your agent calls through `intentshield_call`), the dashboard, the REST API, production settings and the Gemini proposal path.
- [benchmarks.md](benchmarks.md): every benchmark protocol and table (MSB, MCPTox, InjecAgent, AgentDojo, judge, self-disclosure, live harness checks, replayed incidents) and the limits of each.
- [detectors.md](detectors.md): the optional learned detectors, their training, evaluation, negative results, the adaptive attacker and how the operator teaches them.
- [security-review.md](security-review.md): the 2026-10-30 review of the guard itself, with each finding's severity and status, the measured effect of the fixes and what is still open.

Project files in the repository root: [CHANGELOG.md](../CHANGELOG.md), [CONTRIBUTING.md](../CONTRIBUTING.md), [SECURITY.md](../SECURITY.md) (reporting, scope, and what the guard stores on your machine), [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md), [CITATION.cff](../CITATION.cff).

## For contributors

- [architecture-and-testing.md](architecture-and-testing.md): the module map (every module in `src/intentshield/`), the entry paths, the test inventory by area, setup, manual walkthroughs and failure diagnosis.

## The hook verdict fidelity study

The report is the entry point. The other files are working notes with the full record, kept so a number in the report
can be traced to the runs behind it. They are on the `research-notes` branch, in [hook-fidelity/](https://github.com/Suhas-123-cell/IntentShield/tree/research-notes/docs/research-notes/hook-fidelity).

- [hook-fidelity-report.md](hook-fidelity-report.md): what Claude Code, Codex CLI and Gemini CLI do with the verdict a hook returns, what was measured, and the limits of the result.
- [hook-fidelity-report-appendix.md](hook-fidelity-report-appendix.md): the report's denominator variants, per-build detail, rescoring and long caveats.
- [hook-fidelity-study.md](https://github.com/Suhas-123-cell/IntentShield/blob/research-notes/docs/research-notes/hook-fidelity/hook-fidelity-study.md): the full study: method, every measurement, the comparison of what IntentShield and ten other guards decide, threats to validity and the disclosure plan. Written as a working record, with its own vocabulary.
- [hook-fidelity-mitigation.md](https://github.com/Suhas-123-cell/IntentShield/blob/research-notes/docs/research-notes/hook-fidelity/hook-fidelity-mitigation.md): the verdict-translation layer in IntentShield's hook, its regression check, the `intentshield wrap-hook` shim, the process-ancestry mode detector and what the hook decides.
- [hook-fidelity-corpus.md](https://github.com/Suhas-123-cell/IntentShield/blob/research-notes/docs/research-notes/hook-fidelity/hook-fidelity-corpus.md): inventory of 26 published hook-based guards, the byte captures of 6 and the measured replay cells (read the headline per run, not per cell).
- [hook-fidelity-prevalence.md](https://github.com/Suhas-123-cell/IntentShield/blob/research-notes/docs/research-notes/hook-fidelity/hook-fidelity-prevalence.md): how many public repos run an agent headlessly beside a committed hook config.
- [hook-fidelity-stub-feasibility.md](https://github.com/Suhas-123-cell/IntentShield/blob/research-notes/docs/research-notes/hook-fidelity/hook-fidelity-stub-feasibility.md): the model-free stub endpoint, how each harness is pointed at it, and what the harnesses did with it.
- [hook-fidelity-coverage-rerun.md](https://github.com/Suhas-123-cell/IntentShield/blob/research-notes/docs/research-notes/hook-fidelity/hook-fidelity-coverage-rerun.md): which MCP surfaces reach a hook, per harness build, without a model.

## Background and research

- [contribution.md](contribution.md): the verdict, what is claimed and not claimed, and the route that remains (two pages). The long earlier version is [contribution-history.md](https://github.com/Suhas-123-cell/IntentShield/blob/research-notes/docs/research-notes/contribution-history.md).
- [related-work.md](related-work.md): literature survey and the adaptivity plan.
- [coverage-study.md](coverage-study.md): which MCP channels a hook-scoped guard sees versus a proxy, measured with benign markers.
- [research-notes branch](https://github.com/Suhas-123-cell/IntentShield/tree/research-notes/docs/research-notes): archived. Historical drafts, not current claims: the artifact-paper skeleton, the earlier complete-mediation draft (its claim is not supported) and the demo-track paper source.

## Files that are not in the repository

Some of the working notes cite raw run logs, dataset checkouts and trained models under `artifacts/`. That directory is the
author's local working space and is not in the repository. The evidence the tables rest on is committed under
[`results/`](../results/README.md), which also says how each file was produced.
