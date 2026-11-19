# IntentShield documentation

Start with the [README](../README.md) in the repository root. The files here are the reference behind it.

## How it works in 60 seconds

IntentShield puts one set of rules in three places. Each place sees different things, so each stops different things.

| placement | set up with | what it sees | what it stops | what it cannot see |
|---|---|---|---|---|
| **Hook** | `intentshield install <harness>` | the user's real prompt, and every MCP call and result (also shell, file and web calls with `--builtin-tools`) | injected instructions in a call's arguments; a value that came only from a tool result; credentials the user did not give; with `--builtin-tools`, dangerous commands ([rules](rules.md)) | tool descriptions. A harness can skip a hook that is untrusted or runs past its timeout |
| **Proxy** (stdio servers) | `intentshield wrap <file>` | the server's tool descriptions, schemas and results | poisoned or changed descriptions, injected results, parameters that ask for the model's name or prompt | the user's prompt, and servers reached over HTTP |
| **Gateway** | `intentshield-mcp` | the request the model states, and every call it routes through `intentshield_call` | any call outside the policy; a state-changing call waits for a human | a call the model does not route through it |

The hook answers allow, ask or deny. The proxy hides or flags and never asks. The gateway reports ALLOW, REVIEW or BLOCK. Details, per
harness: [layers.md](layers.md#what-each-layer-sees-and-stops).

## Which files are which

- **Product documentation** (using, checking and changing the tool): the [README](../README.md),
  [guide.md](guide.md), [rules.md](rules.md), [layers.md](layers.md), [gateway.md](gateway.md), [detectors.md](detectors.md),
  [benchmarks.md](benchmarks.md), [security-review.md](security-review.md),
  [architecture-and-testing.md](architecture-and-testing.md), [CONTRIBUTING.md](../CONTRIBUTING.md), [SECURITY.md](../SECURITY.md)
  and [CHANGELOG.md](../CHANGELOG.md). A user needs only the README and the guide.
- **Research write-ups** (what the measurements support): [contribution.md](contribution.md), the
  [hook study report](hook-fidelity-report.md) and its [appendix](hook-fidelity-report-appendix.md), [related-work.md](related-work.md)
  and [coverage-study.md](coverage-study.md).
- **Working notes** are not in this tree. The study's working record, the earlier long version of the verdict and superseded
  drafts are kept on the [`research-notes` branch](https://github.com/Suhas-123-cell/IntentShield/tree/research-notes/docs/research-notes). You need not read them. They are there so that a number can be
  traced to the runs behind it, and nothing in the product documentation depends on them. The data they refer to is under
  [`results/`](../results/README.md). `hook-fidelity-archive/` here holds copies of vendor documentation pages.

**A reading path** for someone judging the work. Word counts are from `wc -w`; times assume 250 words a minute.

| step | what you get | words | minutes |
|---|---|---|---|
| the [README](../README.md) down to Results | what it does, how to install it, its threat model, what it stops and does not stop, where the documents are, what is stored locally | 1,619 | 6 |
| [contribution.md](contribution.md) | what the work does and does not support as a research contribution | 1,784 | 7 |
| [hook-fidelity-report.md](hook-fidelity-report.md) | the one study: method, version matrix, four findings, the guard comparison, limits | 3,102 | 12 |
| all three | | 6,505 | 26 |

The first two steps alone take 13 minutes. The report's [appendix](hook-fidelity-report-appendix.md) holds the denominators, the
per-build detail and the long caveats. Everything else is reference to look up a number or a protocol.

Where to go next, by what you want:

- **To use the tool:** [guide.md](guide.md) for running it and [layers.md](layers.md) for what each part sees and stops.
- **To judge the research:** the reading path above, then [Background and research](#background-and-research). The working notes
  on the `research-notes` branch are the full record behind it; read them only to audit a number.
- **To change the code:** [CONTRIBUTING.md](../CONTRIBUTING.md), then [architecture-and-testing.md](architecture-and-testing.md).

## Using IntentShield

- [layers.md](layers.md): what each placement of the guard (hooks, transparent proxy, gateway) sees and stops, what `install`, `wrap`, `scan` and the judge options do in full, and the upstream configuration.
- [guide.md](guide.md): guarding Claude Code, Codex CLI, Cursor and Gemini CLI with hooks and the transparent proxy, what to do when the guard blocks something legitimate, wrapping a third-party hook, scanning the servers you use, troubleshooting, and threat memory and packs.
- [rules.md](rules.md): what the hook denies and asks about for shell, file and web tools (`--builtin-tools`), as tables by command class, and the limits on what it reads.
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
- [related-work.md](related-work.md): the ten closest published works and how IntentShield differs from each.
- [coverage-study.md](coverage-study.md): which MCP channels a hook-scoped guard sees versus a proxy, measured with benign markers.
- [research-notes branch](https://github.com/Suhas-123-cell/IntentShield/tree/research-notes/docs/research-notes): archived. Historical drafts, not current claims: the artifact-paper skeleton, the earlier complete-mediation draft (its claim is not supported) and the demo-track paper source.

## Files that are not in the repository

Some of the working notes cite raw run logs, dataset checkouts and trained models under `artifacts/`. That directory is the
author's local working space and is not in the repository. The evidence the tables rest on is committed under
[`results/`](../results/README.md), which also says how each file was produced.
