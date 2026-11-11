# IntentShield for MCP

[![CI](https://github.com/Suhas-123-cell/IntentShield/actions/workflows/ci.yml/badge.svg)](https://github.com/Suhas-123-cell/IntentShield/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/intentshield-mcp)](https://pypi.org/project/intentshield-mcp/)
[![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](https://github.com/Suhas-123-cell/IntentShield/blob/main/LICENSE)

IntentShield checks what your AI coding agent does with MCP (Model Context Protocol) tools, on your machine, before
anything runs. It reads each tool call, tool description and tool result with deterministic rules and then allows
the call, holds it for you to confirm (an "ask"), or blocks it (a "deny"); the core needs no API key.

It works with Claude Code, Codex CLI, Cursor and Gemini CLI (through their hooks) and with any MCP client that
launches stdio servers (through a proxy). The repository also holds the measurements behind it, under
[Results](https://github.com/Suhas-123-cell/IntentShield/blob/main/README.md#results) and [The hook study](https://github.com/Suhas-123-cell/IntentShield/blob/main/README.md#the-hook-study); they show less than a headline number would suggest.

![IntentShield blocking an injected MCP call](https://raw.githubusercontent.com/Suhas-123-cell/IntentShield/main/docs/demo.gif)

## Install

Python 3.12 or later. Four commands:

```sh
pip install intentshield-mcp       # or: uv tool install intentshield-mcp, or pipx install intentshield-mcp
intentshield install claude        # or codex, cursor, gemini; --scope project for this directory only
intentshield wrap .mcp.json        # put the proxy in front of the MCP servers in this file (see below)
intentshield doctor                # check that the hooks and proxies are installed and run
```

`uv` is needed only for the `uvx` demo below. Install the tool with `pip`, `uv tool` or `pipx`, not through `uvx`, which leaves a
temporary path behind. The PyPI name is `intentshield-mcp`; the plain name `intentshield` belongs to
[a different project with a similar name](https://pypi.org/project/intentshield/) ("Pre-execution intent verification for
AI agents"), not affiliated with this one. The commands and the Python package are still `intentshield`. To undo:
`intentshield uninstall claude` and `intentshield unwrap .mcp.json`.

What to expect:

1. Start the harness and send any prompt; a prompt is enough, no tool call is needed. Codex CLI first asks you to
   trust the new hooks.
2. Run `intentshield doctor`. Until a harness has run a hook it prints
   `FAIL claude (...): installed, but no hook has run since ...` and exits 1; that is expected right after `install`.
   A test event you pipe into `intentshield-hook` yourself does not count as a run, and `doctor` warns about it.
3. A `FAIL` line is a problem. A `note` line states how your harness version behaves and what
   IntentShield already does about it, for example that a hook which prints nothing lets the call run. It needs no action.

For the hooks only, `pip install --no-deps intentshield-mcp` is enough: `intentshield-hook`, `intentshield-wrap-hook`,
`install`, `uninstall`, `doctor`, `demo` and `scan --no-connect` work (checked on Python 3.12 in a clean virtual environment).
`wrap`, a `scan` that connects, the dashboard, the proxy and the gateway demo below need the full install; each prints one line
naming the missing package and exits 2.

If the guard blocks something legitimate or `doctor` reports a problem, see
[Troubleshooting](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#troubleshooting). An optional LLM judge (`--judge groq|gemini|ollama|deepseek`, off by default;
a hosted one sends prompts, arguments and tool text to its provider) is in
[docs/layers.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#the-optional-llm-judge). Terms such as taint, provenance and
headless are defined in [one glossary](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#terms).

**Platforms.** Tested on macOS (development, one CI job) and Linux (CI, Python 3.12 to 3.14). Windows is untested: the fail-closed launcher is POSIX-only.

## See it work

After the install above, the bundled demo runs 13 checks of the gateway mode against a demo MCP server. The JSON report
is on stdout and log lines on stderr, so the one-liner drops stderr and prints the verdict:

```sh
intentshield-mcp-verify --demo --stdio 2>/dev/null | python3 -c "import sys, json; r = json.load(sys.stdin); print(r['status'], r['summary'])"
# PASS {'failed': 0, 'guarded_tools_discovered': 3, 'passed': 13, 'warnings': 0}
```

With nothing installed, and [uv](https://docs.astral.sh/uv/) available, `uvx --from intentshield-mcp intentshield-mcp-verify --demo --stdio`
runs the same demo. It covers the gateway only, not the hooks or `wrap`. To watch the hook decide without a harness, run
`intentshield demo`: three sample shell calls go to the real hook, which prints an allow, an ask and a deny. Nothing runs.

## Put the proxy in front of MCP servers

```sh
intentshield wrap .mcp.json          # Claude Code project servers; Cursor mcp.json and Gemini settings.json work too
intentshield wrap ~/.claude.json     # servers added with `claude mcp add`
intentshield unwrap .mcp.json        # undo; add --dry-run to either command to preview
```

`wrap` rewrites each stdio server to start through `intentshield-mcp --transparent`, which hides poisoned or changed tool
descriptions and flags injected results. HTTP servers (`"url"`) are left alone. A wrapped server sees only the environment
variables its entry names, plus basics such as `PATH` and `HOME`.

`install` and `wrap` write absolute paths of this machine. Do not commit a wrapped project file or a `--scope project`
hook file: a teammate who clones it gets entries that point at paths that do not exist.

`intentshield scan` checks the MCP servers you already use, offline: poisoned descriptions, credentials in configs,
and tools that changed since the last scan. It exits 0 when no error-level finding remains (also when no MCP config is
found), 1 when one does, and 2 when a named file is missing or unreadable or no server could be started or read (a bare
`scan` skips a project's own `.mcp.json` unless you add `--connect-project`). [Details](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#scan-the-mcp-servers-you-already-use).

## What it stops and does not stop

| Stops | Does not stop |
|---|---|
| Instructions injected into a tool call's arguments or a tool result | Plain-language injections with no instruction marker (the optional judge reads these) |
| A value a tool result supplied that the user never gave: an address, URL, path or credential | Most non-English injections: the rules read two phrases in 11 languages |
| Poisoned tool descriptions, and descriptions that change after you accepted them (a "rug pull"), through the proxy | The harness's own shell and file tools, unless installed with `--builtin-tools` (opt-in, best effort; `Grep` is read, `Glob` and directory listings are not) |
| Tools that ask for the model's name or system prompt ("self-disclosure parameters": the guard removes them from the schema) | HTTP MCP servers under `wrap` |
| A hook that cannot start or crashes: `install` adds a launcher that turns it into a refusal (POSIX shells) | A Codex hook you have not trusted yet: Codex skips it silently |

What each layer sees, per harness: [docs/layers.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#what-each-layer-sees-and-stops). All limits: [docs/benchmarks.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/benchmarks.md#limitations).

## Results

The question is how much tool poisoning and prompt injection fixed rules can stop, and at what cost in blocked legitimate work.
The answer is narrower than a headline number suggests.

**Injection detection is weak on text the rules were not written for.** From [docs/benchmarks.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/benchmarks.md):

- On the 1,454 injections from families independent of the rules' tuning, the rules catch 2.1% and rules plus exemplars (a
  nearest-neighbour check against known injections) 18.1%. Over all 2,959 injections they catch 57.8%, but the rules were
  tuned on 1,505 of those.
- The same rules plus exemplars flag 2.5% of the 758 benign texts (15 of 142 hard benign ones: tool descriptions that
  legitimately guide the agent, results that tell the agent its next step, and quoted attacks).
- On the MCPTox replay (1,579 attack responses and 4,907 benign calls, scored by MCPTox's own labels; the rules were developed on
  MCPTox, so this is tuning-set), the full proxy leaves 0.4% attack success, falsely blocks 3.5% of benign calls and sends 46.3%
  of benign calls to review.

**MSB** (MCP Security Bench) runs real MCP servers in Docker with an agent on the host. The tables below use 220 cases, one run each
at temperature 0, with three local agents and Gemini 3.5 Flash-Lite on 99 of the cases. They are new draws of the attack
templates the rules were tuned on: held out from the tuning cases, not from the attack wording. An arm is one setup: no guard, a
trivial baseline, the gateway (IntentShield as an MCP gateway) or the hooks (IntentShield as harness hooks); every arm runs the same
cases. The baseline has no detection: it withholds descriptions, blanks self-disclosure parameters (tool parameters that ask for
the agent's model name or system prompt) and holds every state-changing call (a write, send or delete) for a human.

Harmful actions (a lower number is better):

| agent (paired cases) | no guard | gateway | hooks | baseline | harmful call left in review: gateway / hooks / baseline |
|---|---|---|---|---|---|
| qwen2.5:7b (218) | 58.7% | 0.0% | 0.0% | 0.0% | 0 / 5 / 27 |
| llama3.1:8b (220) | 15.0% | 0.0% | 0.0% | 0.0% | 0 / 2 / 0 |
| ornith:9b (216) | 56.0% | 0.0% | 0.0% | 0.0% | 0 / 3 / 41 |
| Gemini 3.5 Flash-Lite (99) | 29.3% | 0.0% | no arm | 0.0% | 0 / no arm / 2 |

Task completion in percent (higher is better): MSB's `user_task`, on the 139 to 140 cases per local agent (63 for Gemini) where it is defined:

| agent | no guard | gateway | hooks | baseline | gateway minus baseline, points [95% interval] |
|---|---|---|---|---|---|
| qwen2.5:7b | 68.6 | 42.9 | 50.7 | 51.4 | -8.6 [-16.1, -3.8] |
| llama3.1:8b | 70.0 | 22.1 | 57.1 | 36.4 | -14.3 [-26.0, -5.1] |
| ornith:9b | 82.7 | 51.1 | 54.0 | 59.7 | -8.6 [-16.7, -2.5] |
| Gemini 3.5 Flash-Lite | 96.8 | 58.7 | no arm | 66.7 | -7.9 [-19.6, 0.0] |

Reading: no guarded arm let a harmful action run, against 15 to 59% unguarded. That 0.0% does not show better
detection, because the trivial baseline reaches it too, so this metric cannot rank guards. The gateway's measurable gain
is that no harmful call waits in the review queue (the baseline leaves up to 19% of cases there). It costs 8 to 14 points of
task completion against the baseline and more benign calls held for review. For Gemini the interval includes 0.

One more result, with the limit that it is an in-sample check: of the 159 distinct tool schemas the MSB agents saw, the rule that
removes self-disclosure parameters stripped 36 parameters, all on attack servers, and none of the 194 parameters on the clean tools.
The rule was written for the kind of parameter MSB's attack servers add (`llm_model_name`), so this shows that it fires on that
template and not on the clean tools; it is not a detection rate.

What the tables do not show:

- The runs are single, with small local models and one cloud model, on new draws of the tuning templates.
- Only the three qwen2.5:7b arms were rerun on the code of 2026-10-19 with the code version recorded. The other 19 of 22 trace
  files (every hooks, llama, ornith and Gemini arm) come from older code, so the tables do not show that this release gives these numbers.

Every MSB number above comes from committed traces. The other results (LLM judge, Prompt Guard 2, adaptive attackers, MCPTox,
live runs in all four harnesses) are in [docs/benchmarks.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/benchmarks.md) with their protocols and caveats. Overhead: a hook is a
short-lived process of about 70 ms per event, so a guarded MCP call (two events) adds about 140 ms (median of 30 invocations, three runs on an Apple M5
on 2026-11-11, working tree after commit `633014e`; the same script gave 60 to 64 ms per event at `80c9e34`, before the 0.4.3 verdict translation and deadline).

## Reproduce

Run these from a clone, after `uv sync --extra dev`. The PyPI source distribution has no tests or benchmarks.

| command | what it regenerates | external data needed | time |
|---|---|---|---|
| `uv run python benchmarks/paper_numbers.py` | every MSB table above, with paired bootstrap intervals | none: committed traces, no Docker, model or network | about 3 s |
| `uv run intentshield-mcp-verify --demo --stdio` | 13 checks of the gateway mode against a bundled demo server (not the hooks or `wrap`) | none | about 1 s |
| `uv run python benchmarks/hook_fidelity/report_numbers.py` | every figure in the hook-study report | none: committed rows | under 1 s |
| `S=$(mktemp -d); cp -r results/hook-fidelity/compare $S/compare; uv run python benchmarks/hook_fidelity/compare.py summarize $S/compare` | the study's head-to-head tables: it writes `table.md`, `table-r8.md`, `summary.json` and `summary-r8.json` into the copy, so diff them against the committed ones | none: committed rows | under 1 s |
| `uv run python benchmarks/latency.py --calls 50 --hooks 30 --out <file>` | hook and proxy overhead on your machine | none | about 15 s |
| `benchmarks/mcptox.py --replay`, `benchmarks/injection_eval.py` (flags in `results/README.md`) | MCPTox replay rows; injection detection table | MCPTox-Benchmark and InjecAgent checkouts | not timed |

New MSB runs, the live harness checks and the study's guard decisions need Docker, Ollama or a paid API, the harness
builds, or clones of the other guards ([results/README.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/results/README.md), [results/hook-fidelity/README.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/results/hook-fidelity/README.md)).
A few figures come from runs whose rows are not committed; `results/README.md` lists them.

## What is stored locally

The hook keeps per-session state in `~/.intentshield/hooks.db` (file mode 0600, directory mode 0700): your prompts, with any
credential the guard recognises replaced by a short hash, and the values (addresses, URLs, paths) it took from tool calls and
results. A clean session is forgotten after 7 days without activity, one that holds taint or a flag after 30. `threats.db`
holds learned threat memory, which expires after 30 days unless you confirmed the entry. The gateway (`gateway.db`) and each
wrapped server (`proxies/<server>.db`) keep an audit database with call arguments and results, with no expiry.
`~/.intentshield/.env` holds a judge key if you set one. `uninstall` and `unwrap` leave this data in place. [SECURITY.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/SECURITY.md#what-is-stored-locally)
lists every file and how to delete it: uninstall and unwrap first, then `rm -r ~/.intentshield`.

## The hook study

The repository also holds a measurement study of what coding-agent tools do with the verdict a hook returns.

- **Setup.** Real builds of Claude Code, Codex CLI and Gemini CLI, run headless (no human to answer a prompt) on macOS against a
  scripted stub model. Cursor was not measured. IntentShield's own hook is one of the things measured.
- **Deny and ask.** A `deny` the harness parsed was enforced on every build where the hook ran. An `ask` with nobody to
  answer it was refused by Claude Code from 2.1.85 (with Bash pre-approved, which confounds the older builds), ignored by
  Codex CLI, and run or left hanging by Gemini CLI depending on the build (under yolo mode, Gemini CLI's setting that runs every
  tool call without asking, or with the shell allow-listed).
- **Failures.** With the default hook configuration, a hook that ran past its timeout let the call run on every build tested.
  Claude Code's `onFailure: "block"` setting, which `install` writes, blocked it on 2.1.316 (3 of 3 runs) and had no effect on 2.1.281 (2 of 2 ran). A hook that printed nothing, exited 1 or had a missing interpreter was tested on one Claude Code and
  two Codex builds only.
- **Other guards.** Mixed. Before its dangerous-command rules IntentShield let more harmful calls through than two other
  guards on one set (137 of 166 harmful calls, against 31 of 130 for safety-net and 67 of 117 for knox on their own scopes). With
  the opt-in rules it fits its own rule categories (post hoc) and is behind safety-net on denies alone (24 of 85 harmful calls denied,
  against 41 of 85). Some of the items it was scored on have since entered the rules' unit tests; the report says what that changes.
- **Limits and status.** One author, one operating system, a stub model, author-written fixtures, no second coder. It does
  not show that an attacker can bypass a guard. A measurement note and an artifact, not a paper; nothing was sent to a vendor.
  Build counts and the rest are in the [short report](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/hook-fidelity-report.md); the working notes are linked from [docs/README.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/README.md).

## Documentation

- A 20-minute reading path: this README, [docs/contribution.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/contribution.md) (what the work does and does not support as a research contribution), then the [hook study report](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/hook-fidelity-report.md).
- [docs/guide.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md): hooks, the proxy, scan, settings, troubleshooting, with the [built-in tool rules](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#built-in-tools-and-the-dangerous-command-rules) (`--builtin-tools`) and [wrapping a third-party hook](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#wrapping-a-third-party-hook). [docs/gateway.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/gateway.md): the gateway, dashboard and REST API.
  [docs/layers.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md): what each layer sees and stops, judge options, the glossary.
  [docs/benchmarks.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/benchmarks.md): every protocol and table, limitations. [docs/README.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/README.md) indexes the rest.
- [SECURITY.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/SECURITY.md), [CONTRIBUTING.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/CONTRIBUTING.md), [CHANGELOG.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/CHANGELOG.md), [CITATION.cff](https://github.com/Suhas-123-cell/IntentShield/blob/main/CITATION.cff). Licence: Apache-2.0, [LICENSE](https://github.com/Suhas-123-cell/IntentShield/blob/main/LICENSE).
