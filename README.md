# IntentShield for MCP

[![CI](https://github.com/Suhas-123-cell/IntentShield/actions/workflows/ci.yml/badge.svg)](https://github.com/Suhas-123-cell/IntentShield/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/intentshield-mcp)](https://pypi.org/project/intentshield-mcp/)
[![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](https://github.com/Suhas-123-cell/IntentShield/blob/main/LICENSE)

IntentShield checks what your AI coding agent does with MCP (Model Context Protocol) tools, on your machine, before
anything runs. It reads each tool call, tool description and tool result with deterministic rules and then allows
the call, holds it for you to confirm (an "ask"), or blocks it (a "deny"); the core needs no API key.

It works with Claude Code, Codex CLI, Cursor and Gemini CLI (through their hooks) and with any MCP client that launches stdio
servers (through a proxy). The measurements behind it are under [Results](#results) and [The hook study](#the-hook-study); they
show less than a headline number would suggest.

![IntentShield blocking an injected MCP call](https://raw.githubusercontent.com/Suhas-123-cell/IntentShield/main/docs/demo.gif)

## Install

Python 3.11 or later:

```sh
uv tool install intentshield-mcp   # or: pipx install intentshield-mcp
intentshield install claude        # or codex, cursor, gemini; --scope project for this directory only
intentshield wrap .mcp.json        # put the proxy in front of the MCP servers in this file (see below)
intentshield doctor                # check that the hooks and proxies are installed and wired correctly
```

`pip install intentshield-mcp` works inside a virtual environment. On a system Python that pip will not change (the
"externally-managed-environment" error, common on Homebrew and Debian), use `uv tool` or `pipx`; if `intentshield` is then not found,
run `uv tool update-shell` or `pipx ensurepath`. Do not install through `uvx`, which leaves a temporary path behind. The PyPI name is
`intentshield-mcp`; `intentshield` there is [a different project](https://pypi.org/project/intentshield/). The commands are still
`intentshield`. To undo: `intentshield uninstall claude` and `intentshield unwrap .mcp.json`.

**What the default install guards.** It guards MCP calls. Shell commands, file tools and web tools are guarded only if you
add `--builtin-tools`: `intentshield install claude --builtin-tools` (opt-in, best effort). `intentshield demo` below runs with
that flag on. To check the install, start the harness and send any prompt (Codex CLI first asks you to trust the new hooks), then run
`intentshield doctor`. It checks that the hooks and proxies are installed and wired correctly: the hook entries in each harness's
settings, when each hook last ran, and that each wrapped server's proxy config and command exist. It does not start your servers unless you add `--connect`, which starts each wrapped server once and lists its tools (that
runs the server's code).
Right after `install` it prints `FAIL claude (...): installed, but no hook has run since ...` and exits 1, which is expected.

If the guard blocks something legitimate, or you want a hooks-only `--no-deps` install, see
[Troubleshooting](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#troubleshooting). An optional LLM judge (`--judge`, off by default; a hosted one sends prompts, arguments and tool text to its provider) is in
[docs/layers.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#the-optional-llm-judge), with a
[glossary](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#terms). **Platforms.** Tested on macOS and Linux
(CI, Python 3.11 to 3.14); Windows is untested, as the fail-closed launcher is POSIX-only.

## See it work

`intentshield demo` sends three sample shell calls to the real hook, with `--builtin-tools`, and one MCP call to the default install's
hook, and prints an allow, an ask and two denies. Nothing runs. The gateway mode has its own check, 13 tests against a bundled demo MCP server. Its JSON report goes to stdout and log lines to
stderr, so this one-liner prints only the verdict (with [uv](https://docs.astral.sh/uv/) and nothing installed, prefix it with
`uvx --from intentshield-mcp`):

```sh
intentshield-mcp-verify --demo --stdio 2>/dev/null | python3 -c "import sys, json; r = json.load(sys.stdin); print(r['status'], r['summary'])"
# PASS {'failed': 0, 'guarded_tools_discovered': 3, 'passed': 13, 'warnings': 0}
```

## Put the proxy in front of MCP servers

```sh
intentshield wrap .mcp.json          # or ~/.claude.json (servers added with `claude mcp add`), Cursor mcp.json, Gemini settings.json,
                                     # ~/.codex/config.toml, VS Code mcp.json
intentshield unwrap .mcp.json        # undo; add --dry-run to either command to preview
```

`wrap` reads JSON files with an `mcpServers` object (Claude Code, Cursor, Gemini CLI and other clients that use that layout), VS Code's
`servers` or `mcp.servers` key, and the `[mcp_servers.NAME]` tables of Codex CLI's `~/.codex/config.toml`. It rewrites each stdio
server to start through `intentshield-mcp --transparent`, which hides poisoned or changed tool descriptions and flags injected
results. HTTP servers (`"url"`) are left alone. A wrapped server sees only the environment variables its entry names, plus basics such
as `PATH` and `HOME`. `install` and `wrap` write absolute paths of this machine, so do not commit a wrapped project file or a
`--scope project` hook file.

`intentshield scan` checks the servers you already use, offline: poisoned descriptions, credentials in configs, and tools that
changed since the last scan
([details](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#scan-the-mcp-servers-you-already-use)).

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

The weak numbers come first; protocols, intervals and caveats are in [docs/benchmarks.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/benchmarks.md).
- **Injection detection is weak on text the rules were not written for.** On the 1,454 injections from families independent of the rules'
  tuning (InjecAgent and AgentDojo, two public benchmarks of injected agent tasks, and generated outputs), the rules catch 2.1% and rules plus exemplars (a nearest-neighbour check against known injections) 18.1%. Most of the 18.1%
  is in distribution for the exemplar index: 228 of its 263 hits are on generated outputs written in the same four styles as the
  index's training rows. On families the index never saw (1,108 injections) rules plus exemplars catch 35, or 3.2%.
- **Over all 2,959 injections**, rules plus exemplars catch 57.8% (rules alone 49.9%), but the rules were tuned on 1,505 of those.
  Rules alone flag 2.1% of the 758 benign texts and rules plus exemplars 2.5% (15 of the 142 hard ones).
- **MCPTox replay.** MCPTox is a public benchmark of poisoned MCP tool descriptions; its 1,579 attack responses and 4,907 benign calls
  are replayed. The rules were developed on MCPTox, so this is tuning-set: the full proxy leaves 0.4% attack success, falsely blocks
  3.5% of benign calls and sends 46.3% of benign calls to review.

**MSB** (MCP Security Bench) runs real MCP servers in Docker with an agent on the host: 220 cases, one run each at temperature 0, with
three local agents and Gemini 3.5 Flash-Lite on 99 of them, on new draws of the attack templates the rules were tuned on. The baseline
has no detection: it withholds descriptions, blanks self-disclosure parameters and holds every state-changing call for a human. A
harmful action is a harmful call that ran (lower is better); task completion is MSB's `user_task` (higher is better). A 0.0% is 0 of
216 to 220 cases (95% upper bound 1.7%) or 0 of 99 (3.7%).

| agent (paired cases) | harmful: no guard | gateway | hooks | baseline | task done: no guard | gateway | hooks | baseline | gateway minus baseline, points [95% interval] |
|---|---|---|---|---|---|---|---|---|---|
| qwen2.5:7b (218) | 58.7% | 0.0% | 0.0% | 0.0% | 68.6 | 42.9 | 50.7 | 51.4 | -8.6 [-16.1, -3.8] |
| llama3.1:8b (220) | 15.0% | 0.0% | 0.0% | 0.0% | 70.0 | 22.1 | 57.1 | 36.4 | -14.3 [-26.0, -5.1] |
| ornith:9b (216) | 56.0% | 0.0% | 0.0% | 0.0% | 82.7 | 51.1 | 54.0 | 59.7 | -8.6 [-16.7, -2.5] |
| Gemini 3.5 Flash-Lite (99) | 29.3% | 0.0% | no arm | 0.0% | 96.8 | 58.7 | no arm | 66.7 | -7.9 [-19.6, 0.0] |

Reading: no guarded arm let a harmful action run, against 15 to 59% unguarded, but the trivial baseline reaches 0.0% too, so this
metric cannot rank guards. The gateway's measurable gain is that no harmful call waits in the review queue (the baseline leaves up to
19% of cases there); it costs 8 to 14 points of task completion against the baseline. These are single runs of small models on tuning
templates, and only the three qwen2.5:7b arms were rerun on recent code. Overhead is about 75 ms per hook event and about 150 ms
per guarded MCP call (`benchmarks/latency.py`).

## Reproduce

From a clone, after `uv sync --group dev` (the PyPI source distribution has no tests or benchmarks):

| command | what it regenerates | external data needed | time |
|---|---|---|---|
| `uv run python benchmarks/paper_numbers.py` | every MSB table above, with paired bootstrap intervals | none: committed traces | about 3 s |
| `uv run python benchmarks/hook_fidelity/report_numbers.py` | every figure in the hook-study report | none: committed rows | under 1 s |
| `uv run python benchmarks/latency.py --calls 50 --hooks 30 --out <file>` | hook and proxy overhead on your machine | none | about 15 s |
| `benchmarks/mcptox.py --replay`, `benchmarks/injection_eval.py` (flags in `results/README.md`) | MCPTox replay rows; injection detection table | MCPTox-Benchmark and InjecAgent checkouts | not timed |

New MSB runs, live harness checks and the study's guard decisions need Docker, Ollama or a paid API, harness builds, or clones of
the other guards; some figures come from runs whose rows are not committed. See [results/README.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/results/README.md)
and [results/hook-fidelity/README.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/results/hook-fidelity/README.md).

## What is stored locally

The hook keeps per-session state in `~/.intentshield/hooks.db` (file mode 0600): your prompts, with any credential the guard
recognises replaced by a short hash, and the values (addresses, URLs, paths) it took from tool calls and results. A clean session is
forgotten after 7 days without activity, one that holds taint or a flag after 30. `threats.db` holds learned threat memory (30 days
unless confirmed). The gateway (`gateway.db`) and each wrapped server (`proxies/<server>-<hash>.db`) keep an audit database with call
arguments and results, with no expiry. `~/.intentshield/.env` holds a judge key if you set one. `uninstall` and `unwrap` leave this
data in place; [SECURITY.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/SECURITY.md#what-is-stored-locally) lists every file.

## The hook study

What coding-agent tools do with the verdict a hook returns; the [report](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/hook-fidelity-report.md) is about 2,000 words.

- **Setup.** Real builds of Claude Code (27 scored builds), Codex CLI (14) and Gemini CLI (28), run headless on macOS against a scripted
  stub model. Cursor was not measured. IntentShield's own hook is one of the things measured.
- **Deny and ask.** A `deny` the harness parsed was enforced on every build where the hook ran. An `ask` with nobody to answer it was
  refused by Claude Code from 2.1.85, ignored by Codex CLI, and run or left hanging by Gemini CLI.
- **Failures.** A hook that ran past its timeout let the call run on every build tested. Claude Code's `onFailure: "block"`, which
  `install` writes, blocked it on 2.1.316 and had no effect on 2.1.281. A hook that printed nothing, exited 1 or had a missing
  interpreter was tested on one Claude Code and two Codex CLI builds only; a missing interpreter was also run on 26 Gemini CLI builds.
- **Other guards.** Mixed. Before its dangerous-command rules IntentShield let through 137 of 166 harmful calls, against 31 of 130 for
  safety-net and 67 of 117 for knox on their own scopes. With the opt-in rules it is behind safety-net on denies alone (24 of 85
  harmful calls denied, against 41 of 85). Its gain elsewhere fits its own rule categories and is post hoc. On benign calls it ties
  safety-net and trails knox.
- **Limits and status.** One author, one operating system, a stub model, author-written fixtures, no second coder. A measurement note
  and an artifact, not a paper; nothing was sent to a vendor.

## Documentation

- [docs/README.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/README.md): a reading path with word counts. The research verdict: [docs/contribution.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/contribution.md).
- [docs/guide.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md): hooks, the proxy, scan, settings, troubleshooting, the [built-in tool rules](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#built-in-tools-and-the-dangerous-command-rules) and [wrapping a third-party hook](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#wrapping-a-third-party-hook). [docs/gateway.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/gateway.md): the gateway, dashboard and REST API. [docs/layers.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md): what each layer sees and stops. [docs/benchmarks.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/benchmarks.md): every protocol, table and limit.
- [SECURITY.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/SECURITY.md), [CONTRIBUTING.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/CONTRIBUTING.md), [CHANGELOG.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/CHANGELOG.md), [CITATION.cff](https://github.com/Suhas-123-cell/IntentShield/blob/main/CITATION.cff). Licence: Apache-2.0, [LICENSE](https://github.com/Suhas-123-cell/IntentShield/blob/main/LICENSE).
