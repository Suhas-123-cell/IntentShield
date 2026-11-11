# IntentShield for MCP

[![CI](https://github.com/Suhas-123-cell/IntentShield/actions/workflows/ci.yml/badge.svg)](https://github.com/Suhas-123-cell/IntentShield/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/intentshield-mcp)](https://pypi.org/project/intentshield-mcp/)
[![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](https://github.com/Suhas-123-cell/IntentShield/blob/main/LICENSE)

IntentShield is a guard that runs on your machine between an AI coding agent and its MCP (Model Context
Protocol) tools. It checks each tool call, tool description and tool result with deterministic rules, then
allows it, holds it for a human, or blocks it before anything runs. It is for people who run Claude Code, Codex
CLI, Cursor or Gemini CLI against MCP servers and want that checked locally; the core needs no API key. It also
asks a research question: how much tool poisoning and prompt injection can fixed rules stop, at what cost in
blocked legitimate work? The measured answer is under [Results](https://github.com/Suhas-123-cell/IntentShield/blob/main/README.md#results), and it is narrower than a headline
number suggests.

![IntentShield blocking an injected MCP call](https://raw.githubusercontent.com/Suhas-123-cell/IntentShield/main/docs/demo.gif)

## Install

Python 3.12 or later. Install the tool first (not through `uvx`, which leaves a temporary path behind), then
register it with your harness:

```sh
pip install intentshield-mcp       # or: uv tool install intentshield-mcp, or pipx install intentshield-mcp
intentshield install claude        # or codex, cursor, gemini; --scope project for this directory only
```

The PyPI name is `intentshield-mcp`; the plain name belongs to an
[unrelated project](https://pypi.org/project/intentshield/) that is not an MCP guard. The commands and the Python
package are still `intentshield`. To undo: `intentshield uninstall claude`.

For the hooks only, with the standard library and nothing else, `pip install --no-deps intentshield-mcp` is enough:
`intentshield-hook`, `intentshield-wrap-hook`, `install`, `uninstall`, `wrap`, `doctor` and `scan --no-connect` run
(checked on Python 3.12 in a clean virtual environment). The dashboard (`intentshield` with no command), the proxy
(`intentshield-mcp`) and a `scan` that connects to servers need the full install.

What to do next:

1. Start the harness once and send a prompt. Codex CLI first asks you to trust the new hooks.
2. Run `intentshield doctor`. Until a harness has run a hook, it prints
   `FAIL claude (...): installed, but no hook has run since ...` and exits 1. That is expected right after
   `install`, not a broken install. A warning line does not change the exit code. Piping a test event into
   `intentshield-hook` yourself does not count as a run: `doctor` says the event came from a process that is not the
   harness and prints a warning (an IDE that starts the harness under another process name looks the same).

To see the guard work with nothing installed: `uvx --from intentshield-mcp intentshield-mcp-verify --demo --stdio`.
If the guard blocks something legitimate or `doctor` reports a problem, see
[Troubleshooting](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#troubleshooting). An optional LLM judge (`--judge groq|gemini|ollama|deepseek`,
off by default; a hosted one sends prompts, arguments and tool text to its provider) is in
[docs/layers.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#the-optional-llm-judge).

**Platforms.** Tested on macOS (development, and one CI job on Python 3.12) and Linux (CI, Python 3.12 to 3.14). Windows is untested: the fail-closed launcher in the
hook command is for POSIX shells and is left out there.

## Put the proxy in front of MCP servers

```sh
intentshield wrap .mcp.json          # Claude Code project servers; Cursor mcp.json and Gemini settings.json work too
intentshield wrap ~/.claude.json     # servers added with `claude mcp add`
intentshield unwrap .mcp.json        # undo; add --dry-run to either command to preview
```

`wrap` rewrites each stdio server to start through `intentshield-mcp --transparent`, which hides poisoned or
changed tool descriptions and flags injected results. Servers reached over HTTP (`"url"`) are left alone. A
wrapped server sees only the environment variables its entry names, plus basics such as `PATH` and `HOME`.

`install` and `wrap` write absolute paths of this machine. Do not commit a wrapped project file or a project-scope
hook file, and do not re-run them on each machine from a shared checkout: a teammate who clones it gets an entry
that points at a path that does not exist.

`intentshield scan` checks the MCP servers you already use, offline: poisoned descriptions, credentials in configs,
and tools that changed since the last scan. It exits 0 when no error-level finding remains (also when no config is
found), 1 on an error-level finding, and 2 when nothing could be checked (a named file is missing or unreadable,
or no server was started; a bare `scan` skips the servers of a project's own `.mcp.json` unless you add
`--connect-project`). [Details](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#scan-the-mcp-servers-you-already-use).

## What it stops and does not stop

| Stops | Does not stop |
|---|---|
| Instructions injected into a tool call's arguments or a tool result | Plain-language injections with no instruction marker (the optional judge reads these) |
| A value a tool result supplied that the user never gave: an address, URL, path or credential | Most non-English injections: the rules read two phrases in 11 languages |
| Poisoned or changed (rug pull) tool descriptions, through the proxy | The harness's own shell and file tools, unless installed with `--builtin-tools` (opt-in, best effort; `Grep` is read, `Glob` and directory listings are not) |
| Tools asking for the model's name or system prompt | HTTP MCP servers under `wrap` |
| A hook that crashes, on harnesses that have a fail-closed flag | A Codex hook you have not trusted yet: Codex skips it silently |

What each layer sees, per harness, is in
[docs/layers.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#what-each-layer-sees-and-stops).
The full list of limits is in
[docs/benchmarks.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/benchmarks.md#limitations).

## Results

MSB (MCP Security Bench) runs real MCP servers in Docker with an agent on the host. The table is 220 held-out
attack cases, one run each at temperature 0, with three local agents and Gemini 3.5 Flash-Lite on 99 of the cases.
"Trivial baseline" is a guard that withholds descriptions, blanks self-disclosure parameters and holds every
state-changing call for a human. A call waiting for review has not run.

| agent (paired cases) | harm executed, no guard | harm executed, gateway / hooks / baseline | harmful call left in review: gateway / hooks / baseline | task done: no guard / gateway / hooks / baseline |
|---|---|---|---|---|
| qwen2.5:7b (218) | 58.7% | 0.0% on all three | 0 / 5 / 27 | 68.6 / 42.9 / 50.7 / 51.4 |
| llama3.1:8b (220) | 15.0% | 0.0% on all three | 0 / 2 / 0 | 70.0 / 22.1 / 57.1 / 36.4 |
| ornith:9b (216) | 56.0% | 0.0% on all three | 0 / 3 / 41 | 82.7 / 51.1 / 54.0 / 59.7 |
| Gemini 3.5 Flash-Lite (99) | 29.3% | 0.0% / no arm / 0.0% | 0 / no arm / 2 | 96.8 / 58.7 / no arm / 66.7 |

Task completion is MSB's `user_task`, scored on the 139 to 140 cases per local agent (63 for Gemini) where MSB
defines it. Reading: no guarded arm let a harmful action run, against 15 to 59% unguarded. That 0.0% does not
show better detection, because the trivial baseline reaches it too (MSB's harms are file writes or a leaked
model name), so this metric cannot rank guards. The gateway's measurable gain is that no harmful call waits in the
review queue (the baseline leaves up to 19% of cases there), paid for with 8 to 14 points less task completion than
the baseline and more benign calls held for review on all four agents; the runs are single, with small local models.

Every number above comes from committed traces. The other results (the LLM judge and attacks on it, Prompt Guard 2,
adaptive attackers, MCPTox, live runs in all four harnesses, overhead of about 60 to 70 ms per hook event on an Apple
M5) are in [docs/benchmarks.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/benchmarks.md) with their protocols and caveats.

## Reproduce

Run from a clone (`uv sync --extra dev`). The PyPI source distribution has the package and its configs but no tests or
benchmarks, so a test run needs a clone.

| command | what it regenerates | external data needed | time |
|---|---|---|---|
| `python benchmarks/paper_numbers.py` | every MSB table above, with paired bootstrap intervals | none: committed traces, no Docker, model or network | about 3 s |
| `intentshield-mcp-verify --demo --stdio` | 13 checks of the gateway mode against a bundled demo server (not the hooks or `wrap`) | none | about 1 s |
| `python benchmarks/hook_fidelity/compare.py summarize <copy of results/hook-fidelity/compare>` | the study's head-to-head tables (it writes into the directory, so copy it first) | none: committed rows | under 1 s |
| `python benchmarks/latency.py --calls 50 --hooks 30 --out <file>` | hook and proxy overhead on your machine | none | about 15 s |
| `python benchmarks/mcptox.py --replay` (flags in `results/README.md`) | MCPTox replay rows | MCPTox-Benchmark checkout | not timed |
| `python benchmarks/injection_eval.py` (flags in `results/README.md`) | injection detection table | InjecAgent checkout | not timed |

The demo prints one JSON line, not a summary. Read its status like this:

```sh
intentshield-mcp-verify --demo --stdio 2>/dev/null | python -c "import sys, json; r = json.load(sys.stdin); print(r['status'], r['summary'])"
# PASS {'failed': 0, 'guarded_tools_discovered': 3, 'passed': 13, 'warnings': 0}
```

New MSB runs, the live harness checks and the study's guard decisions need Docker, Ollama or a paid API, the
harness builds, or clones of the other guards, so they cannot be rerun from this repository alone
([results/README.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/results/README.md), [results/hook-fidelity/README.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/results/hook-fidelity/README.md)).
CI runs the test suite on every push (badge above).

## What is stored locally

The hook keeps per-session state in `~/.intentshield/hooks.db` (file mode 0600, in a directory of mode 0700): the user's
prompts, with any credential the guard recognises replaced by a short hash, and the values (addresses, URLs, paths) it took
from tool calls and results. A clean session is forgotten after 7 days without activity, a session that holds taint or a flag
after 30. `threats.db` holds learned threat memory: an entry expires 30 days after it was last seen, and one you confirmed does
not expire. The gateway (`gateway.db`) and each wrapped server (`proxies/<server>.db`) keep an audit database with call
arguments and results, and these have no expiry. `~/.intentshield/.env` holds a judge key if you set one. `uninstall` and
`unwrap` leave this data in place. [SECURITY.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/SECURITY.md#what-is-stored-locally)
lists every file and how to delete it: uninstall and unwrap first, then `rm -r ~/.intentshield`.

## The hook study

The repository also holds a measurement study of what Claude Code, Codex CLI and Gemini CLI do with the verdict
a `PreToolUse` hook returns, run on macOS against a scripted stub model (not a real agent) on 23, 17 and 28
sampled builds of the three tools; Cursor was not measured. A parsed `deny` was enforced wherever the hook ran;
an `ask` with nobody to answer it was refused by Claude Code from 2.1.85, ignored by Codex CLI, and run or left
hanging by Gemini CLI depending on the build; and a hook that ran past its timeout let the call run on every
Claude Code and Codex build tested, while a hook that printed nothing, exited 1 or had a missing interpreter was
tested on one Claude Code and two Codex builds only (Gemini CLI blocked a missing interpreter on 22 of 26 sampled
builds). None of this shows that an attacker can bypass a guard, most behaviours are documented by the vendors or
already reported, and the comparison with other guards is mixed (IntentShield trails one of them on denies alone),
rests on one author's fixtures, and makes the study a measurement note and an artifact, not a paper; no report has
been sent to a vendor. Read the
[short report](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/hook-fidelity-report.md) or the
[full record](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/hook-fidelity-study.md).

## Documentation

- [docs/guide.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md): dashboard, gateway, hooks, threat memory, settings, REST API, troubleshooting.
- [docs/layers.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md): what each layer sees and stops, `install` and `wrap` in full, judge options, upstream config.
- [docs/benchmarks.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/benchmarks.md): every protocol and table, live harness checks, limitations.
- [docs/contribution.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/contribution.md) says what the work does and does not support as a research contribution; [docs/README.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/README.md) indexes the rest.
- [SECURITY.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/SECURITY.md), [CONTRIBUTING.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/CONTRIBUTING.md), [CHANGELOG.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/CHANGELOG.md), [CITATION.cff](https://github.com/Suhas-123-cell/IntentShield/blob/main/CITATION.cff).

Since 0.4.3, `intentshield wrap-hook` runs a third-party hook under the same fail-closed launcher and deadline
([guide](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#wrapping-a-third-party-hook)), and `--builtin-tools` adds text rules for dangerous commands
([guide](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#built-in-tools-and-the-dangerous-command-rules)).

## Licence

Apache-2.0; see [LICENSE](https://github.com/Suhas-123-cell/IntentShield/blob/main/LICENSE).
