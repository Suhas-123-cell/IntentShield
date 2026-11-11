# IntentShield for MCP

[![CI](https://github.com/Suhas-123-cell/IntentShield/actions/workflows/ci.yml/badge.svg)](https://github.com/Suhas-123-cell/IntentShield/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/intentshield-mcp)](https://pypi.org/project/intentshield-mcp/)
[![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](https://github.com/Suhas-123-cell/IntentShield/blob/main/LICENSE)

IntentShield checks what your AI coding agent does with MCP (Model Context Protocol) tools, on your machine, before
anything runs. It reads each tool call, tool description and tool result with deterministic rules and then allows
the call, holds it for you to confirm, or blocks it; the core needs no API key.

It works with Claude Code, Codex CLI, Cursor and Gemini CLI (through their hooks) and with any MCP client that
launches stdio servers (through a proxy). The repository also holds the measurements behind it, under
[Results](https://github.com/Suhas-123-cell/IntentShield/blob/main/README.md#results) and [The hook study](https://github.com/Suhas-123-cell/IntentShield/blob/main/README.md#the-hook-study); they show less than a headline number would suggest.

![IntentShield blocking an injected MCP call](https://raw.githubusercontent.com/Suhas-123-cell/IntentShield/main/docs/demo.gif)

## See it work

With nothing installed first, the bundled demo runs 13 checks of the gateway mode against a demo MCP server. The JSON report
is on stdout and log lines on stderr, so the one-liner drops stderr and prints the verdict:

```sh
uvx --from intentshield-mcp intentshield-mcp-verify --demo --stdio 2>/dev/null | python3 -c "import sys, json; r = json.load(sys.stdin); print(r['status'], r['summary'])"
# PASS {'failed': 0, 'guarded_tools_discovered': 3, 'passed': 13, 'warnings': 0}
```

## Install

Python 3.12 or later. Install the tool first (not through `uvx`, which leaves a temporary path behind), then register it:

```sh
pip install intentshield-mcp       # or: uv tool install intentshield-mcp, or pipx install intentshield-mcp
intentshield install claude        # or codex, cursor, gemini; --scope project for this directory only
```

The PyPI name is `intentshield-mcp`; the plain name `intentshield` belongs to
[a different project with a similar name](https://pypi.org/project/intentshield/) ("Pre-execution intent verification for
AI agents"), not affiliated with this one. The commands and the Python package are still `intentshield`. To undo:
`intentshield uninstall claude`.

Next:

1. Start the harness and send any prompt; a prompt is enough, no tool call is needed. Codex CLI first asks you to
   trust the new hooks.
2. Run `intentshield doctor`. Until a harness has run a hook it prints
   `FAIL claude (...): installed, but no hook has run since ...` and exits 1; that is expected right after `install`.
   A test event you pipe into `intentshield-hook` yourself does not count as a run, and `doctor` warns about it.

For the hooks only, with the standard library and nothing else, `pip install --no-deps intentshield-mcp` is enough.
Then `intentshield-hook`, `intentshield-wrap-hook`, `intentshield install`, `uninstall`, `doctor` and
`scan --no-connect` work (checked on Python 3.12 in a clean virtual environment). `wrap`, a `scan` that connects, the
dashboard, the proxy and the demo above need the full install; each prints one line naming the missing package and
exits 2.

If the guard blocks something legitimate or `doctor` reports a problem, see
[Troubleshooting](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#troubleshooting). An optional LLM judge (`--judge groq|gemini|ollama|deepseek`, off by default;
a hosted one sends prompts, arguments and tool text to its provider) is in
[docs/layers.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#the-optional-llm-judge).

**Platforms.** Tested on macOS (development, one CI job on Python 3.12) and Linux (CI, Python 3.12 to 3.14). Windows is untested:
the fail-closed launcher is for POSIX shells and is left out there.

## Terms

- **allow, ask, deny:** the three answers a hook gives. An ask holds the call for you to confirm (the gateway and the
  benchmarks call it "review", and a call in the review queue has not run); a deny blocks it.
- **State-changing call:** a tool call that writes, sends or deletes, as opposed to a read.
- **Taint:** a session is tainted once a tool result in it tried to instruct the agent; values that appeared only in
  such a result are then not trusted. **Rug pull:** a server changes a tool's description after you accepted it.
- **Headless:** nobody is there to answer a prompt (`claude -p`, `codex exec`, `gemini -p`).
- **Arm, paired cases:** one setup in a benchmark (no guard, trivial baseline, gateway, hooks); the same cases run in
  every arm, so arms are compared on paired cases.

More terms (provenance, canary, MSB) are in [docs/layers.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#terms).

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
and tools that changed since the last scan. It exits 0 when no error-level finding remains, 1 on one, and 2 when nothing
could be checked (a bare `scan` skips a project's own `.mcp.json` unless you add `--connect-project`). [Details](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#scan-the-mcp-servers-you-already-use).

## What it stops and does not stop

| Stops | Does not stop |
|---|---|
| Instructions injected into a tool call's arguments or a tool result | Plain-language injections with no instruction marker (the optional judge reads these) |
| A value a tool result supplied that the user never gave: an address, URL, path or credential | Most non-English injections: the rules read two phrases in 11 languages |
| Poisoned or changed (rug pull) tool descriptions, through the proxy | The harness's own shell and file tools, unless installed with `--builtin-tools` (opt-in, best effort; `Grep` is read, `Glob` and directory listings are not) |
| Tools asking for the model's name or system prompt | HTTP MCP servers under `wrap` |
| A hook that cannot start or crashes: `install` adds a launcher that turns it into a refusal (POSIX shells) | A Codex hook you have not trusted yet: Codex skips it silently |

What each layer sees, per harness: [docs/layers.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#what-each-layer-sees-and-stops).
All limits: [docs/benchmarks.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/benchmarks.md#limitations).

## Results

The question is how much tool poisoning and prompt injection fixed rules can stop, and at what cost in blocked legitimate
work. The answer is narrower than a headline number suggests.

MSB (MCP Security Bench) runs real MCP servers in Docker with an agent on the host. The tables use 220 cases, one run each
at temperature 0, with three local agents and Gemini 3.5 Flash-Lite on 99 of the cases. They are new draws of the attack
templates the rules were tuned on: held out from the tuning cases, not from the attack wording. The gateway arm is IntentShield
as an MCP gateway, the hooks arm as harness hooks. "Trivial baseline" withholds descriptions, blanks self-disclosure
parameters and holds every state-changing call for a human.

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

What the tables do not show:

- The runs are single, with small local models and one cloud model, on new draws of the tuning templates.
- Only the three qwen2.5:7b arms (no guard, baseline, gateway) were rerun on the code of 2026-10-19 with the code version
  recorded. The other 19 of 22 trace files (every hooks, llama, ornith and Gemini arm) come from older code, so the tables
  do not show that the current release gives these numbers.

Every number above comes from committed traces. The other results (LLM judge, Prompt Guard 2, adaptive attackers, MCPTox,
live runs in all four harnesses, overhead of about 60 to 70 ms per hook event on an Apple M5) are in [docs/benchmarks.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/benchmarks.md) with their protocols and caveats.

## Reproduce

Run these from a clone, after `uv sync --extra dev`. The PyPI source distribution has no tests or benchmarks.

| command | what it regenerates | external data needed | time |
|---|---|---|---|
| `uv run python benchmarks/paper_numbers.py` | every MSB table above, with paired bootstrap intervals | none: committed traces, no Docker, model or network | about 3 s |
| `uv run intentshield-mcp-verify --demo --stdio` | 13 checks of the gateway mode against a bundled demo server (not the hooks or `wrap`) | none | about 1 s |
| `uv run python benchmarks/hook_fidelity/compare.py summarize <copy of results/hook-fidelity/compare>` | the study's head-to-head tables (it writes into the directory, so copy it first) | none: committed rows | under 1 s |
| `uv run python benchmarks/latency.py --calls 50 --hooks 30 --out <file>` | hook and proxy overhead on your machine | none | about 15 s |
| `benchmarks/mcptox.py --replay`, `benchmarks/injection_eval.py` (flags in `results/README.md`) | MCPTox replay rows; injection detection table | MCPTox-Benchmark and InjecAgent checkouts | not timed |

New MSB runs, the live harness checks and the study's guard decisions need Docker, Ollama or a paid API, the
harness builds, or clones of the other guards ([results/README.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/results/README.md),
[results/hook-fidelity/README.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/results/hook-fidelity/README.md)).

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

- **Setup.** Real builds of Claude Code, Codex CLI and Gemini CLI, run headless on macOS against a scripted stub
  model, not a real agent. Cursor was not measured. IntentShield's own hook is one of the things measured.
- **Deny and ask.** A `deny` the harness parsed was enforced on every build where the hook ran. An `ask` with nobody to
  answer it was refused by Claude Code from 2.1.85 (with Bash pre-approved, which confounds the older builds), ignored by
  Codex CLI, and run or left hanging by Gemini CLI depending on the build (under yolo mode or with the shell allow-listed).
- **Failures.** A hook that ran past its timeout let the call run on every Claude Code and Codex build tested; a hook that
  printed nothing, exited 1 or had a missing interpreter was tested on one Claude Code and two Codex builds only.
- **Other guards.** Mixed. Before its dangerous-command rules IntentShield let more harmful calls through than two other
  guards on one set. With the opt-in rules it let fewer through on a second set written from the same categories as the
  rules, and on denies alone it trails one of the other guards.
- **Limits and status.** One author, one operating system, a stub model, author-written fixtures, no second coder. It does
  not show that an attacker can bypass a guard. A measurement note and an artifact, not a paper; nothing was sent to a vendor.

Build counts and the rest are in the [short report](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/hook-fidelity-report.md); the
[full record](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/hook-fidelity-study.md) has every run.

## Documentation

- [docs/guide.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md): dashboard, gateway, hooks, settings, troubleshooting.
  [docs/layers.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md): what each layer sees and stops, judge options.
  [docs/benchmarks.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/benchmarks.md): every protocol and table, limitations.
- [docs/contribution.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/contribution.md) says what the work does and does not support as a research contribution; [docs/README.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/README.md) indexes the rest.
- Guide sections: [wrapping a third-party hook](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#wrapping-a-third-party-hook) (`intentshield wrap-hook`) and the [built-in tool rules](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#built-in-tools-and-the-dangerous-command-rules) (`--builtin-tools`).
- [SECURITY.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/SECURITY.md), [CONTRIBUTING.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/CONTRIBUTING.md), [CHANGELOG.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/CHANGELOG.md), [CITATION.cff](https://github.com/Suhas-123-cell/IntentShield/blob/main/CITATION.cff). Licence: Apache-2.0, [LICENSE](https://github.com/Suhas-123-cell/IntentShield/blob/main/LICENSE).
