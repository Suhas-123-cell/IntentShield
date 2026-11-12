# IntentShield for MCP

[![CI](https://github.com/Suhas-123-cell/IntentShield/actions/workflows/ci.yml/badge.svg)](https://github.com/Suhas-123-cell/IntentShield/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/intentshield-mcp)](https://pypi.org/project/intentshield-mcp/)
[![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](https://github.com/Suhas-123-cell/IntentShield/blob/main/LICENSE)

IntentShield checks what your AI coding agent does with MCP (Model Context Protocol) tools, on your machine, before
anything runs. It reads each tool call, tool description and tool result with deterministic rules and then allows
the call, holds it for you to confirm (an "ask"), or blocks it (a "deny"); the core needs no API key. Hooks say
allow, ask and deny; the gateway and proxy log the same three outcomes as ALLOW, REVIEW and BLOCK.

It works with Claude Code, Codex CLI, Cursor and Gemini CLI (through their hooks: commands the harness runs before each tool call)
and with any MCP client that launches stdio servers (through a proxy). One author; how the work was produced is in
[Authorship and process](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/contribution.md#authorship-and-process).

**Threat model.**
- **Attacker:** whoever controls text the model reads (an MCP server's tool descriptions and results, a fetched page, a file) and
  wants the agent to make a call you did not ask for.
- **Trusted:** you, your prompts, your machine, the harness and IntentShield's own rules. The model's output and everything an MCP
  server sends are untrusted: scanned, never obeyed. Only the deterministic rules can allow a call; detectors and the judge add evidence.
- **Not covered:** an attacker who already has your shell or controls the harness; the MCP servers' own code; the harness's shell, file
  and web tools unless installed with `--builtin-tools` (best effort); plain-language injections the rules do not read.
- Full text: [Security boundary](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#security-boundary) and [what is in and out of scope](https://github.com/Suhas-123-cell/IntentShield/blob/main/SECURITY.md#in-scope).

![IntentShield blocking an injected MCP call](https://raw.githubusercontent.com/Suhas-123-cell/IntentShield/main/docs/demo.gif)

## Install

Python 3.11 or later and [uv](https://docs.astral.sh/uv/) (`brew install uv`, or `pip install uv`); `pipx` works too.

```sh
uv tool install intentshield-mcp   # or: pipx install intentshield-mcp
intentshield install claude        # or codex, cursor, gemini; --scope project for this directory only (not Codex)
intentshield demo                  # sample calls through the real hook: an allow, an ask and a deny; nothing runs
intentshield doctor                # run it after you start the harness and send it any prompt
intentshield-mcp-verify --demo --stdio --summary   # the proxy's own check against a bundled demo server
```

What you should see:
- `install` prints `installed claude hooks in <the settings file>`, then a `Next:` line.
- `demo` prints one line per sample call (`allow`, `ask`, `deny`) with the rule's reason, then a second `deny` for an MCP call, and exits 0.
- `doctor` right after `install` prints a `warn` that no hook has run yet and exits 0 (since 0.4.4; 0.4.3 printed `FAIL` and
  exited 1). Start the harness (Codex CLI first asks you to trust the hooks), send any prompt and run it again. A line that stays
  `FAIL` is in [Troubleshooting](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#troubleshooting).
- `intentshield-mcp-verify` ends with `PASS 13/13 checks`. It checks the bundled demo server, not the proxy `wrap` installs; `doctor --connect` starts each wrapped server through its proxy.

**What the default install guards.** MCP calls. Shell, file and web tools are guarded only with `--builtin-tools`
(`intentshield install claude --builtin-tools`; opt-in, best effort); `demo` runs its shell calls with that flag on.
The optional LLM judge (`--judge`, off by default; a hosted one sends prompts, arguments and tool text to its provider) is in
[docs/layers.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#the-optional-llm-judge); the [glossary](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#terms) defines the terms.

On a system Python that pip will not change ("externally-managed-environment") use `uv tool` or `pipx`; if `intentshield` is then
not found, run `uv tool update-shell` or `pipx ensurepath`. Do not install through `uvx`, which leaves a temporary path behind.
The PyPI name is `intentshield-mcp`; `intentshield` there is [a different project](https://pypi.org/project/intentshield/).
The package ships no trained model and has no `ml` extra: the optional learned classifiers ([docs/detectors.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/detectors.md)) are trained from a clone. **Platforms:** tested on macOS and Linux (CI, Python 3.11 to 3.14); Windows is untested.

## Put the proxy in front of MCP servers

```sh
intentshield wrap .mcp.json          # or ~/.claude.json (servers added with `claude mcp add`), Cursor mcp.json, Gemini settings.json,
                                     # ~/.codex/config.toml, VS Code mcp.json; restart the client afterwards
intentshield unwrap .mcp.json        # undo; add --dry-run to either command to preview
intentshield scan                    # check the servers you already use; it starts each one to list its tools
```

`wrap` rewrites each stdio server to start through `intentshield-mcp --transparent`, which hides poisoned or changed tool
descriptions and flags injected results. HTTP servers (`"url"`) are left alone. `doctor` prints the exact `wrap` command for each
config file it finds. `install` and `wrap` write absolute paths of this machine, so do not commit a wrapped project file or a
`--scope project` hook file. Formats, the reduced environment a wrapped server sees and what `scan` starts are in the
[guide](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#guard-an-agent-harness-claude-code-codex-cli-cursor-gemini-cli).

## What it stops and does not stop

| Stops | Does not stop |
|---|---|
| Instructions injected into a tool call's arguments or a tool result | Plain-language injections with no instruction marker (the optional judge reads these) |
| A value a tool result supplied that the user never gave: an address, URL, path or credential | Most non-English injections: the rules read two phrases in 11 languages |
| Poisoned tool descriptions, and descriptions that change after you accepted them (a "rug pull"), through the proxy | The harness's own shell and file tools, unless installed with `--builtin-tools` (opt-in, best effort). An MCP filesystem or shell server is read only by its `path` and `command` arguments |
| Tools that ask for the model's name or system prompt: the guard removes them from the schema | HTTP MCP servers under `wrap` |
| A hook that cannot start or crashes: `install` adds a launcher that turns it into a refusal (POSIX shells) | A Codex hook you have not trusted yet: Codex skips it silently |

The left column lists the categories the rules were written for. The measured catch rate on injection text they were not
written for is low: see [Results](#results). What each layer sees, per harness:
[docs/layers.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#what-each-layer-sees-and-stops). All limits:
[docs/benchmarks.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/benchmarks.md#limitations).

## What is stored locally

In `~/.intentshield`:
- `hooks.db` (mode 0600): per-session state. It holds your prompts, with any credential the guard recognises replaced by a short
  hash, and the values (addresses, URLs, paths) taken from tool calls and results. A clean session is forgotten after 7 days without
  activity, one that holds a flag or taint after 30.
- `threats.db`: learned threat memory (30 days unless confirmed).
- `gateway.db` and `proxies/<server>-<hash>.db` for each wrapped server: an audit database with call arguments and results, with no expiry.
- `backups/`: each settings or MCP file as it was before `install` or `wrap` first changed it; it can hold tokens that were already in it.
- `.env`: a judge key, if you set one.

[SECURITY.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/SECURITY.md#what-is-stored-locally) lists every file and the commands for a single one.

## Upgrading and removing

```sh
uv tool upgrade intentshield-mcp && intentshield install claude   # then again for each harness, with your earlier options
intentshield uninstall claude; intentshield unwrap .mcp.json      # undo your files first: they may need the backups
uv tool uninstall intentshield-mcp; rm -r ~/.intentshield         # last
```

Coming from 0.4.3: [Upgrading from 0.4.3](https://github.com/Suhas-123-cell/IntentShield/blob/main/CHANGELOG.md#upgrading-from-043) lists what changes for you, including that a call with MCP arguments over 1,000,000 characters now asks.
Full steps: [Upgrading and removing](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#upgrading-and-removing-intentshield).

## Results

The weak numbers come first. Protocols, intervals, tables and every caveat are in [docs/benchmarks.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/benchmarks.md). The [hook study](#the-hook-study) is below.
- **Injection text the rules were not written for:** the rules catch 28 of 1,427 (2.0%); with exemplars (a nearest-neighbour check) 252 (17.7%),
  mostly generated outputs in the exemplar index's own styles. The rules catch 50.8% of all 2,959 injections, but were tuned on 1,505 of them.
- **MCP Security Bench (MSB):** no guarded arm let a harmful call run, but a trivial baseline did equally well, so the metric cannot rank guards.
  The gateway cost 8 to 14 points of task completion against that baseline. A call held for a human counts as not executed.
- **MCPTox replay (a tuning set):** 0.4% attack success, 3.5% of benign calls blocked and 46.3% sent to review.
- **Limits:** single runs of small models on templates the rules were tuned on. Overhead is about 70 ms per hook event and 140 ms per guarded MCP call.

## The hook study

What coding-agent tools do with the verdict a hook returns: the [report](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/hook-fidelity-report.md) is about 2,800 words and has every count and caveat.
- **Setup.** Claude Code (27 scored builds), Codex CLI (14) and Gemini CLI (28), run headless on macOS against a scripted stub model. Cursor was not measured.
- **Deny and ask.** A `deny` the harness parsed was enforced on every build where the hook ran. An `ask` with nobody to answer it was refused
  by Claude Code from 2.1.85 (the sweep pre-approved Bash; without that, one build, 2.1.316, was tested), ignored by Codex CLI, and run or left hanging by Gemini CLI.
- **Timeouts.** With a 3 s hook timeout the call ran on 22 of 22 Claude Code, 12 of 12 Codex CLI and 1 of 1 Gemini CLI builds. Claude Code's
  `onFailure: "block"`, which `install` writes, blocked it on one build (2.1.316). Other failures were tested on one or two builds.
- **Other guards.** Mixed. Before its dangerous-command rules IntentShield let through 137 of 166 harmful calls, against 31 of 130 for safety-net and 67 of 117 for knox on their own scopes.
  Denies alone, with the opt-in rules as they were when scored, IntentShield denied 24 of 85 harmful calls and safety-net 41 of 85 (p = 0.0033; descriptive only). With the rules now,
  `benchmarks/hook_fidelity/fresh_report.py --current-rules` gives 29 of 85 (p = 0.043), and one item moved would put it above 0.05. Its gain elsewhere fits its own rule categories and is post hoc. On benign calls it ties safety-net and trails knox.
- **Limits.** One author, one operating system, a stub model, author-written fixtures, no second coder. A measurement note and an artifact, not a paper; nothing was sent to a vendor.

## Documentation

- [docs/README.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/README.md): which files are the product documentation, a reading path with word counts, and where the working notes are. The research verdict: [docs/contribution.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/contribution.md).
- [docs/guide.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md): hooks, the proxy, scan, troubleshooting, the [built-in tool rules](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#built-in-tools-and-the-dangerous-command-rules) and [wrapping a third-party hook](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#wrapping-a-third-party-hook).
- [docs/gateway.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/gateway.md): the gateway, dashboard and REST API. [docs/layers.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md): what each layer sees and stops.
- [docs/benchmarks.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/benchmarks.md): every protocol, table and limit, and the commands that regenerate them. [docs/hook-fidelity-report.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/hook-fidelity-report.md): the hook study.
- [SECURITY.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/SECURITY.md), [CONTRIBUTING.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/CONTRIBUTING.md), [CHANGELOG.md](https://github.com/Suhas-123-cell/IntentShield/blob/main/CHANGELOG.md), [CITATION.cff](https://github.com/Suhas-123-cell/IntentShield/blob/main/CITATION.cff). Licence: Apache-2.0, [LICENSE](https://github.com/Suhas-123-cell/IntentShield/blob/main/LICENSE).
