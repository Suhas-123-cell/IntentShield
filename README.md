# IntentShield for MCP

[![CI][ci-badge]][ci]
[![PyPI][pypi-badge]][pypi]
[![Licence: Apache-2.0][licence-badge]][licence]

IntentShield checks what your AI coding agent does with MCP (Model Context Protocol) tools, on your machine, before anything runs:
each call is allowed, held for you to confirm (an "ask"), or blocked (a "deny"). It is for developers who use Claude Code, Codex CLI,
Cursor or Gemini CLI, or any MCP client that starts stdio servers, and who want a poisoned tool or an injected instruction stopped
before it acts. It uses deterministic rules and needs no API key.

Only some harnesses show an ask as a prompt: Claude Code 2.1.85 or later in an interactive session, Cursor for shell commands (with `--builtin-tools`)
and Gemini CLI for shell commands (with `install gemini --gemini-ask`). Everywhere else an ask is a refusal that carries the reason:
Codex CLI, MCP calls on Cursor and Gemini CLI, and any headless run ([what each harness shows][asks]).

"Intent" is what you asked for: the hook and the gateway check each call against your prompt or the request the model states. The
default hook install runs rules and a memory of attacks the rules confirmed; it loads no trained model and calls no LLM judge.
One author; how the work was produced is in [Authorship and process][authorship].

What the harnesses do with a hook's verdict is in [the hook study](#the-hook-study) below.

## Quick start

```sh
uv tool install intentshield-mcp   # or: pipx install intentshield-mcp
intentshield demo                  # sample calls through the real hook: an allow, an ask, a deny; no settings change, nothing runs
intentshield install claude        # or codex, cursor, gemini; guards MCP calls only: add --builtin-tools for shell, file and web tools (best effort)
                                   # --scope project: this directory only (not Codex)
intentshield-mcp-verify --demo --stdio --summary   # the proxy's own check against a bundled demo server
```

What you should see:
- `demo` prints one line per sample call (`allow`, `ask`, `deny`) with the rule's reason, then a second `deny` for an MCP call, and exits 0.
- `install` runs `<harness> --version` once to record the build, prints `installed claude hooks in <the settings file>`, then a `Next:` line.
- Start the harness (Codex CLI first asks you to trust the hooks), send any prompt and run `intentshield doctor`. Right after
  `install` it prints a `warn` that no hook has run yet and exits 0; a line that stays `FAIL` is in [Troubleshooting][troubleshooting].
- If `install` says it could not read the version of the harness, put the harness on `PATH` and run `intentshield doctor`.
  Until then Claude Code, and Gemini CLI with `--gemini-ask`, refuse a call that would normally ask you. On the other harnesses
  no verdict depends on the version.

**What the default install guards.** MCP calls. Shell, file and web tools are guarded only with `--builtin-tools` (opt-in, best effort;
[the rules][rules]); `demo` runs its shell calls with that flag on.

Four words recur. The *harness* is the agent program you run (Claude Code, Codex CLI, Cursor or Gemini CLI). A *hook* is a command the
harness runs before each tool call and asks what to do; `install` registers IntentShield as that command. The *proxy* sits between the
harness and one MCP server; `wrap` puts it there. The *gateway* is an MCP server of IntentShield's own that the agent calls other
tools through. The [glossary][glossary] has the rest.

![IntentShield blocking an injected MCP call][demo-gif]

### Install notes

- Needs Python 3.11 or later and [uv][uv] (`brew install uv`, or `pip install uv`); `pipx` works too.
- On a system Python that pip will not change ("externally-managed-environment") use `uv tool` or `pipx`; if `intentshield` is then
  not found, run `uv tool update-shell` or `pipx ensurepath`. Do not install through `uvx`, which leaves a temporary path behind.
- Verdict handling was measured on Claude Code 2.0.41 to 2.1.316, Codex CLI 0.131.0 to 0.166.0 and Gemini CLI 0.24.5 to 0.66.0; Cursor was
  not measured. On a build older than these an ask is a refusal, not a prompt.
- The PyPI name is `intentshield-mcp`; `intentshield` there is [a different project][pypi-other].
- The package ships no trained model and has no `ml` extra: the optional learned classifiers ([docs/detectors.md][detectors]) are
  trained from a clone. The optional LLM judge (`--judge`, off by default; a hosted one sends prompts, arguments and tool text to its
  provider) is in [docs/layers.md][judge].
- The verify command above ends with `PASS 13/13 checks`. It does not check the proxy `wrap` installs; `doctor --connect` starts each
  wrapped server through its proxy.
- **Platforms:** tested on macOS and Linux (CI, Python 3.11 to 3.14); Windows is untested. The [glossary][glossary] defines the terms
  used here.

## Threat model

- **Attacker:** whoever controls text the model reads (an MCP server's tool descriptions and results, a fetched page, a file) and
  wants the agent to make a call you did not ask for.
- **Trusted:** you, your prompts, your machine, the harness and IntentShield's own rules. The model's output and everything an MCP
  server sends are untrusted: scanned, never obeyed. Only the deterministic rules can allow a call; detectors and the judge add evidence.
- **Not covered:** an attacker who already has your shell or controls the harness; the MCP servers' own code; the harness's shell, file
  and web tools unless installed with `--builtin-tools` (best effort); plain-language injections the rules do not read.
- Full text: [Security boundary][boundary] and [what is in and out of scope][scope].

## Put the proxy in front of MCP servers

```sh
intentshield wrap .mcp.json          # or ~/.claude.json (servers added with `claude mcp add`), Cursor mcp.json, Gemini settings.json,
                                     # ~/.codex/config.toml, VS Code mcp.json; restart the client afterwards
intentshield unwrap .mcp.json        # undo; add --dry-run to either command to preview
intentshield scan                    # lists the tools of your user-level configs' servers (stdio ones are started, HTTP ones connected to)
intentshield scan .mcp.json          # a project .mcp.json is started only when you name it
```

`wrap` rewrites each stdio server to start through `intentshield-mcp --transparent`, which hides poisoned or changed tool
descriptions and flags injected results. HTTP servers (`"url"`) are left alone. `doctor` prints the exact `wrap` command for each
config file it finds.

`scan` and `doctor --connect` do not start servers named by a config in the current directory unless you name the file
(`intentshield scan .mcp.json`) or pass `--connect-project`. With no config at all, `scan` says so and exits 0; with only a project
config it starts nothing and exits 2. `install` and `wrap` write absolute paths of this machine, so do not commit a wrapped project
file or a `--scope project` hook file. Formats, the reduced environment a wrapped server sees and what `scan` starts are in the
[guide][guide-harness].

## What it stops and does not stop

| Stops | Does not stop |
|---|---|
| Instructions injected into a tool call's arguments or a tool result | Plain-language injections with no instruction marker (the optional judge reads these) |
| A value a tool result supplied that the user never gave: an address, URL, path or credential | Most non-English injections: the rules read two phrases in 11 languages |
| Poisoned tool descriptions, and descriptions that change after you accepted them (a "rug pull"), through the proxy | The harness's own shell and file tools, unless installed with `--builtin-tools` (opt-in, best effort). An MCP filesystem or shell server is read only by its `path` and `command` arguments |
| Tools that ask for the model's name or system prompt: the guard removes them from the schema | HTTP MCP servers under `wrap` |
| A hook that cannot start or crashes: `install` adds a launcher that turns it into a refusal (POSIX shells) | A Codex hook you have not trusted yet: Codex skips it silently |

The left column lists the categories the rules were written for; the catch rate on injection text they were not written for is low
([Results](#results)). Per harness: [what each layer sees][sees]. All limits: [docs/benchmarks.md][limitations].

## Documentation

- [docs/README.md][docs-readme]: how it works in 60 seconds, which files are the product documentation, a reading path and where the
  working notes are. The research verdict: [docs/contribution.md][contribution].
- [docs/guide.md][guide]: hooks, the proxy, scan, troubleshooting and [wrapping a third-party hook][wrap-hook].
  [docs/rules.md][rules]: what `--builtin-tools` denies and asks.
- [docs/gateway.md][gateway]: the gateway, dashboard and REST API. [docs/layers.md][layers]: what each layer sees and stops.
- [docs/benchmarks.md][benchmarks]: every protocol, table and limit, and the commands that regenerate them.
  [docs/hook-fidelity-report.md][report]: the hook study.
- [SECURITY.md][security], [CONTRIBUTING.md][contributing], [CHANGELOG.md][changelog], [CITATION.cff][citation].
  Licence: Apache-2.0, [LICENSE][licence].

## What is stored locally

In `~/.intentshield`:
- `hooks.db` (mode 0600): per-session state. It holds your prompts, with any credential the guard recognises replaced by a short
  hash, and the values (addresses, URLs, paths) taken from tool calls and results. A clean session is forgotten after 7 days without
  activity, one that holds a flag or taint after 30.
- `gateway.db` and `proxies/<server>-<hash>.db` for each wrapped server: an audit database with call arguments and results, with no expiry.
- `backups/`: each settings or MCP file as it was before `install` or `wrap` first changed it; it can hold tokens that were already in it.
- `threats.db`: learned threat memory (30 days unless confirmed). `.env`: a judge key, if you set one.

[SECURITY.md][stored] lists every file and the commands for a single one.

## Upgrading and removing

```sh
uv tool upgrade intentshield-mcp && intentshield install claude   # then again for each harness, with your earlier options
intentshield uninstall claude; intentshield unwrap .mcp.json      # undo your files first: they may need the backups
uv tool uninstall intentshield-mcp; rm -r ~/.intentshield         # last
```

Give `install` the options you used before: running it again without `--builtin-tools` turns those rules off.

Coming from 0.4.4: [Upgrading from 0.4.4][upgrade-044] lists what changes for you, including the verdicts that are weaker than in
0.4.4. Coming from 0.4.3: [Upgrading from 0.4.3][upgrade-043]. Full steps: [Upgrading and removing][upgrading].

## Results

The weak numbers come first. Protocols, intervals and every caveat are in [docs/benchmarks.md][benchmarks].
The [hook study](#the-hook-study) is below.
- **Injection text the rules were not written for:** the rules catch 28 of 1,427 (2.0%); with exemplars (a nearest-neighbour check) 252
  (17.7%), mostly generated texts in the index's own styles. The rules catch 50.8% of all 2,959 injections, but were tuned on 1,505 of them.
- **MCP Security Bench** (an attack benchmark for agents that use MCP tools): no guarded arm let a harmful call run (0.0% executed; a call
  held for a human counts as not executed), but a trivial baseline did equally well, so it cannot rank guards. The gateway held 0.69 to
  2.00 benign calls per case for review (the baseline 0.57 to 0.95) and cost 8 to 14 points of task completion against it. 19 of the 22
  trace files carry no provenance record.
- **Overhead:** about 70 ms per hook event and 140 ms per guarded MCP call. **Limits:** single runs of small models on templates the
  rules were tuned on.

## The hook study

What coding-agent tools do with the verdict a hook returns, measured on Claude Code, Codex CLI and Gemini CLI with a scripted stub
model on macOS. The [report][report] has every count and caveat.
- A `deny` the harness parsed was enforced on every build where the hook ran. An `ask` with nobody to answer it is handled three ways.
- With a 3 s hook timeout the call ran on 22 of 22 Claude Code, 12 of 12 Codex CLI and 1 of 1 Gemini CLI builds.
- Against two other published guards the result is mixed: in unattended runs IntentShield's hook trails safety-net on denies alone.
- **Limits:** one author, one operating system, a stub model, author-written fixtures, no second coder; Cursor was not measured;
  nothing was sent to a vendor. A measurement note and an artifact, not a paper.

[ci]: https://github.com/Suhas-123-cell/IntentShield/actions/workflows/ci.yml
[ci-badge]: https://github.com/Suhas-123-cell/IntentShield/actions/workflows/ci.yml/badge.svg
[pypi]: https://pypi.org/project/intentshield-mcp/
[pypi-badge]: https://img.shields.io/pypi/v/intentshield-mcp
[pypi-other]: https://pypi.org/project/intentshield/
[licence]: https://github.com/Suhas-123-cell/IntentShield/blob/main/LICENSE
[licence-badge]: https://img.shields.io/badge/licence-Apache--2.0-blue.svg
[uv]: https://docs.astral.sh/uv/
[demo-gif]: https://raw.githubusercontent.com/Suhas-123-cell/IntentShield/main/docs/demo.gif
[glossary]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#terms
[authorship]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/contribution.md#authorship-and-process
[troubleshooting]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#troubleshooting
[asks]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#when-the-guard-blocks-or-asks-about-something-legitimate
[rules]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/rules.md
[detectors]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/detectors.md
[judge]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#the-optional-llm-judge
[boundary]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#security-boundary
[scope]: https://github.com/Suhas-123-cell/IntentShield/blob/main/SECURITY.md#in-scope
[guide-harness]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#guard-an-agent-harness-claude-code-codex-cli-cursor-gemini-cli
[sees]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md#what-each-layer-sees-and-stops
[limitations]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/benchmarks.md#limitations
[docs-readme]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/README.md
[contribution]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/contribution.md
[guide]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md
[wrap-hook]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#wrapping-a-third-party-hook
[gateway]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/gateway.md
[layers]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/layers.md
[benchmarks]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/benchmarks.md
[report]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/hook-fidelity-report.md
[security]: https://github.com/Suhas-123-cell/IntentShield/blob/main/SECURITY.md
[stored]: https://github.com/Suhas-123-cell/IntentShield/blob/main/SECURITY.md#what-is-stored-locally
[contributing]: https://github.com/Suhas-123-cell/IntentShield/blob/main/CONTRIBUTING.md
[changelog]: https://github.com/Suhas-123-cell/IntentShield/blob/main/CHANGELOG.md
[citation]: https://github.com/Suhas-123-cell/IntentShield/blob/main/CITATION.cff
[upgrade-044]: https://github.com/Suhas-123-cell/IntentShield/blob/main/CHANGELOG.md#upgrading-from-044
[upgrade-043]: https://github.com/Suhas-123-cell/IntentShield/blob/main/CHANGELOG.md#upgrading-from-043
[upgrading]: https://github.com/Suhas-123-cell/IntentShield/blob/main/docs/guide.md#upgrading-and-removing-intentshield
