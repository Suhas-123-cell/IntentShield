# Changelog

User-visible changes go under `## Unreleased` (see [CONTRIBUTING.md](CONTRIBUTING.md#changelog)). Release dates are the dates of the release tags; 0.1.0 was never tagged and has none.

Terms such as taint, provenance, verdict translation and the fail-closed launcher are defined in the [glossary](docs/layers.md#terms).

## Unreleased

## 0.4.4 - 2026-11-12

### Upgrading from 0.4.3

Nothing to run: an installed hook keeps working. What changes for you:

- **Everyone:** `doctor` right after an install exits 0 with a `warn` (0.4.3 exited 1 with a `FAIL`) and prints `note` lines only with
  `--verbose`. `wrap` can exit 1 where it exited 0.
- **Everyone:** `install claude --scope project` writes `.claude/settings.local.json`; install again to move a 0.4.3 hook out of
  `.claude/settings.json`.
- **Everyone:** a `wrap` of a new server names its database `NAME-<hash>.db`; the files of 0.4.3 are used as they are.
- **Everyone:** an injection split between two text blocks, a call named `mcp__x` and a result over 1,000,000 characters are now
  flagged, refused or asked about.
- **Everyone:** a call whose tool name is not text, or a Gemini CLI tool named like an MCP tool with no `mcp_context`, is refused with a
  reason; the transparent proxy answers a message that is not a JSON-RPC request with `-32600`.
- **Everyone:** `pip install intentshield-mcp[dev]` no longer exists; contributors run `uv sync --group dev`.
- **Only with `--builtin-tools`:** more commands are denied or asked about, and a few false asks and denies stop (a backup of
  `~/.ssh/config`, `~/.ssh/known_hosts`); this applies as soon as the package is upgraded. See [the rules](docs/guide.md#built-in-tools-and-the-dangerous-command-rules).

### Added

- `wrap` and `unwrap` read Codex CLI's `~/.codex/config.toml` and VS Code's `mcp.json` and `settings.json`; a file with no servers it
  can read says which formats it reads ([layers.md](docs/layers.md)).
- `doctor` prints an `ok` line per file whose wrapped servers passed. `doctor --connect` starts each wrapped server through its proxy
  and lists its tools (`--connect-project` for servers named by a file in the working directory); without them it starts nothing.
- `doctor --verbose` lists the `note` lines, which `doctor` now counts; paths under your home print as `~/`.
- `intentshield-mcp-verify --summary` prints `PASS 13/13 checks` and one line per failing check.
- `intentshield demo` also sends one MCP call to the default install's hook. `install` says when it guards MCP calls only, and which
  options a reinstall dropped.
- `wrap` ends with a `Next:` line. `wrap-hook --print-entry --harness cursor` notes that the entry needs `"failClosed": true`. `scan`
  names the address of an HTTP server that failed.
- `scan` prints what each matched `tool_poisoning` rule means and the first words that matched; the proxy logs one warning for each
  tool it hides.
- Only with `--builtin-tools`: the hook also reads the arguments of an MCP tool, a path through the file rules and `command` or `cmd`
  through the shell rules. It only makes a verdict stricter ([guide](docs/guide.md#built-in-tools-and-the-dangerous-command-rules)).
- The proxy config takes `trusted_tools` (`server:tool` names). A description that only names a secret file still hides its tool, and
  no longer counts as an attack by its server ([guide](docs/guide.md#troubleshooting)).

### Changed

- A tool result split across adjacent text blocks is scanned as one text, by the hook and by the proxy.
- A tool call named `mcp__x` with no tool part is refused by the Claude Code hook; it was let through.
- `install`, `uninstall`, `wrap` and `unwrap` give a file back with its exact bytes. `uninstall` puts back an original settings file
  that was empty or `{}`.
- Python 3.11 is supported (CI runs 3.11 to 3.14). The development tools moved from the `dev` extra to a dependency group.
- `doctor` right after an `install` is a `warn` that exits 0; the same state an hour later is a `FAIL`. It warns when a Claude Code
  `env` block sets a variable that loosens the guard.
- `install claude --scope project` writes `.claude/settings.local.json`; `uninstall` and `doctor` read both files.
- `wrap` exits 1, with a line on stderr, when it skipped a stdio server because of its entry. `wrap-hook` denies a reply that repeats a
  JSON key.
- The hook's reply carries a note when a variable that loosens the guard is set where it runs (not on Cursor). A tool result over
  1,000,000 characters is scanned at its two ends, and later state-changing calls ask.
- A call whose tool name is not text (Claude Code, Codex CLI), or is named like an MCP tool with no `mcp_context` (Gemini CLI), is
  refused with the reason; with `--builtin-tools` so is a call with no tool name. The transparent proxy answers a message that is
  not a JSON-RPC request with `-32600` and keeps serving.
- `doctor` writes `~/` only where a path starts, so the `wrap` command it prints can be copied. `wrap`'s `Next:` line asks you to close
  the client only for `~/.claude.json`; `scan` cuts a start-up error at a word.
- The help text of `intentshield-mcp --host` said a non-loopback address was accepted with a token; the server refuses it, and the help
  and the error now say so.
- Only with `--builtin-tools`: the rules read the command behind about 80 wrapper programs and the PowerShell cmdlets, deny or ask in
  more cases (a credential given to an unlisted program, `~/.aws`, `/etc/sudoers`, a raw socket, a write to IntentShield's own files, a redirect over a key, `rsync --delete` onto a system directory)
  and ask less in a few; a relative path is read from the call's directory and a file in `~/.ssh` by what it is
  ([the full list](docs/guide.md#built-in-tools-and-the-dangerous-command-rules)).

### Fixed

- A proxy audit database is named like its proxy config (`NAME-<hash>.db`), so two clients' servers of the same name no longer share
  one.
- A failure of the threat-memory file is reported with the name of the method that failed, and the call goes on as if the memory knew
  nothing.

## 0.4.3 - 2026-11-11

- The hook no longer lets an ask nobody can answer run the call, and a hook that cannot start or runs too long is refused,
  not allowed (verdict translation, a fail-closed launcher and a 30 s deadline, written by `install`).
- New `intentshield wrap-hook` runs any third-party hook under the same launcher and translation.
- New opt-in dangerous-command rules for the harness's own shell, file and web tools (`--builtin-tools`). What they deny and ask is in
  [docs/guide.md](docs/guide.md#built-in-tools-and-the-dangerous-command-rules), not here.

### Upgrading from 0.4.2

Run `intentshield install <harness>` again to get the launcher and the deadline. Behaviour that changes for you:

- **Everyone:** `install` writes a hook deadline (`--deadline`, default 30 s) and a fail-closed launcher. `--no-translate` or
  `INTENTSHIELD_HOOK_TRANSLATE=off` restores the old hook.
- **Everyone:** an ask that is not known to reach a person becomes a deny with a reason on Claude Code (it was an ask), Codex
  (already a deny) and Gemini.
- **Everyone:** the default databases of `Storage()`, `IntentShieldService.default()`, `create_mcp_server()` and a proxy config with no
  `database_path` are in `~/.intentshield`, not the working directory. `INTENTSHIELD_DB`, an explicit path and a database already
  in the working directory still win.
- **Everyone:** a command that needs a package that is not installed (after `pip install --no-deps`) prints one line naming it and
  exits 2, not a traceback.
- **Everyone:** `doctor` prints the measured fail-open conditions for the detected version, fails a wrapped server whose command
  does not exist, does not count a hand-piped event as a run, and says plainly when nothing is installed (exit 0). Facts about the
  harness that need no action print as `note`. Its exit status is in `doctor --help`.
- **Everyone:** the hook prints a note on stderr for each loosening `INTENTSHIELD_HOOK_*` or `INTENTSHIELD_THREAT_*` variable in its
  environment (`INTENTSHIELD_HOOK_REVIEW=never`, `_TRANSLATE=off`, `_DEADLINE=0`, `_SOURCED_READS=allow`, `INTENTSHIELD_THREAT_MEMORY=0`,
  or a moved database, pack or catalog path), because a project's settings can set them. A flag on the command line suppresses the note.
- **Everyone:** `intentshield-mcp` over stdio starts when a control or agent token appears only in a `.env` found by searching (a
  checkout's own). 0.4.2 stopped there too, although stdio reads no token. Over `--transport streamable-http`, and in the web API, a
  token that only such a file holds still stops the start.
- **Everyone:** `intentshield wrap-hook` reads every verdict key in a reply (`hookSpecificOutput`, the top level, `continue: false`) and
  sends the strictest of deny, ask and allow. A malformed key anywhere is a deny.
- **Only with `--builtin-tools`:** a deny beats an ask. When the session rules ask and the dangerous-command rules deny, the call is
  denied.

### Added

- **`intentshield demo`** sends three sample shell calls to the real hook and prints allow, ask and deny. Nothing runs and nothing
  is written outside a temporary directory. It needs no harness.
- **`intentshield wrap-hook`** (also `intentshield-wrap-hook`): a silent guard (exit 0, no output) is refused unless `--on-empty allow`;
  `--print-entry` prints the entry to paste in. There is no installer for third-party entries yet
  ([guide](docs/guide.md#wrapping-a-third-party-hook)).
- **Dangerous-command rules** (`--builtin-tools`) run on every shell command, file read and file write that the session rules allow.
  They read the text only, nothing is run, and parsing is linear-time. A call that would switch the guard off asks, even in a clean
  session (a speed bump, not protection). `PowerShell`, `Monitor` and `Grep` are covered; unreadable events are denied.
- **A mode note** ends every reply that came from an ask, saying how the harness mode was read. `INTENTSHIELD_ANCESTRY_SOURCES`
  restricts the sources the detector reads.
- **`install` and `wrap` refuse an ephemeral path** (a `uvx`, `pipx run` or `npx` cache) and name `uv tool install intentshield-mcp`;
  `--allow-ephemeral` overrides it. `install` ends with a "Next:" line and warns that a `--scope project` file holds absolute paths.

### Changed

- **The mode detector** reads ancestry from `/proc` on Linux and from `libproc` on macOS (no new dependency, no process spawned), then
  `ps`, and reads the headless flag from the harness's own arguments. When no source can read it the mode is unknown, not headless.
- **A deny is softened to an ask only on an exact target:** the prompt must name the whole path or host and must not negate it.
- **Shell reading** follows bash for one-line control structures, `cd` and variables set earlier in the line, `$'...'` strings and
  brace lists. Certificates (`cert.pem`, `fullchain.pem`, CA bundles) are not secrets.
- **Help texts** of the top-level command and `wrap-hook` are plain text, with no internal names or repository paths; the `wrap`
  message for an HTTP server gives the guide's URL. `intentshield-mcp-verify --demo` removes its temporary directory and, on a failed
  run, prints the types of the exceptions and the proxy's own last stderr lines.
- **`import intentshield` no longer reads package metadata** (`__version__` is read when first used), which shortens each hook start.
- **Error messages give the cause** where it can be told ("Could not connect to MCP server": command not found, ended before
  answering, no answer in time). `wrap` checks every entry before it writes any file. `scan` exit codes are in `scan --help`.
- **Stored prompts hold a hash in place of a credential** the guard recognises, and `~/.intentshield` is created with mode 0700
  (an existing one you own is tightened). Retention is unchanged.

### Fixed

- **`intentshield-mcp-verify --demo --stdio` failed in a checkout** whose own `.env` held `INTENTSHIELD_CONTROL_TOKEN`, because the
  proxy refused that token (see Upgrading).
- **Interactive asks read as headless** when `ps` cannot run (under `sandbox-exec`, in a container without procps, on Windows) or
  the harness is PID 1: the ask became a refusal with no prompt.
- **Threat memory:** approving a call the hook asked about no longer clears that server's hostile record across sessions.
- **Hook input:** a prompt or argument holding a lone surrogate no longer loses the prompt or fails the hook; a judge reply that is
  valid JSON of the wrong shape is no opinion, not a crash; `~/.intentshield/.env` may hold `export KEY=value` lines.
- **`wrap`, `unwrap` and `scan`:** a wrapped server whose entry sets an empty `env` value starts again; a malformed `scan` entry is
  reported as not scanned instead of a traceback; a named file that does not exist exits 2, where it used to exit 0; a Gemini
  `settings.json` with comments is read as Gemini reads it and restored byte for byte on `uninstall`.
- **The transparent proxy answers what it cannot parse** (error -32602 or -32700) and keeps serving; the protocol library used to
  drop the request and the client waited.
- **Dangerous-command rules:** many spellings of one command (line continuations, tabs, `${IFS}`, empty quotes, comments, brace
  lists) read as the plain command; a command over 50,000 characters, 400 stages, 20,000 words or 3 nesting levels asks; and several
  false refusals are removed (`scp -i`, `git branch -d`, `.env.example`, text in single quotes or quoted here-documents).
- **Still open:** a payload written to a plain file with `echo '...' > x.sh` and run later, and `echo $'...' | sh`.

### Internal

- The wheel is marked typed (`py.typed`) and its classifiers say macOS and Linux. `anyio`, `starlette` and `httpx2`, which the code
  imports, are declared, and `cryptography` is the `signing` extra (Ed25519 threat packs).
- CI runs `mypy` (near-strict, with per-module exceptions), a macOS job, a coverage floor of 85% (91% measured) and a dependency
  audit (weekly; it fails only for an advisory that has a fix). The PyPI upload waits for the full CI run on the tagged commit. The
  source distribution holds the package and its configs, not tests.
- The repository has `CITATION.cff`, `NOTICE`, a code of conduct and a pull-request template.

### Study and benchmarks

The verdict translation came out of a measurement study of Claude Code, Codex CLI and Gemini CLI on a stub model (macOS, one
author; a measurement note, not a paper). Its results, limits and reproduction commands are in the
[report](docs/hook-fidelity-report.md); the committed rows are in `results/hook-fidelity/`. Re-running the committed fixtures
through this release's rules changes 51 `intentshield` decisions: 48 from ask to deny (harmful credential-exfiltration rows) and 3
from deny to ask (`git push -f origin HEAD`); the report says which sets. Overhead of the hook is measured in [docs/benchmarks.md](docs/benchmarks.md).

## 0.4.2 - 2026-10-31

The fixes of a second self-audit (66 findings: 54 fixed, 10 partly fixed, 2 refuted; see "Second audit" in
`docs/security-review.md`), the limits closed after 0.4.1, and a judge that can use your own key. One change to
check before upgrading: a control or agent token set only in a `.env` found by searching (such as a checkout's own)
now stops the gateway from starting; export it or put it in `~/.intentshield/.env`.

- **Credentials, paths and learned memory (second audit, rules-7, rules-8, rules-14 to rules-18, rules-20):** tokens split by
  separators or written as percent, escapes, hex lists, char codes or base32, glued to a word, or split across a key and its value
  are found (other encodings still are not); an inserted `xxxxxxxx` no longer hides a real token, while a documentation token masked
  after a few characters stays a placeholder; `mask()` covers private-key bodies and joined tokens; self-disclosure parameters are
  read in any spelling and nesting; `../` paths join the working directory; the rule safety gate refuses polynomial-backtracking
  patterns; one server, whatever its tool names, can no longer evict what other servers taught the threat memory; account numbers in
  other digit scripts match.

  Credentials found on 19,476 benign texts unchanged (2); hook decisions on 95 real sessions unchanged.
- **Detection rules (second audit, rules-1, rules-3 to rules-6, rules-9, rules-10, rules-12):** textbook override phrases flag
  (one-word variants of the closed list still pass); a negation exempts only a verb it governs, so "do not hesitate to send the
  password to ..." and "do not send a reply, send the password to ..." flag; feed and pack indicators match every spelling of a
  call's URL, address and host, including indicators with a port; `image_exfiltration` reads any case and more forms; bare hosts are
  read on every country code, internationalized domains and common longer domains, and on other root-zone domains after a word that
  points at a destination; IDN, ideographic-dot, octal and IPv6 hosts are read; tenant names on multi-tenant platforms trace and are
  learned, never the platform.

  Injection corpus 2,373 of 5,095 flagged (was 2,371), benign 29/1,365 and READMEs 8/79 unchanged; source code that says "backwards
  compatible" or `reversed(` is no longer read backwards for values.
- **Proxy (second audit, proxy-4 to proxy-9, proxy-11 to proxy-15):** a flagged or unread tool's schema no longer carries the
  withheld text (enum, const, default, long names). `scan` keeps the user's own servers and the pins of servers that did not start.
  An approved read whose upstream fails gets a final answer. A judge outage at connect leaves descriptions unreviewed, not clean.

  A `.env` found by searching can no longer set the proxy config, the tokens or loader variables, and a token found only there stops
  the start: **if your control token is in the checkout's `.env`, export it or move it to `~/.intentshield/.env`**. The output judge
  keeps the readable words inside an encoded blob and mixes random windows into its reading. Oversize results are refused before
  copying. A malformed `Retry-After` no longer raises, and a call lists the upstream once instead of twice. With the judge off or
  passing, tool views are byte-identical. Still open: results over 6 windows are only partly read.
- **Hooks, installer and doctor (second audit, hooks-7, hooks-9 to hooks-14, hooks-17, hooks-18):** `.local`, `.internal` and
  metadata hosts are no longer treated as this machine. After a flagged result, local builds, tests and commits run again on Gemini
  and Codex, unless they carry a tainted value, run a written script, load code through an option or discard work: 984 of 1,503 real
  commands are still refused there, down from 1,240. About 90 persistence points and build configs ask on a write after a flag, and
  Codex `apply_patch` is read.

  Doctor now catches a dead shebang interpreter, disabled hooks, matchers that miss MCP tools and a judge key set only in the shell.
  `wrap` skips servers that use `${VAR}`; `unwrap` works from its backup; Gemini settings with comments are read; `install --judge`
  stores a shell-only key. Sessions with no flag are unchanged (all 2,642 verdicts on 41 private sessions). Still open: a written
  test run after a flag, and lists of known names.
- **Denial of service (second audit, proxy-2, rules-2, rules-13, proxy-1, rules-11, proxy-3, hooks-16, proxy-10):** the output, mailbox, credential and marker regexes are linear (200 KB in under 1 s, was 25 s to minutes); deep tool schemas and outputs no longer crash `connect()` or the scan; the gateway no longer runs an upstream's own regexes; session intent and tainted sets are bounded, with any dropped taint flagging the session. Detection unchanged on the corpus (2371/5095, 29/1365, 8/79) and on 19,476 credential texts; `redis://:pw@host` is now found. Details and what is still open in docs/security-review.md.
- **Judge offline (second audit, hooks-8):** a judge that is down, rate-limited or has no key no longer turns every state-changing MCP call into an ask (Claude Code) or a refusal with a wrong instruction (Codex); its note goes to the model and the rules decide. After a failure that means no network or a refused key (not a timeout, rate limit or unreadable reply, which a hostile output could cause), the hooks skip the judge for 5 minutes: measured with an unreachable endpoint, the first call 1.13 s, the next ones 0.0 s.
- **Judge with your own key:** `install --judge openai:<model>`, `openrouter:<model>` or `custom:<model> --judge-url <URL>` (any OpenAI-compatible endpoint; https, or http to localhost) asks for the key once and stores it, and the URL, in `~/.intentshield/.env`; Groq's free tier stays the default. `install --judge deepseek`, which the README documented, was refused by the installer and now works. A refused `--judge` spec no longer stores a key first. These judges are not measured.
- **Shell parser (second audit, hooks-1 to hooks-6 and hooks-15):** a newline separates commands, comments and unbalanced quotes no
  longer hide a send, variables are read in order, wrappers (`setsid`, `flock`, `busybox`, `env -S`, `bash <(curl ..)`, `printf .. |
  sh`) and inline code no longer hide the command, curl header, cookie and cluster forms count as sends, and options that run
  programs or write files are not read-only.

  Three backstops independent of the parser: only plain syntax is read-only, every address in the raw text (also with escapes
  decoded and variables taken out) is a destination, and a sender next to one in the same statement sends. Parsing is linear
  (200,000 characters in 0.06 to 0.12 s, was 45 to 94 s); commands over 100,000 characters are read from the raw text. Benign cost:
  shell asks on 40 private (uncommitted) sessions from other projects went from 7 to 8 of 1,713; in IntentShield's own sessions
  flagged by injected outputs, from 830 to 1,066 of 3,720. Open residuals are listed in `docs/security-review.md`.
- **Cursor:** with `--builtin-tools`, `beforeShellExecution` now checks each shell command before it runs.
  Measured with `benchmarks/harness_live/cursor_hook_probe.py` on Cursor CLI 2026.10.22: a hook's `ask` or
  `deny` held a command, and `allow` did not skip Cursor's own approval (finding HK4). The same probe found
  that an `ask` on an MCP tool Cursor's allowlist approves ran the call, 3 of 3 times, so IntentShield's MCP
  asks under Cursor are now refusals. A call with no objection gets `{}`, never an empty reply, which a
  fail-closed Cursor hook treats as a failure.
- **Local judge:** Ollama's OpenAI-compatible endpoint keeps 4,096 tokens and cuts a longer prompt to about
  2,050, system prompt first, ignoring `num_ctx` (measured on 0.40); one window of Chinese text was 5,365
  tokens. The judge now uses the native `/api/chat` with `num_ctx` 8,192.
- **Judge time budget:** a hook could wait over 2 minutes on a long output (10 s per request, one retry, 6
  windows). Each check now has a budget (20 s in the hook, 30 s in the proxy); what it leaves unread is
  counted and said. The in-memory answer cache keys on provider and URL as well as the model.
- **Output rules** also read the text reversed and in rot13, and reference-style markdown images as inline
  ones. No new flags on 1,365 benign rows or 79 local READMEs; about 0.5 ms more per text.
- **Provenance:** a host a tool output names bare or as an email's domain now covers its subdomains, except
  under popular sites and registry suffixes. The review gate's output was byte-identical.
- **Shell parser:** reads `eval` and variables the command assigns itself, so `C="curl -F f=@x URL"; $C` and
  `U=URL; curl -d @x $U` show their destination. On 40 private sessions from other projects (not committed), shell asks went from
  4 to 7 of 1,707: each of the three put the user's own site, first seen in a tool output, in a variable, and
  asks as the same command written out would.
- **Relative paths:** the hooks join relative paths to the event's working directory, so `secrets/keys.json`
  in a call meets `/Users/me/proj/secrets/keys.json` in an output, while one the user named stays theirs. On
  40 private (uncommitted) sessions from other projects, MCP asks went from 53 to 55 of 126. `benchmarks/shell_replay.py` now
  passes each transcript's working directory to the hook.
- **Installer:** `install`, `wrap` and `unwrap` write nothing if the settings file changed after they read it
  (Claude Code rewrites `~/.claude.json` often), so a harness's own write is never overwritten; run again.
- **Credentials** are found base64- or hex-encoded, reversed, split over two fields or across lines, and masked
  as written. No new hits on 6,460 corpus rows, 79 READMEs or 12,937 MSB call arguments.

## 0.4.1 - 2026-10-30

The hooks can now guard the harness's own shell, web and file tools (opt-in), `intentshield doctor` checks
that the guard is really in the path, and Gemini CLI can ask instead of refusing (opt-in). Nothing changes
unless you install with the new options, except that refusals on Codex and Gemini now tell the agent not to
retry, and a dropped judge connection no longer blocks a call.

- **Built-in tools, opt-in** (`intentshield install <harness> --builtin-tools`, or `--builtin-tools` on the hook). The hooks now
  read the harness's own shell, web and file tools: Claude Code `Bash`, `WebFetch`, `WebSearch`, `Read`, `Write`, `Edit`; Codex's
  shell tool; Gemini CLI's shell, fetch, search, read and write tools; Cursor's `beforeReadFile` and `afterShellExecution`. A shell
  command is parsed for where it reaches, whether it sends data and which secrets it reads (`src/intentshield/shell.py`).

  A command or fetch to an address from an injected output is denied; sending data to an address that came only from a tool output
  asks, as does reading secrets and sending data out; after an injection, commands that are not read-only ask. A plain download (a
  `curl` GET or HEAD, or `wget -qO-`, that sends no data and writes no file) counts as read-only, but after an injection it still
  asks unless every host it reaches was named by the user, because its address can carry data. Before, re-fetching the page the user
  asked for asked too.

  Fetched pages, search results and remote command output are scanned like MCP results; the user's own files and local command
  output only warn, because the rules fire on ordinary code there. Benign review load (`benchmarks/shell_replay.py`): 0/35 calls on
  the committed fixture; replaying 40 real Claude Code sessions from five projects, 4/1707 shell calls asked (0.2%, 95% CI
  0.1-0.6%), 0/326 reads, 0/473 writes, and MCP asks rose from 47/126 to 53/126 because built-in outputs add observed values.

  On this repository's own sessions, which handle attack text, 741/3405 shell calls asked (21.8%): 7 of 33 sessions read real
  injection text from the network. Off by default until the default is decided.
- A refused call now tells the agent not to retry it and to tell the user instead (Codex CLI and Gemini CLI,
  where an ask is a refusal). In the live built-in tool runs, Gemini CLI retried one refused command up to 75
  times. The Gemini hook also ends the agent's turn (`continue: false`, which Gemini CLI 0.37 honours in
  `BeforeTool`) on the third refusal since the user's last prompt; a new prompt resets the count. Codex is not
  stopped, because its handling of `continue` was not verified. Rerun live with Gemini (3 reps): each refused
  run took 1 refusal instead of 2 to 75 (9 against 116 in total), harm stayed 0/12, the benign task 3/3.
- `intentshield install gemini --gemini-ask` (or `--gemini-ask` / `INTENTSHIELD_HOOK_GEMINI_ASK=1` on the hook):
  Gemini CLI gets a real ask, shown as a prompt with IntentShield's reason, instead of a refusal. Opt-in,
  because measured with a stub hook (`benchmarks/harness_live/gemini_ask_probe.py`): Gemini CLI 0.66.0
  interactive shows a prompt in default and yolo mode, 0.66.0 headless waits for an answer until killed, and
  0.37.1 headless yolo ran the asked call. Denials stay denials. `intentshield doctor` fails when the hook
  has `--gemini-ask` and Gemini CLI is older than 0.66.0, and warns about headless runs otherwise.
- `intentshield doctor`: checks that each harness holds every IntentShield hook, that the hook executable
  exists, that a hosted judge has its key, that the harness has run a hook since the install (the hooks
  now record when each harness last ran one), and which stdio servers are not behind the proxy. Exit 1 on
  a problem.
- A dropped connection to the judge (the server hanging up mid-response, a reset) now counts as no opinion
  and is retried, like a timeout. Before, it raised, and in a hook a crash blocks the call, so a network blip
  at the judge's provider could block a legitimate tool call.
- `--judge deepseek` (`deepseek-flash`, thinking off; paid per token, `DEEPSEEK_API_KEY`). On the output
  judge's test split it caught 86.1% of plain-language injections at 7.4% benign flagged, the highest
  recall measured; as the agent in the judge benchmarks it followed none of 30 jailbreaks and none of 119
  adaptive pages. The judge benchmarks take `--victim deepseek:<model>` and record whether the hook held the
  agent's own sends.

## 0.4.0 - 2026-10-30

A security review of the guard itself: four areas, three passes of fixes, every finding and what is
still open in `docs/security-review.md`. Behaviour changes, so read the list before upgrading.

- **Argument provenance reads canonical values.** An address is the same value in any case, with a
  `+tag`, as an IDN or punycode domain, defanged (`[at]`, `(at)`, ` at ... dot `, `[.]`, `hxxp`), base64 or
  hex encoded, or line-wrapped; a URL in either scheme, with a port, userinfo or a trailing dot, with a
  decimal or hex IP; a path with `~`, `$HOME`, `/Users/me` or `C:\Users\me`; an IBAN with any separator.
  A bare host in an output covers addresses and URLs on exactly that host. On the review's probe, a
  quiet output's value now reaches a state-changing call unasked in 9 of 85 cases, down from 71.
- **Output rules** read tag characters (a run of four or more is a finding in itself), accents and
  combining marks, markup, letters spaced out, `\xNN`/`\uNNNN` escapes, values without their JSON keys,
  role markers at line start, forged XML tool calls and HTML image exfiltration. False flags on 2,000 real
  README files fell from 66 to 27; recall on the injection corpus is unchanged (2,569 of 5,095, from 2,571).
- **Hooks:** Claude Code's failed-call results (`PostToolUseFailure`) are scanned, and Gemini CLI's and
  Cursor's error fields. A tainted or flagged session is kept 30 idle days (was 7). An MCP event without
  an event name is denied. More credential formats and about 40 more write verbs. The catalog's
  read-only decision is keyed on server and tool. A judge objection on a result makes later
  state-changing calls ask (it never denies), and the agent gets a fixed sentence instead of the judge's
  words. The hook says when the judge was unavailable or read only part of a long result.
- **Proxy and gateway:** a server's cache TTL can no longer hide a changed tool listing (rug pull). Schema
  keywords (`pattern`, `format`, `$ref`, required names, ...) are scanned; free text in them quarantines
  the tool. Upstream error results and transparent-mode results get the full inspection, and transparent
  mode honours `allowed_tools` and `prohibited_tools`. A tool with an invalid name or schema is left out
  instead of failing the whole connect. Without a judge verdict a description stays withheld. New caps:
  `max_runs` (50) per session and `max_dry_runs_per_run` (20). Approving one call no longer clears a
  server's hostile mark unless the approval says `"trust_source": true`. `/control` requests with the
  token have their own rate-limit bucket.
- **Threat memory:** a domain is escalated only after 3 distinct source servers, a source turns hostile
  after 5 runs in 7 days (was 3), about 40 documentation and package hosts are protected, and a domain the
  user named is protected like an address.
- **LLM judge:** reads long results in overlapping windows (head, tail and the most suspect middle parts),
  accepts only its own verdict words (anything else is an error, never "clean", and is not cached), and
  objects to call arguments too large to read. The output prompt now names text that speaks to a reviewer
  or claims to be verified, and requests to "whoever reads or summarises" this.
- **`intentshield scan`** starts servers with a minimal environment and starts a project's own config
  (`.mcp.json`, ...) only with `--connect-project`; pins are written atomically with a backup.
- New benchmarks: `benchmarks/judge_jailbreaks.py` (30 hand-written attacks on the judge and 12 benign
  controls, through the real hook) and `benchmarks/adaptive_judge.py` (an LLM attacker that sees the
  judge's prompt and verdicts, against a local agent).
  Through the hook, without a judge, 7 of the 30 jailbreak sends are denied and 23 asked (27 held before; an ask
  is not a stop) and none of the 12 benign ones asked; with Gemini as the judge all 30 results are warned on with no false asks, with qwen2.5:7b
  at 4 false asks of 12. The adaptive attacker evaded on 0 of 24 seeds (1 of 24 with the old prompt), but
  got 34 of 120 pages past the qwen judge; the agent followed none of them.

## Earlier releases

Releases before 0.4.0, each in at most three lines. The full text is in the repository's git history.

### 0.3.6 - 2026-10-30

- The LLM judge can read tool results too (`--judge-outputs`, off by default), to catch plain-language injections with no marker.
  On a test split Gemini 3.5 Flash-Lite caught 77.8% at 3.4% benign false flags, local qwen2.5:7b 24.3% at 0.6%.

### 0.3.5 - 2026-10-29

- New `intentshield scan` (finds and checks the MCP servers you already use, offline); the override rule tolerates one typo; a credential
  the user did not give asks in the hooks and is denied once an injected output was seen.

### 0.3.4 - 2026-10-29

- The rules read "ignore the previous instructions" and "new task:" in 11 languages and in leetspeak; new output rules for text
  addressed to the AI, forged tool calls and image exfiltration.

### 0.3.3 - 2026-10-29

- `install` then `uninstall` restores a JSON settings file byte for byte (so does `wrap`/`unwrap`); the proxy's control routes answer 422,
  not 500, to a bad body; PyPI metadata and internal cleanup.

### 0.3.2 - 2026-10-29

- The proxy's judge has a time budget for tool descriptions at connect (`judge_catalog_budget_seconds`, default 20), so a large catalog
  can no longer hold the client's `initialize` for hours.

### 0.3.1 - 2026-10-29

- Cursor: a call resent with a self-disclosure field already empty is no longer denied again. First live Cursor run
  (`benchmarks/harness_live/run_cursor.sh`).

### 0.3.0 - 2026-10-29

- Breaking: the dashboard needs `INTENTSHIELD_AGENT_TOKEN` when `INTENTSHIELD_PROXY_CONFIG` is set, `intentshield.api` builds no app at import
  (use `create_app()`), and `intentshield.detector` is gone. Hooks fail closed on an output scan that never finishes; Codex hooks need one trust.

### 0.2.3 - 2026-10-29

- The same code as 0.2.2, with the judge recommendation restored in the README.

### 0.2.2 - 2026-10-29

- The same code as 0.2.1, with the final judge results in the package description.

### 0.2.1 - 2026-10-29

- The PyPI name is `intentshield-mcp`. Fixes from a five-part review: an unknown `--review` or `--outputs` value fails closed; an
  `ollama` judge; hook ownership by executable name in the installer; scanner, proxy and threat-memory fixes; the judge measured on held-out
  descriptions (`results/judge/`).

### 0.2.0 - 2026-10-28

- `intentshield install` and `uninstall` register hooks in Claude Code, Codex CLI, Cursor and Gemini CLI; `wrap` and `unwrap` put the
  transparent proxy in front of every stdio server in an `mcpServers` file; the wheel bundles a demo config; PyPI packaging.

### 0.1.0

- Everything before packaging: the gateway, transparent proxy, four harness hooks, detectors, threat memory and packs, benchmarks and papers.
