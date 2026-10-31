# Changelog

## Unreleased

- **Denial of service (second audit, proxy-2, rules-2, rules-13, proxy-1, rules-11, proxy-3, hooks-16, proxy-10):** the output, mailbox, credential and marker regexes are linear (200 KB in under 1 s, was 25 s to minutes); deep tool schemas and outputs no longer crash `connect()` or the scan; the gateway no longer runs an upstream's own regexes; session intent and tainted sets are bounded, with any dropped taint flagging the session. Detection unchanged on the corpus (2371/5095, 29/1365, 8/79) and on 19,476 credential texts; `redis://:pw@host` is now found. Details and what is still open in docs/security-review.md.
- **Judge offline (second audit, hooks-8):** a judge that is down, rate-limited or has no key no longer turns every state-changing MCP call into an ask (Claude Code) or a refusal with a wrong instruction (Codex); its note goes to the model and the rules decide. After a failure that means no network or a refused key (not a timeout, rate limit or unreadable reply, which a hostile output could cause), the hooks skip the judge for 5 minutes: measured with an unreachable endpoint, the first call 1.13 s, the next ones 0.0 s.
- **Judge with your own key:** `install --judge openai:<model>`, `openrouter:<model>` or `custom:<model> --judge-url <URL>` (any OpenAI-compatible endpoint; https, or http to localhost) asks for the key once and stores it, and the URL, in `~/.intentshield/.env`; Groq's free tier stays the default. `install --judge deepseek`, which the README documented, was refused by the installer and now works. A refused `--judge` spec no longer stores a key first. These judges are not measured.
- **Shell parser (second audit, hooks-1 to hooks-6 and hooks-15):** a newline separates commands, comments
  and unbalanced quotes no longer hide a send, variables are read in order, wrappers (`setsid`, `flock`,
  `busybox`, `env -S`, `bash <(curl ..)`, `printf .. | sh`) and inline code no longer hide the command,
  curl header, cookie and cluster forms count as sends, and options that run programs or write files are not
  read-only. Three backstops independent of the parser: only plain syntax is read-only, every address in the
  raw text (also with escapes decoded and variables taken out) is a destination, and a sender next to one in
  the same statement sends. Parsing is linear (200,000 characters in 0.06 to 0.12 s, was 45 to 94 s); commands
  over 100,000 characters are read from the raw text. Benign cost: shell asks on 40 private (uncommitted) sessions from other
  projects went from 7 to 8 of 1,713; in IntentShield's own sessions flagged by injected outputs, from 830 to
  1,066 of 3,720. Open residuals are listed in `docs/security-review.md`.
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

## 0.4.1

The hooks can now guard the harness's own shell, web and file tools (opt-in), `intentshield doctor` checks
that the guard is really in the path, and Gemini CLI can ask instead of refusing (opt-in). Nothing changes
unless you install with the new options, except that refusals on Codex and Gemini now tell the agent not to
retry, and a dropped judge connection no longer blocks a call.

- **Built-in tools, opt-in** (`intentshield install <harness> --builtin-tools`, or `--builtin-tools` on the
  hook). The hooks now read the harness's own shell, web and file tools: Claude Code `Bash`, `WebFetch`,
  `WebSearch`, `Read`, `Write`, `Edit`; Codex's shell tool; Gemini CLI's shell, fetch, search, read and
  write tools; Cursor's `beforeReadFile` and `afterShellExecution`. A shell command is parsed for where it
  reaches, whether it sends data and which secrets it reads (`src/intentshield/shell.py`). A command or
  fetch to an address from an injected output is denied; sending data to an address that came only from a
  tool output asks, as does reading secrets and sending data out; after an injection, commands that are not
  read-only ask. A plain download (a `curl` GET or HEAD, or `wget -qO-`, that sends no data and writes no file)
  counts as read-only, but after an injection it still asks unless every host it reaches was named by the user,
  because its address can carry data. Before, re-fetching the page the user asked for asked too. Fetched pages, search results and remote command output are scanned like MCP results; the
  user's own files and local command output only warn, because the rules fire on ordinary code there.
  Benign review load (`benchmarks/shell_replay.py`): 0/35 calls on the committed fixture; replaying 40 real
  Claude Code sessions from five projects, 4/1707 shell calls asked (0.2%, 95% CI 0.1-0.6%), 0/326 reads,
  0/473 writes, and MCP asks rose from 47/126 to 53/126 because built-in outputs add observed values. On
  this repository's own sessions, which handle attack text, 741/3405 shell calls asked (21.8%): 7 of 33
  sessions read real injection text from the network. Off by default until the default is decided.
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

## 0.4.0

A security review of the guard itself: four reviewers, three rounds of fixes, every finding and what is
still open in `docs/security-review.md`. Behaviour changes, so read the list before upgrading.

- **Argument provenance reads canonical values.** An address is the same value in any case, with a
  `+tag`, as an IDN or punycode domain, defanged (`[at]`, `(at)`, ` at ... dot `, `[.]`, `hxxp`), base64 or
  hex encoded, or line-wrapped; a URL in either scheme, with a port, userinfo or a trailing dot, with a
  decimal or hex IP; a path with `~`, `$HOME`, `/Users/me` or `C:\Users\me`; an IBAN with any separator.
  A bare host in an output covers addresses and URLs on exactly that host. On the reviewer's probe, a
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

## 0.3.6

- The LLM judge can read tool results too (`--judge-outputs` for the hooks and `intentshield install`,
  `"judge_outputs": true` for the proxy; off by default). It is told the user's request and asked whether
  the result addresses the agent with something beyond it, which is how plain-language injections with no
  marker get caught; a request between people in a mailbox or a chat is not. An objection is evidence
  only: the agent is warned and values from that result ask before use. On the corpus's test split,
  Gemini 3.5 Flash-Lite caught 77.8% of plain-language injections at 3.4% benign false flags, and local
  qwen2.5:7b 24.3% at 0.6% (`benchmarks/judge_outputs_eval.py`, `results/judge/`).

## 0.3.5

- The override rule reads "ignore the previous instructions" with one typo in one of its three words
  ("Ignore your previous iunstructions", "Ingore all previous instructions"). A comparison with Meta's
  Prompt Guard 2 showed the rules missing AgentDojo's 27 misspelled cases, which Prompt Guard caught; they
  now catch them, and the comparison is in `docs/detectors.md`.
- `intentshield scan` finds the MCP servers configured for Claude Code, Claude Desktop, Cursor, Gemini CLI,
  Codex CLI, Windsurf and VS Code (or the files named), starts each one, lists its tools without calling
  any, and checks them offline: poisoned descriptions, split instructions, self-disclosure parameters,
  shadowing, shared tool names, credentials written into a config, a config with one that others can read,
  and toxic flows (untrusted content, private data and a way out within one client). It pins each tool's
  hash and keeps reporting a changed one until `--update-pins`. Output as text, JSON or SARIF; exit 1 on
  an error-level finding.
- A credential the user did not give, leaving in a tool call's arguments, now asks in the hooks
  (`REVIEW_CREDENTIAL_EGRESS` in the proxy and gateway) and is denied once an injected output was seen.
  Credentials are recognised by their providers' formats and only ever shown masked.

## 0.3.4

- The output and description rules read "ignore the previous instructions" and "new task:" in German, Spanish,
  French, Portuguese, Italian, Dutch, Russian, Chinese, Japanese, Korean and Hindi, and read leetspeak words as
  letters (`1gn0r3 4ll pr3v10u5 1n5truct10n5`). Addresses, paths and ids are never rewritten, so the threat
  memory learns no address the attacker did not send. The translations run only on text that could match them
  and compile on first use, so scanning other text costs about what it did.
- New output rules: text addressed to the AI that asks for data to leave (`agent_address`), text speaking for
  the user that sends data to an address (`user_proxy`), a JSON tool call with an order to run it
  (`forged_tool_call`), and a markdown image whose URL carries a placeholder to fill (`image_exfiltration`).
  `role_marker` also reads Llama 3, Phi and Gemma template tokens and Alpaca's `### Instruction:`, and text
  after a right-to-left override is read in the order it is shown. Scanning a 4 KB result takes about
  0.4 ms more.

## 0.3.3

Fixes found by a new end-to-end check of the installed wheel:

- `intentshield install` then `uninstall` now gives back a JSON settings file byte for byte whatever its
  formatting. Before, only a file already written with two-space indents came back unchanged; any other was
  reformatted and its non-ASCII text escaped (`"naïve"` became `"na\u00efve"`). The original is kept in
  `~/.intentshield/backups/` until uninstall; if the file was edited in between, the edit is kept and the
  non-ASCII text stays as written. `wrap` and `unwrap` do the same for the `mcpServers` file.
- The proxy's control routes answer 422, not 500, to a JSON body nested deeper than the parser allows, to a
  `decision` that is a list or object, and (instead of 409) to a body that is not UTF-8.

- PyPI metadata: the summary now starts "IntentShield for MCP" and names prompt injection; more keywords
  (`intentshield`, `mcp-security`, `llm-security`, ...), Python 3.14 and AI classifiers, and a Documentation link.
- Internal cleanup with no change in behaviour: the hook handler is split per harness, the proxy's control
  routes moved out of `run_mcp_server` and share one error mapping, and an over-engineering pass removed
  duplicated helpers and dead code (net about 160 lines). `python -m intentshield.install` is gone; use
  `intentshield install`.

## 0.3.2

- The proxy's judge now has a time budget for tool descriptions at connect
  (`judge_catalog_budget_seconds`, default 20). Before, it read every description one by one at up to
  30 s each, so a large catalog could hold the client's `initialize` for hours. Descriptions it does not
  reach get no opinion, as on a judge error, and are listed in an `MCP_JUDGE_BUDGET_SPENT` event.

## 0.3.1

- Cursor: a call resent with a self-disclosure field already empty, as the hook's denial asks, is no
  longer denied again. Before, an empty field still counted as redacted, so on Cursor (which cannot
  rewrite arguments) the call could never go through. Found in the first live Cursor run.
- `benchmarks/harness_live/run_cursor.sh` runs Cursor CLI headless against the attack server (no guard,
  hooks, proxy, both); results in `results/harness-live-cursor/` and `docs/benchmarks.md`.

## 0.3.0

Breaking:

- With `INTENTSHIELD_PROXY_CONFIG` set, the web dashboard refuses to start without
  `INTENTSHIELD_AGENT_TOKEN` (it already required the control token), and `/api/tools`,
  `/api/metrics` and `/api/security/status` need the agent token whenever one is set.
- `intentshield.api` no longer builds an app at import (`intentshield.api.app` is gone); use
  `create_app()`, or `uvicorn --factory intentshield.api:create_app`.
- `intentshield.detector` is removed; `SecuritySignals` is in `intentshield.models`.
- `HarnessGuard` takes its options as keyword arguments only.
- The built-in gateway and the dashboard default their database to `~/.intentshield/gateway.db`
  instead of the working directory.
- Codex CLI: hooks run only after you trust them once in Codex; `intentshield install codex` says so.

Fixes from a second five-critic pass (code quality, guard security, tests and CI, docs and
first-run experience, benchmark rigor); every behaviour change has a regression test.

- Hooks fail closed on an output scan that never finishes: the session is flagged before the
  scan and unflagged only when it completes clean, so a harness timeout on a huge result no
  longer leaves later state-changing calls running as if the output were clean. Values from
  tool outputs that appear in a denial or confirmation reason are escaped and capped at 80
  characters (a URL carrying terminal escape codes can no longer drive the terminal).
  `load_env_file` resolves `~/.intentshield/.env` at call time.
- Proxy: one lock guards the session state (taint, observed values, drift) that the event
  loop and the `to_thread` workers both update; a hung upstream call is cancelled on the loop
  after `read_timeout_seconds` instead of leaking a task; an upstream that dies mid-session
  answers the agent with one bounded `is_error` line (`Upstream MCP server failed (<code>)`)
  and the proxy keeps serving; the security supervisor queues concurrent calls for a worker
  slot within the same deadline instead of scoring them as timeouts at random; `close()`
  stops the supervisor's threads and the threat memory's reader; the judge cache is bounded
  (5,000 answers) and the proxy's judge gets one 15 s attempt like the hooks.
- Gateway storage opens SQLite in WAL mode with a busy timeout; two `assert`s on security
  invariants are explicit `RuntimeError`s (they survive `python -O`); the FastAPI app is no
  longer built at import (`uvicorn --factory`), and `.env` is read from the working directory.
- Installer: `--review` and `--judge` are validated and shell-quoted; a settings file that is
  a symlink is written through to its target; a Cursor `hooks.json` that already existed keeps
  its own `version` key, so install then uninstall restores every harness file byte for byte;
  `uninstall` removes a file that held only IntentShield's hooks; `wrap` names a missing file and
  reports the HTTP servers it skips.
- CLI: `intentshield --version`; help text on every `intentshield-mcp` and `intentshield-threats`
  argument; `intentshield-mcp` prints one line (not an exception-group traceback) when its
  config or a credential variable is missing; `intentshield-mcp-verify` names a missing config
  file; the built-in gateway and dashboard default their database to `~/.intentshield/` instead
  of the working directory.
- Tests and CI: `GROQ_API_KEY`/`GOOGLE_API_KEY` are stripped like `GEMINI_API_KEY`; the two
  tests that depended on the working directory use a generated demo config; the wall-clock and
  sleep-based assertions are gone; CI runs the suite on Python 3.12 and 3.13; new tests cover a
  dead upstream (transparent and gateway), a hung upstream, 20 concurrent calls, Claude Code
  block mode, the Cursor prompt path, the install round trip on every harness and scope, and a
  wrapped server with an `env` block.
- Docs: the README is a 250-line user guide (install, quickstart, what each layer sees and
  stops, one headline table with its caveat, limitations); the operator material moved to
  `docs/guide.md`, the numbers to `docs/benchmarks.md` and `docs/detectors.md`, with
  `docs/README.md` separating user docs from research notes; `SECURITY.md`, `CONTRIBUTING.md`
  and issue templates added. Numbers corrected from the committed traces: 8–14 (not 9–14)
  points of task completion across the four agents, qwen gateway task-tool-executed 39.4%
  (86/218), paired n stated as 218/220/216, self-disclosure denominators labelled as unpaired
  harmful calls, and the injection-detection tables now say which families the rules were
  written on (on the independent families: rules 2.1%, rules+exemplars 18.1%). The Gemini
  adaptive attacker (42/42 evasions; provenance still held every canary) is in the detector
  docs, and the DeBERTa advisory row is marked unconfirmed.
- Second code pass: the proxy lock covers only the merge into the session state, so a slow
  learned detector in a worker no longer stalls the event loop (test: `create_run` returns while
  a detector sleeps); Prompt Guard gets the judge's 15 s / one-retry bound; a judge back-off
  never outlives its budget (`Retry-After: 120` no longer holds a hook); the built-in regex
  security agents run on the caller's thread, so a busy worker pool cannot score a benign call
  as a timeout (threads and the deadline remain for a classifier or custom agent); the legacy
  `detector.py` heuristic is gone, unregistered tools get fixed fail-closed signals; upstream
  close lets cancellation propagate unchanged; the catalog directory is scanned once per
  connect, not once per tool; the judge and Prompt Guard caches are bounded and locked; hook
  transactions roll back on error and the guard can be closed; the control routes share one
  auth wrapper and answer a malformed body with 422.
- Third pass: result scans are counted in flight per session, so two parallel hook processes can
  no longer let a clean scan un-flag a session an injected result just flagged (regression test
  interleaves the two); a hook that fails before it can scan an output flags the session through a
  throwaway connection; the hook guard is closed on exit. Behind the web proxy the agent token is
  now mandatory and the tool list, metrics and security-status routes need it too. `create_app`
  calls python-dotenv correctly again (the previous pass broke `intentshield serve`; a test now
  runs the real call). The missing-credential error names the variables; `wrap`/`unwrap` report
  "already wrapped", restore an empty `args` list exactly, name the generated files they leave
  behind and give one line for invalid JSON; every remaining argument has help text. Tests cover
  the upstream catalog limits and call failures through the fake SDK client, a real child that
  prints garbage and exits, fail-closed for every harness, and eight hook processes sharing one
  database. CI also runs Python 3.14. The README opens with what is not covered and states the
  security boundary in plain words.
- Fourth pass: the MSB case grid is committed (`results/msb/cases.jsonl`, MSB commit recorded in
  the manifest), so `paper_numbers.py` and its test run from a clean clone and in CI; the README's
  provenance sentence now says exactly which rows replay offline; the headline scopes the
  review-queue claim to the gateway (hooks leave 5/2/3 cases); the Gemini review-queue cell,
  three stale MCPTox cells (1.2%, 34.8%, 1.7%) and two unsourced detector cells are corrected
  from committed reports; the adaptive attacker carries its judge-leniency caveats;
  `results/README.md` lists what does not replay offline. Control routes treat only a non-object
  body as 422 (other errors surface), run events are written off the event loop, dropped close
  errors are logged, and the signed-pack test can no longer skip silently.
- Fifth pass: a crashed output scan leaves the session flagged, and an interrupted one says so in
  the confirmation reason; hook migrations only tolerate a concurrent "duplicate column". The test
  conftest now really restores the judge keys after each test (it used to leave a key a test wrote
  in place), and a session-end check fails the run if one leaks. The sdist's own test run is
  green (it ships `benchmarks/coverage`, and the review-gate baseline test skips without
  `results/`). `unwrap` keeps each entry's key order; the README headline is two plain sentences.
- Live Codex CLI check (`benchmarks/harness_live/run_codex.sh`, local qwen2.5:7b, no cost): unguarded the
  notes reached the attacker in 3/3 runs; with the hooks installed but not trusted, also 3/3, because
  Codex 0.165 silently skips hooks nobody has trusted; with the transparent proxy, 0/3 (the
  agent did not call `send_email` after the proxy's warning on the injected result).
  `intentshield install codex` now says the hooks must be trusted once in Codex before they run. With
  the hooks trusted, the `PreToolUse` hook denied the attacker's `send_email` in 3/3 runs.
- Benchmarks: `paper_numbers.py` also prints task-tool-executed, truncated and Wilson cells and
  the README headline strings, with a test; the MCPTox replay was regenerated on current code
  (quarantine+provenance 19/1579 = 1.2%); the injection evaluation inputs and the Gemini judge
  report are committed under `results/`.

## 0.2.3

- Same code; the README's judge results now carry their recommendation, which the 0.2.2
  description lacked after the results restructure.

## 0.2.2

- Same code as 0.2.1; the package description carries the final judge results (Groq
  `gpt-oss-120b` measured) and recommendation, which 0.2.1 was built before.

## 0.2.1

- PyPI distribution name is `intentshield-mcp`; the plain name belongs to an unrelated project.

Fixes from a five-reviewer pass (security, silent failures, Python quality, over-engineering,
competitor gap analysis), each with a regression test in `tests/test_review_fixes.py`:

- Hooks: an unknown `--review`/`--outputs` value from the environment now fails closed (exit 2)
  instead of silently disabling every review branch; a read-verb tool name with a destructive
  verb (`get_and_purge`, `query_and_drop`) counts as state-changing; output values are written in
  one transaction (about 55x faster on large results).
- Judge: `ollama` provider (local, no key); hooks give it one 10 s attempt and then report it
  unavailable in the model's context and on stderr, instead of minutes of free-tier back-off.
- Installer: ownership of a hook entry is decided by the executable's basename, so `uninstall`
  removes only IntentShield's handler and `install` repairs a stale path; the Codex block is a
  properly escaped TOML string; the command is shell-quoted; settings files are written
  atomically; `wrap` names are injective across servers and client files, reject `__`, validate
  the generated config before touching the client file, and share one threat-memory file with the
  hooks (`~/.intentshield/threats.db`).
- Scanner: a user-typed prompt exempts only the whole sentence it contains, not any match whose
  trigger words appear somewhere in the prompt; `process.env` is not a sensitive target; bare
  hosts, IPv4 addresses and host:port are traced values (MCPTox quarantine+provenance 1.3% to
  1.2%); the shadowing check tokenizes once (no 19 s start-up past 512 tools); ASCII text skips
  normalization.
- Proxy and gateway: a re-seen provenance value is no longer evicted ahead of fresh ones; a
  failing result inspector no longer leaves an executed mutation unaudited; bearer tokens compare
  as bytes (a non-ASCII header was a 500); the gateway database is created 0600.
- Threat memory: long texts are scanned head and tail, so padding cannot hide a payload from pack
  rules and fingerprints.
- New: `benchmarks/self_disclosure_eval.py` and `results/self-disclosure.{md,json}`, the
  precision and harm-share measurement of self-disclosure parameter stripping.
- Architecture review fixes: an agent-written gateway intent no longer exempts values the proxy
  had already seen in a tool output (`trusted_intent` restores the old behaviour for trusted
  channels); the hook takes the operator's read-only decision from the proxy catalog; wrapped
  proxies read each other's catalogs for cross-server shadowing; hook sessions are pruned after
  7 days; the classifier import is lazy; two unused storage helpers are gone.
- Judge: measured on the held-out descriptions Groq `gpt-oss-120b` (99.7% recall, 2.8% clean flagged,
  the default), local `ollama:qwen2.5:7b` (99.0%, 3.7%, offline alternative) and `llama3.1:8b`
  (unusable, 19.4% clean flagged); `results/judge/`. `intentshield install <harness> --judge` stores
  the Groq key once in `~/.intentshield/.env`, and a hook with a judge but no key says so and lets
  the rules decide.

## 0.2.0

- `intentshield install <harness>` registers the hooks in Claude Code, Codex CLI, Cursor or Gemini CLI
  (user or project scope); `intentshield uninstall` removes them again.
- `intentshield wrap <mcp.json>` puts the transparent proxy in front of every stdio server in an
  `mcpServers` file, with one generated proxy config per server; `intentshield unwrap` restores them.
  This works for any MCP client that launches stdio servers from such a file.
- `intentshield` now takes subcommands; with none it still runs the local dashboard (`serve`).
- The wheel bundles a demo proxy config, so `intentshield-mcp-verify` runs from a plain
  `pip install` without the repository.
- Packaging: PyPI metadata, a trimmed sdist, `ruff` in the dev extra with a committed config, and a
  publish workflow that builds, smoke-tests the wheel and releases on `v*` tags via trusted publishing.

## 0.1.0

- Everything before packaging: the gateway, transparent proxy, four harness hooks, detectors,
  threat memory and packs, benchmarks and papers. See the README and `docs/`.
