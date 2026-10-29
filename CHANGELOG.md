# Changelog

## Unreleased

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
