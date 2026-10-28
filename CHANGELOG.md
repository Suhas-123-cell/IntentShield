# Changelog

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
