# Changelog

## 0.2.0 (unreleased)

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
