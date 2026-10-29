---
name: Bug report
about: The guard made a wrong decision, crashed, or failed to install
title: ""
labels: bug
---

**Version and placement**
`intentshield-mcp` version, Python version, and which layer: hooks (`intentshield-hook <harness>`), transparent proxy (`intentshield-mcp --transparent`) or gateway.

**What happened**
The decision (ALLOW / REVIEW / BLOCK, or allow / ask / deny) and what you expected. Paste the reason code if there is one.

**Reproduction**
The smallest config, hook event or tool call that shows it. Replace real addresses, keys and personal data with benign markers; never paste credentials.

**Logs**
Relevant stderr or JSON log lines (decision lines carry run, tool, decision and reason codes, never arguments).
