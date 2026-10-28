# Security policy

## Supported versions

Only the latest 0.2.x release on PyPI (`intentshield-mcp`) receives fixes. Older releases are not patched; upgrade instead.

## Reporting a vulnerability

- Sensitive reports (anything an attacker could use before a fix ships): use GitHub private vulnerability reporting on the repository (Security tab, "Report a vulnerability"). Do not open a public issue.
- Non-sensitive reports (hardening suggestions, false positives or negatives on published samples, documentation errors): the Issues page.

Include the IntentShield version, the harness or transport (hooks, transparent proxy, gateway), a minimal reproduction and what the guard decided (ALLOW, REVIEW, BLOCK, or allow/ask/deny in a hook). Never include real credentials, real tool outputs with personal data, or working attack payloads aimed at a third-party product; benign markers are enough.

## In scope

- The guard failing open: a call that should be REVIEW or BLOCK but executes, a hook that crashes or exits without denying, a catalog change that does not fail closed.
- Bypasses of the hook or proxy: injected instructions, provenance or self-disclosure parameters that reach the upstream server or the model despite the rules, cross-server shadowing or rug pulls that are not caught.
- Secret leakage: API keys, bearer tokens or `env` values appearing in logs, in the SQLite databases (`hooks.db`, `threats.db`, the proxy database), in verifier JSON, in tool results or in exceptions.
- Weaknesses in the approval and control endpoints (token handling, binding, rate limits) and in threat-pack verification.

## Out of scope

- Attacks against third-party MCP servers themselves (their own code, hosting or credentials). IntentShield guards the agent's calls to them; it does not secure them.
- Model behaviour that the guard never sees (built-in shell and file tools are left to the harness, by design).
- Detection gaps that are already documented as limitations in `docs/benchmarks.md` and `docs/detectors.md` (for example plain-language injections from independent sources). Reports with a new sample are still welcome as issues.

## Responsible disclosure

The project practices responsible disclosure for issues it finds in other products: findings are measured with benign markers, reported to the vendor first, and not published as working bypasses. Reports to this project are handled the same way.
