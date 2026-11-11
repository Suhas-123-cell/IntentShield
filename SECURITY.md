# Security policy

## Supported versions

Only the latest release on PyPI (`intentshield-mcp`) receives fixes. Older releases are not patched; upgrade instead.

## Reporting a vulnerability

- Sensitive reports (anything an attacker could use before a fix ships): use GitHub private vulnerability reporting on the repository (Security tab, "Report a vulnerability"). Do not open a public issue.
- Non-sensitive reports (hardening suggestions, false positives or negatives on published samples, documentation errors): the Issues page.

Include the IntentShield version, the harness or transport (hooks, transparent proxy, gateway), a minimal reproduction and what the guard decided (ALLOW, REVIEW, BLOCK, or allow/ask/deny in a hook). Never include real credentials, real tool outputs with personal data, or working attack payloads aimed at a third-party product; benign markers are enough.

## What to expect after a report

IntentShield has one maintainer and no paid support, so response is best effort and there is no service-level agreement.
The maintainer aims to acknowledge a private report within about two weeks and to say whether it is accepted. A fix
ships in a new release on PyPI, and the release notes name the issue. Please wait at least 90 days after a report before
publishing details, and say if you need a different date.

Reporters are credited by name in the release notes and the changelog entry unless they ask not to be.

## In scope

- The guard failing open: a call that should be REVIEW or BLOCK but executes, a hook that crashes or exits without denying, a catalog change that does not fail closed.
- Bypasses of the hook or proxy: injected instructions, provenance or self-disclosure parameters that reach the upstream server or the model despite the rules, cross-server shadowing or rug pulls that are not caught.
- Secret leakage: API keys, bearer tokens or `env` values appearing in logs, in the SQLite databases (`hooks.db`, `threats.db`, the proxy database), in verifier JSON, in tool results or in exceptions.
- Weaknesses in the approval and control endpoints (token handling, binding, rate limits) and in threat-pack verification.

## Out of scope

- Attacks against third-party MCP servers themselves (their own code, hosting or credentials). IntentShield guards the agent's calls to them; it does not secure them.
- Model behaviour that the guard never sees (built-in shell and file tools are left to the harness, by design).
- Memory exhaustion by a misbehaving upstream server. The MCP Python SDK reads a server's messages
  without a size limit (stdio lines, HTTP bodies and SSE events), so `max_result_bytes` and
  `max_total_schema_bytes` apply only after a message is read in full. This is a known gap, to be raised
  with the SDK.
- Detection gaps that are already documented as limitations in `docs/benchmarks.md` and `docs/detectors.md` (for example plain-language injections from independent sources). Reports with a new sample are still welcome as issues.

## What is stored locally

The guard keeps state on your machine, under `~/.intentshield/` unless a variable or a flag names another path. It sends
nothing anywhere itself; only the optional judge and Prompt Guard send text to a provider you chose (see the
[guide](docs/guide.md)).

| File | What it holds | How long |
|---|---|---|
| `hooks.db` (`INTENTSHIELD_HOOK_DB` or `--db`) | per session: the user's prompts, the values taken from tool results, and the last hook time and working directory per harness (details below the table) | a session is deleted after 7 days without a hook event, or 30 days if a result in it was flagged (details below the table) |
| `threats.db` (`INTENTSHIELD_THREAT_DB`) | what rule-confirmed attacks used: addresses, URLs, accounts, paths, word fingerprints of the injected sentences, and how often each server produced attacks | an entry expires 30 days after it was last seen; one the operator confirmed does not expire |
| `proxies/*.db`, `gateway.db`, `intentshield.db` | the audit of a proxy (`proxies/NAME-<hash>.db`, one per wrapped server and client file; a server wrapped by 0.4.3 keeps its `NAME.db`) or the gateway: runs with the user's intent, call arguments, decisions, approvals and the results of executed mutations | no expiry |
| `.env` | the judge API keys `install --judge` stored | until you remove them |
| `backups/`, `installs.json`, `harness-versions.json` | the exact bytes of each settings or MCP file before `install` or `wrap` first changed it (these can hold tokens that were already in that file), when `install` last ran, and each harness's version | no expiry |
| `tools/` (only with `tool_catalog_dir`) | the names and descriptions of the tools a proxy shows | rewritten when the proxy starts |

What `hooks.db` holds, per session:

- the user's prompts, at most 200,000 characters (the first 20,000 and the newest rest), with every credential the guard
  recognises in them replaced by a short hash of it;
- the values taken from tool results that were flagged;
- the recipients, URLs, accounts and paths seen in any tool result (the values, not the result text);
- the time and working directory of each harness's last hook.

Each hook event renews a session's 7 days. Working directories are deleted after 30 days. The cleanup runs whenever a
hook next opens the file.

`hooks.db`, `threats.db` and `.env` are created readable by their owner only (mode 0600), and `~/.intentshield` itself is created
with mode 0700 (an existing one that you own is tightened to 0700 the next time the hook, `install`, `wrap`, a proxy, `scan` or a threat pack uses it). A file made by an
older version may be more open, so run `chmod 600` on it. The hash that replaces a credential in a stored prompt is only there so
the guard can tell later that you gave that very value; it does not keep the value. A credential the guard does not recognise
stays in the prompt text as you typed it.

`intentshield scan` and `intentshield doctor --connect` start the MCP servers named in your own client files, which runs their code with
your user rights; `--no-connect` (scan) and plain `doctor` start nothing. A server named by a file in the working directory, which a
repository may have chosen, is started only with `--connect-project`.

Since 0.4.3 the library's default databases (`Storage()`, `IntentShieldService.default()`, `create_mcp_server()` and a proxy
config with no `database_path`) are in `~/.intentshield`, as the command line's are. Before that they were `intentshield.db`
and `intentshield-mcp.db` in the working directory, and a file of that name already in the working directory keeps being used, so an upgrade keeps
its data: move or delete it to start using `~/.intentshield`. The configs `configs/mcp-proxy.demo.json` and `mcp-proxy.uvx.json` still name
`intentshield-mcp.db` in the working directory. When a detection or grounding agent fails and the guard fails closed, it logs the
name of the exception class at warning level, never its message, which may hold call arguments.

To delete it, first run `intentshield uninstall <harness>` and `intentshield unwrap <file>` so that no hook or proxy entry
points at a missing file; `unwrap` and `uninstall` may need the backups. Then remove what you want:

```sh
rm -f ~/.intentshield/hooks.db*    # prompts and observed values; a later hook event starts a new file
rm -f ~/.intentshield/threats.db*  # what the threat memory learned
rm -r ~/.intentshield              # everything above, judge keys and backups included
```

There is no command that forgets a single session.

## Responsible disclosure

The project practices responsible disclosure for issues it finds in other products: findings are measured with benign markers, reported to the vendor first, and not published as working bypasses. Reports to this project are handled the same way.
