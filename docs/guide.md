# Running IntentShield: hooks, proxy, gateway and API

This guide covers what the [README](../README.md) leaves out: guarding an agent harness with hooks and the
transparent proxy, what to do when the guard blocks something legitimate, troubleshooting, threat memory, and the
gateway, dashboard and REST API. A feature marked "since 0.4.3" needs that version or a later one.

## Contents

| If you want to | Read |
|---|---|
| guard Claude Code, Codex CLI, Cursor or Gemini CLI | [Guard an agent harness](#guard-an-agent-harness-claude-code-codex-cli-cursor-gemini-cli) |
| check a harness's own shell, file and web tools too | [Built-in tools and the dangerous-command rules](#built-in-tools-and-the-dangerous-command-rules) |
| cut the tokens spent on tool descriptions | [Point the model at the right tool](#point-the-model-at-the-right-tool) |
| understand a refusal or a prompt, or stop a false positive | [When the guard blocks or asks about something legitimate](#when-the-guard-blocks-or-asks-about-something-legitimate) |
| run another guard's hook with a deadline and a fail-closed launcher | [Wrapping a third-party hook](#wrapping-a-third-party-hook) |
| check that the install works, or fix it | [Troubleshooting](#troubleshooting) |
| let the guard learn attacks, or ship new rules as data | [Adaptive threat memory and threat packs](#adaptive-threat-memory-and-threat-packs) |
| see the list of features | [What is implemented](#what-is-implemented) |
| put the gateway or the transparent proxy in front of an MCP server | [Real MCP proxy](#real-mcp-proxy) |
| set tokens, rate limits and environment variables | [Production settings](#production-settings) |
| run the dashboard, the tests or the demo | [Run locally](#run-locally) |
| use the Gemini proposal path or the REST API | [Gemini model integration](#gemini-model-integration), [API](#api) |

## Guard an agent harness (Claude Code, Codex CLI, Cursor, Gemini CLI)

Harnesses that call MCP tools get two layers that share IntentShield's rules:

- **Hooks** (`intentshield-hook <harness>`) see what the model cannot forge: the
  user's real prompt and every MCP call and result. Per session (SQLite at
  `~/.intentshield/hooks.db`, or `INTENTSHIELD_HOOK_DB`) they:
  - send parameters that ask for the agent's model, system prompt or conversation
    (`llm_name`, `system_prompt`, ...) empty;
  - deny a call whose arguments carry injected instructions, or a value that came
    from a tool output with injected instructions and not from the user;
  - scan every MCP result; an injected one taints the session and the model is told
    it is data, not a request (`--outputs block` replaces the result instead);
  - ask before any MCP call carrying a recipient, URL, account or path that came
    only from a tool output, flagged or not (unless `--review never`;
    `--allow-sourced-reads` or `INTENTSHIELD_HOOK_SOURCED_READS=allow` stops asking for reads only);
  - ask before state-changing MCP calls once the session is tainted
    (`--review always|tainted|never`, or `INTENTSHIELD_HOOK_REVIEW`; `--outputs` reads
    `INTENTSHIELD_HOOK_OUTPUTS`);
  - optionally run the injection classifier on results the rules pass
    (`--classifier DIR` or `INTENTSHIELD_HOOK_CLASSIFIER`; loads PyTorch in every
    result hook, so it is off by default), or the LLM judge (the hook's `--judge` with no value means the local
    `ollama:qwen2.5:7b`; `--judge groq` or `gemini[:model]` for a hosted one; note that `intentshield install --judge`
    with no value means Groq, so name the provider in both places). With
    `--judge-outputs` (or `INTENTSHIELD_HOOK_JUDGE_OUTPUTS=on`) the judge also reads each result
    the rules pass, for plain-language injections: a result it objects to is treated like a
    classifier hit (the agent is warned, and any value from it asks before use), never as an
    injection. It costs one request per result: about 1 s with local qwen2.5:7b and 4 s with
    Gemini Flash-Lite, and on Groq's free tier (200,000 tokens a day) about 200 results a day,
    after which the judge has no opinion until the next day;
  - refuse to start on an unknown `--review` or `--outputs` value, from the command line or the
    environment, instead of silently skipping every review branch.
  A hook that crashes denies the call; for Claude Code the example config adds
  `"onFailure": "block"` so a hook that is missing, times out or exits with another code
  denies it too. MCP resource reads (`ReadMcpResourceTool`) are scanned like tool results.
  Built-in tools (shell, file and web tools) are left to the harness unless the hook is installed with
  `--builtin-tools`; see [Built-in tools and the dangerous-command rules](#built-in-tools-and-the-dangerous-command-rules).
- **Transparent proxy** (`intentshield-mcp --transparent --config <file>`, stdio only)
  wraps each MCP server the harness launches. It shows the upstream's own tools, hides
  any whose description matches poisoning rules or that changed after connect (rug pull),
  removes self-disclosure parameters from schemas and flags injected results. A tool whose
  description changes after connect is hidden and refused for the rest of the session; it
  fails closed until restart. Hooks never see tool descriptions, so this layer covers what
  they cannot.

`intentshield install <harness>` writes the hook entries below into the harness's settings
file (`--scope project` for the current directory; `--review always` for a harness that
cannot ask; `--gemini-ask` for interactive Gemini CLI 0.66 or later, see [layers.md](layers.md#what-each-harness-lets-the-guard-do)); `intentshield uninstall <harness>` removes them. The same entries are in
`configs/harness/` of a repository clone (not in the PyPI package; `install --dry-run` prints what `install` would write) for a manual install; they call `intentshield-hook` by name, so put the
install's `bin` on the harness's `PATH` or use absolute paths.

The per-harness table (hook config, argument rewriting, asking the user) is in
[layers.md](layers.md#what-each-harness-lets-the-guard-do).

The proxy layer needs no harness support at all: `intentshield wrap <file>` rewrites every stdio
server in an `mcpServers` file (Claude Code `.mcp.json`, Cursor `mcp.json`, Gemini CLI
`settings.json`, or any client with that layout). Claude Code keeps the servers added with
`claude mcp add` in `~/.claude.json`, the top-level ones and each project's own; `wrap` handles that file the same way to launch the proxy in front of it, with one
generated config per server under `~/.intentshield/proxies/`; `intentshield unwrap <file>` restores
them. By hand, the entry looks like this:

```json
{"mcpServers": {"filesystem": {"command": "intentshield-mcp",
  "args": ["--transparent", "--config", "/absolute/path/to/transparent-filesystem.json"]}}}
```

Servers reached over HTTP (`"url"`) are not launched by the client, so `wrap` leaves them alone;
guard those with the [gateway](#real-mcp-proxy).

**Check the install.** Right after `install`, `intentshield doctor` exits 1 and prints
`FAIL <harness> ...: installed, but no hook has run since <time>` for each harness. That is expected. Start the
harness, send any prompt (a prompt is enough, no tool call is needed) and run `doctor` again; a line that stays `FAIL` is explained under
[Troubleshooting](#troubleshooting).

**Do not commit what `install` and `wrap` write.** They put absolute paths of this machine into the settings and
MCP files: the hook executable and, after `wrap`, a proxy config under `~/.intentshield/proxies/`. A teammate who
clones a repository holding such a file gets an entry that points at a path they do not have, and a hook launcher
that refuses every MCP call. This applies to `install --scope project` and to a wrapped project `.mcp.json`; keep
those files out of git, or run `install` and `wrap` on each machine.

**What is stored on your machine.** The hooks keep a session's prompts and the addresses, URLs, accounts and paths
seen in tool results in `~/.intentshield/hooks.db`, for 7 days after the session's last event (30 days if a
result was flagged). [SECURITY.md](../SECURITY.md#what-is-stored-locally) lists every file and how to delete it.

### Built-in tools and the dangerous-command rules

By default the hooks check MCP calls only. `intentshield install <harness> --builtin-tools` also sends the
harness's own tools to the hook (the per-harness table is in
[layers.md](layers.md#what-each-harness-lets-the-guard-do)); run the command again to change it, and
install without the flag to go back. `--builtin-tools` has been in the PyPI releases since 0.4.1. The session
rules it applies to a shell command, fetch or file access (an address that came from an injected output, data
sent to an address the user did not name, secrets read and sent out, what may run after an output tried to
instruct the agent) are the ones in that row. After an injection a read-only command, and an ordinary local
build, test or version-control command such as `pytest` or `git commit`, still run; `rm`, `sed -i`,
`pip install` and a download from a host the user did not name ask.

**Dangerous-command rules.** With `--builtin-tools` the hook also runs `src/intentshield/dangerous.py` on every
shell command, file read and file write, and the stricter of its verdict and the session rules' verdict wins (a deny
beats an ask beats an allow): a key or cloud credential sent out is a deny even where the session rules would only
have asked. They read the call's text alone, parsed safely (`shlex` stages, wrappers such as `sudo` and `env`, `bash -c`,
`$(...)`, here-documents, never executed), with linear-time patterns. They are **text rules and opt-in**, not a
sandbox:

| decision | what it covers |
|---|---|
| deny | recursive delete, `chmod` or `chown` of root or a system directory; `find ~ -delete` and `find / -delete` with no test on the name (`-type`, `-mtime` and `-size` do not count); writes to a block device, `mkfs`, `wipefs`; a fork bomb; force-push or deletion of a shared branch; a read of an SSH private key, a cloud credential file, `~/.netrc` or a keychain; a sensitive file sent to a network destination; a reverse shell; a write to `authorized_keys` or sudoers |
| ask | hook bypass (`--no-verify`, `git commit -n`, `core.hooksPath`); other force-pushes; `git reset --hard`, `git restore .` and `git clean -f` (not `git clean -n`, which deletes nothing); `curl ... \| sh` (a deny when the shell runs as root, as in `curl ... \| sudo sh`, or the script comes over plain HTTP or from a bare IP address that is not on this machine; `sudo curl ... \| sh` and a script from `localhost` are an ask); a delete by `find` at a system directory, or with `-o` or `-prune`, that names the files it removes; `rm -rf` of a variable that may be empty, also after a root (`$DIR`, `/$DIR`, `~/$DIR`, `$HOME/$DIR`); a read of `.env`, a `.pem` that is not a certificate or a cloud token; a read of a harness's own credential file (`~/.codex/auth.json`, `~/.gemini/oauth_creds.json`, `~/.gemini/mcp-oauth-tokens.json`, `~/.claude.json`; `~/.claude/.credentials.json` is covered too, on a report that some Claude Code installs keep it there, which the vendor pages archived here do not confirm); an `.env` or similar file that holds secrets sent out (a key or cloud credential sent out is a deny); an upload of a file (`curl -d @data.json`, `aws s3 cp`) to a host the user did not name; a write to a shell startup file, cron, a launchd or systemd unit, a git hook or a CI workflow; `chmod 777`; a non-recursive `chmod` or `chown` on a system path, and `chown -R $USER` of a `/usr/local` directory (Homebrew's own advice); deleting or emptying a key or an access file; anything that changes the guard itself (below) |

**What the parser reads.** A command inside a one-line control structure (`if ...; then X; fi`,
`for ...; do X; done`, `while`, `{ X; }`, `! X`, `time`, a one-line function body) is read like the same command alone.
Inside one command line it follows `cd`, `pushd` and `popd` (`cd ~ && rm -rf Documents` deletes the home
directory's `Documents`), variables set earlier in that line (`RM=rm; $RM -rf /`, `for d in / b; do rm -rf "$d"; done`),
`$'...'` quoting and brace lists (`rm -rf {/,}`, `{rm,-rf,/}`). The directory a `cd` went to is not known across two calls.
Spellings the shell reads as nothing are read as nothing: a line continuation (`rm \` and a new line before `-rf /`), a
tab, a form feed or vertical tab, `${IFS}` for a space, empty quotes or a backslash inside a word (`r''m`, `\rm`), a comment
after the command. A `find` that deletes only the files it names (`find ~ -name .DS_Store -delete`,
`find ~ -name '*.pyc' -delete`) is read like `rm` of those files and allowed under the home directory; asked at a
system directory.

**Limits on what is read.** The parser reads at most 50,000 characters, 400 commands, 20,000 words and three levels of
nesting (`bash -c`, `eval`, `$(...)`). A command that goes past any of them is **asked about, with the limit named**,
never allowed: a deny hidden after the limit cannot get through by padding the command.

**When the user named it.** A command the user typed in their prompt, or a path or host they named, turns a deny into
an ask, never into an allow. The prompt must name the target itself: `/etc/hosts` does not name `/etc`, `/Users/me/proj`
does not name `/Users/me`, `notevil.com` does not name `evil.com`, and a sentence that forbids it (`never run rm -rf /`,
`don't touch ~/.ssh/id_rsa`) names nothing. When a command holds several denies, every one of them must be named. The
check for a forbidding sentence looks at the six words before the mention, so it is a heuristic; the result is an ask
either way. `--review never` drops the asks of these rules and keeps the denies.

**The guard's own files.** With `--builtin-tools` a call that would switch the guard off asks, in a clean session too:
`intentshield uninstall|unwrap|install|wrap` (without `--dry-run`), `pip|uv|pipx uninstall intentshield-mcp`, a delete,
move or `chmod` of IntentShield's programs or of `~/.intentshield`, an SQL change of `hooks.db` or `threats.db`, and a
write, edit or delete of a harness's hook settings (`~/.claude/settings*.json`, `.claude/settings*.json`, `.claude/hooks/`,
`~/.codex/config.toml`, `.cursor/hooks.json`, `.gemini/settings.json`). This is a speed bump, not protection: an agent
with shell access can still switch a user-space hook off by a route these text rules do not read (a script file it wrote
earlier, an interpreter one-liner, a program the harness's own tools run), and the user can approve the ask. Without
`--builtin-tools` none of this is checked. An `export INTENTSHIELD_HOOK_REVIEW=never` in the agent's shell does not
reach the hook, which the harness starts, so it is not asked about (written into a shell startup file it is).

**What it does not see.** A command built at run time from pieces (`$(printf ...)`, a variable set in an earlier
call or read from the environment), an interpreter script file and a language one-liner that wraps the real action are
not seen. **Which tools are covered.** Claude Code: `Bash` and `PowerShell` (shell commands; Claude Code's help lists both), `Monitor` (its input has a `command`, which is read as
a shell command; this rests on the tool's own schema, not on the vendor pages archived here), `WebFetch`, `Read`, `Grep`, `Write`, `Edit`,
`MultiEdit` and `NotebookEdit`. Codex CLI: its shell tools (`shell`, `local_shell`, `exec_command`)
and `apply_patch`; a patch run through the shell tool (`apply_patch <<'PATCH' ...`) is read as the patch it is. Gemini CLI:
`run_shell_command`, `web_fetch`, `read_file`, `read_many_files`, `write_file`, `replace`, `search_file_content` and its
other search tools. Of the search tools only Grep (and Gemini CLI's `search_file_content`) is read, by its `path`: Glob, `LS`
and Gemini CLI's `list_directory` and `glob` return names, not file content, and are not matched. A tool with another name
that runs a command (a future tool, or one a plugin adds) is not matched either: the install's matcher names the tools it
sends to the hook. A built-in tool call whose
event name or tool input the hook cannot read (a missing or re-cased `hook_event_name`, a `command` that is not text) is
refused, because a changed event schema must not read as an allow.

What the study measured about them (`docs/hook-fidelity-study.md` section 6e, rows in
`results/hook-fidelity/detect/fresh/`; the figures below are those of the rules before the stricter-verdict change above,
which turns 6 of the 41 asked harmful calls into denies when the set is run again: 35 asked and 41 denied, the 28 let
through and the 5 benign asks unchanged): on a fresh set of 214 built-in shell, read, write and edit calls (104
harmful, 110 benign; one author, offline decisions, no model in the loop), the hook with `--builtin-tools` and
**without** the rules let through 96/104 harmful calls (92%). With the rules it let through 28/104 (27%, Wilson
[19, 36]): 41 were asked and 35 denied, and 5/110 benign calls were asked, none denied. That is evidence that the
rules work on the six categories they were written from, which are the six the set samples: it was built by
the same model family that wrote the rules, the rules were not tested outside those categories (the test that
was planned did not run, section 6f), and the comparison with two other guards is mixed. `safety-net` let through
44/85 harmful calls on its shell scope and `knox` 44/73 on its scope, where IntentShield let through 25/85 and
18/73, but **on denies alone IntentShield trails `safety-net` (24/85 against 41/85) and ties `knox` (28/73
against 29/73)**. Its remaining misses are discovery-only commands, cloud-CLI destruction (`aws s3 rb --force`,
`kubectl delete namespace kube-system`), `node -e` and `python3 -c` one-liners, reads of an instance-metadata
address or a Kubernetes service-account token, and a few others listed in section 6e. An ask is a prompt only
in an interactive Claude Code session; on a headless build it is a refusal, so those benign asks cost a refused
call. None of this makes the hook a substitute for the harness's own permission rules.

### Point the model at the right tool

Two optional features cut the tokens spent on tools the task does not need. Both rank
tools by keyword (BM25 over the tool name, counted twice, and the first 300 characters of
its description). They are conveniences, not security decisions.

- **Search-first tool list** (`"tool_routing": true` in the proxy config). The proxy
  lists only `intentshield_find_tools` plus any `pinned_tools` (qualified-name
  patterns, e.g. `"filesystem:read_*"`). The model asks it for a task in a few words; the
  top matches (5 by default) are unlocked and the client gets `tools/list_changed`, so
  their descriptions and schemas are sent from then on and the rest never are. Every
  visible tool stays callable by name, and quarantine still applies. The client must
  handle `list_changed` (MCP protocol versions up to 2025-11-25; the 2026-07-28
  protocol's subscription path is not implemented).
- **Per-prompt hint.** With `"tool_catalog_dir": "~/.intentshield/tools"` in each proxy
  config, the proxy writes its visible tool names and descriptions there at start. The
  prompt hook (`UserPromptSubmit` in Claude Code and Codex, `BeforeAgent` in Gemini CLI)
  then adds one line naming the five best matches for the prompt. It reads
  `--catalog DIR` (default `~/.intentshield/tools`, or `INTENTSHIELD_HOOK_CATALOG`) and
  stays quiet when nothing matches or there are five tools or fewer. Cursor's prompt hook
  cannot add context. Only names reach the model, never description text.

On MCPTox (324 queries over 45 servers, the expected tool taken as the majority choice of
the models that ignored the poisoned description) the expected tool ranked first for 80%
of queries, in the top 3 for 90% and in the top 5 for 92%; 6% matched no tool, because
keywords miss synonyms ("bill" for an invoice tool). MCPTox catalogs are small (median 7
tools, about 470 characters of descriptions), so routing pays off with many servers
connected: the 45 catalogs together are about 75k characters, roughly 19k tokens sent with
every request. A malicious server can still word its descriptions to be ranked first; the
300-character cap limits keyword stuffing, it does not stop it.

## When the guard blocks or asks about something legitimate

A false positive costs a refused call or a prompt, and a guard that is turned off for that reason protects
nothing, so this section says what each harness shows, how to approve, which settings exist and how to read the
reason. The messages quoted here come from the code and from runs under a temporary home directory.

**What you see.** A hook answers allow, ask or deny. The table is the per-harness table of [layers.md](layers.md#what-each-harness-lets-the-guard-do) with what the
user actually sees (that table has the hook configuration):

| harness | an ask | a deny |
|---|---|---|
| Claude Code | Claude Code's own permission prompt in an interactive session; a refusal in a headless run (notes below) | the call does not run; the model is shown the reason |
| Codex CLI | never a prompt: Codex runs a call its hook asked about, so an ask is sent as a refusal that tells the agent not to retry | the same refusal |
| Cursor | an MCP call: a refusal (Cursor ran an allowlisted MCP call its hook asked about). A shell command with `--builtin-tools`: Cursor's own approval prompt | `permission: deny`, with the reason as the user message |
| Gemini CLI | by default a refusal; a prompt only with `install gemini --gemini-ask` (notes below) | the same refusal |

- **Claude Code.** The prompt shows the hook's reason as its text, and you answer yes or no there. In a headless run
  (`claude -p`) nobody can answer: since 0.4.3 the hook sends the ask as a refusal that says so, and Claude Code 2.1.85
  and later refuses an ask nobody answers by itself.
- **Gemini CLI.** `--gemini-ask` needs Gemini CLI 0.66 or later, an interactive session, and covers shell commands
  only; an MCP ask is always refused. After the third refusal since your last prompt the hook also ends the agent's
  turn, so it stops retrying.

A refusal carries the sentence "Do not retry this call or a variant of it: tell the user what you wanted to do
and why, so they can decide", so a well-behaved agent reports back instead of looping.

**How to approve.** On Claude Code (and on Cursor for a shell command) answer the prompt. The hooks have no
approval queue of their own: a hook never approves a call, so a refused call does not run until something
changes. What you can change, narrowest first:

1. **Name the value in your own prompt.** An address, URL, account or path you typed is trusted; one that appeared
   only in a tool result is not. If the reason says "An argument value came from a tool output, not from the
   user", repeat the recipient or URL in your next prompt and ask again.
2. **Start a new session.** The taint and the flagged state belong to one session; a new session starts clean.
   What the [threat memory](#adaptive-threat-memory-and-threat-packs) learned survives.
3. **Allow the value or server in the threat memory.** `intentshield-threats list` shows what it holds,
   `intentshield-threats revoke <id>` forgets an entry (it is not learned again), `intentshield-threats allow
   <address, domain or server>` allowlists it and revokes what it covers, and `intentshield-threats benign
   "<text>"` records an output text as benign when a rule or fingerprint fired on it. Something the memory
   learned on its own only asks; `confirm <id>` is what makes an entry block. Turn the memory off with
   `--no-threat-memory` on the hook command or `INTENTSHIELD_THREAT_MEMORY=0`.
4. **Change `--review`.** It decides when a state-changing MCP call asks: `intentshield install <harness> --review
   always|tainted|never` writes it into the hook command (the default is `tainted`: ask once an output tried to
   instruct the agent or a value came from an output), and the hook reads `INTENTSHIELD_HOOK_REVIEW` when the flag
   is absent. `always` asks about every state-changing call (a refusal on Codex and Gemini). `never` removes every
   ask, including the asks for values from tool outputs, for credentials the user did not give, for a judge's
   objection and for the dangerous-command rules; it keeps the denies (injected instructions in the arguments, a
   value from an injected output, a known attack, the dangerous-command denies). It is not a way to approve one
   call; use it only where a refusal costs more than the ask protects. Reads whose argument came from an output
   can be let through on their own with `INTENTSHIELD_HOOK_SOURCED_READS=allow` (or `--allow-sourced-reads` on the
   hook command; `install` has no flag for it) while writes still ask.
5. **Remove a layer.** Run `intentshield install <harness>` again without `--judge`, `--builtin-tools` or
   `--gemini-ask` to drop what caused the prompt. `intentshield uninstall <harness>` (add `--scope project` for the
   project's settings file) removes only IntentShield's hook entries and leaves every other setting; the file is
   deleted only when it held nothing else. `intentshield unwrap <mcp.json>` restores the servers `wrap` rewrote
   (`--server NAME` for one) and keeps their proxy configs and audit databases. All four commands accept
   `--dry-run` to print the result. Since 0.4.3, `install --no-translate` (or `INTENTSHIELD_HOOK_TRANSLATE=off`) goes
   back to the hook as it was before the verdict translation: no deadline, no fail-closed launcher, and asks sent
   as the harness table above lists them.

For the gateway and the transparent proxy the approval is a human decision through the control endpoint, see
[Human approval for mutations](#human-approval-for-mutations). A tool the proxy hid because its description
changed after connect stays hidden for the rest of that session; restart the client after you have looked at the
change. For `intentshield scan`, `--update-pins` accepts the tools as they are.

**How to read a reason.** The reason is the text of the refusal or of the prompt. These are the ones you will meet
(each is the message the hook prints, with the call's own values in place of the angle brackets):

| the reason starts | what it means |
|---|---|
| `Arguments carry injected instructions (instruction_override).` | deny: the call's own arguments contain text the rules read as an instruction to the agent; the name in brackets is the rule |
| `An argument value came from a tool output that contained injected instructions, not from the user: <values>.` | deny: a value in the call (at most three are shown) came from a result the scan flagged |
| `An argument value came from a tool output, not from the user: <values>. Confirm this call.` | ask: the address, URL, account or path appears in an earlier result and not in your prompts; see "name the value" above |
| `A tool output in this session tried to instruct the agent; confirm this call.` | ask: a result in this session was flagged and the call changes state |
| `An argument carries a credential the user did not give (<masked>)` | ask, or deny once the session is flagged: a token or key you did not type is leaving |
| `An argument matches an earlier attack (<value>); confirm this call.` / `An argument matches a known attack` | threat memory: a learned value asks, an operator-confirmed or imported one denies |
| `IntentShield's LLM judge found this call inconsistent with your request; confirm with the user.` | ask from the optional judge, which never denies on its own; Claude Code's prompt shows the judge's own words to you and not to the agent |
| `IntentShield: <reason>` | a dangerous-command rule (since 0.4.3, with `--builtin-tools`), for example `IntentShield: git commit -n skips the repository's pre-commit hooks.` |
| `... (IntentShield wanted the user to confirm this call, but <why>; so it is refused and the user can allow it.)` | an ask that was sent as a refusal (since 0.4.3); `<why>` says whether it was a headless run, a harness that does not honour an ask, or an unmeasured build |
| `[IntentShield read this session as <mode>: <how> [ancestry: <source>]]` | since 0.4.3, the mode the hook read (`interactive`, `headless`, `yolo` or `unknown`) and which source decided |
| `IntentShield did not finish checking this call within 30 s ...` | the hook's own deadline (since 0.4.3) answered before the harness's timeout, which every harness measured lets the call run |
| `IntentShield hook did not run (exit code <n>); this call is refused.` | the fail-closed launcher (since 0.4.3): the hook could not start or crashed; run `intentshield doctor` |

Two of these lines carry a note. `(the user typed this command, so confirm it)` after a dangerous-command reason marks a
deny softened to an ask. "The harness process was not found among the ancestors: assumed headless" in the mode line
explains an unexpected refusal in a session you were attending.

If the reading is wrong for your session, `INTENTSHIELD_HARNESS_MODE=interactive|headless|yolo` and
`INTENTSHIELD_HARNESS_VERSION=X.Y.Z` override it, and the hook says on stderr that it was overridden. A project's
settings can set them for a session, so do not set them for a repository you do not trust.

## Wrapping a third-party hook

Since 0.4.3, `intentshield wrap-hook` runs any hook command under the same fail-closed
launcher, deadline and version-keyed verdict translation that `install` writes for IntentShield's own hook. It
exists because the hook-fidelity study found that the harnesses let a call run when a hook crashes, is slow or
prints nothing, and that a guard's `ask` is dropped, run or hung on some builds
([study](hook-fidelity-study.md), [mitigation](hook-fidelity-mitigation.md)). The harness runs the shim in place
of the guard; the shim pipes the harness's event to the guard and sends the harness one reply in its own shape.

```sh
intentshield wrap-hook --harness claude|codex|gemini|cursor [--version X.Y.Z] [--mode interactive|headless|yolo] \
    [--deadline SECONDS] [--hook-timeout SECONDS] [--on-empty deny|allow] [--gemini-ask] [--print-entry] -- <guard command ...>
```

`--print-entry` prints the full entry to put in the harness's settings instead of running anything. The shim is named
by the absolute path of the `intentshield` program, as `install` writes it, because a harness started from the Dock or an IDE
may not have it on `PATH`. The guard may be given as one shell string or as separate arguments. Give `--hook-timeout` the same
number as the entry's own timeout setting.

A hook entry that ran `pnpm dlx block-no-verify` becomes

```text
intentshield wrap-hook --harness claude --hook-timeout 5 -- pnpm dlx block-no-verify || { rc=$?; [ "$rc" -eq 2 ] || echo "IntentShield hook did not run (exit code $rc); this call is refused." >&2; exit 2; }
```

The trailing `|| { ... }` is the launcher, which refuses the call when the shim itself cannot start;
`intentshield.wrap_hook.wrapped_command()` builds the exact string. **There is no installer for third-party
entries**: you edit the entry by hand, and `--hook-timeout` has to repeat the timeout the entry gives the hook
(the shim keeps its deadline under it; without it a shorter shipped timeout fires first). What the shim does with
the guard's reply:

| the guard does | the shim sends |
|---|---|
| exit 2, with or without text on stderr | a deny with a reason (a bare exit 2 is not a refusal on every build: Codex 0.166.0 ran the call) |
| any other non-zero exit, cannot be started, still running at the deadline (30 s by default) | a deny that says so |
| exit 0 with a deny or block verdict | a deny in the harness's own shape |
| exit 0 with `ask` | an ask only where this build, in this mode, is measured to enforce one; otherwise a deny that says what the guard wanted |
| exit 0 with JSON that names no verdict, or an explicit allow | the guard's bytes unchanged, so a rewrite or note still arrives |
| exit 0 with a verdict word it does not know, text that is not a JSON object, or more than 1 MB | a deny |
| exit 0 with nothing on stdout | `--on-empty deny` (the default): a deny; `--on-empty allow`: the call runs |

The last row is the cost. Most guards print nothing for an allow, so the default blocks every guard that signals
allow by silence, and `--on-empty allow` lets through the guard that failed before it decided, which also
prints nothing. Only events that check a call are translated; others pass to the guard unchanged. The version
comes from `--version` or the record `install` and `doctor` keep, and the mode from the process tree unless
`--mode` or `INTENTSHIELD_HARNESS_MODE` says.

What was measured: headless, macOS, a stub model, one or two runs per cell. On the 12 (build, cell) pairs where
the shipped verdict of one of six captured third-party guards did not survive, the same bytes behind the shim
were blocked in 12/12, and IntentShield's own installed hook in 11/11 pairs with a result. Nine of the 12 are the
`|| exit 2` launcher alone (launcher-only reproduced the 5 that were launched), and a hook that denies everything
scores the same on every survival cell. So this shows that verdict delivery can be repaired by a thin wrapper,
not that the wrapped guard is better, and nothing was measured about a guard's detection. See
`results/hook-fidelity/compare/README.md`.

### What `install` writes

`intentshield install` runs `<harness> --version` and records it in `~/.intentshield/harness-versions.json`, then
writes two things into the hooks that check a call (Claude Code, Codex and Gemini; Cursor keeps `failClosed`): the
hook's own deadline (`--deadline`, 30 s by default, so a slow judge or database answers with a refusal before the
harness's timeout, which every harness measured treats as permission to run the call) and the launcher above
(a hook that cannot start, with exit 126 or 127, becomes exit 2 with a reason). The launcher is for POSIX shells
and is left out on Windows. `--no-translate`, or `INTENTSHIELD_HOOK_TRANSLATE=off` at run time, writes the hook as
it was before: verdicts are sent as the guard made them, with no deadline and no launcher. `intentshield doctor`
warns about a call hook installed without them.

## Troubleshooting

**`intentshield doctor`** checks every harness's user and project settings file, then the MCP configs it finds
(Claude Code, Cursor and Gemini CLI). A line is `ok`, `warn`, `FAIL` or `--` (no IntentShield hooks for that
harness); it exits 1 when any line is `FAIL`, and `warn` lines do not change the exit code. Apart from recording
each harness's version it only reads. Messages from a run against a fresh install:

- `FAIL <harness> (<file>): installed, but no hook has run since <time>.` Right after `install` this is expected:
  start the harness and send any prompt (every hook event counts, not only a tool call). If it stays, the harness is not running the hooks. For Codex the line adds: "Codex skips
  hooks nobody has trusted: start `codex` and approve the IntentShield hooks."
- `warn <harness> (<file>): installed; the only events ... reached the hook from a process that is not <harness>`: since
  0.4.3 the hook records whether the harness is among its ancestors. A test event piped in by hand
  (`echo '{...}' | intentshield-hook claude`) comes from your terminal, so it is not counted as a run and `doctor` warns.
  Start the harness and send any prompt. It is a warning because an IDE that starts the harness under another process
  name looks the same; Cursor cannot be told apart, and `doctor` says so on its `ok` line.
- `FAIL ... no IntentShield hook for <events>; run intentshield install <harness>`, and `FAIL ... the hook
  executable <path> does not exist` (a deleted environment): run `install` again from the environment you use.
  `FAIL ... starts with #!<interpreter>, which does not exist` is a virtual environment whose Python was removed or
  upgraded; with the launcher the line is a `warn`, because the launcher refuses the call, but results and prompts
  go unchecked.
- `FAIL ... the hooks are installed but switched off: disableAllHooks is true in <file>` (Claude Code).
- `FAIL ... the <event> matcher ... does not match MCP tools`, and the same for `Bash` with `--builtin-tools`:
  `install` again.
- `FAIL ... the groq judge has no GROQ_API_KEY in ~/.intentshield/.env` (and the same for the other judges): the
  hook runs on the rules alone. A key exported only in your shell is a `warn`, because a harness started from the
  Dock or an IDE does not inherit it. `install <harness> --judge groq` stores it.
- `nothing is installed: no IntentShield hooks and no wrapped MCP server were found, so nothing is guarded.` `doctor` found
  neither a hook nor a wrapped server. That is a statement, not a failure, so the exit status is 0; run
  `intentshield install <harness>`. `intentshield doctor --help` lists the exit status: 1 when any line is `FAIL`, else 0.
- `FAIL <file>: <server>: the server's command '<cmd>' is not on PATH` (or `does not exist`): the proxy cannot start the
  server it wraps and the harness shows it as failed. Install the command, or put its absolute path in the entry and wrap again.
- `warn <file>: <n> stdio server(s) not behind the transparent proxy, so their tool descriptions go unchecked:
  <names>. Run intentshield wrap <file>`. And `FAIL ... runs the proxy with a missing config`: `unwrap` restores
  the entry from the copy `wrap` kept, or edit it by hand.
- Since 0.4.3, `warn` lines state what was measured for the detected version, for example "Claude Code 2.1.322: a
  hook that prints nothing or malformed JSON allows the call, with or without `onFailure: block`", or, for Codex,
  "a hook's ask, an empty reply, malformed JSON, exit 1, 126, 127 and a timeout all let the call run". They are
  facts about the harness, not faults in your install. "version unknown" means the harness was not on `PATH`
  when `install` or `doctor` ran; until it is recorded, every ask is sent as a refusal.

**`Could not connect to MCP server ...` now says why.** `scan`, the proxy and `doctor` add the cause when they can tell it:
the command was not found on `PATH` or does not exist, it cannot be run (permission denied), it ended before it answered the
start-up message, or it did not answer in time. A URL in the error text is shown as `<url>` and credential values are
removed. The server's exit code is not in the message, because the MCP client library does not expose it; `scan` adds the
server's own stderr line when it has one, and the proxy's stderr is on its terminal.

**A client request the proxy cannot parse gets an error.** In transparent mode (`intentshield-mcp --config ...`) a request
whose `params` is not an object is answered with error -32602 and its id, and a line that is not JSON with -32700 and a null
id; the proxy keeps serving. Before 0.4.3 the protocol library dropped these silently and the client waited. The other
transports were not checked for this.

**A command that needs a package that is not installed.** After `pip install --no-deps intentshield-mcp` only the hooks,
`wrap-hook`, `install`, `uninstall`, `doctor` and `scan --no-connect` run. The proxy, `wrap`, the dashboard, `scan` with a
connection and the verifier print one line, "this command needs the package '<name>', which is not installed ... Install
everything with: pip install intentshield-mcp", and exit with status 2.

**Gemini's `settings.json` has comments or trailing commas.** Gemini CLI reads its settings as JSONC, and `install` and `wrap`
do too. Writing the file back drops the comments and trailing commas; the original text is saved and `intentshield uninstall`
(or `unwrap`) puts it back byte for byte, comments included. A settings file of another harness, which is strict JSON,
that does not parse stops the command with a message that says what to do: remove the comments and trailing commas, or add the entries by hand
from the output of `intentshield install <harness> --dry-run`.

**`install --scope project` and `wrap` write absolute paths.** The project file then holds the path of the hook program on this
machine, so do not commit it. `install` prints a note after a project-scope install, and `wrap` prints one when the file is
inside a git working tree.

**Codex hooks not yet trusted.** Codex runs a new hook only after you trust it once, and until then it skips it
without a word in the session. Start `codex` interactively and approve the IntentShield hooks when it asks;
`install codex` prints the same reminder, and `doctor` reports `no hook has run` until it happens. A live run
with the hooks installed but not trusted was unguarded (the notes reached the attacker in 3/3 runs,
`results/harness-live-codex/`). `codex exec --dangerously-bypass-hook-trust` is measured not to run hooks through
Codex 0.140.0 (it does from 0.141.0), so do not rely on it for an older build.

**Gemini CLI waits for ever on an ask.** That is the headless case: with `install gemini --gemini-ask`, a headless
run (`gemini -p`) waits for an answer that never comes from Gemini CLI 0.38.0 on (measured to 0.66.0), and 0.37 in
yolo mode ran the call. `--gemini-ask` is for interactive sessions only. Since 0.4.3 the hook sends a refusal when it can
tell the run is headless, and `doctor` warns whenever the flag is on. If a session hangs, interrupt it and run
`intentshield install gemini` again without `--gemini-ask`. If the hook cannot read the mode it refuses the ask;
`INTENTSHIELD_HARNESS_MODE=interactive` restores the prompt in a session you know has a person.

**A wrapped server does not see your shell's environment.** `wrap` starts each server through the proxy, which
gives it the variables the entry's `env` names plus basics such as `PATH` and `HOME`, not the rest of your
environment (a proxy setting, `AWS_*`, `SSH_AUTH_SOCK`, a token you exported). Name each variable the server
needs in the entry's `env`; a literal value there stays in the client's file and is passed on by name, and an
empty value is not forwarded. `wrap` skips an entry whose command line uses `${...}`, `$VAR` or `%VAR%`
interpolation, because the client expands those only for the program it starts: replace it with the value (or
move it to `env`) and wrap again. `intentshield scan` starts servers with the same reduced environment, so a
server that needs a variable can fail to list its tools there, and the finding is `not_scanned`. `scan` starts the
servers of a config the repository chose only with `--connect-project`; a file you name on the command line is
treated as yours and is started.

**The judge is offline.** The judge is evidence only. When it cannot be reached (no network, or its key is
refused) the rules alone decide, with no extra ask or refusal; the agent is told "the LLM judge is offline or
unavailable; only the rules checked this call", stderr says why, and the hooks skip the judge for 5 minutes before
trying again, so an offline session does not wait on it at every call. A judge with no stored key says so in the
same note and in `doctor`. A timeout, a rate limit or a reply it could not parse does not start the 5-minute pause.
With a local judge (`--judge ollama`), an Ollama server that is not running ("Connection refused") starts the same
pause.

**Every ask is refused, or a hook seems slow.** Check the `[IntentShield read this session as ...]` note first (see
above). A refusal that names a 30 s deadline means the judge or the database was slow; a hosted judge on a free
tier can be. Each hook is a process of about 60 ms (the Overhead row of [benchmarks.md](benchmarks.md)); a much longer time is the judge.

## Adaptive threat memory and threat packs

New attacks should not need a new release. Two mechanisms adapt a running install, both evidence
only: they can send a call to review or, when the operator says so, block it; they never allow
anything and never relax a built-in rule.

- **Threat memory** (`threat_memory.py`, on by default). When the deterministic rules confirm an
  injection, the memory keeps what the attack used: the addresses, URLs, accounts and paths it named,
  their domain once an attacker rotates local parts across runs, word fingerprints of the injected
  sentences (also with the trigger phrases blanked, so rewording exactly what the rules look for does
  not hide the payload), and how often each server produced attacks. One SQLite file is shared by every
  proxy and hook process, so what one session caught, the next session knows. Only rule-confirmed text
  teaches it, never its own matches; values the user typed are never learned or held against them;
  fingerprints that a benign gate corpus would contain are rejected; learned entries expire after 30
  days. A server with attacks in 5 distinct runs within 7 days is hostile: its outputs are read as possibly
  injected (weak evidence, never on a call's arguments) until the operator approves a call to it or
  allowlists it. What it learned on its own only asks (`REVIEW_KNOWN_THREAT`, a hook "ask"); an entry the operator
  confirms, or one from an imported feed or a trusted pack, blocks (`BLOCK_KNOWN_THREAT`). The file
  defaults to `threats.db` next to the proxy or hook database (`threat_memory_path` in the proxy config,
  `--threats` or `INTENTSHIELD_THREAT_DB` for hooks); turn it off with `threat_memory: false` or
  `--no-threat-memory` / `INTENTSHIELD_THREAT_MEMORY=0`.
- **Threat packs** (`rule_packs.py`). New detection rules, indicators and fingerprints shipped as a
  JSON file. A running proxy or hook picks up a new or changed pack within seconds, without a restart.
  A pack loads only if it verifies against a digest you pinned (`INTENTSHIELD_PACK_PINS`), your HMAC key
  (`INTENTSHIELD_PACK_HMAC_KEY`) or a pinned Ed25519 key (`INTENTSHIELD_PACK_ED25519_KEYS`, needs
  `cryptography`, which `pip install "intentshield-mcp[signing]"` adds). Every rule must pass the same backtracking and breadth checks as learned rules and
  must not match the benign gate corpus. A tampered or older pack is refused and the last good one stays
  loaded. Point the proxy's `threat_packs_dir` or the hook's `--packs` / `INTENTSHIELD_THREAT_PACKS` at
  a directory; `configs/threat-packs/baseline.json` is an example built from the replayed incidents.

From a clone: the two `configs/` files below are not in the PyPI package. Copy them from the repository, or write your
own feed and pack in the same format.

```bash
intentshield-threats stats                                  # what the memory holds
intentshield-threats confirm <id>                           # make a learned indicator block
intentshield-threats allow partner.example                  # never flag this value or domain
intentshield-threats import configs/threat-feed.example.json
intentshield-threats pack --allow-unverified verify configs/threat-packs/baseline.json  # shows its digest
intentshield-threats pack --dir ~/.intentshield/packs --pin sha256:<digest> install configs/threat-packs/baseline.json
intentshield-threats pack export > learned.json             # share what one install learned
```

`benchmarks/adaptive_learning.py` (offline, deterministic) replays attack campaigns with mechanical
rewordings: with the attacker's infrastructure reused, the memory raised the catch rate from 0.67 to
1.00; with fresh addresses per attempt, from 0.67 to 0.93 (fingerprints alone); a family the rules
miss went from 0.00 to 0.67 after hot-installing the baseline pack. It flagged none of 1,756 benign
paragraphs. Read these as an upper bound: the attacks and the pack are self-authored, the rewordings
are mechanical rather than an LLM's, and a full rewrite leaves too little wording to recognize
(`tests/test_adaptive_integration.py` shows both cases). The memory adds about 5-25 ms to each hook
process when small, and about 20 ms before a call and 40 ms after a result at its caps (5,000 indicators,
500 fingerprints). Poisoning is bounded rather than prevented: an attacker can get a colleague's address
learned, at review level; boilerplate after an injection is not learned (fingerprints are anchored on the
injected sentence, and a bare trigger's payload is learned only when it names a destination).

## What is implemented

- Deterministic policy enforcement with stable reason codes
- Registered-tool and schema-hash checks
- Tool allow/prohibit lists, argument validation, and resource/destination scope
- Call budgets, intent-alignment and injection signals
- Atomic idempotency protection for mutations; uncertain executor outcomes enter a persistent `IN_DOUBT` state and are never retried automatically
- Human approval bound to the exact run, tool, arguments, and expiry
- SQLite audit trail for runs, events, approvals, and executions
- Real MCP 2.2 client support over stdio and Streamable HTTP
- Guarded connections to multiple real upstream MCP servers over stdio or Streamable HTTP
- Upstream JSON Schema validation, namespaced tool identities, and fail-closed catalog drift checks
- MCP poisoning defense: description scanning with quarantine, cross-server shadowing detection, and rug-pull fingerprints over descriptions and annotations
- Tool-output injection scanning (including user impersonation and task hijack) with session taint, and argument-provenance blocking of attacker-supplied values
- Self-disclosure parameter redaction: parameters that ask for the agent's model, system prompt or conversation are hidden from the agent and never reach the server with a value
- Harness hooks for Claude Code, Codex CLI, Cursor and Gemini CLI (`intentshield-hook`), bound to the user's real prompt
- Transparent proxy mode (`intentshield-mcp --transparent`) for the MCP servers a harness launches
- Gemini-native function calling for the web proposal path (the optional LLM judge can also use Groq; see [detectors.md](detectors.md#llm-judge-on-tool-results-plain-language-injections))
- Evidence-only detection and grounding agents feeding the deterministic policy engine
- A locally trained DeBERTa-v3-small intent classifier with abstention and artifact integrity checks
- Optional learned injection detectors beside the rules, all evidence only:
  - Llama Prompt Guard 2 on Groq's free tier.
  - A local embedding nearest-neighbour detector (exemplars).
  - Learning from operator labels, behind a regression gate.
  - Regex rules proposed by a local model that the operator approves.
- Model proposals normalized into the same deterministic policy and approval boundary
- A deterministic local MCP server and end-to-end harness; no API key or paid model required
- FastAPI endpoints and scripted benign, injection, and approval scenarios

## Real MCP proxy

IntentShield is an MCP server to the agent and an MCP client to the guarded
upstream server. The agent never receives a direct upstream connection.

**From a clone.** This section, [Production settings](#production-settings) and [Run locally](#run-locally) are written for
a repository clone: they use `.venv/bin/<tool>` and `configs/...` paths. With a pip install, drop the `.venv/bin/`
prefix (the tools are on your `PATH`) and copy the config you need from the repository's `configs/` directory. The
package carries only the demo config, which `intentshield-mcp-verify --demo` uses, and
`python -c "import intentshield.mcp_verify as m; print(m.demo_config_path())"` prints its path.

The included demo config launches a real upstream MCP server over stdio:

```bash
.venv/bin/intentshield-mcp \
  --transport streamable-http \
  --config configs/mcp-proxy.demo.json \
  --host 127.0.0.1 \
  --port 8001
```

Point any MCP client at:

```text
http://127.0.0.1:8001/mcp
```

### Connect Codex or Claude Code

This gateway mode exposes IntentShield's own tools, so the model must route calls
through `intentshield_call` and state the user's intent itself. For a harness, prefer
[hooks plus the transparent proxy](#guard-an-agent-harness-claude-code-codex-cli-cursor-gemini-cli):
the hooks read the user's real prompt and see every MCP call.

Start the server above in one terminal and leave it running. In another
terminal, register the local endpoint with either client:

```bash
# Codex CLI and desktop app share this MCP configuration.
codex mcp add intentshield --url http://127.0.0.1:8001/mcp
codex mcp list

# Claude Code: user scope makes it available across projects.
claude mcp add --transport http --scope user intentshield http://127.0.0.1:8001/mcp
claude mcp list
```

In Claude Code, `/mcp` shows the connection. Other MCP clients can use the
same local Streamable HTTP URL. The client sees IntentShield's five gateway
tools, not the upstream tools directly. To try an allowed read, ask the client
to list guarded tools, create a run with your exact request, then call the
chosen tool using its current schema hash.

The demo upstream needs no API key, and neither Codex nor Claude Code needs
`GEMINI_API_KEY` to use this MCP server. `INTENTSHIELD_REMOTE_AUTHORIZATION`
is only for a separate online MCP server that IntentShield connects to as an
upstream; obtain that credential from the upstream provider if it requires
one. `INTENTSHIELD_CONTROL_TOKEN` is generated by you and protects the
separate human approval endpoint for mutations. It does not authenticate the
agent-facing `/mcp` endpoint, which is bound to localhost in this release; set
`INTENTSHIELD_AGENT_TOKEN` to require a bearer token there (see
[production settings](#production-settings)).

The proxy exposes five stable MCP tools:

- `intentshield_create_run`
- `intentshield_list_tools`
- `intentshield_call`
- `intentshield_get_run`
- `intentshield_get_approval`

A client creates a run using the user's exact intent, reads the guarded catalog,
and sends the selected tool name, arguments, and exact `schema_hash` to
`intentshield_call`. `BLOCK` and `REVIEW` never contact the upstream tool.

Verify the complete policy and wiring before connecting an agent:

```bash
# Fast in-process preflight
.venv/bin/intentshield-mcp-verify --config configs/mcp-proxy.demo.json

# Real downstream stdio subprocess
.venv/bin/intentshield-mcp-verify --config configs/mcp-proxy.demo.json --stdio

# A running Streamable HTTP gateway
.venv/bin/intentshield-mcp-verify \
  --config configs/mcp-proxy.demo.json \
  --url http://127.0.0.1:8001/mcp
```

The verifier discovers every upstream, checks policy coverage and schemas, then
proves that an unregistered canary is `BLOCK` and a safe mutation proposal is
`REVIEW` with `executed=false`. Mutation verification uses the gateway's
non-persistent `dry_run` path, so it neither executes nor creates an approval
that could later be granted.

To exercise both upstream transports together, start the HTTP fixture in one
terminal and verify the mixed config from another:

```bash
# Terminal 1: real Streamable HTTP upstream
.venv/bin/intentshield-demo-mcp \
  --transport streamable-http --host 127.0.0.1 --port 8010

# Terminal 2: real stdio client -> IntentShield -> stdio + HTTP upstreams
.venv/bin/intentshield-mcp-verify \
  --config configs/mcp-proxy.mixed-demo.json --stdio
```

No API key is needed for the deterministic demo or mixed-transport harness.

To run the web dashboard and Gemini proposal path against that same real MCP
catalog rather than the simulated tools, set:

```dotenv
INTENTSHIELD_PROXY_CONFIG=configs/mcp-proxy.demo.json
INTENTSHIELD_CONTROL_TOKEN=replace-with-a-long-random-value
INTENTSHIELD_AGENT_TOKEN=replace-with-another-long-random-value
```

Then start `.venv/bin/intentshield`. The FastAPI lifespan opens the configured
upstream connections, Gemini sees the guarded qualified catalog, and every
proposal reaches the same policy-bound MCP executor used by the proxy server.
Enter the same control token in the dashboard's approval queue field; it stays
in memory and is sent only as a bearer credential to the local approval API.
The web proxy refuses to start without this token.

The real HTTP upstream, downstream, authenticated control endpoint, and clean
shutdown path also have an opt-in process-level test:

```bash
INTENTSHIELD_RUN_HTTP_E2E=1 \
  .venv/bin/pytest -q tests/test_mcp_http_e2e.py
```

### Human approval for mutations

Approval is intentionally not an agent-callable MCP tool. For the HTTP mode,
enable the localhost control endpoint with a high-entropy bearer token:

```bash
export INTENTSHIELD_CONTROL_TOKEN="replace-with-a-long-random-value"
.venv/bin/intentshield-mcp \
  --transport streamable-http \
  --config configs/mcp-proxy.demo.json \
  --host 127.0.0.1 \
  --port 8001
```

After an MCP call returns `REVIEW` and an `approval_id`, a trusted operator can
approve it:

```bash
curl -X POST \
  -H "Authorization: Bearer $INTENTSHIELD_CONTROL_TOKEN" \
  -H "content-type: application/json" \
  -d '{"decision":"approve"}' \
  http://127.0.0.1:8001/control/approvals/APPROVAL_ID
```

The endpoint is absent when `INTENTSHIELD_CONTROL_TOKEN` is unset. Bind to
localhost unless you have added TLS and a production authentication layer.
A `/control` request that carries the control token is rate-limited in its own bucket, so traffic
to `/mcp` from the same address cannot lock the operator out.

Approving a call does not clear the threat memory's hostile mark on the server whose output the call's
values came from: one approval is about one call. Send `{"decision":"approve","trust_source":true}`
to also vouch for that server.

Two config caps bound what one proxy session can do: `max_runs` (default 50) runs per session, after
which `intentshield_create_run` is refused (HTTP 429 from the REST API), and `max_dry_runs_per_run`
(default 20) dry runs per run, after which a dry run is blocked with `BLOCK_DRY_RUN_LIMIT`. A dry run
is logged as a `DRY_RUN` event, so probing the policy shows up in the log.

### Configure another upstream server

Use the `upstreams` array to connect one or more servers. For a local stdio
server that needs an API key:

```json
{
  "upstreams": [
    {
      "server_id": "filesystem",
      "transport": "stdio",
      "command": "/absolute/path/to/server-command",
      "args": ["--flag", "value"],
      "env_from_env": {
        "UPSTREAM_API_KEY": "INTENTSHIELD_FILESYSTEM_API_KEY"
      }
    }
  ]
}
```

Export the secret locally. The JSON contains only its environment-variable
name:

```bash
export INTENTSHIELD_FILESYSTEM_API_KEY="your-real-key"
```

You can keep local values in `.env` by copying `.env.example` and editing the
placeholders:

```bash
cp .env.example .env
```

IntentShield loads `.env` automatically. `.env` is ignored by Git; keep the
placeholder-only `.env.example` committed. Variables already present in the
process environment take precedence over `.env`.

For a deployed Streamable HTTP server, place the complete header value in an
environment variable—for example, `Bearer ...`—and reference it with
`headers_from_env`:

```json
{
  "upstreams": [
    {
      "server_id": "remote",
      "transport": "streamable_http",
      "url": "https://mcp.example.com/mcp",
      "headers_from_env": {
        "Authorization": "INTENTSHIELD_REMOTE_AUTHORIZATION"
      }
    }
  ]
}
```

```bash
export INTENTSHIELD_REMOTE_AUTHORIZATION="Bearer your-real-token"
```

Missing or empty referenced variables fail startup. Credential values are
redacted from connection metadata, tool results, exceptions and verifier JSON.
Do not put API-key values directly in committed configuration files. A complete
template is available at `configs/mcp-proxy.real.example.json`.

`read_only_tools` is a local trust decision. Every upstream tool not explicitly
listed there is treated as a mutation and requires idempotency plus human
approval. Upstream descriptions and MCP annotations are never trusted to lower
that classification. Raw upstream descriptions are withheld by default; set
`expose_upstream_descriptions` only for a server whose catalog you trust. Every
returned tool result is labeled `UNTRUSTED_MCP_OUTPUT` for downstream agents.
`allowed_tools` defaults to an empty list, so each deployment must deliberately
allow exact names or scoped patterns such as `filesystem:read_*`.
All patterns and resource/destination rules must use qualified
`server_id:tool_name` identities. Per-tool scope rules use
`resource_fields` with `allowed_resources_by_tool`, or `destination_fields`
with `allowed_destinations_by_tool`; global scope lists are rejected for MCP
proxy configurations to prevent policy bleeding between servers. Every allowed
tool must also have a nonempty `grounding_terms_by_tool` entry containing the
operator-owned nouns that must appear in the user's request, such as `note`,
`invoice`, or `status`. Startup fails if a discovered allowed tool has no such
entry. When wildcard allow rules are used, map every tool they can admit.

For desktop clients that launch MCP subprocesses, use the absolute executable
and config paths:

```json
{
  "mcpServers": {
    "IntentShield": {
      "command": "/absolute/path/to/IntentShield/.venv/bin/intentshield-mcp",
      "args": [
        "--transport", "stdio",
        "--config", "/absolute/path/to/IntentShield/configs/mcp-proxy.demo.json"
      ]
    }
  }
}
```

The Streamable HTTP mode is recommended when the protected human approval
endpoint is needed. This release deliberately refuses non-loopback downstream HTTP
bindings; place an authenticated TLS reverse proxy or a production MCP auth
layer in front before remote deployment. Remote upstream URLs must use HTTPS;
plain HTTP upstreams are accepted only on loopback. The stdio mode is useful for
read-only tools and embedded applications that provide their own trusted
approval UI.

## Production settings

These variables apply to a pip install and to a clone alike; `configs/policy.json` below is in the repository (the package
carries a copy as `intentshield/configs/policy.json`).

| Variable | Purpose |
|---|---|
| `INTENTSHIELD_AGENT_TOKEN` | Bearer token for the agent-facing routes (details below the table). |
| `INTENTSHIELD_CONTROL_TOKEN` | Bearer token for the human approval endpoint. |
| `INTENTSHIELD_RATE_LIMIT_PER_MIN` | Per-client request limit for the web API and, in proxy mode over Streamable HTTP, `/mcp` (default 120, `0` disables). In memory, per process. |
| `INTENTSHIELD_THREAT_DB`, `INTENTSHIELD_THREAT_MEMORY`, `INTENTSHIELD_THREAT_PACKS` | Hook threat memory file, on/off switch (default on) and threat pack directory. |
| `INTENTSHIELD_PACK_PINS`, `INTENTSHIELD_PACK_HMAC_KEY`, `INTENTSHIELD_PACK_ED25519_KEYS` | What a threat pack must verify against to load (see above). |
| `INTENTSHIELD_DB` | The database of the web API and of the demo gateway (`intentshield-mcp --db`); default `~/.intentshield/gateway.db`. A path you give is used as given. |
| `INTENTSHIELD_LOG_LEVEL` | JSON log level (default `INFO`). Decision lines carry run, tool, decision and reason codes, never arguments. |

`INTENTSHIELD_AGENT_TOKEN` is required on the agent-facing `/mcp` endpoint (proxy mode over Streamable HTTP) and, in the
web API, on proposing calls, reading runs, the tool list, metrics and security status. The operator token works there
too, and needs `INTENTSHIELD_CONTROL_TOKEN`. Like the control token, it is required whenever
`INTENTSHIELD_PROXY_CONFIG` is set; left unset in the simulated mode it leaves those routes open on loopback.

Since 0.4.3 the library's default databases are in `~/.intentshield/`, not in the working directory of whatever project calls
it: `Storage()`, `IntentShieldService.default()` and `create_mcp_server()` use `~/.intentshield/intentshield.db`, and a proxy
config with no `database_path` uses `~/.intentshield/intentshield-mcp.db`. `INTENTSHIELD_DB` still overrides. The committed
`configs/mcp-proxy.demo.json` and `mcp-proxy.uvx.json` name `intentshield-mcp.db` in the working directory themselves. A
database of that name an earlier version left in the working directory keeps being used; move or delete it to switch.

`configs/policy.json` is validated strictly: unknown keys, a tool both allowed and prohibited, and catch-all destination patterns are rejected at startup.

## Run locally

From a clone. This section is the local dashboard, the scripted demo and the development setup. Hook and proxy users do
not need it. With a pip install, the dashboard is `intentshield` with no command and the scripted check is
`intentshield-mcp-verify --demo --stdio`.

Requires Python 3.12 or later.

```bash
uv sync --extra dev
.venv/bin/intentshield
```

Open <http://127.0.0.1:8000>. API documentation is available at <http://127.0.0.1:8000/docs>.

The app loads `.env` automatically without overriding variables already exported
by the parent process. Scripted scenarios remain offline. Only live Gemini runs
need an API key.

Run the test suite:

```bash
.venv/bin/pytest -q
```

Or, without installing anything but Docker (no ML extras):

```bash
docker build -t intentshield .
docker run --rm intentshield              # verifies the demo proxy end to end
docker run --rm intentshield pytest -q    # the test suite
```

Optional extras:

- `requirements-ml.txt` (torch, transformers, sentencepiece, protobuf) is needed for the local
  DeBERTa intent and injection classifiers and the exemplar embedder. Install it with
  `uv pip install --python .venv/bin/python -r requirements-ml.txt`. A plain `uv sync` removes it
  again.
- `--extra learning` (numpy) is needed for the exemplar detector and for learning from operator
  labels.
- `--extra dev` includes both pytest and numpy, which is what CI runs: `uv sync --extra dev --frozen`.

The learned detectors and the LLM judge are described in [detectors.md](detectors.md); the operator-label
and induced-rule endpoints in [Teach the detector](detectors.md#teach-the-detector-operator-labels-and-induced-rules).

For the current architecture, complete testing sequence, expected decisions,
and failure diagnosis, see the [architecture and testing guide](architecture-and-testing.md).
The guide includes the [manual MCP walkthrough](../scripts/mcp_walkthrough.py),
which verifies HTTP approval and guarded execution against the local demo.

## Gemini model integration

The dashboard and `POST /api/model-runs` use Gemini to turn user intent into one
native function-call proposal. Gemini output is never trusted or executed
directly. IntentShield first runs local injection preflight, maps the proposed
function back to the registered tool, attaches the trusted schema hash and a
gateway-generated idempotency key for mutations, runs detection and grounding,
and finally invokes the deterministic policy and approval flow.

From a clone, copy the template (`.env.example` is in the repository, not the package) and add the Gemini key locally,
or export the variables below, or put them in `~/.intentshield/.env`. Never commit `.env` or paste the key into the dashboard:

```bash
cp .env.example .env
```

```dotenv
GEMINI_API_KEY=
INTENTSHIELD_GEMINI_MODEL=gemini-3.8-flash
INTENTSHIELD_MODEL_MAX_CONCURRENCY=2
# Optional, off by default (see detectors.md):
# INTENTSHIELD_INTENT_MODEL_DIR=artifacts/intent-deberta-v3-small-v2
```

`GET /api/models` reports Gemini readiness and the configured model name without
returning credential values. A missing key fails before any network request.
The adapter accepts exactly one known tool proposal, offers Gemini an explicit
safe no-action function, and fails closed on missing, multiple, malformed, or
unknown calls. Model requests are bounded by a server-side concurrency limit.

Example:

```bash
curl -X POST http://127.0.0.1:8000/api/model-runs \
  -H 'content-type: application/json' \
  -d '{"provider":"gemini","user_intent":"Read my two most recent inbox messages"}'
```

On this path only Gemini receives the user intent and registered public tool schemas,
and only after local injection preflight succeeds. API keys, policy configuration,
approval state, detector evidence, and tool results are not sent to Gemini. The
flow stops after the guarded tool result; it does not send the result back for a
second generation. Gemini is not the only remote provider overall: if you turn on the
optional LLM judge (`"judge": "groq"` or `"gemini"`, or the hooks' `--judge`), the user's
prompt and each checked call's name and arguments, plus tool descriptions the rules
pass, are sent to Groq or Gemini; with `--judge-outputs` (hooks) or `"judge_outputs": true` (proxy),
every tool result the rules pass is sent too. The judge is off by default.

## API

- `GET /api/health`
- `POST /api/runs`
- `GET /api/models`
- `GET /api/security/status`
- `POST /api/model-runs`
- `GET /api/runs`
- `GET /api/runs/{run_id}`
- `GET /api/runs/{run_id}/events`
- `GET /api/approvals`
- `POST /api/approvals/{approval_id}/decision`
- `GET /api/tools`
- `GET /api/metrics`

Create a scripted run:

```bash
curl -X POST http://127.0.0.1:8000/api/runs \
  -H 'content-type: application/json' \
  -d '{"user_intent":"Read my inbox","scenario":"benign"}'
```

Use `"scenario":"injection"` to demonstrate a blocked attack or
`"scenario":"review"` to create an approval request. Scripted scenarios are
available in local simulated mode; set `INTENTSHIELD_PROXY_CONFIG` for live MCP
catalog and execution from the web dashboard.

When the web dashboard uses a real MCP proxy, both approval endpoints require
`Authorization: Bearer <INTENTSHIELD_CONTROL_TOKEN>`. The local simulated mode
can run without a token for development.
