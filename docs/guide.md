# Running IntentShield: hooks, proxy, scan and troubleshooting

This guide covers what the [README](../README.md) leaves out: guarding an agent harness with hooks and the
transparent proxy, what to do when the guard blocks something legitimate, scanning the servers you already use, wrapping a
third-party hook, threat memory, and troubleshooting. The gateway, dashboard, REST API and production settings are in
[gateway.md](gateway.md). A feature marked "since 0.4.3" needs that version or a later one.

## Contents

| If you want to | Read |
|---|---|
| guard Claude Code, Codex CLI, Cursor or Gemini CLI | [Guard an agent harness](#guard-an-agent-harness-claude-code-codex-cli-cursor-gemini-cli) |
| check a harness's own shell, file and web tools too | [Built-in tools and the dangerous-command rules](#built-in-tools-and-the-dangerous-command-rules) |
| cut the tokens spent on tool descriptions | [Point the model at the right tool](#point-the-model-at-the-right-tool) |
| understand a refusal or a prompt, or stop a false positive | [When the guard blocks or asks about something legitimate](#when-the-guard-blocks-or-asks-about-something-legitimate) |
| run another guard's hook with a deadline and a fail-closed launcher | [Wrapping a third-party hook](#wrapping-a-third-party-hook) |
| check the MCP servers you already use | [Scan the servers you use](#scan-the-servers-you-use) |
| check that the install works, or fix it | [Troubleshooting](#troubleshooting) |
| let the guard learn attacks, or ship new rules as data | [Adaptive threat memory and threat packs](#adaptive-threat-memory-and-threat-packs) |
| run the gateway, the dashboard or the REST API, or set tokens and limits | [gateway.md](gateway.md) |

## Guard an agent harness (Claude Code, Codex CLI, Cursor, Gemini CLI)

Harnesses that call MCP tools get two layers that share IntentShield's rules:

- **Hooks** (`intentshield-hook <harness>`) see what the model cannot forge: the user's real prompt and every MCP call and
  result. State is kept per session in SQLite at `~/.intentshield/hooks.db` (or `INTENTSHIELD_HOOK_DB`). A hook:
  - sends parameters that ask for the agent's model, system prompt or conversation (`llm_name`, `system_prompt`, ...) empty;
  - denies a call whose arguments carry injected instructions, or a value that came from a tool output with injected
    instructions and not from the user;
  - scans every MCP result, including MCP resource reads (`ReadMcpResourceTool`); an injected result taints the session and the
    model is told it is data, not a request (`--outputs block` replaces the result instead);
  - asks before an MCP call that carries a recipient, URL, account or path that came only from a tool output
    (unless `--review never`; `--allow-sourced-reads` or `INTENTSHIELD_HOOK_SOURCED_READS=allow` stops asking for reads only);
  - asks before state-changing MCP calls once the session is tainted (`--review always|tainted|never`, or
    `INTENTSHIELD_HOOK_REVIEW`; `--outputs` reads `INTENTSHIELD_HOOK_OUTPUTS`);
  - refuses to start on an unknown `--review` or `--outputs` value, from the command line or the environment, instead of
    silently skipping every review branch;
  - denies the call when the hook itself crashes. For Claude Code the entry `install` writes adds `"onFailure": "block"`, so a
    hook that is missing, times out or exits with another code denies the call too.

  Built-in tools (shell, file and web tools) are left to the harness unless the hook is installed with `--builtin-tools`; see
  [Built-in tools and the dangerous-command rules](#built-in-tools-and-the-dangerous-command-rules).

  Two optional readers of results, both off by default:
  - **Injection classifier** on results the rules pass: `--classifier DIR` or `INTENTSHIELD_HOOK_CLASSIFIER`. It loads PyTorch in
    every result hook.
  - **LLM judge**: the hook's `--judge` with no value means the local `ollama:qwen2.5:7b`; `--judge groq` or `gemini[:model]`
    names a hosted one. `intentshield install --judge` with no value means Groq, so name the provider in both places.
  - **Judge on results** (`--judge-outputs`, or `INTENTSHIELD_HOOK_JUDGE_OUTPUTS=on`): the judge also reads each result the rules
    pass, for plain-language injections. A result it objects to is treated like a classifier hit (the agent is warned, and any
    value from it asks before use), never as an injection.
  - **Cost of the judge:** one request per result, about 1 s with local qwen2.5:7b and 4 s with Gemini Flash-Lite. On Groq's
    free tier (200,000 tokens a day) that is about 200 results a day, after which the judge has no opinion until the next day.
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
`settings.json`, or any client with that layout), in VS Code's `servers` key (`mcp.json`) or `mcp.servers` key (`settings.json`), and in the
`[mcp_servers.NAME]` tables of Codex CLI's `~/.codex/config.toml`; `unwrap` gives the file back byte for byte. Claude Code keeps the servers added with
`claude mcp add` in `~/.claude.json`, the top-level ones and each project's own; `wrap` handles that file the same way to launch the proxy in front of it, with one
generated config per server under `~/.intentshield/proxies/`; `intentshield unwrap <file>` restores
them. By hand, the entry looks like this:

```json
{"mcpServers": {"filesystem": {"command": "intentshield-mcp",
  "args": ["--transparent", "--config", "/absolute/path/to/transparent-filesystem.json"]}}}
```

Servers reached over HTTP (`"url"`) are not launched by the client, so `wrap` leaves them alone;
guard those with the [gateway](gateway.md#real-mcp-proxy).

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
instruct the agent) are the ones in that row. One difference between the tools: in a session where an output tried to instruct the
agent, `curl` to a host the user did not name asks, but `WebFetch` to one is not asked about (fetching a page an output linked to is how
agents browse); it is refused only when the address came from the injected output or carries a credential. After an injection a read-only command, and an ordinary local
build, test or version-control command such as `pytest` or `git commit`, still run; `rm`, `sed -i`,
`pip install` and a download from a host the user did not name ask.

**Dangerous-command rules.** With `--builtin-tools` the hook also runs `src/intentshield/dangerous/` on every
shell command, file read and file write, and the stricter of its verdict and the session rules' verdict wins (a deny
beats an ask beats an allow): a key or cloud credential sent out is a deny even where the session rules would only
have asked. They read the call's text alone, parsed safely (`shlex` stages, the wrappers listed below, `bash -c`,
`$(...)`, here-documents, never executed), with linear-time patterns. They are **text rules and opt-in**, not a
sandbox:

**Deny** (a deny cannot be approved in the prompt, so these are the cases where the target is plainly the whole machine or a secret):

- Destruction: a recursive `rm` of root, the home directory or a system directory (`/`, `~`, `/etc`, `/usr`, `/var/lib`);
  a recursive `chmod` or `chown` of root or a system directory whatever the mode (`chmod -R 644 /`, `chown -R me /usr/lib`),
  and of the home directory with `sudo` or a zero or world-writable mode; `find ~ -delete` and `find / -delete` with no
  test on the name (`-type`, `-mtime` and `-size` do not count); a write to a block device, `mkfs`, `wipefs`; a fork bomb.
- Git: a force-push or deletion of a shared branch (`main`, `master`, `develop`, `release`, `release/...`, `release-1.2`,
  `hotfix`, ...), also by refspec (`HEAD:main`).
- Credentials: a read of an SSH private key, a cloud credential file, `~/.netrc` or a keychain; a sensitive file sent to
  a network destination; a reverse shell; a write to `authorized_keys` or sudoers.

**Ask** (a prompt in an interactive Claude Code session; a refusal where nobody can answer):

- Git: hook bypass (`--no-verify`, `git commit -n`, `core.hooksPath`); any other force-push, including the usual one after
  a rebase (`git push --force-with-lease origin HEAD`, `git push -f origin my-feature`) and a branch such as
  `release-candidate`; `git reset --hard`, `git restore .` and `git clean -f` (not `git clean -n`, which deletes nothing).
- Downloads: `curl ... | sh`. It is a deny when the shell runs as root (`curl ... | sudo sh`) or the script comes over
  plain HTTP or from a bare IP address that is not on this machine; `sudo curl ... | sh` and a script from `localhost`
  are an ask.
- Deletes: `sudo rm -rf` of a direct subdirectory of a system directory (`/opt/app`, `/etc/app.d`; a deny cannot be
  approved, and these are common clean-ups); a delete by `find` at a system directory, or with `-o` or `-prune`, that names
  the files it removes; `rm -rf` of a variable that may be empty, also after a root or home (`$DIR`, `/$DIR`, `~/$DIR`,
  `$HOME/$DIR`, `/*$DIR`).
- Permissions: `chmod 777`; a `chmod` to `000` or to a world-writable mode, or any `chown`, of a system path (not
  `chmod 644 /etc/hosts`); a recursive `chmod` or `chown` of the home
  directory (without `sudo`) or of a `/usr/local` directory, and `chown -R $USER` or `chown -R $(whoami)` of a
  `/usr/local` directory (Homebrew's own advice).
- Credentials read or sent: a read of `.env`, a `.pem` that is not a certificate, a cloud token, or a file named like a
  key inside a test directory (`tests/fixtures/id_rsa`); a read of a harness's own credential file (`~/.codex/auth.json`,
  `~/.gemini/oauth_creds.json`, `~/.gemini/mcp-oauth-tokens.json`, `~/.claude.json`; `~/.claude/.credentials.json` is
  covered too, on a report that some Claude Code installs keep it there, which the vendor pages archived here do not
  confirm); an `.env` or similar file that holds secrets sent out as a file (a key or cloud credential sent out is a deny, and so is
  the output of `cat .env` put into a request to a host the user did not name); an upload
  of a file (`curl -d @data.json`, `aws s3 cp`) to a host the user did not name. The key named by `ssh -i`, `scp -i` or
  `-o IdentityFile=` only signs a login and is not a read of the key; a copy of a private key (`id_rsa.bak`, `id_ed25519~`) is
  the key, wherever it lies.
- Persistence and the guard: a write to a shell startup file, cron, a launchd or systemd unit, a git hook or a CI workflow
  (`.zshrc` and `.zshrc.local` ask; a copy that nothing runs, `.zshrc.bak`, `.bashrc.orig` or `.bashrc~`, does not);
  deleting or emptying a key or an access file; anything that changes the guard itself (below).
- Too big to read: a path, a command, a brace list or a loop past a limit (next sections).

**What the parser reads.** A command inside a one-line control structure (`if ...; then X; fi`,
`for ...; do X; done`, `while`, `{ X; }`, `! X`, `time`, a one-line function body) is read like the same command alone.
Inside one command line it follows `cd`, `pushd` and `popd` (`cd ~ && rm -rf Documents` deletes the home
directory's `Documents`), variables set earlier in that line (`RM=rm; $RM -rf /`, `for d in / b; do rm -rf "$d"; done`),
`$'...'` quoting and brace lists (`rm -rf {/,}`, `{rm,-rf,/}`). The directory a `cd` went to is not known across two calls.
The program behind a **wrapper** is the command that is judged, so a deny keeps its verdict in front of any of them. The wrappers
are the programs that run another program, read from the manual pages of coreutils (`env`, `nice`, `nohup`, `stdbuf`,
`timeout`, `chroot`), util-linux (`chrt`, `flock`, `ionice`, `nsenter`, `runuser`, `script`, `setarch`, `setpriv`, `setsid`,
`taskset`, `unshare`), the BSD and macOS base systems (`arch`, `caffeinate`, `lockf`, `sandbox-exec`, `xcrun`) and the usual
tools around them: `sudo`, `doas`, `pkexec`, `run0`, `su -c`, `sg`, `command`, `builtin`, `exec`, `time`, `watch`, `xargs`,
`parallel`, `busybox`, `toybox`, `strace`, `ltrace`, `valgrind`, `gdb --args`, `numactl`, `cpulimit`, `prlimit`, `systemd-run`,
`systemd-inhibit`, `fakeroot`, `proxychains`, `torsocks`, `faketime`, `xvfb-run`, `dbus-run-session`, `firejail`, `bwrap`,
`screen`, `sshpass`, `ssh-agent`, and the `run` or `exec` subcommand of `uv`, `poetry`, `pipenv`, `pdm`, `hatch`, `rye`, `conda`,
`bundle`, `direnv`, `mise`, `asdf`, `rbenv`, `pyenv`, `npm`, `pnpm` and `yarn`. An option that takes a value is skipped
(`flock -w 5 /tmp/l rm ...`, `taskset -c 0,1 ...`, `stdbuf -o L ...`, `bwrap --ro-bind / / ...`), a shell text a wrapper runs is read as
a command line (`flock f -c '...'`, `script -qc '...'`, `sudo -s ...`, `runuser -l u -c '...'`, `watch '...'`), and `ssh host ...`
is read as the command the remote shell runs (`ssh host 'rm -rf /'` is a deny). The command `find -exec`, `-execdir`, `-ok` and
`-okdir` run, and the one `fd -x` runs, is read like `xargs`'s (`find . -exec rm -rf / \;` is a deny; `{}` stands for the file
found). Container and cluster wrappers (`docker run`, `docker exec`, `kubectl exec`) are not read: what they run does not run on
this machine.
Spellings the shell reads as nothing are read as nothing: a line continuation (`rm \` and a new line before `-rf /`), a
tab, a form feed or vertical tab, `${IFS}` for a space, empty quotes or a backslash inside a word (`r''m`, `\rm`), a comment
after the command, `$@` or `$()` or `${X:-}` (empty where they stand), a default that is spelled out (`${RM:-rm} -rf /` is
`rm -rf /`), NUL bytes (bash ignores them in a script), and a long option cut short the way the program accepts it
(`git push --del origin main`, `git reset --har`, `rm --rec --fo ~`, `chmod --rec 000 /etc`, `sudo --us root rm -rf /`).
A `$(...)` inside a word does not end the command (`rm -rf $(pwd) /`). A glob made of glob characters alone at the root
or home (`/[a-z]*`, `/?`) is read as everything in it, and `echo / | xargs rm -rf` is read as `rm -rf /`. A `find` that
deletes only the files it names (`find ~ -name .DS_Store -delete`,
`find ~ -name '*.pyc' -delete`) is read like `rm` of those files and allowed under the home directory; asked at a
system directory.

**Limits on what is read.** The parser reads at most 50,000 characters, 400 commands, 20,000 words, 200 command substitutions
and three levels of nesting (`bash -c`, `eval`, `$(...)`), and reads through at most eight wrappers in front of a command
(`sudo sudo ... rm -rf /` with nine). A command that goes past any of them is **asked about, with the limit named**,
never allowed: a deny hidden after the limit cannot get through by padding the command. The same holds for the rest: a
path is read to 1,000 characters after repeated slashes and `/./` are collapsed (so `~/.ssh/./././id_rsa` padded to any
length is still the key), and a path that is still longer is asked about; a brace list of more than 300 characters, 16
alternatives, 64 words or four levels is asked about; a variable set by a `for` loop over more than 32 words is asked about
where it is used; a patch is read file by file whatever its size. After an injection, a script or `package.json` that
is written and holds more than 200,000 characters (500 strings for `package.json`) is asked about. A test lists every limit of
the three readers (`dangerous`, `shell`, `harness`) and puts a deny behind each, so that a new limit cannot be added without one.

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
reach the hook, which the harness starts, so it is not asked about (written into a shell startup file it is). A hook that
does start with such a setting in its environment (`INTENTSHIELD_HOOK_REVIEW=never`, `INTENTSHIELD_HOOK_TRANSLATE=off`,
`INTENTSHIELD_HOOK_DEADLINE=0`, `INTENTSHIELD_HOOK_SOURCED_READS=allow`, `INTENTSHIELD_THREAT_MEMORY=0`, or a moved
`INTENTSHIELD_HOOK_DB`, `INTENTSHIELD_THREAT_DB`, `INTENTSHIELD_THREAT_PACKS` or `INTENTSHIELD_HOOK_CATALOG`) says so on
stderr for every call, unless a flag on its command line takes the place of the variable.

**What it does not see.** A command built at run time from pieces (`$(printf ...)`, a variable set in an earlier
call or read from the environment), an interpreter script file and a language one-liner that wraps the real action are
not seen; neither is what a container, a cluster or a test runner runs (`docker run`, `kubectl exec`, `git rebase --exec`, a
`Makefile` target). **Which tools are covered.** Claude Code: `Bash` and `PowerShell` (shell commands; Claude Code's help lists both), `Monitor` (its input has a `command`, which is read as
a shell command; this rests on the tool's own schema, not on the vendor pages archived here), `WebFetch`, `Read`, `Grep`, `Write`, `Edit`,
`MultiEdit` and `NotebookEdit`. **PowerShell** gets the POSIX reading above (a native program such as `git`, `curl.exe` or
`dd`, and the POSIX aliases `rm`, `cat` and `curl`, are read as they are) and a reading of the cmdlets that correspond to the rules:
`Remove-Item` (`ri`, `rd`, `del`, `erase`) with `-Recurse` and `-Force` of a root, the home directory or a system directory, also
as `$HOME`, `$env:USERPROFILE`, `C:\`, `C:\Windows` and `C:\Users\name`; `Get-Content` (`gc`, `type`) of a credential file;
`Invoke-WebRequest` or `Invoke-RestMethod` (`iwr`, `irm`) that uploads a file with `-InFile` or from a pipe; a download run with
`Invoke-Expression` (`iex`), in a pipe or around it; and `pwsh -Command` or `-EncodedCommand`. Parameters may be cut short as
PowerShell accepts it (`-r`, `-fo`). Other cmdlets are **not read**: `Set-Content`, `Out-File` and `Copy-Item` to a startup file,
`Start-Process`, .NET calls such as `[IO.File]::Delete`, and scripts. A tool name that starts with `mcp__` but has no server or no
tool part is refused. Codex CLI: its shell tools (`shell`, `local_shell`, `exec_command`)
and `apply_patch`; a patch run through the shell tool (`apply_patch <<'PATCH' ...`) is read as the patch it is. Gemini CLI:
`run_shell_command`, `web_fetch`, `read_file`, `read_many_files`, `write_file`, `replace`, `search_file_content` and its
other search tools. Of the search tools only Grep (and Gemini CLI's `search_file_content`) is read, by its `path`: Glob, `LS`
and Gemini CLI's `list_directory` and `glob` return names, not file content, and are not matched. A tool with another name
that runs a command (a future tool, or one a plugin adds) is not matched either: the install's matcher names the tools it
sends to the hook. A built-in tool call whose
event name or tool input the hook cannot read (a missing or re-cased `hook_event_name`, a `command` that is not text) is
refused, because a changed event schema must not read as an allow.

What the study measured about them (`docs/research-notes/hook-fidelity/hook-fidelity-study.md` section 6e, rows in
`results/hook-fidelity/detect/fresh/`; the figures below are those of the rules before the stricter-verdict change above,
which turns 6 of the 41 asked harmful calls into denies, and one denied call (`git push -f origin HEAD`, an ask now
that `HEAD` may be a feature branch) into an ask, when the set is run again: 36 asked and 40 denied, the 28 let through
and the 5 benign asks unchanged): on a fresh set of 214 built-in shell, read, write and edit calls (104
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
   always|tainted|never` writes it into the hook command (the default is `tainted`: ask once an output tried to instruct the agent or
   a value came from an output), and the hook reads `INTENTSHIELD_HOOK_REVIEW` when the flag is absent. `always` asks about every
   state-changing call (a refusal on Codex and Gemini).

   `never` removes every ask, including the asks for values from tool outputs, for credentials the user did not give, for a judge's
   objection and for the dangerous-command rules; it keeps the denies (injected instructions in the arguments, a value from an
   injected output, a known attack, the dangerous-command denies). It is not a way to approve one call; use it only where a refusal
   costs more than the ask protects.

   Reads whose argument came from an output can be let through on their own with `INTENTSHIELD_HOOK_SOURCED_READS=allow` (or
   `--allow-sourced-reads` on the hook command; `install` has no flag for it) while writes still ask.
5. **Remove a layer.** Run `intentshield install <harness>` again without `--judge`, `--builtin-tools` or
   `--gemini-ask` to drop what caused the prompt. `intentshield uninstall <harness>` (add `--scope project` for the
   project's settings file) removes only IntentShield's hook entries and leaves every other setting; the file is
   deleted only when it held nothing else. `intentshield unwrap <mcp.json>` restores the servers `wrap` rewrote
   (`--server NAME` for one) and keeps their proxy configs and audit databases. All four commands accept
   `--dry-run` to print the result. Since 0.4.3, `install --no-translate` (or `INTENTSHIELD_HOOK_TRANSLATE=off`) goes
   back to the hook as it was before the verdict translation: no deadline, no fail-closed launcher, and asks sent
   as the harness table above lists them.

For the gateway and the transparent proxy the approval is a human decision through the control endpoint, see
[Human approval for mutations](gateway.md#human-approval-for-mutations). A tool the proxy hid because its description
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
settings can set these, and the other `INTENTSHIELD_HOOK_*` and `INTENTSHIELD_THREAT_*` variables
(`INTENTSHIELD_HOOK_REVIEW=never`, `INTENTSHIELD_HOOK_TRANSLATE=off`, `INTENTSHIELD_HOOK_DEADLINE=0`,
`INTENTSHIELD_HOOK_SOURCED_READS=allow`, `INTENTSHIELD_THREAT_MEMORY=0`, and the database, pack and catalog paths), for a
session. The hook names each one that loosens it on stderr. Do not set them for a repository you do not trust.

## Wrapping a third-party hook

Since 0.4.3, `intentshield wrap-hook` runs any hook command under the same fail-closed
launcher, deadline and version-keyed verdict translation that `install` writes for IntentShield's own hook. It
exists because the hook-fidelity study found that the harnesses let a call run when a hook crashes, is slow or
prints nothing, and that a guard's `ask` is dropped, run or hung on some builds
([study](research-notes/hook-fidelity/hook-fidelity-study.md), [mitigation](research-notes/hook-fidelity/hook-fidelity-mitigation.md)). The harness runs the shim in place
of the guard; the shim pipes the harness's event to the guard and sends the harness one reply in its own shape.

```sh
intentshield wrap-hook --harness claude|codex|gemini|cursor [--version X.Y.Z] [--mode interactive|headless|yolo] \
    [--deadline SECONDS] [--hook-timeout SECONDS] [--on-empty deny|allow] [--gemini-ask] [--print-entry] -- <guard command ...>
```

`--print-entry` prints the full entry to put in the harness's settings instead of running anything. The shim is named
by the absolute path of the `intentshield` program, as `install` writes it, because a harness started from the Dock or an IDE
may not have it on `PATH`. The guard may be given as one shell string or as separate arguments. Give `--hook-timeout` the same
number as the entry's own timeout setting. For Cursor, `install` relies on `"failClosed": true` in the hook entry and not on the
launcher below, so set that key on a Cursor entry as well.

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
| exit 0 with several verdicts (for example in `hookSpecificOutput` and at the top level, or `continue: false`) | the strictest: deny over ask over allow |
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

## Scan the servers you use

```sh
intentshield scan                  # every MCP config found; or name files: intentshield scan .mcp.json
intentshield scan --no-connect     # read the configs only; start no server
intentshield scan --format sarif   # for GitHub code scanning; also --format json
```

`scan` starts each server as its client would (with only the environment its config names plus basics such as `PATH` and `HOME`),
lists its tools without calling any, and checks them offline: poisoned descriptions, split instructions, self-disclosure
parameters, shadowed names, credentials written into a config, and tools that changed since the last scan. It exits 0 when no
error-level finding remains (also when no MCP config is found), 1 when one does, and 2 when a named file is missing or unreadable
or no server could be started or read. The full description and exit codes are in
[layers.md](layers.md#scan-the-mcp-servers-you-already-use).

## Troubleshooting

**`intentshield doctor`** checks every harness's user and project settings file, then the MCP configs it finds
(Claude Code, Cursor, Gemini CLI, Codex CLI and VS Code). For each file whose wrapped servers passed it prints an `ok` line that names
them: the proxy config exists and the server's command is found. The summary counts the problems, the warnings and the notes.
`--connect` also starts each wrapped server once through its proxy and lists its tools, which runs the server's code;
`--connect-project` adds the servers named by files in the working directory. A line is `ok`, `note`, `warn`, `FAIL` or `--` (no IntentShield hooks for that
harness); it exits 1 when any line is `FAIL`, and `note` and `warn` lines do not change the exit code. A `note` line is a measured
fact about your harness version (for example that a hook which prints nothing lets the call run) and needs no action; only
`FAIL` is a fault. A repeated line is printed and counted once. Apart from recording
each harness's version it only reads (and starts nothing unless you pass `--connect`). Messages from a run against a fresh install:

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
`wrap-hook`, `install`, `uninstall`, `doctor`, `demo` and `scan --no-connect` run (`doctor --connect` says it needs the full install). The proxy, `wrap`, the dashboard, `scan` with a
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

**A wrapped server does not see your shell's environment.** `wrap` starts each server through the proxy, which gives it the
variables the entry's `env` names plus basics such as `PATH` and `HOME`, not the rest of your environment (a proxy setting,
`AWS_*`, `SSH_AUTH_SOCK`, a token you exported). Name each variable the server needs in the entry's `env`; a literal value there
stays in the client's file and is passed on by name, and an empty value is not forwarded.

`wrap` skips an entry whose command line uses `${...}`, `$VAR` or `%VAR%` interpolation, because the client expands those only for
the program it starts: replace it with the value (or move it to `env`) and wrap again. `intentshield scan` starts servers with the
same reduced environment, so a server that needs a variable can fail to list its tools there, and the finding is `not_scanned`.
`scan` starts the servers of a config the repository chose only with `--connect-project`; a file you name on the command line is
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

- **Threat memory** (`threat_memory.py`, on by default). When the deterministic rules confirm an injection, the memory keeps what
  the attack used: the addresses, URLs, accounts and paths it named, their domain once an attacker rotates local parts across runs,
  word fingerprints of the injected sentences (also with the trigger phrases blanked, so rewording exactly what the rules look for
  does not hide the payload), and how often each server produced attacks. One SQLite file is shared by every proxy and hook process,
  so what one session caught, the next session knows.

  Only rule-confirmed text teaches it, never its own matches; values the user typed are never learned or held against them;
  fingerprints that a benign gate corpus would contain are rejected; learned entries expire after 30 days. A server with attacks in
  5 distinct runs within 7 days is hostile: its outputs are read as possibly injected (weak evidence, never on a call's arguments)
  until the operator approves a call to it or allowlists it.

  What it learned on its own only asks (`REVIEW_KNOWN_THREAT`, a hook "ask"); an entry the operator confirms, or one from an
  imported feed or a trusted pack, blocks (`BLOCK_KNOWN_THREAT`). The file defaults to `threats.db` next to the proxy or hook
  database (`threat_memory_path` in the proxy config, `--threats` or `INTENTSHIELD_THREAT_DB` for hooks); turn it off with
  `threat_memory: false` or `--no-threat-memory` / `INTENTSHIELD_THREAT_MEMORY=0`.
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

`benchmarks/adaptive_learning.py` (offline, deterministic) replays attack campaigns with mechanical rewordings: with the
attacker's infrastructure reused, the memory raised the catch rate from 0.67 to 1.00; with fresh addresses per attempt, from 0.67
to 0.93 (fingerprints alone); a family the rules miss went from 0.00 to 0.67 after hot-installing the baseline pack. It flagged
none of 1,756 benign paragraphs.

Read these as an upper bound: the attacks and the pack are self-authored, the rewordings are mechanical rather than an LLM's, and
a full rewrite leaves too little wording to recognize (`tests/test_adaptive_integration.py` shows both cases). The memory adds
about 5-25 ms to each hook process when small, and about 20 ms before a call and 40 ms after a result at its caps (5,000
indicators, 500 fingerprints).

Poisoning is bounded rather than prevented: an attacker can get a colleague's address learned, at review level; boilerplate after
an injection is not learned (fingerprints are anchored on the injected sentence, and a bare trigger's payload is learned only when
it names a destination).
