# Hook fidelity study: how often do guard hooks run with no human present?

Status: measurement note for `docs/research-notes/hook-fidelity/hook-fidelity-study.md` (its section 10, threats to validity, cites the prevalence numbers).
The scripts that produced it are committed (`benchmarks/hook_fidelity/prevalence/`, read-only GitHub code search through `gh`), but they hard-code the scratch directory of the run, and the 378 MB of fetched file text and the list of the 36 repositories are not committed: **the numbers are not reproducible offline from this branch** (section 8). Data collected 2026-10-31, 18:58 to 20:41 UTC (code search) and 20:41 to about 21:30 UTC (file fetches).

## 1. What was measured, in one paragraph

Public GitHub code search was used to find workflow files that run a coding-agent harness unattended (the official
GitHub Actions for Claude Code, Codex and Gemini CLI, plus raw `claude -p`, `claude --print`, `codex exec`,
`gemini -p`, `gemini --prompt`, `cursor-agent -p` and `cursor-agent --print` calls). Every candidate file was downloaded
and re-checked with a regex, so the counts below are verified invocations, not search-engine totals. For each repo found,
the harness's project hook file at the default branch (`.claude/settings.json`, `.codex/hooks.json` or
`.codex/config.toml`, `.gemini/settings.json`, `.cursor/hooks.json`) was fetched and parsed. This gives the number of
public repos that both run an agent headlessly in a workflow and ship a project hook config. It is a measurement of
configuration co-occurrence in public repos. It does not show that any hook fired, or what any hook returned.

## 2. Headline numbers

Verified headless invocations in workflow files (union of all queries, 29,620 candidate files fetched, 28,661 verified):

| Harness and form | Workflow files | Repos | Repos with a project hook config (any event) | Repos with a pre-execution hook event |
|---|---|---|---|---|
| Claude Code via `anthropics/claude-code-action` | 22,613 | 15,676 | 1,984 (12.7%) | 1,071 (6.8%) |
| Claude Code via `claude -p` or `claude --print` | 2,200 | 1,453 | 215 (14.8%) | 122 (8.4%) |
| Claude Code, either form (union) | | 16,939 | 2,138 (12.6%) | 1,159 (6.8%) |
| Codex via `openai/codex-action` | 1,546 | 1,070 | 30 (2.8%) | 11 (1.0%) |
| Codex via `codex exec` | 384 | 318 | 12 (3.8%) | 4 (1.3%) |
| Codex, either form (union) | | 1,368 | 41 (3.0%) | 14 (1.0%) |
| Gemini CLI via `google-github-actions/run-gemini-cli` | 1,987 | 997 | 4 (0.4%) | 1 (0.1%) |
| Gemini CLI via `gemini -p` or `--prompt` | 78 | 56 | 0 | 0 |
| Gemini, either form (union) | | 1,044 | 4 (0.4%) | 1 (0.1%) |
| Cursor CLI via `cursor-agent -p` or `--print` | 121 | 60 | 5 (8.3%) | 4 (6.7%) |
| All four harnesses | 28,661 | 19,026 distinct | 2,188 | 1,178 |

Definitions:

- "Pre-execution hook event" means the config names an event that can return allow, ask or deny before a tool runs:
  `PreToolUse` (Claude, Codex), `BeforeTool` (Gemini), or `preToolUse`, `beforeShellExecution` or `beforeMCPExecution`
  (Cursor). It does not mean the hook is a security guard. Many are formatters, loggers or style checks (section 6).
- Percentages are shares of the enumerated headless repos in that row. They describe this index, not all of GitHub
  (section 7). No confidence intervals are given, because this is a census of what the search index returned, not a random
  sample.
- 19,026 is distinct repos. 319 repos use two of the four harnesses and 33 use three.
- The Claude rows include 428 workflow files named `*.lock.yml`. These are compiled GitHub Agentic Workflows files, a
  templated output format, and a few organisations account for many of them. Excluding repos whose only hits are
  `.lock.yml` files barely moves the Claude count (16,939 to 16,821).
- Concentration: 13,237 of the 19,026 repos (70%) have exactly one matching workflow file. 419 repos have five or more
  (2,990 files). The largest single repo has 55 files (`review-bench/github_gh-aw`, a mirror of the gh-aw project; I did not look further). Counting repos, not
  files, is therefore the right unit.

Inline hooks (hooks configured in the workflow YAML itself rather than a repo file, for example the action's `settings:`
input) are rare: workflow files containing hook-like text (a loose regex, so some are false positives) number 67 for the
Claude action (54 repos), 14 for `claude -p`, 4 for Codex and 0 for Gemini and Cursor. Search cross-check: `anthropics/claude-code-action PreToolUse path:.github/workflows`
returned 77 files.

### 2.1 Ask-capable guards, Claude only

A static scan of the 1,159 Claude repos with a `PreToolUse` hook (script text only, nothing was run):

| Question | Repos |
|---|---|
| Hook command points at a repo-local script that was fetched | 589 |
| Of those, script text contains an exit-2 block pattern | 359 |
| Of those, script text contains `permissionDecision` | 180 |
| Of those, script text sets `permissionDecision` to `"ask"` (tight regex) | 36 |
| Hook command is inline, a package (`npx ...`), a home-directory path or a script not found in the repo | 570 |

So at least 36 repos (0.2% of the 16,939 headless Claude repos, 3.1% of the 1,159 with a `PreToolUse` hook) run a headless
Claude workflow and ship a repo script that can return `ask`. This is a lower bound, because the 570 repos whose hooks
could not be read statically may also return `ask`. It is also a text match, not proof that the `ask` path is reachable.
Of the 36, the workflows mostly use `--allowedTools` (26), and a few use `--permission-mode` (4), `--setting-sources`
(2, which can exclude project settings), or `--dangerously-skip-permissions` (1). Nearly all (33) use
`claude-code-action`. The 36 repos are listed in the scratch data, not here. Most repo-local guards in this population
block with exit 2 and never use `ask` at all, so the headline question (what does a hook `ask` do with no human) bears on
a small slice of the public population by this count.

## 3. Does the action load project hooks at all?

Checked in source, not by running anything. `anthropics/claude-code-action` (main branch, fetched 2026-10-31),
`base-action/src/parse-sdk-options.ts` lines 338 to 345, sets `settingSources: ["user", "project", "local"]` unless the
workflow passes `--setting-sources`. So a repo's committed `.claude/settings.json` hooks are loaded by default in action
runs, and the action docs say its `settings` input accepts hooks (`docs/configuration.md`). I did not check the
equivalent for `openai/codex-action` or `run-gemini-cli`. For `codex exec`, the round 1 report found that untrusted
project hooks are silently skipped, so for Codex a hook config in the repo does not imply the hook runs.
Cursor documents that cloud agents run `.cursor/hooks.json` hooks, which is a further unattended path this study did not
count (section 7).

## 4. Search method, exact queries and tool limits

Tool: GitHub's REST code search (`GET /search/code`, legacy engine) through the local `gh` CLI, authenticated as the
user's own GitHub account, read-only. The firecrawl tools were not used to count: `firecrawl_search` is a web search, and
`firecrawl_research_search_github` searches issues, PRs and READMEs, not file contents, so neither can return
per-file code hits. Firecrawl web search was used only to check vendor docs (Cursor hooks and cloud agents, Claude Code
settings). No firecrawl results are counted anywhere in this note.

Limits of the engine that matter for the numbers:

- Only the first 1,000 results per query are retrievable. To get past the cap, each query was split by file size
  (`size:lo..hi`, adaptive halving over 0 to 400,000 bytes) until every shard had 1,000 results or fewer. No shard was
  truncated and no shard returned `incomplete_results: true`. 703 search requests were made for the enumerations.
- `total_count` is an estimate. The sum over shards disagreed with the unsharded total: 22,997 files against 22,912 for
  the Claude action (+0.4%), 2,043 against 1,184 for the Gemini action (+73%), 1,602 against 1,432 for the Codex action.
  Totals above 1,000 look quantised. Unsharded totals are therefore reported as returned, never used as counts.
- Unscoped phrase counts are meaningless: `"claude -p"` returned 348,160, `"codex exec"` 316,416, `"gemini -p"`
  17,632, `"cursor-agent -p"` 4,656. The engine tokenises the phrase, so flags and short words match anywhere. Only the
  path-scoped queries with regex re-verification were used.
- Phrase queries have low precision, which is why every candidate was downloaded and re-checked (table below).
  `"codex exec"` kept only 53% of candidates. Action-name queries kept 97 to 98%.
- Index scope: GitHub documents that code search covers the default branch only, skips very large files and repos, and
  does not index most forks. Fork hits were 0 in every result. The index is not the whole of GitHub, and its coverage is
  unknown. The search can also lag recent pushes.
- Recall: the queries do not cover SDK use (the Claude Agent SDK, `codex` or `gemini` called from Python or Node),
  wrapper scripts called from a workflow (`./scripts/run-claude.sh`), composite or reusable actions defined elsewhere,
  aliases (`agent -p`), `npx`, `bunx` or `docker run` forms, or CI systems other than GitHub Actions.

Queries (all path-scoped to `.github/workflows`; run 2026-10-31 UTC; `total_count` is the unsharded estimate):

| Name | Query | Window (UTC) | Reported total | Candidates | Regex-verified files (share) | Verified repos | Requests |
|---|---|---|---|---|---|---|---|
| h_cc_action | `anthropics/claude-code-action path:.github/workflows` | 20:04-20:41 | 22,912 | 22,997 | 22,596 (98%) | 15,664 | 266 |
| h_cc_p | `"claude -p" path:.github/workflows` | 19:05-19:09 | 1,672 | 1,846 | 1,528 (83%) | 1,139 | 29 |
| h_cc_print | `"claude --print" path:.github/workflows` | 19:04-19:05 | 708 | 675 | 657 (97%) | 306 | 8 |
| h_codex_exec | `"codex exec" path:.github/workflows` | 19:09-19:10 | 747 | 705 | 375 (53%) | 310 | 8 |
| h_codex_action | `openai/codex-action path:.github/workflows` | 19:10-19:14 | 1,432 | 1,602 | 1,546 (97%) | 1,070 | 30 |
| h_gem_action | `google-github-actions/run-gemini-cli path:.github/workflows` | 19:14-19:18 | 1,184 | 2,043 | 1,987 (97%) | 997 | 34 |
| h_gem_p | `"gemini -p" path:.github/workflows` | 19:18-19:19 | 78 | 78 | 70 (90%) | 49 | 1 |
| h_gem_prompt | `"gemini --prompt" path:.github/workflows` | 19:19 | 8 | 8 | 4 (50%) | 4 | 1 |
| h_cur_p | `"cursor-agent -p" path:.github/workflows` | 19:19 | 112 | 114 | 110 (96%) | 54 | 2 |
| h_cur_print | `"cursor-agent --print" path:.github/workflows` | 19:19 | 11 | 11 | 10 (91%) | 5 | 1 |

The union table in section 2 is larger than any single row's "verified" column because a file found by one query is
re-classified for every pattern it contains (for example a workflow found by the `codex exec` query that also uses the
Claude action). Cursor has no official GitHub Action that I found, so only CLI forms were searched.

Hook-config queries (the search side; used as a cross-check, not as the main numerator):

| Query | Reported total | Enumerated files | Repos |
|---|---|---|---|
| `path:.claude filename:settings.json PreToolUse` | 22,240 | 22,569 | 22,316 |
| `path:.codex filename:hooks.json PreToolUse` | 2,556 | 2,819 | 2,781 |
| `path:.codex filename:config.toml PreToolUse` | 164 | 187 | 187 |
| `path:.gemini filename:settings.json BeforeTool` | 319 | 400 | 396 |
| `path:.cursor filename:hooks.json beforeShellExecution` | 699 | 700 | 699 |
| `path:.cursor filename:hooks.json preToolUse` | 682 | 700 | 697 |
| `path:.cursor filename:hooks.json beforeMCPExecution` | 148 | 194 | 193 |

The intersection was computed two ways. Method A (main): fetch the hook config of every headless repo from
`raw.githubusercontent.com/<repo>/HEAD/<path>`, 20,779 fetches, 0 errors, 404 meaning "no file". Method B (cross-check):
intersect the enumerated headless repos with the enumerated search-side hook-config repos (root-path files only).
Method B gave 1,028 Claude, 14 Codex, 1 Gemini and 4 Cursor repos, against 1,159, 14, 1 and 4 from method A. Method B is
lower for Claude because the code-search index does not contain every file. Method A is the one reported.

Other co-location queries (counts only, 2026-10-31 19:02 to 19:04 UTC):
`"claude -p" PreToolUse path:.github/workflows` 16; `"codex exec" hooks path:.github/workflows` 131;
`openai/codex-action hooks path:.github/workflows` 162; `anthropics/claude-code-action hooks path:.github/workflows`
1,038 (the word "hooks" matches unrelated text); `google-github-actions/run-gemini-cli BeforeTool path:.github/workflows` 0;
`cursor-agent hooks.json path:.github/workflows` 5; `path:.github/workflows extension:yml` 8,306,688 (all workflow files,
for scale; the engine's estimate).

## 5. Hand-checked sample of 20

Selection: seeded random draw (seed 20261031) from the verified headless repos. 12 are random from repos with no
pre-execution hook (4 Claude action, 3 `claude -p`, 2 Codex action, 1 `codex exec`, 1 Gemini action, 1 Cursor).
8 are random from the repos that have a pre-execution hook config (3 Claude action, 2 `claude -p`, and one each for
Codex action, Gemini action and Cursor), because hook-bearing repos are rare and a plain random draw would show almost
none. This is a stratified illustration, not a basis for rates. For each I read the workflow's trigger, the invocation,
its permission flags and the hook config, and looked up repo metadata and the workflow's run history through the GitHub API
(run counts are as of 2026-10-31 and can be lower than history if runs were deleted). I did not read every line of each
workflow, and I did not read the hook scripts except where noted.

| # | Repo and file | Stratum | What it does | Hook config at HEAD | Runs (total, latest) |
|---|---|---|---|---|---|
| 1 | bajenlelle/sc-desktop `claude-fix.yml` | random, Claude action | On issue events and comments, Claude proposes a fix (`--allowedTools` set). | SessionStart only (installs dependencies); no pre-execution hook | 366, 2026-10-30 |
| 2 | WilliamZhang20/protocol-emulator-compiler `claude.yml` | random, Claude action | The stock `@claude` mention workflow (issue and PR comment events), no flags. | none | 2, 2026-10-16 |
| 3 | shuchi111/trade-testing `pr-review.yml` | random, Claude action | PR review on `pull_request`, restricted by `--allowedTools`, long prompt. | none | 26, 2026-07-24 |
| 4 | rube-de/tickticksync `claude-code-review.yml` | random, Claude action | PR review via the `/code-review` plugin command with `--comment`, SHA-pinned action. | none | 24, 2026-03-12 |
| 5 | jdh313/jdh-agents `plugin-review.yml` | random, `claude -p` | Weekly schedule; Claude searches the web for plugin best practices and reviews the repo's plugins. | none | 43, 2026-10-26 |
| 6 | IngRetrius/daily-dot `daily-dot.yml` | random, `claude -p` | Scheduled; `claude -p "."` with `--max-turns 1`, `--disallowedTools`, run from `/tmp` with its own `CLAUDE_CONFIG_DIR`, so repo settings are deliberately not in play. | none | 196, 2026-10-31 |
| 7 | qburst-tikson/ai-flutter-sample `ai-qa.yml` | random, `claude -p` | On push to a branch; Claude follows a QA prompt file with read tools, `Write` and read-only `git` Bash patterns, 30 turns. | none | 4, 2026-10-22 |
| 8 | DesenvolvedoresLEGAL/noidcrm `noid-code-health-audit.yml` | random, Codex action | Scheduled read-only code-health audit that opens issues. | none | 189, 2026-10-31 |
| 9 | codemod/codex-review-action `fork-review.yml` | random, Codex action | A 26 KB reusable workflow (`workflow_call`) wrapping the action to review fork PRs, with an authorisation step. A library, not an end deployment. | none | 0 |
| 10 | blaineg04/EllenG-Cup `elleng-local-codex-pilot.yml` | random, `codex exec` | On push or dispatch, `codex exec --sandbox workspace-write` reads a task file and uploads a patch artifact. A pilot. | none | 4, 2026-10-27 |
| 11 | gahojin/refresh-versions-plugin `gemini-review.yml` | random, Gemini action | PR review through the action's `/pr-code-review` command. | none | 12, 2026-10-21 |
| 12 | Miyamura80/LLM-Boardgames `cursor_fix_ci_failures.yml` | random, Cursor | After a failed CI run, `cursor-agent -p ... --force` is asked to fix it. | none | 0 (repo last pushed 2026-09-22) |
| 13 | aelsheikh-reno/opsmind `claude-fix.yml` | hook-bearing, Claude action | After a failing run, Claude proposes a fix. | PreToolUse: Bash to `guard-bash.sh`, Write or Edit to `guard-write.sh`; both scripts block with exit 2 and do not emit `permissionDecision` | 203, 2026-08-22 |
| 14 | Pankaj809/local-ai-company-registration `translate-i18n-claude.yml` | hook-bearing, Claude action | Dispatch-triggered translation of i18n files, 120 turns, `--allowedTools`. | PreToolUse on Bash runs `npx -y block-no-verify@1.1.1`, a third-party package fetched at run time | 0 |
| 15 | Coltosaur/Core-War-Reimagined `claude.yml` | hook-bearing, Claude action | Stock `@claude` mention workflow. | PreToolUse on Read, Edit, Write, NotebookEdit, Grep and Bash runs `protect-env.py` through a wrapper that exits 2 if the script is missing or not executable, so the author hand-built fail-closed handling | 279, 2026-10-29 |
| 16 | abdul-qadirdeveloper/mdibook `ci.yml` | hook-bearing, `claude -p` | On PR and push, Claude summarises a failed CI log in three lines (`--max-turns 3`, `--allowedTools`). | Five PreToolUse gates (spec, protected paths, PII in logs, test edits, production); the five scripts block with exit 2, none emits `permissionDecision` | 30, 2026-10-19 |
| 17 | SocketDev/socket-btm `get-green.lock.yml` | hook-bearing, `claude -p` | A 117 KB compiled `gh-aw` workflow (`--permission-mode acceptEdits`) that tries to get CI green. | PreToolUse with matcher `.*` runs an org-wide "fleet" hook (`index.cjs`); script not read | 0 |
| 18 | NiraiHayakawa/webapp-blueprint `pr-review-codex.yml` | hook-bearing, Codex action | PR review comments. | `.codex/hooks.json` PreToolUse on `mcp__ramune__*`, `apply_diff`, `write_file`, via an inline `node -e` that imports the repo's own adapter; script not read | 10, 2026-08-29 |
| 19 | alexanderdfree/Fantasy_Football_ML_AWS `gemini-invoke.yml` | hook-bearing, Gemini action | A reusable workflow (`workflow_call`) that invokes Gemini on request. | `.gemini/settings.json` BeforeTool: a path guard on write tools and a pre-PR gate on shell tools (600 s timeout); scripts not read | 0 for this file |
| 20 | streamlit/streamlit `ai-fix-flaky-e2e-tests.yml` | hook-bearing, Cursor | Scheduled; `cursor-agent -p "$PROMPT" --force` fixes flaky end-to-end tests (46k stars). | `.cursor/hooks.json` beforeShellExecution entries of type `prompt` (policy text judged by a model), not a script that returns a verdict | 37, 2026-10-30 |

What the sample shows, and its limits:

- 15 of 20 workflows have at least one recorded run, and 11 ran in the 30 days before collection. Of the 5 with no
  runs, 2 are reusable `workflow_call` libraries (#9, #19) and 3 have no recorded run (#12, #14, #17). Four more last
  ran before October (#3, #4, #13, #18). So a workflow match is not evidence of unattended execution in the last month:
  9 of these 20 had no run in that window. The sample is too small to turn that into a rate.
- Triggers are a mix: scheduled (4), comment or issue events from a person who is not watching the run (3), PR events,
  push, `workflow_run` and manual dispatch. A scheduled run (#5, #6, #8, #20) has no human at all. A comment-triggered
  run has a person who started it but nobody answering a permission prompt.
- 14 of 20 repos have 0 stars; the one large project is #20. The index is dominated by small repos.
- I read the hook scripts for #13 and #16 only: they block with exit 2 and never emit `permissionDecision`. #15's
  wrapper is visible in its settings file (fail-closed on a missing script) but I did not read `protect-env.py`. #14 uses
  a third-party package whose source I did not read. #20's hooks are Cursor `prompt` hooks, a different mechanism from a
  script verdict. So none of the sampled hook-bearing repos is known to exercise the study's headline case (an `ask`
  with no human).
- #6 shows a pattern that matters for interpreting counts: a workflow can run `claude -p` but outside the repo and with
  a separate config directory, so the repo's hook file never applies. Counting co-occurrence overstates exposure in such
  cases. I did not measure how common that is; it needs a check of `cd`, `CLAUDE_CONFIG_DIR`, `--setting-sources` and
  `--settings` across the full set.

## 6. What the pre-execution hooks mostly are

The event counts across headless Claude repos with any hook config (n = 2,138): PreToolUse 1,159, PostToolUse 1,148,
SessionStart 864, Stop 592, UserPromptSubmit 221, PreCompact 117, SessionEnd 101, SubagentStop 93. Codex (n = 41): Stop 23,
PostToolUse 18, SessionStart 18, PreToolUse 14. Cursor (n = 5): beforeShellExecution 4, afterFileEdit 5, stop 4. The
sample in section 5 suggests many `PreToolUse` hooks are project hygiene (protect `.env`, block `--no-verify`, enforce a
build tool) rather than security guards, and most block with exit 2 rather than returning `ask`. I did not classify all
1,159.

## 7. What these numbers can and cannot show

Can show:

- Headless agent runs in public workflows are common and not a corner case. About 17,000 public repos in the index run
  Claude Code in a workflow, about 1,400 run Codex, about 1,000 run Gemini CLI and about 60 run the Cursor CLI.
- A non-trivial minority of the Claude repos (about 1 in 15) commit a pre-execution hook config, so hook verdicts do
  reach unattended runs in practice, at least in configuration. For Codex, Gemini and Cursor the co-occurrence is small
  (14, 1 and 4 repos), too small to say anything beyond "it exists".
- `ask` returned by a repo-local script is rare in this population: at least 36 Claude repos, out of 1,159 with a
  pre-execution hook.
- The Codex/Gemini/Cursor figures are small in absolute terms, which also means "nobody notices if fidelity is broken
  there" is not something these data can contradict.

Cannot show:

- That a hook fired, was trusted, or returned any verdict in any run. Config presence is not execution. Codex in
  particular skips untrusted project hooks in `exec`, and Claude runs can pass `--setting-sources` or run from a
  different directory.
- Real-world prevalence on GitHub as a whole. The index is partial and of unknown coverage, skews towards small repos
  (70% of repos have one matching file; most sampled repos have 0 stars), and counts template copies and abandoned
  repos as deployments. A match is an upper bound on deployment and, for many repos, on use.
- The larger population that this study cannot see at all: unattended runs on developer machines or servers via
  scripts, cron, the Agent SDK or `claude -p` in a shell, where user-level, managed or plugin hooks apply; other CI
  systems; private repos; Claude Code on the web and Cursor cloud agents, which run hooks without a person at the
  prompt. Third-party guards are normally installed at user level (`~/.claude/settings.json` and equivalents), and a
  CI runner has no user-level settings. So repo-level counts say little about where installed third-party guards run
  headlessly. This is the largest gap, and it points the other way from the repo counts: the repo counts may understate the
  population that matters most for the headline question.
- Rates over time. Everything is a snapshot of one day, and no query was repeated to measure the engine's run-to-run
  variance (the two unsharded totals I did see twice, 22,912 and 1,672, matched an hour apart).
- Anything about vendor behaviour. This note does not measure enforcement; the harness cells in
  `docs/research-notes/hook-fidelity/hook-fidelity-study.md` do.
- Hook-config snapshot skew: workflow files are read at the commit the index holds; hook files at the default branch
  head on 2026-10-31. A repo can have changed in between, or a workflow may check out another ref.

How to cite it safely: "Of the public GitHub repos that GitHub code search returned for `anthropics/claude-code-action`,
`claude -p` or `claude --print` in workflow files on 2026-10-31 (16,939 repos), 1,159 (6.8%) also committed a
`.claude/settings.json` with a `PreToolUse` hook; at least 36 had a repo-local hook script that can return `ask`.
These are configuration counts in a partial index, not execution counts."

## 8. Reproduction

The scripts are committed under `benchmarks/hook_fidelity/prevalence/` (11 scripts and 2 specs) but read and write the session scratchpad paths below, and the raw data is not committed, so the counts cannot be regenerated from the branch alone. In the scratchpad:
`.../scratchpad/prev_scripts/` (`cs2.py` sharded search, `fetch.py` file download, `analyze.py` classifier and regexes,
`hookcheck.py` hook-config fetch, `final.py` aggregates, `scripts.py` static hook-script scan, `sub.py` per-pattern rates,
`sample.py` the seeded sample) and `.../scratchpad/prev_data/` (per-query JSON with every enumerated hit and its
`html_url`, `hookcache.json`, `script_rows.json`, `sample_sel.json`, `sample_digest.txt`). The regexes are in
`analyze.py`; they look for the invocation on a single logical line (backslash continuations joined, comment lines
dropped), so a command split in other ways is missed. All downloaded text was treated as data and never executed. If
this should become part of the study, move the scripts under `benchmarks/hook_fidelity/` and add a small test for the
regexes.

Compute and access notes: 703 code-search requests and roughly 52,000 raw-file GETs, all read-only, under the user's own
`gh` login for search. No claude, codex,
cursor-agent or gemini process was started, and no model API was called.
