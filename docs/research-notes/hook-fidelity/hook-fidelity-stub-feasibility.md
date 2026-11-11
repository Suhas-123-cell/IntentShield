# Hook-fidelity arm S: stub model endpoint, feasibility note

Status (round 3, 2026-11-01): the stub was built and unit-tested from source and docs, and **round 3 pointed Claude Code, Codex and Gemini CLI at
it and ran them**: the predictions below were tested (section 8 lists what held and what did not). Cursor has no stub. Where a section
below still says "prediction" or "unknown until the pilot", section 8 supersedes it. Nothing was run against a real model, a paid API or a real
account (Cursor's three launches used the user's free plan and hit the usage limit).

Files: `benchmarks/hook_fidelity/stub_model.py` (endpoint), `tests/test_hook_fidelity_stub.py` (37 tests, no harness
launched; the request shapes in them are written from source and docs, none was recorded from a live client). Protocol context: `docs/research-notes/hook-fidelity/hook-fidelity-study.md`, section "Arms".

Labels: DOC = vendor docs; SRC = vendor source read in this task (Codex `rust-v0.165.0`, Gemini CLI `v0.66.0` and the
installed 0.66.0 bundle); BLIND = closed source or not read, so a guess; PILOT = cannot be known without running.

## 1. What the stub is

One stdlib `http.server` process per run, bound to `127.0.0.1` on a random port (printed as one JSON line, also written to
`--port-file`). Its answer is a pure function of the request, so retries and side requests cannot desynchronise it:

| Request | Answer |
|---|---|
| offers no tools (title, summary, classifier calls) | text `stub ok` |
| carries a tool result (any API) | final text from the script, turn ends |
| otherwise, tools offered | exactly the one scripted tool call, with the run nonce in its arguments |

Wire formats served: Anthropic Messages (`POST .../v1/messages`, JSON and SSE, plus `count_tokens`), OpenAI Responses
(`POST .../responses`, SSE), Gemini `models/<m>:generateContent` / `:streamGenerateContent` (SSE with `alt=sse`, or a JSON
array without it) / `:countTokens`. There is deliberately **no Chat Completions route**: Codex 0.165 rejects
`wire_api = "chat"` at config load (SRC `model-provider-info/src/lib.rs:105,135`), so Responses is the only wire format
Codex can use with a custom provider.

The JSONL log has, per request: redacted headers (values of anything named like auth, key, token, secret, cookie, account
or user-id, or shaped like `sk-...`, `AIza...`, `Bearer ...`, become `<redacted len=N>`; `user-agent` and `anthropic-beta`
are kept as version evidence), the query with key-like parameters redacted, `model`, `stream`, **`offered_tools`** (the tool
names the harness exposed, namespaces flattened to `mcp__notes__search_notes` form), `scripted_tool_offered` (was the
scripted name among them), the decision, the call index, and **`tool_results`** (is_error and the first 300 characters of
what the harness sent back: a hook's block reason, or the command output). That last field is a second witness besides the
side-effect oracle: a deny shows up as a tool result that never ran the command, a hang as a call with no next request.
`--dump-dir` writes each request body (key-shaped strings scrubbed) for the pilot's "recorded shape" comparison.

Limits of the stub, all by design: the model never refuses, never emits malformed arguments, never retries after a tool
error, never plans a second tool call. It tests the harness's hook path, not model behaviour. A tool name the harness did
not offer is still emitted (and logged `scripted_tool_offered: false`) so the run shows up as INVALID instead of silently
becoming a text answer.

## 2. Wire names are not hook names

The script needs the name the *model* sees, which differs from the name a hook matcher sees. Cross-check
`benchmarks/hook_fidelity/configs.py::MATCHERS` against this table; `offered_tools` in the log settles any doubt.

| Harness | Shell (wire / hook) | File write | MCP `search_notes` on server `notes` |
|---|---|---|---|
| Claude Code | `Bash` / `Bash` (DOC) | `Write` / `Write` (DOC) | `mcp__notes__search_notes` both (DOC) |
| Codex 0.165 | `exec_command` with `cmd` / hook name `Bash` (SRC `core/src/tools/handlers/shell_spec.rs:89`, `hook_names.rs:36`) | freeform `custom_tool_call` `apply_patch` with a patch string, hook name `apply_patch` with matcher aliases `Write`, `Edit` (SRC `hook_names.rs:36-44`) | `{"type":"namespace","name":"mcp__notes__"}` containing function `search_notes`; the call carries `namespace` plus bare `name`; hook name `mcp__notes__search_notes` (SRC `codex-mcp/src/tools.rs:229`, `tools/src/responses_api.rs:54`) |
| Gemini CLI 0.66 | `run_shell_command` with `command` (SRC `tools/definitions/base-declarations.ts:56`) | `write_file` (SRC same file:61) | `mcp_notes_search_notes` (SRC `tools/mcp-tool.ts:30-49`) |

Codex's tool surface depends on the model's metadata, in three ways (SRC, rust-v0.165.0):

1. Shell: an unknown slug such as `stub-model` gets fallback metadata with `UnifiedExec`, hence `exec_command`
   (`models-manager/src/model_info.rs:98-106`); a bundled slug may select another shell tool type.
2. Write: the fallback sets `apply_patch_tool_type: None`, and the `apply_patch` handler is registered only when it is some
   (`spec_plan.rs:1425`), so with `stub-model` no `apply_patch` tool is offered at all. A scripted `custom_tool_call` for
   `apply_patch` would be a call to a tool the model never saw. Codex write cells need a bundled slug.
3. MCP: bundled slugs set `supports_search_tool: true` in `models.json`, which makes MCP tools `ToolExposure::Deferred`
   (`mcp_tool_exposure.rs:158`, `spec_plan.rs:266`): they are then not in `tools` at all until a `tool_search` round trip.
   The fallback has `supports_search_tool: false`, so `stub-model` offers MCP tools directly. The unknown-slug arm therefore
   tests a non-production MCP exposure, the same kind of caveat as Claude Code's `ENABLE_TOOL_SEARCH=false` below.

So the script's `by_api.openai` entry must be taken from a pilot log's `offered_tools`, not from this table alone, and the pilot
must log `offered_tools` for `stub-model` AND for one bundled slug. Codex write and MCP cells are labelled with the configuration
they actually cover; production-like exposure is not claimed until it is shown (including whether Codex dispatches a deferred
namespaced tool that `tool_search` never loaded).

Example script (the runner would generate it per run, with the real nonce):

```json
{"nonce": "<nonce>",
 "call": {"name": "Bash", "args": {"command": "touch ran-{nonce}.txt"}},
 "by_api": {"openai": {"name": "exec_command", "args": {"cmd": "touch ran-{nonce}.txt"}},
            "gemini": {"name": "run_shell_command", "args": {"command": "touch ran-{nonce}.txt"}}},
 "final_text": "stub done {nonce}"}
```

Start: `python -I benchmarks/hook_fidelity/stub_model.py --script s.json --log /abs/requests.jsonl --port-file /abs/port`
(`--max-calls` defaults to 1, so a re-sample after a block or a side request cannot run the scripted call twice; pass
`--max-calls 0` for unlimited. `--dump-dir` is off by default and only accepted under an `artifacts` directory or a temp
directory, because a request body carries the system prompt and any memory text; e-mail addresses and home paths are scrubbed
as well as key-shaped strings.)

Round-2 changes after the critique: the OpenAI body no longer carries `end_turn` (Codex 0.165 reads it at
`core/src/session/turn.rs:3239`, where `false` sets `needs_follow_up`, so an unblocked-then-blocked turn could have been
re-sampled and the scripted call issued again; I found no evidence that the public Responses API sends the field, and Codex
treats an absent value as none); the Anthropic stream has the `ping` event after `message_start` and the two cache usage fields
as 0; a `Transfer-Encoding: chunked` request body is decoded instead of read as empty; `call_index` is assigned under the lock
that counts calls; the listen backlog is 128 so a burst of side requests is not reset; a tool-less side call logs
`side_call_head`, the first 160 scrubbed characters of its system or last message, so the pilot can say what each one was.
Missing and still open: `request-id` response header on the Anthropic route, a real client accepting any of this.

## 3. Per harness: how to point it at the stub

In every case HOME (or the harness's own config-dir variable) is a fresh directory, the key is a made-up string, and the
URL is `http://127.0.0.1:<port>`. Blocking everything except loopback at the OS level is the only way to *prove* no
silent fallback; section 5 says what is needed.

### 3.1 Claude Code (closed source; DOC only; version here 2.1.316)

```
HOME=<fresh>  CLAUDE_CONFIG_DIR=<fresh>/claude
ANTHROPIC_BASE_URL=http://127.0.0.1:<port>
ANTHROPIC_API_KEY=sk-ant-stub-not-a-real-key
DISABLE_TELEMETRY=1  DISABLE_ERROR_REPORTING=1  DISABLE_AUTOUPDATER=1  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
ENABLE_TOOL_SEARCH=false
```

- `ANTHROPIC_BASE_URL` overrides the endpoint; `ANTHROPIC_API_KEY` is sent as `X-Api-Key` and, in `-p`, "is always used when
  present" (no approval prompt) (DOC, authentication and env-vars pages, fetched 2026-11-01). Precedence puts
  `ANTHROPIC_AUTH_TOKEN` above the API key and both above a stored login, so a stored subscription login is not used while
  the key is set. Do not set `ANTHROPIC_AUTH_TOKEN` as well: it changes which header the stub sees, not what is tested.
- `CLAUDE_CONFIG_DIR` moves settings, history and plugins, and on macOS the Keychain entry is keyed to that directory (DOC).
  `~/.config/anthropic` profiles are outside `CLAUDE_CONFIG_DIR` but are under the fresh HOME if HOME is overridden.
  **Gap in the current runner**: `configs.py::_claude` returns `isolated_home=False`, i.e. the real HOME. The stub arm should
  isolate (PILOT: confirm no user-level hooks, plugins or managed settings leak, by checking the first request's `tools` and
  the hook listing).
- Managed settings (an MDM profile or a machine-wide managed-settings file, if one exists on the host) are not relocated by
  HOME or `CLAUDE_CONFIG_DIR` (BLIND, from the docs' description of managed settings; not checked on this machine).
- Do not use `--bare`: the authentication page says bare mode does not read OAuth or profile credentials, and bare mode is
  documented as a faster-start mode; whether it runs hooks was not read (BLIND, PILOT).

What may change code path with a custom base URL (DOC unless noted):

- **MCP tool search.** `ENABLE_TOOL_SEARCH` unset "defers MCP tools, except in the cases that keep tool search off"; the
  env-vars page says a gateway can reject tool-search betas and links to a gateway section that was not read. In a default
  first-party session MCP tools are deferred (the model would call a search tool first), so the production hook path for an MCP
  tool may include a second, built-in tool call. With the stub, `ENABLE_TOOL_SEARCH=false` makes the MCP tool appear directly in
  `tools`. That is a deliberate difference from the default production path and must be stated for the MCP cells (PILOT: log
  `offered_tools` with the variable unset and set; if the unset case offers no `mcp__notes__*`, the stub arm covers the "tool
  search off" configuration only).
- Fine-grained tool streaming is "off by default on gateway connections"; gzip request compression is skipped through a proxy
  (the stub also decodes gzip, so either is fine). Remote Control is disabled for a non-Anthropic host (irrelevant to `-p`).
- API-key authentication versus a subscription login is a different auth mode. The docs do not say that permission or hook
  code branches on it; nothing in the public docs rules it out (BLIND). The protocol's validation arm M (real model) is the
  check, and it needs a subscription, so it needs an explicit go-ahead.
- Background model calls (a small-model call for titles or classification) go to the same base URL; the stub answers them with
  text because they offer no tools. Whether any of them expects structured output and fails soft is PILOT (the log's
  `text:no-tools-offered` rows list every such call).

Unknown until the pilot: the exact request sequence in `-p` (count of `/v1/messages` and `count_tokens` calls), whether
`-p` with a base URL and a fake key skips or adds a startup check, whether the SSE shape here (standard Messages events, tool
input delivered as one `input_json_delta`) is accepted without a `thinking` or `cache_*` usage field, and whether a pinned
2.1.x binary behaves like the current one.

### 3.2 Codex CLI 0.165 (SRC `rust-v0.165.0`; Responses API only)

`$CODEX_HOME/config.toml` (CODEX_HOME must exist, SRC `utils/home-dir/src/lib.rs:6-11`), run with
`STUB_API_KEY=stub-not-a-real-key` in the environment:

```toml
model = "stub-model"            # or a bundled slug; see below
model_provider = "stub"
approval_policy = "never"
check_for_update_on_startup = false
[analytics]
enabled = false
[feedback]
enabled = false
[model_providers.stub]
name = "stub"
base_url = "http://127.0.0.1:<port>/v1"     # the client appends "/responses" (SRC codex-client/src/provider.rs:55-62)
env_key = "STUB_API_KEY"
wire_api = "responses"
request_max_retries = 0
stream_max_retries = 0
```

(plus the existing `[mcp_servers.notes]` and `[[hooks.PreToolUse]]` blocks from `configs.py::_codex`, which currently names
`model_provider = "ollama"` and would be replaced). `env_key` is read from the named variable and `requires_openai_auth`
defaults to false, so no login is involved (SRC `model-provider-info/src/lib.rs:154,199-201`). Do not set `OPENAI_API_KEY` or
`CODEX_API_KEY`.

Wire format the stub implements (SRC): request `POST <base>/responses` with `Accept: text/event-stream`, body
`ResponsesApiRequest` (`codex-api/src/common.rs:279`); SSE events parsed by `process_responses_event`
(`codex-api/src/sse/responses.rs:346-520`): `response.output_item.done` carrying a `ResponseItem` is what delivers a tool call
(`function_call` with `arguments` as a JSON *string*, `call_id`, optional `namespace`; or `custom_tool_call` with `input`), and
`response.completed` must carry `response.id` and, if `usage` is present, integer `input_tokens`, `output_tokens`,
`total_tokens`. A stream that ends without `response.completed` is an error ("stream closed before response.completed").
Item ids must look like `<prefix>_<suffix>` (`protocol/src/response_item_id.rs`); the stub's do.

What may change code path with a custom provider (SRC unless noted):

- Request compression is zstd only for the ChatGPT backend with the OpenAI provider (`core/src/client.rs:1769-1777`), so a
  custom provider sends plain JSON. WebSocket transport is off unless `supports_websockets` is set (default false,
  `model-provider-info/src/lib.rs:202-204`), so the HTTP SSE path is used. Both differ from a logged-in user's transport.
  Hook dispatch sits downstream of response parsing, so the transport should not matter for the hook, but that is an inference.
- Model metadata: an unknown slug logs "Unknown model ... fallback model metadata" and uses `UnifiedExec`
  (`models-manager/src/model_info.rs:98-106`). The remote `/models` refresh runs only for the Codex backend, command auth or
  API-key discovery with a `model_catalog_url` (`models-manager/src/manager.rs:729-733`,
  `model-provider/src/models_endpoint.rs:235-237`), none of which applies here, so I expect no `/models` call. A bundled slug
  would give production-like tool metadata if the bundled catalog is used for a custom provider (PILOT: not established). Choose
  by comparing `offered_tools` of a stub run with a bundled slug against one with `stub-model`.
- Telemetry: analytics events go to the ChatGPT backend and the sender is gated on the auth manager's credential
  (`analytics/src/client.rs:960-975`); whether any event is sent for a custom provider with `env_key` was not established, so
  the config disables analytics and feedback and the pilot checks the network (PILOT). The update check is also disabled.
- Sandbox: Seatbelt/bwrap apply to spawned tool processes; the model request is made by the Codex process itself. I did not
  read the sandbox code to confirm the model call is outside it (PILOT: a stub run under `--sandbox workspace-write` is the test).
- Hooks need trust (DOC and SRC, see `vendor-semantics.md`): independent of the stub, but the stub arm must record the trust
  state in each row.

Unknown until the pilot: which shell tool a bundled slug exposes, what the hook payload's `tool_name`/`tool_input` look like for
`exec_command` (hook name `Bash`, but the field carrying the command was not read), whether `codex exec --json` prints tool-call
events usable as a third witness, and whether a second request without a tool result occurs after a hook failure (the stub
would then issue the call again, and `call_index` would show it).

### 3.3 Gemini CLI (SRC `v0.66.0`, plus the installed 0.66.0 bundle)

```
HOME=<fresh>  GEMINI_CLI_HOME=<fresh>          # homedir() prefers GEMINI_CLI_HOME (SRC core/src/utils/paths.ts:19-27)
GEMINI_API_KEY=stub-not-a-real-key
GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:<port>
```

`<fresh>/.gemini/settings.json` must keep `security.auth.selectedType = "gemini-api-key"` (as `configs.py::_gemini` does) and
should add `"privacy": {"usageStatisticsEnabled": false}`. The docs require HTTPS for the base URL "unless pointing to
`localhost` (or `127.0.0.1` / `[::1]`)" (DOC `docs/reference/configuration.md:2740-2747`; the code at
`contentGenerator.ts:133-139` only checks that it parses as a URL). The SDK builds `<base>/v1beta/models/<model>:streamGenerateContent?alt=sse`
(`GOOGLE_GENAI_API_VERSION` overrides the version segment); the stub matches on the `models/<m>:<verb>` suffix, so a version or
prefix segment does not matter. The installed bundle's SSE reader accepts `\n\n`, `\r\r` and `\r\n\r\n`
(`responseLineRE`), and the stub uses CRLF.

What may change code path with a custom base URL (SRC):

- **Auth mode.** If `selectedType` is not set, `getAuthTypeFromEnv()` returns `AuthType.GATEWAY` whenever
  `GOOGLE_GEMINI_BASE_URL` is set, before it considers `GEMINI_API_KEY` (`contentGenerator.ts:80-100`). `GATEWAY` differs from
  `USE_GEMINI` in model resolution (`createContentGenerator`, `resolveModel(..., authType === USE_GEMINI || USE_VERTEX_AI ||
  launched)`), in `getUseCustomToolModelSync` (true only for `USE_GEMINI`, `config.ts:3589`) and in how an empty key is sent. So
  `selectedType = "gemini-api-key"` is load-bearing for fidelity, and the pilot should log which authType the process reports.
- **Telemetry.** `privacy.usageStatisticsEnabled` defaults to true (SRC `settingsSchema.ts:970-976`) and also adds an
  `x-gemini-api-privileged-user-id` header (redacted in the stub log). Disable it; a loopback-only network proves nothing else leaves.
- **Version support.** `GOOGLE_GEMINI_BASE_URL` appears in `contentGenerator.ts` from 0.66.0 and HEAD but not in 0.37.1, where the
  only mention outside tests is the sandbox pass-through (`cli/src/utils/sandbox.ts:524`). The installed 0.66.0 bundle's
  `@google/genai` reads the variable itself (`getBaseUrl(..., getEnv("GOOGLE_GEMINI_BASE_URL"))`), so 0.37.1 may work through its SDK
  version; that is UNVERIFIED and the version sweep (0.37.1 vs 0.66.0) depends on it. Fallback for 0.37.1 or any version: the CLI has a
  hidden `--fake-responses <file>` flag backed by `FakeContentGenerator` (SRC `cli/src/config/config.ts:474-483`,
  `core/src/core/fakeContentGenerator.ts`), which replays recorded responses with no network. Hooks run in the scheduler above
  the content generator, so that path still exercises the hook code; it skips request construction and tool-declaration
  generation and needs a fixed response order. It is a vendor test hook, not a documented interface.
- Side calls: the CLI makes tool-less `generateContent` calls (classifier, next-speaker checks and similar). The stub answers
  plain text; for Gemini `classifierStrategy` and `checkNextSpeaker` catch a parse failure and fall through and `generateJson`
  retries on invalid JSON (SRC, checked in the round-2 critique), so the effect is extra tool-less requests, not a failure. For
  Claude Code the same side calls are an open risk (some could affect permission decisions in `-p`, for example a Bash command
  classification, independently of the hook): the pilot reads `side_call_head` of every `text:no-tools-offered` row and checks that
  the R0 outcome is unchanged by them.
- Model name: use a real model id with `-m`, not `stub-model`, so model resolution and availability checks take the normal
  branch; the stub ignores it. Whether an unknown id is accepted was not read.

Unknown until the pilot: whether `-p` issues requests other than `streamGenerateContent`; whether `-o json` output
is enough for attempt evidence (the stub log now supplies it independently, which resolves the build critique's "BLOCKED can
never be established for file-level Gemini cells" for any cell where the model request is made); and the 0.37.1 and HEAD
behaviour of everything above.

### 3.4 Cursor CLI: no stub

Closed source with a hosted backend; no documented base-URL override was found in the research round, so the stub does not
apply. Cursor stays real-model, one build, a dated case study (protocol, "Arms"). Not investigated further here.

## 4. How the stub arm differs from production, per harness

| | Claude Code | Codex | Gemini |
|---|---|---|---|
| Credential type | API key, not subscription login | custom-provider key, not ChatGPT login or OpenAI key | API key (if `selectedType` kept) |
| Transport | plain HTTP, gateway mode | HTTP SSE, no zstd, no WebSocket | plain HTTP |
| Tool set | `ENABLE_TOOL_SEARCH=false` makes MCP tool visible up front | unknown slug: shell is `exec_command`, no `apply_patch`, MCP tools offered directly; bundled slug: MCP tools deferred behind `tool_search` (SRC, section 3.2) | same tools as production expected |
| Hook code | unchanged as far as docs say (BLIND) | downstream of parsing (inference) | scheduler above the generator (SRC) |
| Model behaviour | none by design | none | none |

The protocol's rule stands: arm S cells are labelled "stub, scoped to this configuration", and a harness that fails its
phase-0 gate drops to "real model, pilot quality".

## 4b. Environment the runner gives every harness

HOME and the XDG and npm cache directories are the run's own; the environment is a small allowlist (PATH-like basics and names
given with `--pass-env`), host `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` are never passed and `NO_PROXY=127.0.0.1,localhost,::1` is
set (Gemini's `config.getProxy()` would otherwise route an http base URL through a host proxy). Isolating HOME is a precondition
of the stub arm and the runner refuses a run that is not isolated; `configs.py::_claude` now isolates it too (the earlier note
that it returned the real HOME is obsolete).

## 5. Network isolation (still not built)

A fake key against a real host would return 401 and fail loudly, but telemetry or an update check to a vendor host could
succeed or time out silently, and a stored login could be used if HOME leaked. The stub arm should run each harness under a
profile that allows only loopback: on macOS `sandbox-exec` with `(deny network*)` and `(allow network* (remote ip "localhost:*"))`
is the likely mechanism, but **I did not test that it works for these binaries** (Node and Rust programs, a Keychain lookup, the
DNS resolver) and `sandbox-exec` is deprecated. Cheaper partial check: record `lsof -i` / `nettop` for the process tree during the
pilot. Either way the stub log alone cannot show what did *not* go to the stub.

## 6. Phase-0 pilot checklist, per harness (no real model)

1. Start the stub with a script for the `R1` neutral hook plus the shell tool; point the harness as in section 3, isolated HOME.
2. Pass: the side-effect file exists (RAN) with no hook, and with the neutral hook R1; the stub log has a `tool_call` row with
   `scripted_tool_offered: true`, followed by a row with `tool_results` (the harness ran the tool and reported back).
3. Record: `offered_tools` for shell, write and MCP; the sequence of `kind`/`decision` per run; the first row's `user-agent`
   (version banner); the authType or login method the harness reports; every non-loopback connection seen.
4. Fail-closed check: a deny hook (R2) yields `tool_results` with the block reason and no file; the next request is the final-text
   answer, not a second call.
5. Compare the config banner and the tool list with a real-model run (arm M) before any matrix cell is called "validated".
6. Repeat the stub run twice; the two logs must agree row for row apart from timestamps, ports and hashes.

If step 2 fails for Claude Code or Gemini because the harness rejects the stub's SSE or JSON, the likely repairs are small
(missing usage fields, a `thinking` block, an `id` on a Gemini `functionCall`); capture the harness's stderr and the
`--dump-dir` request before changing the stub.

## 7. What was and was not verified here

- Verified by test (37 tests): stub behaviour for the three request shapes (including a plain-data contract of the fields the
  Codex, Gemini and Anthropic clients require, written from the sources read; the pilot's pass criterion is the real client
  accepting the stream, not this test), redaction of key-shaped headers, query and dumps (no fake key
  appears in the log or dump files), stdlib-only imports, loopback binding, the command line and the script validator.
- Verified by reading source: the Codex Responses request path, SSE event handling and `ResponseItem` shapes at `rust-v0.165.0`
  only (the stub's Codex shape was not re-read at HEAD); the Gemini CLI base-URL, auth-type and telemetry code at `v0.66.0`,
  with `v0.37.1` and HEAD compared for the base-URL line only; the installed 0.66.0 bundle's SSE regex and base-URL read.
- Verified by docs: Claude Code's `ANTHROPIC_BASE_URL`, key and token behaviour, auth precedence, `CLAUDE_CONFIG_DIR`, telemetry
  and `ENABLE_TOOL_SEARCH` rows (fetched 2026-11-01; the env-vars page is long and read in two passes through an extractor; the
  tool-search-through-a-gateway section was not read).
- Not verified: any harness accepting the stub's responses; Claude Code's wire shape beyond the public Messages format (no source);
  anything about Cursor; network isolation; whether any harness reaches a vendor host despite the overrides.


## 8. Round-3 outcome: what the harnesses did with the stub (measured; supersedes the predictions above)

Evidence: `results/hook-fidelity/claude/pilot/`, `.../codex/pilot.md`, `.../gemini/smoke/`, the three lanes' `runs.jsonl`; study section 3.

| harness | accepted the stub | held | did not hold |
|---|---|---|---|
| Claude Code 2.1.316 | yes, first try (10 of 10 pilot runs; 251 of 251 core runs: exactly 2 `POST /v1/messages`, 0 `count_tokens`, 0 side calls) | the PATH `touch` shim survives the Bash tool (4 of 4); `ENABLE_TOOL_SEARCH=false` puts the MCP tool in the request; fake key beats a stored login | `--tools ''` disables `ReadMcpResourceTool` (resource cells use `--tools ReadMcpResourceTool`); older releases send HEAD probes, a Warmup request (2.1.0, which consumed the scripted call: not interpretable) and up to 4 tool-less side calls (2.0.41) |
| Codex 0.131.0 to 0.166.0 | yes (428 of 428 matrix rows: one scripted call, two stub requests) | custom `model_providers` block with `wire_api = "responses"`; `stub-model` slug gets `exec_command`, no `apply_patch`, MCP offered directly | the shell tool is `exec_command` for the bundled slug (gpt-5.5) too, not `shell_command`; Codex runs `/bin/zsh -lc`, so the PATH shim is skipped and the scripted command calls the shim by absolute path; the MCP namespace is `mcp__notes` on 0.165 and 0.166 (and `mcp__probe__` on 0.131.0); a bundled slug defers the MCP tool but the scripted call is still dispatched and hooked; with default features Codex made startup requests to non-stub hosts (apps and plugins now off, a refusing proxy logs the rest); `--dangerously-bypass-hook-trust` has no effect in `codex exec` before 0.143 |
| Gemini CLI 0.24.5 to 0.66.0 | yes, `GOOGLE_GEMINI_BASE_URL` plus `selectedType = gemini-api-key` plus a fake key worked on all 28 releases including 0.37.1, so the `--fake-responses` fallback was never needed | Gemini runs `bash -c` (not a login shell): the shim works; `stream-json` carries `tool_use` with name and parameters | default approval does not offer the shell tool or untrusted MCP tools, so the stub's scripted call there is a registry effect, not a hook verdict |
| Cursor CLI | not applicable (closed hosted backend; `--endpoint` never tried) | | login is in the keychain; a fresh HOME is "Not logged in" |

The phase-0 agreement gate (arm M agreeing with the stub on R0, R1, R3 and R4) was **never run for any harness**, so every stub result is
labelled "stub arm, unvalidated against a real model".
