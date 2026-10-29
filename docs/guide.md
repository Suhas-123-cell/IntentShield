# Running IntentShield: gateway, proxy, hooks, settings and API

Moved from the README on 2026-10-29 so the README stays a short user guide. Section names and anchors are unchanged.

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
- Gemini-native function calling for the web proposal path (the optional LLM judge can also use Groq; see "LLM call judge")
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

## Run locally

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

Copy the template and add the Gemini key locally. Never commit `.env` or paste
the key into the dashboard:

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
  days. A server with attacks in 3 distinct runs within 7 days is hostile: its outputs are read as possibly
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
  `cryptography`). Every rule must pass the same backtracking and breadth checks as learned rules and
  must not match the benign gate corpus. A tampered or older pack is refused and the last good one stays
  loaded. Point the proxy's `threat_packs_dir` or the hook's `--packs` / `INTENTSHIELD_THREAT_PACKS` at
  a directory; `configs/threat-packs/baseline.json` is an example built from the replayed incidents.

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

## Production settings

| Variable | Purpose |
|---|---|
| `INTENTSHIELD_AGENT_TOKEN` | Bearer token required on the agent-facing `/mcp` endpoint (proxy mode over Streamable HTTP) and, in the web API, on proposing calls, reading runs, the tool list, metrics and security status (the operator token works there too; needs `INTENTSHIELD_CONTROL_TOKEN`). Required, like the control token, whenever `INTENTSHIELD_PROXY_CONFIG` is set; unset in the simulated mode leaves those routes open on loopback. |
| `INTENTSHIELD_CONTROL_TOKEN` | Bearer token for the human approval endpoint. |
| `INTENTSHIELD_RATE_LIMIT_PER_MIN` | Per-client request limit for the web API and, in proxy mode over Streamable HTTP, `/mcp` (default 120, `0` disables). In memory, per process. |
| `INTENTSHIELD_THREAT_DB`, `INTENTSHIELD_THREAT_MEMORY`, `INTENTSHIELD_THREAT_PACKS` | Hook threat memory file, on/off switch (default on) and threat pack directory. |
| `INTENTSHIELD_PACK_PINS`, `INTENTSHIELD_PACK_HMAC_KEY`, `INTENTSHIELD_PACK_ED25519_KEYS` | What a threat pack must verify against to load (see above). |
| `INTENTSHIELD_LOG_LEVEL` | JSON log level (default `INFO`). Decision lines carry run, tool, decision and reason codes, never arguments. |

`configs/policy.json` is validated strictly: unknown keys, a tool both allowed and prohibited, and catch-all destination patterns are rejected at startup.

## Real MCP proxy

IntentShield is an MCP server to the agent and an MCP client to the guarded
upstream server. The agent never receives a direct upstream connection.

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
agent-facing `/mcp` endpoint, which is bound to localhost in this MVP; set
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
endpoint is needed. This MVP deliberately refuses non-loopback downstream HTTP
bindings; place an authenticated TLS reverse proxy or a production MCP auth
layer in front before remote deployment. Remote upstream URLs must use HTTPS;
plain HTTP upstreams are accepted only on loopback. The stdio mode is useful for
read-only tools and embedded applications that provide their own trusted
approval UI.

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
    result hook, so it is off by default), or the LLM judge (`--judge` alone means the local
    `ollama:qwen2.5:7b`; `--judge groq` or `gemini[:model]` for a hosted one). With
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
  Built-in tools (shell, file edits) are left to the harness.
- **Transparent proxy** (`intentshield-mcp --transparent --config <file>`, stdio only)
  wraps each MCP server the harness launches. It shows the upstream's own tools, hides
  any whose description matches poisoning rules or that changed after connect (rug pull),
  removes self-disclosure parameters from schemas and flags injected results. A tool whose
  description changes after connect is hidden and refused for the rest of the session; it
  fails closed until restart. Hooks never see tool descriptions, so this layer covers what
  they cannot.

`intentshield install <harness>` writes the hook entries below into the harness's settings
file (`--scope project` for the current directory; `--review always` for a harness that
cannot ask); `intentshield uninstall <harness>` removes them. The same entries are in
`configs/harness/` for a manual install; they call `intentshield-hook` by name, so put the
install's `bin` on the harness's `PATH` or use absolute paths.

The per-harness table (hook config, argument rewriting, asking the user) is in the
[README](../README.md#what-each-layer-sees-and-stops).

The proxy layer needs no harness support at all: `intentshield wrap <file>` rewrites every stdio
server in an `mcpServers` file (Claude Code `.mcp.json`, Cursor `mcp.json`, Gemini CLI
`settings.json`, or any client with that layout) to launch the proxy in front of it, with one
generated config per server under `~/.intentshield/proxies/`; `intentshield unwrap <file>` restores
them. By hand, the entry looks like this:

```json
{"mcpServers": {"filesystem": {"command": "intentshield-mcp",
  "args": ["--transparent", "--config", "/absolute/path/to/transparent-filesystem.json"]}}}
```

Servers reached over HTTP (`"url"`) are not launched by the client, so `wrap` leaves them alone;
guard those with the [gateway](#real-mcp-proxy).

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
