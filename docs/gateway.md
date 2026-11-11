# The gateway, dashboard and REST API

The gateway is the third way to run IntentShield: an MCP server that your agent calls through `intentshield_call`, with a
dashboard, an approval queue and a REST API. Most people want hooks and the transparent proxy instead; those are in
[guide.md](guide.md). This page covers the feature list, the gateway and its upstream servers, production settings, running
from a clone, the Gemini proposal path and the REST API. What each placement of the guard sees and stops is in
[layers.md](layers.md#what-each-layer-sees-and-stops).

## Contents

| If you want to | Read |
|---|---|
| see the list of features | [What is implemented](#what-is-implemented) |
| put the gateway in front of an MCP server | [Real MCP proxy](#real-mcp-proxy) |
| set tokens, rate limits and environment variables | [Production settings](#production-settings) |
| run the dashboard, the tests or the demo | [Run locally](#run-locally) |
| use the Gemini proposal path or the REST API | [Gemini model integration](#gemini-model-integration), [API](#api) |

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
[hooks plus the transparent proxy](guide.md#guard-an-agent-harness-claude-code-codex-cli-cursor-gemini-cli):
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

`read_only_tools` is a local trust decision. Every upstream tool not explicitly listed there is treated as a mutation and requires
idempotency plus human approval. Upstream descriptions and MCP annotations are never trusted to lower that classification. Raw
upstream descriptions are withheld by default; set `expose_upstream_descriptions` only for a server whose catalog you trust. Every
returned tool result is labeled `UNTRUSTED_MCP_OUTPUT` for downstream agents. `allowed_tools` defaults to an empty list, so each
deployment must deliberately allow exact names or scoped patterns such as `filesystem:read_*`.

All patterns and resource/destination rules must use qualified `server_id:tool_name` identities. Per-tool scope rules use
`resource_fields` with `allowed_resources_by_tool`, or `destination_fields` with `allowed_destinations_by_tool`; global scope
lists are rejected for MCP proxy configurations to prevent policy bleeding between servers. Every allowed tool must also have a
nonempty `grounding_terms_by_tool` entry containing the operator-owned nouns that must appear in the user's request, such as
`note`, `invoice`, or `status`. Startup fails if a discovered allowed tool has no such entry.

When wildcard allow rules are used, map every tool they can admit.

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
A token that only a `.env` found by searching held (a checkout's own) is ignored, and the web API and
`intentshield-mcp --transport streamable-http` refuse to start on it; export the variable or put it in `~/.intentshield/.env`. A stdio
proxy reads no token, so it starts either way (since 0.4.3).

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

Requires Python 3.11 or later.

```bash
uv sync --group dev
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
  `uv pip install --python .venv/bin/python -r requirements-ml.txt` from a clone. A plain `uv sync` removes it again. No trained model ships in the package.
- `--extra learning` (numpy) is needed for the exemplar detector and for learning from operator
  labels.
- The `dev` dependency group (pytest, numpy, the linters; not published with the package) is what CI installs: `uv sync --group dev --frozen`.

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
