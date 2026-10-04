"""Agent-facing Model Context Protocol server for IntentShield.

This module intentionally exposes a small set of *gateway* tools instead of
publishing an upstream server's tools directly.  An MCP client first creates a
run bound to a user intent, then proposes calls through ``intentshield_call``.
Only the policy service is allowed to reach an executor.

Approval decisions are deliberately not exposed as MCP tools. A model that can
approve its own request would collapse the human authorization boundary. In
Streamable HTTP mode an optional bearer-protected control endpoint is available
to a trusted operator; MCP clients may only inspect approval status.

The optional MCP dependency is imported lazily enough that the rest of the
IntentShield package remains usable without it.  Calling ``create_mcp_server``
without the dependency installed produces an actionable error.
"""

from __future__ import annotations

import argparse
from contextlib import asynccontextmanager
import hmac
import os
from pathlib import Path
from typing import Any, Literal, Protocol

# pyrefly: ignore [missing-import]
from dotenv import load_dotenv
from pydantic import ValidationError

from .models import GatewayResult, ToolCall
from .ratelimit import RateLimiter
from .service import IntentShieldService

try:  # Keep the core gateway importable when the optional MCP SDK is absent.
    from mcp.server import MCPServer
except ImportError as exc:  # pragma: no cover - depends on the installed extras
    MCPServer = None  # type: ignore[assignment,misc]
    _MCP_IMPORT_ERROR: ImportError | None = exc
else:
    _MCP_IMPORT_ERROR = None


class GatewayService(Protocol):
    """Narrow interface consumed by the MCP facade.

    Keeping this protocol smaller than ``IntentShieldService`` makes it
    possible to wire a registry backed by remote MCP executors without making
    the transport layer depend on a concrete upstream-client implementation.
    """

    storage: Any

    def create_run(self, user_intent: str, scenario: str | None = None) -> str: ...

    def evaluate_and_execute(
        self, run_id: str, user_intent: str, call: ToolCall
    ) -> GatewayResult: ...

    def evaluate_only(self, run_id: str, call: ToolCall) -> GatewayResult: ...

    def tool_catalog(self) -> list[dict[str, Any]]: ...


class IntentShieldMCPFacade:
    """Transport-independent operations registered as MCP tools."""

    def __init__(self, service: GatewayService) -> None:
        self.service = service

    def create_run(self, user_intent: str) -> dict[str, Any]:
        """Create a run whose persisted user intent is immutable."""
        normalized = user_intent.strip()
        if not normalized:
            raise ValueError("user_intent must not be empty")
        if len(normalized) > 2_000:
            raise ValueError("user_intent must be at most 2000 characters")
        run_id = self.service.create_run(normalized)
        return {
            "run_id": run_id,
            "user_intent": normalized,
            "status": "RUNNING",
            "next": "Call intentshield_list_tools, then intentshield_call with the exact schema_hash.",
        }

    def list_tools(self) -> dict[str, Any]:
        """Return the policy-visible catalog and exact schema bindings."""
        tools = self.service.tool_catalog()
        return {
            "tools": tools,
            "count": len(tools),
            "notice": (
                "Use the exact schema_hash returned here. A changed or missing hash is denied "
                "as schema drift. Tools are not reachable except through intentshield_call."
            ),
        }

    def call(
        self,
        run_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        schema_hash: str,
        idempotency_key: str | None = None,
        approval_id: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Evaluate a proposed tool call and execute it only when allowed."""
        if not run_id.strip():
            raise ValueError("run_id must not be empty")
        if not tool_name.strip():
            raise ValueError("tool_name must not be empty")
        if not schema_hash.strip():
            raise ValueError("schema_hash must not be empty")

        try:
            call = ToolCall(
                tool_name=tool_name,
                arguments=arguments,
                schema_hash=schema_hash,
                idempotency_key=idempotency_key,
                approval_id=approval_id,
            )
        except ValidationError as exc:
            raise ValueError(f"Invalid guarded call: {exc}") from exc

        # The service reads the persisted intent as authoritative.  Passing an
        # empty value here prevents this protocol surface from introducing a
        # second, caller-controlled intent channel.
        try:
            result = (
                self.service.evaluate_only(run_id, call)
                if dry_run
                else self.service.evaluate_and_execute(run_id, "", call)
            )
        except KeyError as exc:
            raise ValueError(f"Unknown run: {run_id}") from exc
        return result.model_dump(mode="json")

    def get_run(self, run_id: str) -> dict[str, Any]:
        """Return run state without replaying untrusted tool-result content."""
        run = self.service.storage.get_run(run_id)
        if not run:
            raise ValueError(f"Unknown run: {run_id}")
        return {
            "run_id": run["id"],
            "status": run["status"],
            "call_count": run["call_count"],
            "created_at": run["created_at"],
            "completed_at": run["completed_at"],
        }

    def get_approval(self, approval_id: str) -> dict[str, Any]:
        """Inspect a pending/decided approval without granting authority."""
        approval = self.service.storage.get_approval(approval_id)
        if not approval:
            raise ValueError(f"Unknown approval: {approval_id}")
        return {
            "approval_id": approval["id"],
            "run_id": approval["run_id"],
            "tool_name": approval["tool_name"],
            "status": approval["status"],
            "expires_at": approval["expires_at"],
            "notice": "Approval decisions must be made through the trusted human control plane.",
        }


def _require_mcp() -> Any:
    if MCPServer is None:
        raise RuntimeError(
            "The MCP SDK is required for this server. Install the project's MCP dependency "
            "or run `python -m pip install mcp`."
        ) from _MCP_IMPORT_ERROR
    return MCPServer


def create_mcp_server(
    service: GatewayService | None = None,
    *,
    database_path: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8001,
    streamable_http_path: str = "/mcp",
) -> Any:
    """Build the real MCP server used by stdio or Streamable HTTP clients.

    A caller that supplies a custom service can back its ``ToolSpec`` executors
    with upstream MCP clients.  This module only knows the narrow gateway
    interface above; it never offers an upstream bypass.
    """
    if service is not None and database_path is not None:
        raise ValueError("Pass either service or database_path, not both")
    if not (1 <= port <= 65_535):
        raise ValueError("port must be between 1 and 65535")
    if not streamable_http_path.startswith("/"):
        raise ValueError("streamable_http_path must start with '/'")

    mcp_server = _require_mcp()
    gateway = service or IntentShieldService.default(
        database_path or os.getenv("INTENTSHIELD_DB", "intentshield.db")
    )
    facade = IntentShieldMCPFacade(gateway)
    server = mcp_server(
        "IntentShield",
        instructions=(
            "IntentShield is the sole authorization path to guarded tools. First create a run "
            "with the user's exact intent, inspect the catalog, and pass the exact schema hash "
            "when proposing a call. REVIEW means execution did not occur and a human decision "
            "is required outside this agent-facing server. Never claim a REVIEW or BLOCK result "
            "was executed."
        ),
    )

    @server.tool(name="intentshield_create_run")
    def create_run(user_intent: str) -> dict[str, Any]:
        """Bind a new security run to the user's exact natural-language intent."""
        return facade.create_run(user_intent)

    @server.tool(name="intentshield_list_tools")
    def list_tools() -> dict[str, Any]:
        """List guarded tools, JSON schemas, mutation flags, and current schema hashes."""
        return facade.list_tools()

    @server.tool(name="intentshield_call")
    def guarded_call(
        run_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        schema_hash: str,
        idempotency_key: str | None = None,
        approval_id: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Propose a guarded call; only an ALLOW result can reach the tool executor.

        Mutations require a unique idempotency_key. A REVIEW response contains an
        approval_id but has not executed. After a human approves through the
        control plane, inspect status/result rather than self-approving.
        """
        return facade.call(
            run_id,
            tool_name,
            arguments,
            schema_hash,
            idempotency_key,
            approval_id,
            dry_run,
        )

    @server.tool(name="intentshield_get_run")
    def get_run(run_id: str) -> dict[str, Any]:
        """Inspect a run's decision status and call count."""
        return facade.get_run(run_id)

    @server.tool(name="intentshield_get_approval")
    def get_approval(approval_id: str) -> dict[str, Any]:
        """Inspect approval status; this tool cannot approve its own request."""
        return facade.get_approval(approval_id)

    return server


def create_proxy_mcp_server(config: Any) -> Any:
    """Build an MCP server whose executors are tools on a real upstream server."""
    from .mcp_proxy import MCPProxyRuntime

    runtime = MCPProxyRuntime(config)

    @asynccontextmanager
    async def lifespan(_server: Any):
        async with runtime:
            yield {"runtime": runtime}

    server = _require_mcp()(
        "IntentShield",
        instructions=(
            "All upstream tools are behind IntentShield. Create a run for the user's exact "
            "intent, list the guarded catalog, and call only with the current schema hash. "
            "REVIEW and BLOCK never mean that the upstream tool executed."
        ),
        lifespan=lifespan,
    )

    @server.tool(name="intentshield_create_run")
    async def create_run(user_intent: str) -> dict[str, Any]:
        """Bind a new guarded run to an immutable user intent."""
        normalized = user_intent.strip()
        if not normalized or len(normalized) > 2_000:
            raise ValueError("user_intent must contain 1 to 2000 characters")
        run_id = await runtime.create_run(normalized)
        return {"run_id": run_id, "status": "RUNNING"}

    @server.tool(name="intentshield_list_tools")
    async def list_tools() -> dict[str, Any]:
        """List guarded upstream tools and their exact bound schema hashes."""
        tools = await runtime.tool_catalog()
        return {"tools": tools, "count": len(tools)}

    @server.tool(name="intentshield_call")
    async def guarded_call(
        run_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        schema_hash: str,
        idempotency_key: str | None = None,
        approval_id: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Evaluate and, only after ALLOW, forward one call to the upstream MCP server."""
        call = ToolCall(
            tool_name=tool_name,
            arguments=arguments,
            schema_hash=schema_hash,
            idempotency_key=idempotency_key,
            approval_id=approval_id,
        )
        result = (
            await runtime.evaluate_only(run_id, call)
            if dry_run
            else await runtime.evaluate_and_execute(run_id, call)
        )
        return result.model_dump(mode="json")

    @server.tool(name="intentshield_get_run")
    async def get_run(run_id: str) -> dict[str, Any]:
        """Inspect a guarded run without granting new authority."""
        run = await runtime.get_run(run_id)
        if not run:
            raise ValueError(f"Unknown run: {run_id}")
        return {key: run[key] for key in (
            "id", "status", "call_count", "created_at", "completed_at"
        )}

    @server.tool(name="intentshield_get_approval")
    async def get_approval(approval_id: str) -> dict[str, Any]:
        """Poll approval status and retrieve its terminal result when ready."""
        approval = await runtime.get_approval(approval_id)
        if not approval:
            raise ValueError(f"Unknown approval: {approval_id}")
        return {
            **{key: approval[key] for key in (
                "id", "run_id", "tool_name", "status", "expires_at"
            )},
            "ready": approval["ready"],
            "completion": approval["completion"],
        }

    # Exposed for trusted embedding applications and the integration harness;
    # it is intentionally not registered as an MCP tool.
    server.intentshield_runtime = runtime
    return server


def run_mcp_server(
    *,
    transport: Literal["stdio", "streamable-http"] = "stdio",
    database_path: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8001,
    streamable_http_path: str = "/mcp",
    proxy_config: str | Path | None = None,
    control_token: str | None = None,
    agent_token: str | None = None,
) -> None:
    """Run IntentShield for a real MCP client over stdio or Streamable HTTP."""
    if transport == "streamable-http" and host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError(
            "Remote MCP binding is disabled in this MVP; use a loopback host or embed "
            "IntentShield behind an authenticated TLS reverse proxy."
        )
    if proxy_config is not None:
        from .mcp_proxy import MCPProxyConfig

        server = create_proxy_mcp_server(MCPProxyConfig.from_file(proxy_config))
    else:
        server = create_mcp_server(
            database_path=database_path,
            host=host,
            port=port,
            streamable_http_path=streamable_http_path,
        )
    if transport == "streamable-http" and proxy_config is not None:
        import uvicorn
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.requests import Request
        from starlette.responses import JSONResponse

        app = server.streamable_http_app(
            streamable_http_path=streamable_http_path,
            stateless_http=True,
            json_response=True,
            host=host,
        )

        if agent_token:
            async def require_agent_token(request: Request, call_next):
                if request.url.path.startswith("/control/"):
                    return await call_next(request)
                supplied = request.headers.get("authorization", "")
                if not hmac.compare_digest(supplied, f"Bearer {agent_token}"):
                    return JSONResponse({"error": "unauthorized"}, status_code=401)
                return await call_next(request)

            app.add_middleware(BaseHTTPMiddleware, dispatch=require_agent_token)

        limiter = RateLimiter.from_env()
        if limiter is not None:
            async def rate_limit(request: Request, call_next):
                client = request.client.host if request.client else "unknown"
                if not limiter.allow(client):
                    return JSONResponse(
                        {"error": "rate limit exceeded"}, status_code=429, headers={"Retry-After": "1"}
                    )
                return await call_next(request)

            # Added last so it runs first and also throttles unauthenticated floods.
            app.add_middleware(BaseHTTPMiddleware, dispatch=rate_limit)

        if control_token:
            async def decide_approval(request: Request) -> JSONResponse:
                supplied = request.headers.get("authorization", "")
                expected = f"Bearer {control_token}"
                if not hmac.compare_digest(supplied, expected):
                    return JSONResponse({"error": "unauthorized"}, status_code=401)
                try:
                    payload = await request.json()
                    decision = payload.get("decision")
                    if decision not in {"approve", "reject"}:
                        return JSONResponse(
                            {"error": "decision must be approve or reject"}, status_code=422
                        )
                    result = await server.intentshield_runtime.decide_approval(
                        request.path_params["approval_id"], decision == "approve"
                    )
                    return JSONResponse(result.model_dump(mode="json"))
                except KeyError:
                    return JSONResponse({"error": "approval not found"}, status_code=404)
                except ValueError as exc:
                    return JSONResponse({"error": str(exc)}, status_code=409)

            app.add_route(
                "/control/approvals/{approval_id}", decide_approval, methods=["POST"]
            )

        uvicorn.run(app, host=host, port=port, log_level="info")
    elif transport == "streamable-http":
        server.run(
            transport=transport,
            host=host,
            port=port,
            streamable_http_path=streamable_http_path,
            stateless_http=True,
            json_response=True,
        )
    else:
        server.run(transport=transport)


def main(argv: list[str] | None = None) -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Run the IntentShield MCP gateway")
    parser.add_argument(
        "--transport", choices=("stdio", "streamable-http"), default="stdio"
    )
    parser.add_argument("--db", default=os.getenv("INTENTSHIELD_DB", "intentshield.db"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--path", default="/mcp")
    parser.add_argument(
        "--config",
        help="JSON config for a guarded real upstream MCP server",
    )
    parser.add_argument(
        "--control-token-env",
        default="INTENTSHIELD_CONTROL_TOKEN",
        help="Environment variable containing the bearer token for the local approval endpoint",
    )
    args = parser.parse_args(argv)
    run_mcp_server(
        transport=args.transport,
        database_path=args.db,
        host=args.host,
        port=args.port,
        streamable_http_path=args.path,
        proxy_config=args.config,
        control_token=os.getenv(args.control_token_env) if args.config else None,
        agent_token=os.getenv("INTENTSHIELD_AGENT_TOKEN") if args.config else None,
    )


if __name__ == "__main__":  # pragma: no cover - exercised by real MCP clients
    main()
