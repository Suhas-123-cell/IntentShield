from __future__ import annotations

import asyncio
import hmac
import os
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, AsyncIterator

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .envfile import load_environment, require_tokens
from .mcp_proxy import MCPProxyConfig, MCPProxyRuntime, RunLimitError
from .model_gateway import ModelGateway, ModelProviderError, ModelProviderStatus
from .models import ApprovalDecisionRequest, GatewayResult, ModelRunRequest, RunCreateRequest, ToolCall
from .ratelimit import RateLimiter
from .service import IntentShieldService

DEFAULT_DB = Path.home() / ".intentshield" / "gateway.db"  # not the working directory


def _access_tokens(control_token: str | None, agent_token: str | None, proxy: bool) -> tuple[str, str]:
    """(the operator's control token, the agent token) from the arguments or the environment, and a refusal of a combination that
    would leave a route open."""
    approval_token = (control_token or os.getenv("INTENTSHIELD_CONTROL_TOKEN") or "").strip()
    # Optional: when set, proposing calls and reading runs (which hold executed tool results)
    # needs this token or the operator's.
    run_token = (agent_token or os.getenv("INTENTSHIELD_AGENT_TOKEN") or "").strip()
    if proxy and not approval_token:
        raise ValueError(
            "INTENTSHIELD_CONTROL_TOKEN is required when the web MCP proxy is enabled"
        )
    if run_token and not approval_token:
        # Without it the approval queue, which shows requests and results, would stay open.
        raise ValueError("INTENTSHIELD_CONTROL_TOKEN is required when INTENTSHIELD_AGENT_TOKEN is set")
    if proxy and not run_token:
        # Behind the proxy, /api/runs drives real upstream tools and shows their results: no local
        # process may do that without a credential.
        raise ValueError("INTENTSHIELD_AGENT_TOKEN is required when the web MCP proxy is enabled")
    return approval_token, run_token


def _model_concurrency() -> int:
    """How many calls to a model provider may run at once (``INTENTSHIELD_MODEL_MAX_CONCURRENCY``, 1 to 16, default 2)."""
    try:
        wanted = int(os.getenv("INTENTSHIELD_MODEL_MAX_CONCURRENCY", "2"))
    except ValueError:
        wanted = 2
    return max(1, min(wanted, 16))


async def _run_call(request: RunCreateRequest, runtime: MCPProxyRuntime | None,
                    service: Callable[[], IntentShieldService]) -> GatewayResult:
    """A run created from a request that holds a scripted scenario or one call."""
    if bool(request.scenario) == bool(request.call):
        raise HTTPException(422, "Provide exactly one of scenario or call")
    if request.scenario:
        if runtime is not None:
            raise HTTPException(422, "Scripted scenarios are unavailable in MCP proxy mode")
        return await asyncio.to_thread(
            service().execute_scenario, request.user_intent, request.scenario
        )
    run_id = (
        await runtime.create_run(request.user_intent)
        if runtime is not None
        else await asyncio.to_thread(service().create_run, request.user_intent)
    )
    if request.call is None:  # not an assert: a check that stays when Python runs with -O
        raise HTTPException(422, "Provide exactly one of scenario or call")
    if runtime is not None:
        return await runtime.evaluate_and_execute(run_id, request.call)
    return await asyncio.to_thread(
        service().evaluate_and_execute, run_id, request.user_intent, request.call
    )


async def _run_with_model(request: ModelRunRequest, runtime: MCPProxyRuntime | None,
                          service: Callable[[], IntentShieldService], models: ModelGateway,
                          model_slots: asyncio.Semaphore) -> dict[str, Any]:
    """One run in which a model provider proposes the call: the preflight check of the request, the proposal, then the
    same evaluation and execution as a call sent in directly."""
    statuses = {item.provider: item for item in models.statuses()}
    selected = statuses[request.provider]
    if runtime is not None:
        run_id = await runtime.create_run(request.user_intent)
    else:
        run_id = await asyncio.to_thread(
            service().create_run, request.user_intent, f"model:{request.provider}"
        )
    preflight = await asyncio.to_thread(
        service().preflight_intent, request.user_intent
    )
    await asyncio.to_thread(
        service().storage.add_event,
        run_id,
        "SECURITY_PREFLIGHT",
        preflight.model_dump(mode="json"),
    )
    if preflight.injection_score >= service().config.injection_block_threshold:
        await asyncio.to_thread(service().storage.finish_run, run_id, "BLOCK")
        raise HTTPException(400, {
            "code": "SECURITY_PREFLIGHT_BLOCKED",
            "message": "The request was blocked before Gemini egress",
            "run_id": run_id,
        })
    await asyncio.to_thread(service().storage.add_event, run_id, "MODEL_REQUESTED", {
        "provider": request.provider,
        "model": selected.model,
    })
    try:
        async with model_slots:
            proposal = await asyncio.to_thread(
                models.propose, request.provider, request.user_intent, service().registry
            )
    except ModelProviderError as exc:
        event = "MODEL_NO_ACTION" if exc.code == "MODEL_NO_ACTION" else "MODEL_ERROR"
        run_status = "BLOCK" if exc.code == "MODEL_NO_ACTION" else "ERROR"
        await asyncio.to_thread(service().storage.add_event, run_id, event, exc.as_dict())
        await asyncio.to_thread(service().storage.finish_run, run_id, run_status)
        status_code = {
            "MODEL_PROVIDER_NOT_CONFIGURED": 503,
            "MODEL_NO_ACTION": 409,
        }.get(exc.code, 502)
        raise HTTPException(status_code, exc.as_dict()) from exc

    spec = service().registry[proposal.tool_name]
    call = ToolCall(
        tool_name=proposal.tool_name,
        arguments=proposal.arguments,
        schema_hash=spec.schema_hash,
        idempotency_key=f"{run_id}:model-call:1" if spec.mutation else None,
    )
    await asyncio.to_thread(service().storage.add_event, run_id, "MODEL_PROPOSAL", {
        "provider": proposal.provider,
        "model": proposal.model,
        "tool_name": proposal.tool_name,
        "arguments": proposal.arguments,
    })
    result = (
        await runtime.evaluate_and_execute(run_id, call)
        if runtime is not None
        else await asyncio.to_thread(
            service().evaluate_and_execute, run_id, request.user_intent, call
        )
    )
    return {
        **result.model_dump(mode="json"),
        "model_provider": proposal.provider,
        "model_name": proposal.model,
    }


def _add_rate_limit(app: FastAPI, limiter: RateLimiter, approval_token: str) -> None:
    """Limit the requests of each client address; the operator's approval requests have a bucket of their own."""

    @app.middleware("http")
    async def rate_limit(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        client = request.client.host if request.client else "unknown"
        if approval_token and request.url.path.startswith("/api/approvals") and hmac.compare_digest(
                request.headers.get("authorization", "").encode(), f"Bearer {approval_token}".encode()):
            # One client address covers every local process: junk posted to the run routes must not
            # lock the operator out of approvals, so a request proving the control token has its own bucket.
            client = f"operator:{client}"
        if request.url.path not in ("/health", "/api/health") and not limiter.allow(client):
            return JSONResponse(
                {"detail": "rate limit exceeded"}, status_code=429, headers={"Retry-After": "1"}
            )
        return await call_next(request)


def _bearer_check(accepted_tokens: list[str], message: str) -> Callable[..., None]:
    """A route dependency that wants ``Authorization: Bearer <token>`` for one of ``accepted_tokens``, and lets every request
    through when there are none."""
    accepted = [f"Bearer {token}".encode() for token in accepted_tokens]

    def check(authorization: Annotated[str | None, Header()] = None) -> None:
        if not accepted:
            return
        if authorization is None or not any(hmac.compare_digest(authorization.encode(), item) for item in accepted):
            raise HTTPException(401, message, headers={"WWW-Authenticate": "Bearer"})

    return check


def _add_health_route(app: FastAPI, runtime: MCPProxyRuntime | None) -> None:
    """The health check."""

    @app.get("/health")
    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": "mcp-proxy" if runtime else "offline"}


def _add_run_routes(app: FastAPI, runtime: MCPProxyRuntime | None, service: Callable[[], IntentShieldService],
                    models: ModelGateway, model_slots: asyncio.Semaphore, require_run_access: Callable[..., None]) -> None:
    """The routes that create, list and read runs, and the model runs."""

    @app.post("/api/runs", status_code=201)
    async def create_run(request: RunCreateRequest, _authorized: None = Depends(require_run_access)) -> GatewayResult:
        return await _run_call(request, runtime, service)

    @app.get("/api/models")
    def list_models() -> list[ModelProviderStatus]:
        return models.statuses()

    @app.post("/api/model-runs", status_code=201)
    async def create_model_run(request: ModelRunRequest,
                               _authorized: None = Depends(require_run_access)) -> dict[str, Any]:
        return await _run_with_model(request, runtime, service, models, model_slots)

    @app.get("/api/runs")
    def list_runs(
        limit: int = Query(default=100, ge=1, le=500),
        _authorized: None = Depends(require_run_access),
    ) -> list[dict[str, Any]]:
        return service().storage.list_runs(limit)

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str, _authorized: None = Depends(require_run_access)) -> dict[str, Any]:
        run = service().storage.get_run(run_id)
        if not run:
            raise HTTPException(404, "Run not found")
        return {**run, "events": service().storage.list_events(run_id)}

    @app.get("/api/runs/{run_id}/events")
    def get_events(run_id: str, _authorized: None = Depends(require_run_access)) -> list[dict[str, Any]]:
        if not service().storage.get_run(run_id):
            raise HTTPException(404, "Run not found")
        return service().storage.list_events(run_id)


def _add_approval_routes(app: FastAPI, runtime: MCPProxyRuntime | None, service: Callable[[], IntentShieldService],
                         require_approval_access: Callable[..., None]) -> None:
    """The routes that list approvals and decide them."""

    @app.get("/api/approvals")
    def list_approvals(
        status: str | None = None,
        _authorized: None = Depends(require_approval_access),
    ) -> list[dict[str, Any]]:
        return service().storage.list_approvals(status.upper() if status else None)

    @app.post("/api/approvals/{approval_id}/decision")
    async def decide_approval(
        approval_id: str,
        request: ApprovalDecisionRequest,
        _authorized: None = Depends(require_approval_access),
    ) -> GatewayResult:
        try:
            if runtime is not None:
                return await runtime.decide_approval(
                    approval_id, request.decision == "approve", request.trust_source
                )
            return await asyncio.to_thread(
                service().decide_approval, approval_id, request.decision == "approve"
            )
        except KeyError:
            raise HTTPException(404, "Approval not found") from None
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc


def _add_status_routes(app: FastAPI, runtime: MCPProxyRuntime | None, service: Callable[[], IntentShieldService],
                       require_run_access: Callable[..., None]) -> None:
    """The routes for the tool catalog, the metrics and the security status."""

    @app.get("/api/tools", dependencies=[Depends(require_run_access)])
    async def tools() -> list[dict[str, Any]]:
        if runtime is not None:
            return await runtime.tool_catalog()
        return service().tool_catalog()

    @app.get("/api/metrics", dependencies=[Depends(require_run_access)])
    def metrics() -> dict[str, Any]:
        return service().storage.metrics()

    @app.get("/api/security/status", dependencies=[Depends(require_run_access)])
    def security_status() -> dict[str, Any]:
        return service().security_status()


def _add_dashboard(app: FastAPI) -> None:
    """The dashboard's page and files, mounted after the API routes so static content can never shadow ``/api``."""

    static_dir = Path(__file__).with_name("static")
    if static_dir.exists():
        # Mount after API routes so static content can never shadow /api.
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

        @app.get("/", include_in_schema=False)
        def dashboard() -> FileResponse:
            return FileResponse(static_dir / "index.html")


def create_app(
    database_path: str | Path | None = None,
    model_gateway: ModelGateway | None = None,
    proxy_config: str | Path | None = None,
    control_token: str | None = None,
    agent_token: str | None = None,
) -> FastAPI:
    # the operator's directory, minus what only the user may set; a token that only that file held stops the start
    refused = load_environment(load_dotenv, usecwd=True)
    require_tokens(refused, tuple(name for name, given in (("INTENTSHIELD_CONTROL_TOKEN", control_token),
                                                           ("INTENTSHIELD_AGENT_TOKEN", agent_token)) if not given))
    proxy_path = proxy_config or os.getenv("INTENTSHIELD_PROXY_CONFIG")
    approval_token, run_token = _access_tokens(control_token, agent_token, bool(proxy_path))
    runtime: MCPProxyRuntime | None = None
    local_service: IntentShieldService | None = None
    if proxy_path:
        config = MCPProxyConfig.from_file(proxy_path)
        if database_path is not None:
            config = config.model_copy(update={"database_path": str(database_path)})
        runtime = MCPProxyRuntime(config)
    else:
        local_service = IntentShieldService.default(
            database_path or os.getenv("INTENTSHIELD_DB") or DEFAULT_DB
        )
    models = model_gateway or ModelGateway()
    model_slots = asyncio.Semaphore(_model_concurrency())

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if runtime is not None:
            await runtime.connect()
            app.state.service = runtime.service
        try:
            yield
        finally:
            if runtime is not None:
                await runtime.close()

    app = FastAPI(title="IntentShield", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["127.0.0.1", "localhost", "testserver"],
    )
    @app.middleware("http")
    async def security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        # The dashboard holds an approve button: it must not be framed by another site.
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        return response

    @app.exception_handler(RunLimitError)
    async def run_limit(_request: Request, exc: RunLimitError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=429)

    limiter = RateLimiter.from_env()
    if limiter is not None:
        _add_rate_limit(app, limiter, approval_token)

    app.state.service = local_service
    app.state.model_gateway = models
    app.state.proxy_runtime = runtime

    def service() -> IntentShieldService:
        current: IntentShieldService | None = app.state.service
        if current is None:
            raise RuntimeError("IntentShield service is not ready")
        return current

    require_approval_access = _bearer_check([approval_token] if approval_token else [],
                                            "A valid operator control token is required")
    require_run_access = _bearer_check([t for t in (run_token, approval_token) if t] if run_token else [],
                                       "A valid agent or operator token is required")

    _add_health_route(app, runtime)
    _add_run_routes(app, runtime, service, models, model_slots, require_run_access)
    _add_approval_routes(app, runtime, service, require_approval_access)
    _add_status_routes(app, runtime, service, require_run_access)
    _add_dashboard(app)

    return app

