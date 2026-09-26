from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import os
from pathlib import Path
from typing import AsyncIterator

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .model_gateway import ModelGateway, ModelProviderError
from .mcp_proxy import MCPProxyConfig, MCPProxyRuntime
from .models import ApprovalDecisionRequest, ModelRunRequest, RunCreateRequest, ToolCall
from .service import IntentShieldService


def create_app(
    database_path: str | Path | None = None,
    model_gateway: ModelGateway | None = None,
    proxy_config: str | Path | None = None,
) -> FastAPI:
    load_dotenv()
    proxy_path = proxy_config or os.getenv("INTENTSHIELD_PROXY_CONFIG")
    runtime: MCPProxyRuntime | None = None
    local_service: IntentShieldService | None = None
    if proxy_path:
        config = MCPProxyConfig.from_file(proxy_path)
        if database_path is not None:
            config = config.model_copy(update={"database_path": str(database_path)})
        runtime = MCPProxyRuntime(config)
    else:
        local_service = IntentShieldService.default(
            database_path or os.getenv("INTENTSHIELD_DB", "intentshield.db")
        )
    models = model_gateway or ModelGateway()
    try:
        model_concurrency = int(os.getenv("INTENTSHIELD_MODEL_MAX_CONCURRENCY", "2"))
    except ValueError:
        model_concurrency = 2
    model_slots = asyncio.Semaphore(max(1, min(model_concurrency, 16)))

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
    app.state.service = local_service
    app.state.model_gateway = models
    app.state.proxy_runtime = runtime

    def service() -> IntentShieldService:
        current = app.state.service
        if current is None:
            raise RuntimeError("IntentShield service is not ready")
        return current

    @app.get("/health")
    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": "mcp-proxy" if runtime else "offline"}

    @app.post("/api/runs", status_code=201)
    async def create_run(request: RunCreateRequest):
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
        assert request.call is not None
        if runtime is not None:
            return await runtime.evaluate_and_execute(run_id, request.call)
        return await asyncio.to_thread(
            service().evaluate_and_execute, run_id, request.user_intent, request.call
        )

    @app.get("/api/models")
    def list_models():
        return models.statuses()

    @app.post("/api/model-runs", status_code=201)
    async def create_model_run(request: ModelRunRequest):
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

    @app.get("/api/runs")
    def list_runs(limit: int = Query(default=100, ge=1, le=500)):
        return service().storage.list_runs(limit)

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str):
        run = service().storage.get_run(run_id)
        if not run:
            raise HTTPException(404, "Run not found")
        return {**run, "events": service().storage.list_events(run_id)}

    @app.get("/api/runs/{run_id}/events")
    def get_events(run_id: str):
        if not service().storage.get_run(run_id):
            raise HTTPException(404, "Run not found")
        return service().storage.list_events(run_id)

    @app.get("/api/approvals")
    def list_approvals(status: str | None = None):
        return service().storage.list_approvals(status.upper() if status else None)

    @app.post("/api/approvals/{approval_id}/decision")
    async def decide_approval(approval_id: str, request: ApprovalDecisionRequest):
        try:
            if runtime is not None:
                return await runtime.decide_approval(
                    approval_id, request.decision == "approve"
                )
            return await asyncio.to_thread(
                service().decide_approval, approval_id, request.decision == "approve"
            )
        except KeyError:
            raise HTTPException(404, "Approval not found") from None
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/tools")
    async def tools():
        if runtime is not None:
            return await runtime.tool_catalog()
        return service().tool_catalog()

    @app.get("/api/metrics")
    def metrics():
        return service().storage.metrics()

    @app.get("/api/security/status")
    def security_status():
        return service().security_status()

    static_dir = Path(__file__).with_name("static")
    if static_dir.exists():
        # Mount after API routes so static content can never shadow /api.
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

        @app.get("/", include_in_schema=False)
        def dashboard():
            return FileResponse(static_dir / "index.html")

    return app


app = create_app()
