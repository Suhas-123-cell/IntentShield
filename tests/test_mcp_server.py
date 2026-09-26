from pathlib import Path

import pytest

from intentshield.mcp_server import IntentShieldMCPFacade, create_mcp_server, run_mcp_server
from intentshield.models import Decision
from intentshield.policy import PolicyConfig
from intentshield.service import IntentShieldService
from intentshield.storage import Storage
from intentshield.tools import SimulatedEmailTools, build_registry


@pytest.fixture
def facade(tmp_path: Path) -> IntentShieldMCPFacade:
    email = SimulatedEmailTools()
    registry = build_registry(email)
    config = PolicyConfig(
        allowed_tools=set(registry),
        allowed_resources={"inbox", "outbox"},
        allowed_destinations=["*@example.com"],
        call_budget=4,
        injection_block_threshold=0.75,
        minimum_intent_alignment=0.6,
        approval_ttl_seconds=60,
    )
    service = IntentShieldService(Storage(tmp_path / "mcp.db"), config, registry, email)
    return IntentShieldMCPFacade(service)


def test_facade_runs_real_gateway_path(facade: IntentShieldMCPFacade):
    run = facade.create_run("Read my inbox")
    catalog = facade.list_tools()
    read = next(tool for tool in catalog["tools"] if tool["name"] == "read_inbox")

    result = facade.call(
        run["run_id"],
        "read_inbox",
        {"resource": "inbox", "limit": 1},
        read["schema_hash"],
    )

    assert result["decision"] == Decision.ALLOW
    assert result["executed"] is True
    assert result["result"]["count"] == 1
    assert facade.get_run(run["run_id"])["status"] == Decision.ALLOW


def test_facade_review_never_self_approves(facade: IntentShieldMCPFacade):
    run = facade.create_run("Send Alice a status email")
    send = next(
        tool for tool in facade.list_tools()["tools"] if tool["name"] == "send_email"
    )
    result = facade.call(
        run["run_id"],
        "send_email",
        {
            "resource": "outbox",
            "to": "alice@example.com",
            "subject": "Status",
            "body": "Approved status update.",
        },
        send["schema_hash"],
        idempotency_key="mcp-review-1",
    )

    assert result["decision"] == Decision.REVIEW
    assert result["executed"] is False
    approval = facade.get_approval(result["approval_id"])
    assert approval["status"] == "PENDING"
    assert not hasattr(facade, "decide_approval")


def test_facade_dry_run_never_executes_or_creates_approval(
    facade: IntentShieldMCPFacade,
):
    run = facade.create_run("Send Alice a status email")
    send = next(
        tool for tool in facade.list_tools()["tools"] if tool["name"] == "send_email"
    )
    result = facade.call(
        run["run_id"],
        "send_email",
        {
            "resource": "outbox",
            "to": "alice@example.com",
            "subject": "Status",
            "body": "Verification only.",
        },
        send["schema_hash"],
        idempotency_key="dry-run-only",
        dry_run=True,
    )

    assert result["decision"] == Decision.REVIEW
    assert result["executed"] is False
    assert result["approval_id"] is None
    assert facade.service.storage.list_approvals() == []
    assert facade.get_run(run["run_id"])["call_count"] == 0
    assert facade.service.email_tools.execution_count == 0


def test_facade_rejects_missing_schema_binding(facade: IntentShieldMCPFacade):
    run = facade.create_run("Read my inbox")
    with pytest.raises(ValueError, match="schema_hash"):
        facade.call(run["run_id"], "read_inbox", {"resource": "inbox"}, "")


def test_fastmcp_dependency_is_actionable_when_missing(tmp_path: Path):
    try:
        server = create_mcp_server(database_path=tmp_path / "server.db")
    except RuntimeError as exc:
        assert "MCP SDK" in str(exc)
    else:
        assert server is not None


def test_streamable_http_refuses_unauthenticated_remote_binding():
    with pytest.raises(ValueError, match="Remote MCP binding is disabled"):
        run_mcp_server(transport="streamable-http", host="0.0.0.0")
