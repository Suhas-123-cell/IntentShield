from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from intentshield.api import create_app


def test_dashboard_and_static_assets_are_served(tmp_path: Path):
    with TestClient(create_app(tmp_path / "assets.db")) as client:
        dashboard = client.get("/")
        styles = client.get("/static/styles.css")
        script = client.get("/static/app.js")

        assert dashboard.status_code == 200
        assert "text/html" in dashboard.headers["content-type"]
        assert styles.status_code == 200
        assert "text/css" in styles.headers["content-type"]
        assert script.status_code == 200
        assert "javascript" in script.headers["content-type"]
        assert "LIVE MODEL" in dashboard.text
        assert 'id="model-provider"' in dashboard.text
        assert '"/model-runs"' in script.text


def test_api_run_approval_and_metrics(tmp_path: Path):
    with TestClient(create_app(tmp_path / "api.db")) as client:
        assert client.get("/api/health").json() == {"status": "ok", "mode": "offline"}
        benign = client.post("/api/runs", json={"user_intent": "Read inbox", "scenario": "benign"})
        assert benign.status_code == 201
        assert benign.json()["decision"] == "ALLOW"

        review = client.post("/api/runs", json={"user_intent": "Email Alice", "scenario": "review"})
        approval_id = review.json()["approval_id"]
        pending = client.get("/api/approvals", params={"status": "pending"}).json()
        assert pending[0]["id"] == approval_id
        approved = client.post(f"/api/approvals/{approval_id}/decision", json={"decision": "approve"})
        assert approved.json()["decision"] == "ALLOW"
        assert approved.json()["executed"] is True

        run_id = benign.json()["run_id"]
        detail = client.get(f"/api/runs/{run_id}").json()
        assert detail["events"][-1]["kind"] == "TOOL_EXECUTED"
        metrics = client.get("/api/metrics").json()
        assert metrics["runs"] == 2
        assert metrics["executions"] == 1
        assert len(client.get("/api/tools").json()) == 2
        security = client.get("/api/security/status").json()
        assert security["agents"] == ["detection", "grounding"]
        assert security["evidence_only"] is True
        assert security["policy_required"] is True
        assert "ready" in security["intent_classifier"]


def test_api_rejects_client_forged_security_scores(tmp_path: Path):
    with TestClient(create_app(tmp_path / "forged.db")) as client:
        tool = next(tool for tool in client.get("/api/tools").json() if tool["name"] == "read_inbox")
        response = client.post("/api/runs", json={
            "user_intent": "Do not read my inbox",
            "call": {
                "tool_name": "read_inbox",
                "arguments": {"resource": "inbox", "limit": 2},
                "schema_hash": tool["schema_hash"],
                "injection_score": 0,
                "intent_alignment": 1,
            },
        })
        assert response.status_code == 422


def test_web_proxy_refuses_to_start_without_control_token(
    tmp_path: Path, monkeypatch,
):
    monkeypatch.delenv("INTENTSHIELD_CONTROL_TOKEN", raising=False)
    config = Path(__file__).parents[1] / "configs" / "mcp-proxy.demo.json"

    with pytest.raises(ValueError, match="CONTROL_TOKEN"):
        create_app(
            database_path=tmp_path / "missing-token.db",
            proxy_config=config,
            control_token="",
        )


def test_web_runtime_uses_real_guarded_mcp_catalog(tmp_path: Path):
    config = Path(__file__).parents[1] / "configs" / "mcp-proxy.demo.json"
    with TestClient(
        create_app(
            database_path=tmp_path / "web-proxy.db",
            proxy_config=config,
            control_token="test-control-token",
        )
    ) as client:
        assert client.get("/api/health").json() == {
            "status": "ok",
            "mode": "mcp-proxy",
        }
        tools = client.get("/api/tools").json()
        read = next(item for item in tools if item["name"] == "demo:read_note")
        append = next(item for item in tools if item["name"] == "demo:append_note")
        response = client.post("/api/runs", json={
            "user_intent": "Read the welcome note",
            "call": {
                "tool_name": read["name"],
                "arguments": {"note_id": "welcome"},
                "schema_hash": read["schema_hash"],
            },
        })

        mutation = client.post("/api/runs", json={
            "user_intent": "Append a line to the welcome note",
            "call": {
                "tool_name": append["name"],
                "arguments": {"note_id": "welcome", "text": "Checked."},
                "schema_hash": append["schema_hash"],
                "idempotency_key": "web-proxy-mutation-1",
            },
        }).json()
        unauthorized_list = client.get("/api/approvals")
        unauthorized = client.post(
            f"/api/approvals/{mutation['approval_id']}/decision",
            json={"decision": "approve"},
        )
        authorized = client.post(
            f"/api/approvals/{mutation['approval_id']}/decision",
            headers={"Authorization": "Bearer test-control-token"},
            json={"decision": "approve"},
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["decision"] == "ALLOW"
    assert payload["executed"] is True
    assert payload["result"]["trust"] == "UNTRUSTED_MCP_OUTPUT"
    assert mutation["decision"] == "REVIEW"
    assert unauthorized_list.status_code == 401
    assert unauthorized.status_code == 401
    assert authorized.status_code == 200
    assert authorized.json()["decision"] == "ALLOW"
