from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys

from intentshield.mcp_verify import main, verify_mcp


def _write_config(tmp_path: Path, **overrides: object) -> Path:
    config: dict[str, object] = {
        "upstream": {
            "server_id": "demo",
            "transport": "stdio",
            "command": sys.executable,
            "args": ["-m", "intentshield.demo_mcp_server"],
        },
        "database_path": str(tmp_path / "verify.db"),
        "allowed_tools": ["demo:*"],
        "prohibited_tools": [],
        "read_only_tools": ["demo:read_note", "demo:execution_stats"],
        "destination_fields": {},
    }
    config.update(overrides)
    upstreams = config.get("upstreams") or [config.get("upstream")]
    server_ids = [item["server_id"] for item in upstreams if isinstance(item, dict)]
    config["grounding_terms_by_tool"] = {
        f"{server_id}:{tool}": terms
        for server_id in server_ids
        for tool, terms in {
            "read_note": ["note", "welcome"],
            "append_note": ["note", "line", "welcome"],
            "execution_stats": ["execution", "stats"],
        }.items()
    }
    path = tmp_path / "proxy.json"
    path.write_text(json.dumps(config))
    return path


def _upstream(server_id: str) -> dict[str, object]:
    return {
        "server_id": server_id,
        "transport": "stdio",
        "command": sys.executable,
        "args": ["-m", "intentshield.demo_mcp_server"],
    }


def test_verifier_uses_real_client_and_reports_complete_policy(tmp_path: Path) -> None:
    report = asyncio.run(verify_mcp(_write_config(tmp_path)))

    assert report["status"] == "PASS"
    assert report["summary"] == {
        "passed": 13,
        "failed": 0,
        "warnings": 0,
        "guarded_tools_discovered": 3,
    }
    assert report["artifacts"]["downstream_tools"] == [
        "intentshield_call",
        "intentshield_create_run",
        "intentshield_get_approval",
        "intentshield_get_run",
        "intentshield_list_tools",
    ]
    assert report["artifacts"]["verification_mode"] == "in_process_preflight"
    assert report["artifacts"]["upstreams"] == [
        {"server_id": "demo", "transport": "stdio"}
    ]
    assert [item["name"] for item in report["artifacts"]["guarded_catalog"]] == [
        "demo:append_note",
        "demo:execution_stats",
        "demo:read_note",
    ]
    non_executing = next(
        check for check in report["checks"] if check["id"] == "non_executing_verification"
    )
    assert non_executing["status"] == "PASS"
    assert non_executing["details"]["invoked_gateway_tools"] == [
        "intentshield_list_tools",
        "intentshield_create_run",
        "intentshield_call",
        "intentshield_create_run",
        "intentshield_call",
    ]
    behavior = {check["id"]: check for check in report["checks"]}
    assert behavior["blocked_call_zero_execution"]["status"] == "PASS"
    assert behavior["mutation_review_zero_execution"]["status"] == "PASS"
    assert behavior["mutation_review_zero_execution"]["details"]["approval_created"] is False
    assert behavior["credential_indirection"]["status"] == "PASS"
    assert behavior["resource_policy"]["status"] == "PASS"


def test_verifier_fails_closed_for_incomplete_policy(tmp_path: Path) -> None:
    report = asyncio.run(
        verify_mcp(
            _write_config(
                tmp_path,
                allowed_tools=["demo:read_note", "demo:missing_*"],
                read_only_tools=["demo:read_note", "demo:also_missing"],
            )
        )
    )

    assert report["status"] == "FAIL"
    by_id = {check["id"]: check for check in report["checks"]}
    assert by_id["allowed_policy_coverage"]["status"] == "FAIL"
    assert by_id["allowed_policy_coverage"]["details"]["unmatched_patterns"] == [
        "demo:missing_*"
    ]
    assert by_id["policy_partition"]["details"]["uncovered_tools"] == [
        "demo:append_note",
        "demo:execution_stats",
    ]
    assert by_id["read_only_policy"]["status"] == "FAIL"


def test_verifier_reports_multiple_upstreams_and_qualified_destination_rules(
    tmp_path: Path,
) -> None:
    path = _write_config(
        tmp_path,
        upstream=None,
        upstreams=[_upstream("alpha"), _upstream("beta")],
        allowed_tools=["alpha:*", "beta:*"],
        read_only_tools=[
            "alpha:read_note",
            "alpha:execution_stats",
            "beta:read_note",
            "beta:execution_stats",
        ],
        destination_fields={"alpha:append_note": "text"},
        allowed_destinations_by_tool={"alpha:append_note": ["safe-*"]},
    )

    report = asyncio.run(verify_mcp(path))

    assert report["status"] == "PASS"
    assert report["artifacts"]["upstreams"] == [
        {"server_id": "alpha", "transport": "stdio"},
        {"server_id": "beta", "transport": "stdio"},
    ]
    destination = next(
        check for check in report["checks"] if check["id"] == "destination_policy"
    )
    assert destination["status"] == "PASS"
    assert destination["details"]["bindings"] == [
        {"tool": "alpha:append_note", "field": "text"}
    ]


def test_main_emits_deterministic_json_and_nonzero_on_failure(
    tmp_path: Path, capsys
) -> None:
    missing = tmp_path / "missing.json"

    first_exit_code = main(["--config", str(missing)])
    first_output = capsys.readouterr().out
    second_exit_code = main(["--config", str(missing)])
    second_output = capsys.readouterr().out

    assert first_exit_code == second_exit_code == 1
    assert first_output == second_output
    report = json.loads(first_output)
    assert report["status"] == "FAIL"
    assert report["checks"][0]["id"] == "verification_runtime"


def test_failure_report_never_echoes_configured_secret(tmp_path: Path, capsys) -> None:
    canary = "super-secret-api-key-canary"
    path = _write_config(
        tmp_path,
        upstream={
            **_upstream("demo"),
            "headers": {"authorization": canary},
        },
    )

    exit_code = main(["--config", str(path)])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert canary not in output
    assert json.loads(output)["status"] == "FAIL"


def test_stdio_wire_mode_launches_real_downstream_subprocess(tmp_path: Path) -> None:
    report = asyncio.run(
        verify_mcp(_write_config(tmp_path), verification_mode="stdio_wire")
    )

    assert report["status"] == "PASS"
    assert report["artifacts"]["verification_mode"] == "stdio_wire"
