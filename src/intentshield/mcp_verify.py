"""Non-executing verification of an IntentShield MCP proxy configuration.

The verifier uses the official high-level MCP client against the actual
IntentShield server object. It exercises gateway policy operations while
requiring ``executed=false`` for every canary; no guarded upstream tool is run.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import sys
from typing import Any

from dotenv import load_dotenv
from jsonschema import Draft202012Validator
from mcp import Client, StdioServerParameters

from .mcp_proxy import MCPProxyConfig
from .mcp_upstream import _credential_shaped_name
from .mcp_server import create_proxy_mcp_server


_GATEWAY_TOOLS = {
    "intentshield_call",
    "intentshield_create_run",
    "intentshield_get_approval",
    "intentshield_get_run",
    "intentshield_list_tools",
}

_VERIFICATION_MODES = {"in_process_preflight", "stdio_wire", "streamable_http_wire"}


def _check(
    check_id: str,
    passed: bool,
    message: str,
    *,
    details: dict[str, Any] | None = None,
    severity: str = "error",
) -> dict[str, Any]:
    status = "PASS" if passed else ("WARN" if severity == "warning" else "FAIL")
    result: dict[str, Any] = {
        "id": check_id,
        "status": status,
        "message": message,
    }
    if details:
        result["details"] = details
    return result


def _matched_patterns(
    config: MCPProxyConfig, patterns: list[str], tool_names: list[str]
) -> tuple[list[str], list[str]]:
    matched: list[str] = []
    unmatched: list[str] = []
    for pattern in sorted(patterns):
        target = matched if any(config._matches(name, [pattern]) for name in tool_names) else unmatched
        target.append(pattern)
    return matched, unmatched


def _destination_bindings(
    config: MCPProxyConfig, catalog: list[dict[str, Any]]
) -> tuple[list[dict[str, str]], list[str], list[dict[str, str]]]:
    """Resolve destination mappings exactly as the proxy runtime does."""
    resolved: list[dict[str, str]] = []
    unmatched: set[str] = set(config.destination_fields)
    invalid_fields: list[dict[str, str]] = []

    for tool in catalog:
        qualified = str(tool["name"])
        # The runtime intentionally accepts only qualified keys. An unqualified
        # destination rule could silently apply to the same raw name on the
        # wrong upstream server.
        if qualified not in config.destination_fields:
            continue
        unmatched.discard(qualified)
        field = config.destination_fields[qualified]
        schema = tool.get("schema", {})
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if (
            not isinstance(properties, dict)
            or field not in properties
            or not isinstance(required, list)
            or field not in required
        ):
            invalid_fields.append({"tool": qualified, "field": field})
        else:
            resolved.append({"tool": qualified, "field": field})

    return (
        sorted(resolved, key=lambda item: (item["tool"], item["field"])),
        sorted(unmatched),
        sorted(invalid_fields, key=lambda item: (item["tool"], item["field"])),
    )


def _resource_bindings(
    config: MCPProxyConfig, catalog: list[dict[str, Any]]
) -> tuple[list[dict[str, str]], list[str], list[dict[str, str]]]:
    """Resolve per-tool resource mappings against discovered schemas."""
    resolved: list[dict[str, str]] = []
    unmatched: set[str] = set(config.resource_fields)
    invalid_fields: list[dict[str, str]] = []

    for tool in catalog:
        qualified = str(tool["name"])
        if qualified not in config.resource_fields:
            continue
        unmatched.discard(qualified)
        field = config.resource_fields[qualified]
        schema = tool.get("schema", {})
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if (
            not isinstance(properties, dict)
            or field not in properties
            or not isinstance(required, list)
            or field not in required
        ):
            invalid_fields.append({"tool": qualified, "field": field})
        else:
            resolved.append({"tool": qualified, "field": field})

    return (
        sorted(resolved, key=lambda item: (item["tool"], item["field"])),
        sorted(unmatched),
        sorted(invalid_fields, key=lambda item: (item["tool"], item["field"])),
    )


def _credential_policy_check(config: MCPProxyConfig) -> dict[str, Any]:
    """Require credential-shaped values to use environment indirection."""
    literal_bindings: list[dict[str, str]] = []
    for upstream in config.upstream_configs:
        for name in upstream.headers:
            if _credential_shaped_name(name):
                literal_bindings.append(
                    {"server_id": upstream.server_id, "binding": f"header:{name}"}
                )
        for name in upstream.env or {}:
            if _credential_shaped_name(name):
                literal_bindings.append(
                    {"server_id": upstream.server_id, "binding": f"env:{name}"}
                )
    literal_bindings.sort(key=lambda item: (item["server_id"], item["binding"]))
    return _check(
        "credential_indirection",
        not literal_bindings,
        "Credential-shaped bindings use environment-variable indirection."
        if not literal_bindings
        else "Move literal credential bindings to env_from_env or headers_from_env.",
        details={"literal_credential_bindings": literal_bindings},
    )


def _policy_checks(
    config: MCPProxyConfig, catalog: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    names = sorted(str(tool["name"]) for tool in catalog)
    allowed = sorted(name for name in names if config.is_allowed(name))
    prohibited = sorted(name for name in names if config.is_prohibited(name))
    uncovered = sorted(set(names) - set(allowed) - set(prohibited))
    conflicts = sorted(set(allowed) & set(prohibited))

    allowed_matched, allowed_unmatched = _matched_patterns(config, config.allowed_tools, names)
    prohibited_matched, prohibited_unmatched = _matched_patterns(
        config, config.prohibited_tools, names
    )
    read_only_matched, read_only_unmatched = _matched_patterns(
        config, config.read_only_tools, names
    )
    read_only = sorted(name for name in names if config.is_read_only(name))
    unsafe_read_only = sorted(
        name for name in read_only if name not in allowed or name in prohibited
    )

    resolved_destinations, unmatched_destination_tools, invalid_destination_fields = (
        _destination_bindings(config, catalog)
    )
    destination_patterns = {
        tool_name: sorted(patterns)
        for tool_name, patterns in sorted(config.allowed_destinations_by_tool.items())
    }
    empty_destination_patterns = sorted(
        [
            {"tool": tool_name, "pattern": pattern}
            for tool_name, patterns in destination_patterns.items()
            for pattern in patterns
            if not pattern.strip()
        ],
        key=lambda item: (item["tool"], item["pattern"]),
    )
    destination_errors: list[str] = []
    if unmatched_destination_tools:
        destination_errors.append("destination mapping references an undiscovered tool")
    if invalid_destination_fields:
        destination_errors.append(
            "destination mapping references a missing or optional schema property"
        )
    resolved_names = {item["tool"] for item in resolved_destinations}
    pattern_names = set(destination_patterns)
    if resolved_names != pattern_names:
        destination_errors.append(
            "destination fields and per-tool destination patterns are not equally bound"
        )
    if empty_destination_patterns:
        destination_errors.append("allowed_destinations contains an empty pattern")

    resolved_resources, unmatched_resource_tools, invalid_resource_fields = (
        _resource_bindings(config, catalog)
    )
    resource_patterns = {
        tool_name: sorted(patterns)
        for tool_name, patterns in sorted(config.allowed_resources_by_tool.items())
    }
    empty_resource_patterns = sorted(
        [
            {"tool": tool_name, "pattern": pattern}
            for tool_name, patterns in resource_patterns.items()
            for pattern in patterns
            if not pattern.strip()
        ],
        key=lambda item: (item["tool"], item["pattern"]),
    )
    resource_errors: list[str] = []
    if unmatched_resource_tools:
        resource_errors.append("resource mapping references an undiscovered tool")
    if invalid_resource_fields:
        resource_errors.append(
            "resource mapping references a missing or optional schema property"
        )
    resolved_resource_names = {item["tool"] for item in resolved_resources}
    if resolved_resource_names != set(resource_patterns):
        resource_errors.append(
            "resource fields and per-tool resource patterns are not equally bound"
        )
    if empty_resource_patterns:
        resource_errors.append("allowed_resources contains an empty pattern")

    return [
        _check(
            "allowed_policy_coverage",
            bool(config.allowed_tools) and not allowed_unmatched,
            "Allowed-tool patterns match the discovered catalog."
            if config.allowed_tools and not allowed_unmatched
            else "Every configured allowed-tool pattern must match a discovered tool.",
            details={
                "matched_patterns": allowed_matched,
                "unmatched_patterns": allowed_unmatched,
                "allowed_tools": allowed,
            },
        ),
        _check(
            "prohibited_policy_coverage",
            not prohibited_unmatched,
            "Prohibited-tool patterns are valid for the discovered catalog."
            if not prohibited_unmatched
            else "A configured prohibited-tool pattern does not match the discovered catalog.",
            details={
                "matched_patterns": prohibited_matched,
                "unmatched_patterns": prohibited_unmatched,
                "prohibited_tools": prohibited,
            },
        ),
        _check(
            "policy_partition",
            not uncovered and not conflicts,
            "Every discovered tool has exactly one allowed or prohibited policy classification."
            if not uncovered and not conflicts
            else "Discovered tools must be classified without allowed/prohibited overlap.",
            details={"uncovered_tools": uncovered, "conflicting_tools": conflicts},
        ),
        _check(
            "read_only_policy",
            not read_only_unmatched and not unsafe_read_only,
            "Read-only patterns resolve only to allowed, non-prohibited tools."
            if not read_only_unmatched and not unsafe_read_only
            else "Read-only entries must resolve to allowed, non-prohibited tools.",
            details={
                "matched_patterns": read_only_matched,
                "unmatched_patterns": read_only_unmatched,
                "read_only_tools": read_only,
                "unsafe_read_only_tools": unsafe_read_only,
            },
        ),
        _check(
            "destination_policy",
            not destination_errors,
            "Destination bindings and allow patterns are internally consistent."
            if not destination_errors
            else "Destination policy is not completely bound to discovered tool schemas.",
            details={
                "bindings": resolved_destinations,
                "allowed_destination_patterns_by_tool": destination_patterns,
                "unmatched_tool_keys": unmatched_destination_tools,
                "invalid_fields": invalid_destination_fields,
                "empty_patterns": empty_destination_patterns,
                "errors": destination_errors,
            },
        ),
        _check(
            "resource_policy",
            not resource_errors,
            "Resource bindings and allow values are internally consistent."
            if not resource_errors
            else "Resource policy is not completely bound to discovered tool schemas.",
            details={
                "bindings": resolved_resources,
                "allowed_resources_by_tool": resource_patterns,
                "unmatched_tool_keys": unmatched_resource_tools,
                "invalid_fields": invalid_resource_fields,
                "empty_values": empty_resource_patterns,
                "errors": resource_errors,
            },
        ),
    ]


def _schema_value(schema: dict[str, Any]) -> Any:
    """Synthesize a conservative JSON value or raise ValueError when unsafe."""
    if "const" in schema:
        return schema["const"]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    if "default" in schema:
        return schema["default"]
    if any(keyword in schema for keyword in ("$ref", "oneOf", "anyOf", "allOf", "not")):
        raise ValueError("composed or referenced schema")

    value_type = schema.get("type")
    if isinstance(value_type, list):
        non_null = [item for item in value_type if item != "null"]
        value_type = non_null[0] if len(non_null) == 1 else None
    if value_type == "object" or (
        value_type is None and isinstance(schema.get("properties"), dict)
    ):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list):
            raise ValueError("invalid object schema")
        return {
            name: _schema_value(properties[name])
            for name in sorted(required)
            if name in properties and isinstance(properties[name], dict)
        }
    if value_type == "array":
        items = schema.get("items")
        minimum = int(schema.get("minItems", 0))
        if minimum and not isinstance(items, dict):
            raise ValueError("array items are not synthesizable")
        return [_schema_value(items) for _ in range(minimum)] if minimum else []
    if value_type == "string":
        if "pattern" in schema or "format" in schema:
            raise ValueError("patterned or formatted string")
        minimum = int(schema.get("minLength", 0))
        maximum = schema.get("maxLength")
        value = "verification"
        if minimum > len(value):
            value += "x" * (minimum - len(value))
        if maximum is not None and len(value) > int(maximum):
            value = value[: int(maximum)]
        return value
    if value_type == "integer":
        return int(schema.get("minimum", schema.get("exclusiveMinimum", -1) + 1))
    if value_type == "number":
        return float(schema.get("minimum", schema.get("exclusiveMinimum", -1) + 1))
    if value_type == "boolean":
        return False
    if value_type == "null":
        return None
    raise ValueError("unsupported schema type")


def _synthesize_arguments(schema: dict[str, Any]) -> dict[str, Any] | None:
    try:
        value = _schema_value(schema)
        if not isinstance(value, dict):
            return None
        if list(Draft202012Validator(schema).iter_errors(value)):
            return None
        return value
    except (TypeError, ValueError, OverflowError):
        return None


def _glob_example(pattern: str) -> str:
    """Build a deterministic candidate for a simple fnmatch allow pattern."""
    result: list[str] = []
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "*":
            result.append("verification")
        elif character == "?":
            result.append("x")
        elif character == "[":
            end = pattern.find("]", index + 1)
            if end == -1:
                result.append("[")
            else:
                choices = pattern[index + 1:end]
                if choices.startswith("!"):
                    choices = choices[1:]
                result.append(next((item for item in choices if item.isalnum()), "x"))
                index = end
        else:
            result.append(character)
        index += 1
    return "".join(result)


async def _behavior_checks(
    client: Client,
    config: MCPProxyConfig,
    catalog: list[dict[str, Any]],
    invoked_tools: list[str],
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    invoked_tools.append("intentshield_create_run")
    block_run = await client.call_tool(
        "intentshield_create_run",
        {"user_intent": "Verify that an unregistered tool is blocked"},
    )
    block_run_id = (block_run.structured_content or {}).get("run_id")
    invoked_tools.append("intentshield_call")
    blocked = await client.call_tool(
        "intentshield_call",
        {
            "run_id": block_run_id,
            "tool_name": "__intentshield_verification_unregistered__",
            "arguments": {},
            "schema_hash": "verification-canary",
        },
    )
    blocked_payload = blocked.structured_content or {}
    block_passed = (
        blocked.is_error is not True
        and blocked_payload.get("decision") == "BLOCK"
        and blocked_payload.get("executed") is False
    )
    checks.append(
        _check(
            "blocked_call_zero_execution",
            block_passed,
            "An unregistered canary call was blocked without execution."
            if block_passed
            else "The gateway did not prove BLOCK with executed=false for an unregistered call.",
            details={
                "decision": blocked_payload.get("decision"),
                "executed": blocked_payload.get("executed"),
            },
        )
    )

    candidates: list[tuple[dict[str, Any], dict[str, Any]]] = []
    allowed_mutations: list[str] = []
    for tool in catalog:
        name = str(tool.get("name", ""))
        if (
            tool.get("mutation") is True
            and tool.get("available") is not False
            and config.is_allowed(name)
            and not config.is_prohibited(name)
            and isinstance(tool.get("schema"), dict)
        ):
            allowed_mutations.append(name)
            arguments = _synthesize_arguments(tool["schema"])
            if arguments is not None:
                resource_field = config.resource_fields.get(name)
                if resource_field:
                    allowed = sorted(config.allowed_resources_by_tool.get(name, set()))
                    if allowed:
                        arguments[resource_field] = allowed[0]
                destination_field = config.destination_fields.get(name)
                if destination_field:
                    patterns = config.allowed_destinations_by_tool.get(name, [])
                    if patterns:
                        arguments[destination_field] = _glob_example(patterns[0])
                if list(Draft202012Validator(tool["schema"]).iter_errors(arguments)):
                    continue
                candidates.append((tool, arguments))

    if not candidates:
        no_mutation_surface = not allowed_mutations
        checks.append(
            _check(
                "mutation_review_zero_execution",
                no_mutation_surface,
                "No allowed mutation exists, so no mutation REVIEW probe is required."
                if no_mutation_surface
                else "Allowed mutations exist but none had safely synthesizable verification arguments.",
                details={"allowed_mutations": sorted(allowed_mutations)},
            )
        )
        return checks

    tool, arguments = sorted(candidates, key=lambda item: item[0]["name"])[0]
    raw_name = str(tool["name"]).rsplit(":", 1)[-1].replace("_", " ")
    invoked_tools.append("intentshield_create_run")
    review_run = await client.call_tool(
        "intentshield_create_run",
        {"user_intent": f"Use {raw_name} for this verification request"},
    )
    review_run_id = (review_run.structured_content or {}).get("run_id")
    invoked_tools.append("intentshield_call")
    reviewed = await client.call_tool(
        "intentshield_call",
        {
            "run_id": review_run_id,
            "tool_name": tool["name"],
            "arguments": arguments,
            "schema_hash": tool["schema_hash"],
            "idempotency_key": f"verification-{review_run_id}",
            "dry_run": True,
        },
    )
    reviewed_payload = reviewed.structured_content or {}
    review_passed = (
        reviewed.is_error is not True
        and reviewed_payload.get("decision") == "REVIEW"
        and reviewed_payload.get("executed") is False
        and reviewed_payload.get("approval_id") is None
    )
    checks.append(
        _check(
            "mutation_review_zero_execution",
            review_passed,
            "A dry-run mutation required approval without execution or a persisted approval."
            if review_passed
            else "The gateway did not prove REVIEW with executed=false for a guarded mutation.",
            details={
                "tool": tool["name"],
                "decision": reviewed_payload.get("decision"),
                "executed": reviewed_payload.get("executed"),
                "approval_created": reviewed_payload.get("approval_id") is not None,
            },
        )
    )
    return checks


async def verify_mcp(
    config_path: str | Path,
    *,
    verification_mode: str = "in_process_preflight",
    url: str | None = None,
) -> dict[str, Any]:
    """Connect a real MCP client and return a stable, JSON-safe report."""
    if verification_mode not in _VERIFICATION_MODES:
        raise ValueError("unsupported verification mode")
    if verification_mode == "streamable_http_wire" and not url:
        raise ValueError("streamable_http_wire requires a URL")
    path = Path(config_path).expanduser().resolve()
    config = MCPProxyConfig.from_file(path)
    if verification_mode == "in_process_preflight":
        target: Any = create_proxy_mcp_server(config)
    elif verification_mode == "stdio_wire":
        target = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m",
                "intentshield.mcp_server",
                "--transport",
                "stdio",
                "--config",
                str(path),
            ],
        )
    else:
        target = url
    invoked_tools: list[str] = []

    async with Client(target) as client:
        downstream = await client.list_tools()
        downstream_names = sorted(tool.name for tool in downstream.tools)
        invoked_tools.append("intentshield_list_tools")
        catalog_result = await client.call_tool("intentshield_list_tools", {})
        if catalog_result.is_error:
            raise RuntimeError("IntentShield catalog call returned an MCP tool error")
        payload = catalog_result.structured_content
        if not isinstance(payload, dict) or not isinstance(payload.get("tools"), list):
            raise RuntimeError("IntentShield catalog response is missing structured tools")
        catalog = sorted(payload["tools"], key=lambda tool: str(tool.get("name", "")))

        behavioral_checks = await _behavior_checks(client, config, catalog, invoked_tools)

    checks: list[dict[str, Any]] = [
        _credential_policy_check(config),
        _check(
            "downstream_gateway_surface",
            set(downstream_names) == _GATEWAY_TOOLS,
            "The downstream client sees only the five IntentShield gateway tools."
            if set(downstream_names) == _GATEWAY_TOOLS
            else "The downstream MCP tool surface differs from the required gateway surface.",
            details={
                "expected": sorted(_GATEWAY_TOOLS),
                "discovered": downstream_names,
            },
        ),
        _check(
            "upstream_catalog_connection",
            bool(catalog),
            "The proxy connected to the upstream MCP server and discovered tools."
            if catalog
            else "The upstream MCP server returned an empty tool catalog.",
            details={"tool_count": len(catalog)},
        ),
    ]

    malformed: list[str] = []
    for item in catalog:
        if not isinstance(item, dict):
            malformed.append("<non-object-entry>")
        elif (
            not isinstance(item.get("name"), str)
            or not isinstance(item.get("schema"), dict)
            or not isinstance(item.get("schema_hash"), str)
            or not isinstance(item.get("mutation"), bool)
        ):
            malformed.append(str(item.get("name", "<missing-name>")))
    malformed.sort()
    drifted = sorted(
        str(item.get("name"))
        for item in catalog
        if isinstance(item, dict)
        and (item.get("schema_drift") is True or item.get("available") is False)
    )
    checks.append(
        _check(
            "catalog_integrity",
            not malformed and not drifted,
            "Every guarded catalog entry has a schema binding and is currently available."
            if not malformed and not drifted
            else "The guarded catalog contains malformed or unavailable entries.",
            details={"malformed_tools": malformed, "unavailable_or_drifted_tools": drifted},
        )
    )
    if not malformed:
        checks.extend(_policy_checks(config, catalog))
    else:
        checks.append(
            _check(
                "policy_coverage",
                False,
                "Policy coverage cannot be evaluated for a malformed catalog.",
            )
        )
    checks.extend(behavioral_checks)
    checks.append(
        _check(
            "non_executing_verification",
            all(name in _GATEWAY_TOOLS for name in invoked_tools),
            "Verification invoked gateway policy operations but no guarded upstream tool executed.",
            details={"invoked_gateway_tools": invoked_tools},
        )
    )

    failed = sum(item["status"] == "FAIL" for item in checks)
    warnings = sum(item["status"] == "WARN" for item in checks)
    passed = sum(item["status"] == "PASS" for item in checks)
    status = "PASS" if failed == 0 else "FAIL"
    next_actions = (
        [
            "Policy, behavioral guards, and MCP wiring verified; run the full adversarial harness before production use.",
            "Keep real API credentials in the upstream server environment, not in this report.",
        ]
        if status == "PASS"
        else [
            "Fix every FAIL check in the configuration and rerun verification.",
            "Do not connect an agent to this proxy until the report status is PASS.",
        ]
    )
    if status == "PASS" and verification_mode == "in_process_preflight":
        next_actions.insert(
            0,
            "This was an in-process preflight; rerun with --stdio or --url to verify a wire transport.",
        )

    return {
        "status": status,
        "summary": {
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "guarded_tools_discovered": len(catalog),
        },
        "checks": checks,
        "next_actions": next_actions,
        "artifacts": {
            "config": str(path),
            "verification_mode": verification_mode,
            "upstreams": [
                {"server_id": item.server_id, "transport": item.transport}
                for item in sorted(config.upstream_configs, key=lambda item: item.server_id)
            ],
            "downstream_tools": downstream_names,
            "guarded_catalog": [
                {
                    "name": item["name"],
                    "mutation": item["mutation"],
                    "schema_hash": item["schema_hash"],
                }
                for item in catalog
                if isinstance(item, dict)
                and all(key in item for key in ("name", "mutation", "schema_hash"))
            ],
        },
    }


def _failure_report(config_path: str | Path, exc: Exception) -> dict[str, Any]:
    path = Path(config_path).expanduser().resolve()
    return {
        "status": "FAIL",
        "summary": {
            "passed": 0,
            "failed": 1,
            "warnings": 0,
            "guarded_tools_discovered": 0,
        },
        "checks": [
            {
                "id": "verification_runtime",
                "status": "FAIL",
                "message": "The MCP verification run could not complete.",
                "details": {
                    "error_type": type(exc).__name__,
                    # Exception strings from configuration validators can echo
                    # literal API keys. Never include them in machine output.
                    "error": "Verification failed; diagnostic values are redacted.",
                },
            }
        ],
        "next_actions": [
            "Check the configuration and upstream MCP server, then rerun verification.",
            "Do not connect an agent to this proxy until the report status is PASS.",
        ],
        "artifacts": {"config": str(path)},
    }


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(
        description="Verify a real upstream MCP server through IntentShield without tool execution"
    )
    parser.add_argument("--config", required=True, help="IntentShield MCP proxy JSON config")
    transport = parser.add_mutually_exclusive_group()
    transport.add_argument(
        "--stdio",
        action="store_true",
        help="Launch IntentShield as a real stdio MCP subprocess",
    )
    transport.add_argument(
        "--url",
        help="Verify an already-running IntentShield Streamable HTTP MCP endpoint",
    )
    args = parser.parse_args(argv)
    mode = (
        "stdio_wire"
        if args.stdio
        else "streamable_http_wire"
        if args.url
        else "in_process_preflight"
    )
    try:
        report = asyncio.run(
            verify_mcp(args.config, verification_mode=mode, url=args.url)
        )
    except Exception as exc:  # CLI boundary: always emit a machine-readable report.
        report = _failure_report(args.config, exc)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
