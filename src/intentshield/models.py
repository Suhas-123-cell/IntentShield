from __future__ import annotations

from enum import StrEnum
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Decision(StrEnum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class ReasonCode(StrEnum):
    ALLOW_POLICY_SATISFIED = "ALLOW_POLICY_SATISFIED"
    ALLOW_APPROVAL_VERIFIED = "ALLOW_APPROVAL_VERIFIED"
    ALLOW_IDEMPOTENT_REPLAY = "ALLOW_IDEMPOTENT_REPLAY"
    REVIEW_MUTATION_REQUIRES_APPROVAL = "REVIEW_MUTATION_REQUIRES_APPROVAL"
    BLOCK_TOOL_NOT_REGISTERED = "BLOCK_TOOL_NOT_REGISTERED"
    BLOCK_SCHEMA_DRIFT = "BLOCK_SCHEMA_DRIFT"
    BLOCK_TOOL_NOT_ALLOWED = "BLOCK_TOOL_NOT_ALLOWED"
    BLOCK_TOOL_PROHIBITED = "BLOCK_TOOL_PROHIBITED"
    BLOCK_INVALID_ARGUMENTS = "BLOCK_INVALID_ARGUMENTS"
    BLOCK_RESOURCE_OUT_OF_SCOPE = "BLOCK_RESOURCE_OUT_OF_SCOPE"
    BLOCK_DESTINATION_OUT_OF_SCOPE = "BLOCK_DESTINATION_OUT_OF_SCOPE"
    BLOCK_CALL_BUDGET_EXCEEDED = "BLOCK_CALL_BUDGET_EXCEEDED"
    BLOCK_INJECTION_DETECTED = "BLOCK_INJECTION_DETECTED"
    BLOCK_INTENT_MISMATCH = "BLOCK_INTENT_MISMATCH"
    BLOCK_IDEMPOTENCY_REQUIRED = "BLOCK_IDEMPOTENCY_REQUIRED"
    BLOCK_IDEMPOTENCY_CONFLICT = "BLOCK_IDEMPOTENCY_CONFLICT"
    BLOCK_APPROVAL_NOT_FOUND = "BLOCK_APPROVAL_NOT_FOUND"
    BLOCK_APPROVAL_NOT_APPROVED = "BLOCK_APPROVAL_NOT_APPROVED"
    BLOCK_APPROVAL_EXPIRED = "BLOCK_APPROVAL_EXPIRED"
    BLOCK_APPROVAL_REJECTED = "BLOCK_APPROVAL_REJECTED"
    BLOCK_APPROVAL_MISMATCH = "BLOCK_APPROVAL_MISMATCH"
    BLOCK_APPROVAL_CONSUMED = "BLOCK_APPROVAL_CONSUMED"
    BLOCK_IDEMPOTENCY_IN_PROGRESS = "BLOCK_IDEMPOTENCY_IN_PROGRESS"
    BLOCK_EXECUTION_IN_DOUBT = "BLOCK_EXECUTION_IN_DOUBT"
    BLOCK_SECURITY_AGENTS = "BLOCK_SECURITY_AGENTS"


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    schema_hash: str | None = None
    idempotency_key: str | None = None
    approval_id: str | None = None

    @model_validator(mode="after")
    def bound_arguments(self) -> "ToolCall":
        encoded = json.dumps(self.arguments, separators=(",", ":"), ensure_ascii=True)
        if len(encoded.encode("utf-8")) > 262_144:
            raise ValueError("tool arguments exceed the 256 KiB limit")

        item_count = 0

        def visit(value: Any, depth: int) -> None:
            nonlocal item_count
            if depth > 16:
                raise ValueError("tool arguments exceed the nesting limit")
            if isinstance(value, dict):
                item_count += len(value)
                for child in value.values():
                    visit(child, depth + 1)
            elif isinstance(value, list):
                item_count += len(value)
                for child in value:
                    visit(child, depth + 1)
            if item_count > 10_000:
                raise ValueError("tool arguments exceed the item limit")

        visit(self.arguments, 0)
        return self


class GatewayResult(BaseModel):
    run_id: str
    decision: Decision
    reason_codes: list[ReasonCode]
    tool_name: str
    arguments: dict[str, Any]
    approval_id: str | None = None
    executed: bool = False
    replayed: bool = False
    result: dict[str, Any] | None = None
    injection_score: float = Field(ge=0.0, le=1.0)
    intent_alignment: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=1.0)
    security_assessment: dict[str, Any] | None = None


class RunCreateRequest(BaseModel):
    user_intent: str = Field(min_length=1, max_length=2000)
    scenario: Literal["benign", "injection", "review"] | None = None
    call: ToolCall | None = None


class ModelRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_intent: str = Field(min_length=1, max_length=2000)
    provider: Literal["gemini"] = "gemini"


class ApprovalDecisionRequest(BaseModel):
    decision: Literal["approve", "reject"]


class PolicyContext(BaseModel):
    run_id: str
    user_intent: str
    call_index: int = Field(default=1, ge=1)
    call: ToolCall
    injection_score: float = Field(ge=0.0, le=1.0)
    intent_alignment: float = Field(ge=0.0, le=1.0)
    approval_verified: bool = False
    security_disposition: Literal["CLEAR_FOR_POLICY", "REVIEW", "BLOCK"] = (
        "CLEAR_FOR_POLICY"
    )
