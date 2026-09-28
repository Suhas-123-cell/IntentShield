from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from .models import Decision, PolicyContext, ReasonCode
from .tools import ToolSpec


class PolicyConfig(BaseModel):
    allowed_tools: set[str] = Field(default_factory=set)
    prohibited_tools: set[str] = Field(default_factory=set)
    allowed_resources: set[str] = Field(default_factory=set)
    allowed_destinations: list[str] = Field(default_factory=list)
    call_budget: int = Field(default=4, ge=1)
    injection_block_threshold: float = Field(default=0.75, ge=0, le=1)
    minimum_intent_alignment: float = Field(default=0.60, ge=0, le=1)
    approval_ttl_seconds: int = Field(default=600, ge=1)

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyConfig":
        return cls.model_validate(json.loads(Path(path).read_text()))


class PolicyOutcome(BaseModel):
    decision: Decision
    reason_codes: list[ReasonCode]
    parsed_arguments: dict[str, Any] | None = None


class PolicyEngine:
    """Pure, deterministic policy evaluation. It never executes a tool."""

    def __init__(self, config: PolicyConfig, registry: dict[str, ToolSpec]) -> None:
        self.config = config
        self.registry = registry

    def evaluate(self, context: PolicyContext) -> PolicyOutcome:
        call = context.call
        spec = self.registry.get(call.tool_name)
        if spec is None:
            return self._block(ReasonCode.BLOCK_TOOL_NOT_REGISTERED)
        if call.tool_name in self.config.prohibited_tools:
            return self._block(ReasonCode.BLOCK_TOOL_PROHIBITED)
        if call.tool_name not in self.config.allowed_tools:
            return self._block(ReasonCode.BLOCK_TOOL_NOT_ALLOWED)
        if call.schema_hash != spec.schema_hash:
            return self._block(ReasonCode.BLOCK_SCHEMA_DRIFT)
        if context.call_index > self.config.call_budget:
            return self._block(ReasonCode.BLOCK_CALL_BUDGET_EXCEEDED)
        if context.injection_score >= self.config.injection_block_threshold:
            return self._block(ReasonCode.BLOCK_INJECTION_DETECTED)

        if spec.resource_field:
            raw_resource = call.arguments.get(spec.resource_field)
            if (
                spec.resource_field not in call.arguments
                or not isinstance(raw_resource, str)
                or not raw_resource.strip()
            ):
                return self._block(ReasonCode.BLOCK_RESOURCE_OUT_OF_SCOPE)
        if spec.destination_field:
            raw_destination = call.arguments.get(spec.destination_field)
            if (
                spec.destination_field not in call.arguments
                or not isinstance(raw_destination, str)
                or not raw_destination.strip()
            ):
                return self._block(ReasonCode.BLOCK_DESTINATION_OUT_OF_SCOPE)

        try:
            parsed_model = spec.parse_arguments(call.arguments)
        except (ValidationError, ValueError):
            return self._block(ReasonCode.BLOCK_INVALID_ARGUMENTS)
        parsed = parsed_model.model_dump(mode="json")

        if spec.resource_field:
            resource = parsed.get(spec.resource_field)
            allowed_resources = (
                spec.allowed_resources_override
                if spec.allowed_resources_override is not None
                else self.config.allowed_resources
            )
            if not isinstance(resource, str) or (
                allowed_resources and resource not in allowed_resources
            ):
                return self._block(ReasonCode.BLOCK_RESOURCE_OUT_OF_SCOPE)
        if spec.destination_field:
            destination = parsed.get(spec.destination_field)
            allowed_destinations = (
                spec.allowed_destinations_override
                if spec.allowed_destinations_override is not None
                else self.config.allowed_destinations
            )
            if not isinstance(destination, str) or not any(
                    fnmatch.fnmatchcase(destination, pattern)
                    for pattern in allowed_destinations
                ):
                return self._block(ReasonCode.BLOCK_DESTINATION_OUT_OF_SCOPE)

        if context.intent_alignment < self.config.minimum_intent_alignment:
            return self._block(ReasonCode.BLOCK_INTENT_MISMATCH)
        if context.security_disposition == "BLOCK":
            return self._block(ReasonCode.BLOCK_SECURITY_AGENTS)

        if spec.mutation and not call.idempotency_key:
            return self._block(ReasonCode.BLOCK_IDEMPOTENCY_REQUIRED)
        if spec.mutation and not context.approval_verified:
            return PolicyOutcome(
                decision=Decision.REVIEW,
                reason_codes=[ReasonCode.REVIEW_MUTATION_REQUIRES_APPROVAL],
                parsed_arguments=parsed,
            )
        return PolicyOutcome(
            decision=Decision.ALLOW,
            reason_codes=[
                ReasonCode.ALLOW_APPROVAL_VERIFIED if spec.mutation else ReasonCode.ALLOW_POLICY_SATISFIED
            ],
            parsed_arguments=parsed,
        )

    @staticmethod
    def _block(reason: ReasonCode) -> PolicyOutcome:
        return PolicyOutcome(decision=Decision.BLOCK, reason_codes=[reason])
