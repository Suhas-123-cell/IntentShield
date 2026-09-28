from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def stable_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


class ReadInboxArgs(BaseModel):
    resource: str = Field(default="inbox", pattern="^inbox$")
    limit: int = Field(default=10, ge=1, le=100)


class SendEmailArgs(BaseModel):
    resource: str = Field(default="outbox", pattern="^outbox$")
    # A deliberately conservative syntactic check keeps the MVP dependency-free.
    # It is not intended to provide RFC-complete email validation.
    to: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=320)
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=10000)


class MCPArguments(BaseModel):
    """Lossless container for arguments already checked against MCP JSON Schema."""

    model_config = ConfigDict(extra="allow")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    args_model: type[BaseModel]
    mutation: bool
    destination_field: str | None
    executor: Callable[[BaseModel], dict[str, Any]]
    schema_override: dict[str, Any] | None = None
    public_schema_override: dict[str, Any] | None = None
    argument_validator: Callable[[dict[str, Any]], None] | None = None
    upstream_id: str | None = None
    upstream_tool_name: str | None = None
    resource_field: str | None = "resource"
    allowed_resources_override: set[str] | None = None
    allowed_destinations_override: list[str] | None = None
    grounding_terms: tuple[str, ...] = ()

    @property
    def schema(self) -> dict[str, Any]:
        return self.schema_override or self.args_model.model_json_schema()

    @property
    def schema_hash(self) -> str:
        return stable_hash(self.schema)

    @property
    def public_schema(self) -> dict[str, Any]:
        return self.public_schema_override or self.schema

    def parse_arguments(self, arguments: dict[str, Any]) -> BaseModel:
        if self.argument_validator is not None:
            self.argument_validator(arguments)
        return self.args_model.model_validate(arguments)


class SimulatedEmailTools:
    """Safe local tools. Execution effects remain inspectable in tests and demos."""

    def __init__(self) -> None:
        self.inbox = [
            {"from": "alice@example.com", "subject": "Status", "body": "Project is on track."},
            {"from": "ops@example.com", "subject": "Reminder", "body": "Review the audit queue."},
        ]
        self.outbox: list[dict[str, Any]] = []
        self.execution_count = 0

    def read_inbox(self, parsed: BaseModel) -> dict[str, Any]:
        args = ReadInboxArgs.model_validate(parsed)
        self.execution_count += 1
        return {"messages": self.inbox[: args.limit], "count": min(args.limit, len(self.inbox))}

    def send_email(self, parsed: BaseModel) -> dict[str, Any]:
        args = SendEmailArgs.model_validate(parsed)
        self.execution_count += 1
        message = args.model_dump()
        message["message_id"] = f"msg-{len(self.outbox) + 1:04d}"
        self.outbox.append(message)
        return {"message_id": message["message_id"], "status": "sent"}


def build_registry(email_tools: SimulatedEmailTools | None = None) -> dict[str, ToolSpec]:
    tools = email_tools or SimulatedEmailTools()
    return {
        "read_inbox": ToolSpec(
            name="read_inbox",
            description="Read messages from the simulated inbox.",
            args_model=ReadInboxArgs,
            mutation=False,
            destination_field=None,
            executor=tools.read_inbox,
            grounding_terms=("inbox", "email", "emails", "message", "messages"),
        ),
        "send_email": ToolSpec(
            name="send_email",
            description="Send an email through the simulated outbox.",
            args_model=SendEmailArgs,
            mutation=True,
            destination_field="to",
            executor=tools.send_email,
            grounding_terms=("email", "mail", "message"),
        ),
    }
