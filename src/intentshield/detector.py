from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from .models import ToolCall
from .tools import canonical_json


class SecuritySignals(BaseModel):
    injection_score: float = Field(ge=0.0, le=1.0)
    intent_alignment: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=1.0)


_INJECTION_PATTERNS = (
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?",
    r"(?:system|developer)\s+(?:prompt|message|instructions?)",
    r"(?:reveal|steal|exfiltrat|leak|upload)\w*\s+(?:the\s+)?(?:secret|credential|token|password|data)",
    r"(?:send|forward|email)\s+.*(?:attacker|evil|unauthori[sz]ed)",
    r"\bexfiltrat(?:e|ion|ing)\b",
)


def _negates(text: str, action: str) -> bool:
    return bool(re.search(
        rf"\b(?:do\s+not|don't|never|must\s+not|stop)\b[^.!?]{{0,50}}\b(?:{action})\w*\b",
        text,
    ))


def _alignment(user_intent: str, tool_name: str, arguments: dict[str, Any]) -> float:
    text = user_intent.lower()
    if tool_name == "read_inbox":
        if _negates(text, r"read|check|open|access|view"):
            return 0.05
        if any(word in text for word in ("read", "check", "show", "view", "list", "inbox", "email")):
            return 0.95
        return 0.30
    if tool_name == "send_email":
        if _negates(text, r"send|email|message|write|forward"):
            return 0.05
        if not any(word in text for word in ("send", "email", "message", "write", "forward")):
            return 0.15
        destination = str(arguments.get("to", "")).lower().split("@", 1)[0]
        if destination and destination in text:
            return 0.98
        return 0.75

    # Namespaced MCP tools use ``server_id:tool_name``. Match the operator-
    # selected tool's action family against the persisted user intent without
    # trusting an upstream description or annotations.
    raw_name = tool_name.rsplit(":", 1)[-1].lower()
    name_tokens = set(re.findall(r"[a-z0-9]+", raw_name))
    intent_tokens = set(re.findall(r"[a-z0-9]+", text))
    action_families = (
        ({"read", "get", "list", "search", "find", "show", "view", "fetch"},
         {"read", "get", "list", "search", "find", "show", "view", "check", "fetch"}),
        ({"send", "create", "write", "update", "append", "delete", "remove", "move"},
         {"send", "create", "write", "update", "append", "delete", "remove", "move"}),
    )
    for tool_verbs, intent_verbs in action_families:
        matched = name_tokens & tool_verbs
        if matched:
            verb_pattern = "|".join(sorted(matched))
            if _negates(text, verb_pattern):
                return 0.05
            if intent_tokens & intent_verbs:
                return 0.90
    meaningful = name_tokens - {"tool", "api", "mcp"}
    if meaningful & intent_tokens:
        return 0.80
    return 0.50


def compute_security_signals(user_intent: str, call: ToolCall, *, mutation: bool = False) -> SecuritySignals:
    """Compute trusted, deterministic signals from intent and the proposed call.

    This conservative heuristic is the offline MVP detector boundary. A local ML
    detector may replace its internals later, but callers cannot provide scores.
    """
    content = f"{call.tool_name}\n{canonical_json(call.arguments)}".lower()
    hits = sum(bool(re.search(pattern, content)) for pattern in _INJECTION_PATTERNS)
    injection = min(0.99, 0.05 + 0.47 * hits) if hits else 0.02
    alignment = _alignment(user_intent, call.tool_name, call.arguments)
    mutation_risk = 0.35 if mutation else 0.0
    risk = max(injection, 1.0 - alignment, mutation_risk)
    return SecuritySignals(
        injection_score=round(injection, 4),
        intent_alignment=round(alignment, 4),
        risk_score=round(risk, 4),
    )
