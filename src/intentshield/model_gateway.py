"""Gemini adapter that turns user intent into one untrusted tool proposal.

Provider output stops at the IntentShield boundary.  This module never executes
tools and never supplies policy scores; it only normalizes a native function
call into a tool name and arguments for the deterministic gateway to evaluate.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import json
import os
import re
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from pydantic import BaseModel, ConfigDict

from .tools import ToolSpec


ModelProvider = Literal["gemini"]
_MAX_RESPONSE_BYTES = 2_000_000
_NO_ACTION_FUNCTION = "intentshield_no_action"
_SYSTEM_PROMPT = (
    "You are the proposal stage of an authorization gateway. Select exactly one "
    "available function that directly matches the user's stated intent and provide "
    "only the arguments needed for that function. Never claim that a tool ran, never "
    "expand the requested scope, and never provide authorization or security scores."
)


@dataclass(frozen=True)
class _ProviderSettings:
    key_env: str
    model_env: str
    default_model: str


_SETTINGS = _ProviderSettings(
    key_env="GEMINI_API_KEY",
    model_env="INTENTSHIELD_GEMINI_MODEL",
    default_model="gemini-3.5-flash",
)


class ModelProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: ModelProvider
    model: str
    tool_name: str
    arguments: dict[str, Any]


class ModelProviderStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: ModelProvider
    model: str
    configured: bool
    key_environment_variable: str


class ModelProviderError(RuntimeError):
    def __init__(self, code: str, message: str, *, provider: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.provider = provider

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message, "provider": self.provider}


_Transport = Callable[[str, Mapping[str, str], dict[str, Any], float], dict[str, Any]]


class ModelGateway:
    """Call configured Gemini and normalize its native function call."""

    def __init__(
        self,
        *,
        environ: Mapping[str, str] | None = None,
        transport: _Transport | None = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        self._environ = environ if environ is not None else os.environ
        self._transport = transport or _post_json
        self._timeout_seconds = timeout_seconds

    def statuses(self) -> list[ModelProviderStatus]:
        return [
            ModelProviderStatus(
                provider="gemini",
                model=self._model(),
                configured=bool(self._environ.get(_SETTINGS.key_env, "").strip()),
                key_environment_variable=_SETTINGS.key_env,
            )
        ]

    def propose(
        self,
        provider: ModelProvider,
        user_intent: str,
        registry: Mapping[str, ToolSpec],
    ) -> ModelProposal:
        api_key = self._environ.get(_SETTINGS.key_env, "").strip()
        if not api_key:
            raise ModelProviderError(
                "MODEL_PROVIDER_NOT_CONFIGURED",
                f"Gemini is not configured; set {_SETTINGS.key_env}",
                provider=provider,
            )
        if not registry:
            raise ModelProviderError(
                "MODEL_TOOLS_UNAVAILABLE",
                "No tools are registered for model proposals",
                provider=provider,
            )

        model = self._model()
        declarations, aliases = _tool_declarations(registry)
        raw = self._call_gemini(api_key, model, user_intent, declarations)
        calls = _gemini_calls(raw)

        if len(calls) != 1:
            raise ModelProviderError(
                "MODEL_RESPONSE_INVALID",
                f"Expected exactly one tool proposal from {provider}; received {len(calls)}",
                provider=provider,
            )
        alias, arguments = calls[0]
        if alias == _NO_ACTION_FUNCTION:
            raise ModelProviderError(
                "MODEL_NO_ACTION",
                "Gemini selected the safe no-action outcome",
                provider=provider,
            )
        tool_name = aliases.get(alias)
        if tool_name is None:
            raise ModelProviderError(
                "MODEL_RESPONSE_INVALID",
                f"{provider} proposed an unknown tool",
                provider=provider,
            )
        if not isinstance(arguments, dict):
            raise ModelProviderError(
                "MODEL_RESPONSE_INVALID",
                f"{provider} returned non-object tool arguments",
                provider=provider,
            )
        return ModelProposal(
            provider=provider,
            model=model,
            tool_name=tool_name,
            arguments=arguments,
        )

    def _model(self) -> str:
        return self._environ.get(_SETTINGS.model_env, "").strip() or _SETTINGS.default_model

    def _call_gemini(
        self,
        api_key: str,
        model: str,
        user_intent: str,
        declarations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{quote(model, safe='')}:generateContent"
        )
        payload = {
            "systemInstruction": {"parts": [{"text": _SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": user_intent}]}],
            "tools": [{"functionDeclarations": declarations}],
            "toolConfig": {
                "functionCallingConfig": {
                    "mode": "ANY",
                    "allowedFunctionNames": [item["name"] for item in declarations],
                }
            },
        }
        return self._request(
            "gemini", url, {"x-goog-api-key": api_key}, payload
        )

    def _request(
        self,
        provider: ModelProvider,
        url: str,
        headers: Mapping[str, str],
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            return self._transport(url, headers, payload, self._timeout_seconds)
        except ModelProviderError as exc:
            if exc.provider == "remote":
                raise ModelProviderError(
                    exc.code, exc.message, provider=provider
                ) from exc
            raise
        except Exception as exc:
            raise ModelProviderError(
                "MODEL_PROVIDER_UNAVAILABLE",
                f"{provider} request failed: {type(exc).__name__}",
                provider=provider,
            ) from exc


def _provider_schema(value: Any) -> Any:
    """Remove schema annotations that are unnecessary or inconsistently supported."""

    if isinstance(value, dict):
        return {
            key: _provider_schema(child)
            for key, child in value.items()
            if key not in {"$schema", "title", "default", "examples"}
        }
    if isinstance(value, list):
        return [_provider_schema(child) for child in value]
    return value


def _tool_declarations(
    registry: Mapping[str, ToolSpec],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    declarations: list[dict[str, Any]] = []
    aliases: dict[str, str] = {}
    for index, (tool_name, spec) in enumerate(sorted(registry.items())):
        base = re.sub(r"[^A-Za-z0-9_-]+", "_", tool_name).strip("_-") or f"tool_{index}"
        alias = base[:64]
        if alias in aliases:
            suffix = f"_{index}"
            alias = f"{alias[:64 - len(suffix)]}{suffix}"
        aliases[alias] = tool_name
        declarations.append({
            "name": alias,
            "description": spec.description,
            "parameters": _provider_schema(spec.public_schema),
        })
    declarations.append({
        "name": _NO_ACTION_FUNCTION,
        "description": (
            "Select this when the user did not ask to use any available tool, "
            "the request is ambiguous, or no tool is safely grounded."
        ),
        "parameters": {"type": "object", "properties": {}},
    })
    return declarations, aliases


def _gemini_calls(payload: dict[str, Any]) -> list[tuple[str, Any]]:
    calls: list[tuple[str, Any]] = []
    candidates = payload.get("candidates")
    if not isinstance(candidates, list):
        return calls
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        content = candidate.get("content")
        parts = content.get("parts") if isinstance(content, dict) else None
        if not isinstance(parts, list):
            continue
        for part in parts:
            function_call = part.get("functionCall") if isinstance(part, dict) else None
            if isinstance(function_call, dict):
                calls.append((function_call.get("name", ""), function_call.get("args", {})))
    return calls


def _post_json(
    url: str,
    headers: Mapping[str, str],
    payload: dict[str, Any],
    timeout_seconds: float,
) -> dict[str, Any]:
    request = Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - fixed HTTPS URLs
            body = response.read(_MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        message = _redact_message(
            _provider_error_message(exc.read(_MAX_RESPONSE_BYTES + 1)),
            headers.values(),
        )
        raise ModelProviderError(
            "MODEL_PROVIDER_HTTP_ERROR",
            f"Model provider returned HTTP {exc.code}: {message}",
            provider="remote",
        ) from exc
    except URLError as exc:
        raise ModelProviderError(
            "MODEL_PROVIDER_UNAVAILABLE",
            f"Model provider connection failed: {type(exc.reason).__name__}",
            provider="remote",
        ) from exc
    if len(body) > _MAX_RESPONSE_BYTES:
        raise ModelProviderError(
            "MODEL_RESPONSE_TOO_LARGE",
            "Model provider response exceeded the size limit",
            provider="remote",
        )
    try:
        decoded = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ModelProviderError(
            "MODEL_RESPONSE_INVALID",
            "Model provider returned invalid JSON",
            provider="remote",
        ) from exc
    if not isinstance(decoded, dict):
        raise ModelProviderError(
            "MODEL_RESPONSE_INVALID",
            "Model provider returned a non-object response",
            provider="remote",
        )
    return decoded


def _provider_error_message(body: bytes) -> str:
    try:
        payload = json.loads(body[:_MAX_RESPONSE_BYTES])
        error = payload.get("error") if isinstance(payload, dict) else None
        message = error.get("message") if isinstance(error, dict) else None
        if isinstance(message, str) and message.strip():
            return message.strip()[:500]
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    return "request rejected"


def _redact_message(message: str, values: Any) -> str:
    redacted = message
    secrets: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        stripped = value.strip()
        if stripped:
            secrets.add(stripped)
        if stripped.casefold().startswith("bearer ") and stripped[7:].strip():
            secrets.add(stripped[7:].strip())
    for secret in sorted(secrets, key=len, reverse=True):
        redacted = redacted.replace(secret, "[REDACTED]")
    return redacted
