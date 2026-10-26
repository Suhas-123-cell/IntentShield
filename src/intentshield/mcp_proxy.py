"""Policy-bound bridge from IntentShield to a real upstream MCP server."""

from __future__ import annotations

import asyncio
import fnmatch
import itertools
import json
from pathlib import Path
import re
from typing import Any, Callable

from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .injection_classifier import InjectionClassifier
from .judge import Judge
from .mcp_inspect import (
    authority_values, distinctive_values, scan_description, scan_output, scan_output_collapsed, scan_server,
    schema_text, self_disclosure_fields, sourced_from, tool_text,
)
from .mcp_upstream import MCPCallResult, MCPTool, MCPUpstream, MCPUpstreamConfig
from .models import GatewayResult, ReasonCode, ToolCall
from .policy import PolicyConfig
from .service import IntentShieldService
from .storage import Storage
from .tools import MCPArguments, ToolSpec, catch_all_destination, stable_hash


class MCPProxyConfig(BaseModel):
    """Local trust policy plus connection details for one upstream server."""

    model_config = ConfigDict(extra="forbid")

    # ``upstream`` remains accepted for existing single-server configs.
    upstream: MCPUpstreamConfig | None = None
    upstreams: list[MCPUpstreamConfig] = Field(default_factory=list)
    database_path: str = "intentshield-mcp.db"
    allowed_tools: list[str] = Field(default_factory=list)
    prohibited_tools: list[str] = Field(default_factory=list)
    read_only_tools: list[str] = Field(default_factory=list)
    resource_fields: dict[str, str] = Field(default_factory=dict)
    destination_fields: dict[str, str] = Field(default_factory=dict)
    allowed_resources_by_tool: dict[str, set[str]] = Field(default_factory=dict)
    allowed_destinations_by_tool: dict[str, list[str]] = Field(default_factory=dict)
    grounding_terms_by_tool: dict[str, set[str]] = Field(default_factory=dict)
    expose_upstream_descriptions: bool = False
    # Tools whose description or schema text matches poisoning rules are shown
    # as unavailable and every call to them is blocked.
    quarantine_poisoned_tools: bool = True
    # A recipient, URL, account or path whose only source is a tool output sends the
    # call to review, whether or not the scanners flagged that output.
    review_output_sourced_arguments: bool = True
    # Optional local classifier (``intentshield.injection_training``) run on descriptions
    # and outputs the rules pass. A hit withholds the description or flags the output
    # and sends affected calls to review; it never allows anything.
    injection_classifier_dir: str | None = None
    # Optional LLM judge (``judge.py``): "groq" or "gemini", optionally ":model". It reads
    # descriptions the rules pass, and each read-only call that would otherwise run against
    # the user's request; an objection withholds the tool or sends the call to review.
    # It never allows anything. The key comes from GROQ_API_KEY or GEMINI_API_KEY.
    judge: str | None = None
    # Optional Llama Prompt Guard 2 on Groq (``prompt_guard.py``): a model id from
    # ``prompt_guard.MODELS``. Read like the classifier, on descriptions and outputs the rules
    # pass; evidence only. The key comes from GROQ_API_KEY.
    prompt_guard: str | None = None
    # Optional exemplar detector (``exemplars.py``): an index dir from
    # ``python -m intentshield.exemplars seed`` and the embedder it was built with.
    exemplar_index_dir: str | None = None
    embedder_dir: str = "artifacts/embedder-e5-small"
    # Learning from operator labels into the exemplar index (``learning.py``): JSONL files of
    # labelled texts whose ``validation`` rows are the gate's regression set. Empty: no learning.
    learning_regression: list[str] = Field(default_factory=list)
    # Rule induction (``signatures.py``): a local Ollama model that proposes regexes for confirmed
    # injections. Proposals that pass the gates wait for the operator; approved rules are a learned
    # detector. Needs learning. None: no proposals (approved rules still load).
    signature_model: str | None = None
    signature_host: str = "http://127.0.0.1:11434"
    # Transparent mode: list only intentshield_find_tools plus ``pinned_tools`` (qualified-name
    # patterns); each search unlocks its matches and tells the client the list changed, so
    # unused tool descriptions are not sent with every model request. Not a security
    # boundary: every visible tool stays callable by name.
    tool_routing: bool = False
    pinned_tools: list[str] = Field(default_factory=list)
    # Transparent mode writes the visible tool names and descriptions here at start, for the
    # hooks' per-prompt tool hint (``intentshield-hook --catalog``).
    tool_catalog_dir: str | None = None
    allowed_resources: set[str] = Field(default_factory=set)
    allowed_destinations: list[str] = Field(default_factory=list)
    call_budget: int = Field(default=8, ge=1)
    injection_block_threshold: float = Field(default=0.75, ge=0, le=1)
    minimum_intent_alignment: float = Field(default=0.60, ge=0, le=1)
    # Ungrounded reads pass (evidence, not a veto); mutations and negated reads stay strict.
    lenient_reads: bool = False
    approval_ttl_seconds: int = Field(default=600, ge=1)
    max_upstreams: int = Field(default=8, ge=1, le=64)
    max_total_tools: int = Field(default=2_000, ge=1, le=100_000)
    max_total_schema_bytes: int = Field(default=16_000_000, ge=1, le=128_000_000)
    max_result_bytes: int = Field(default=4_000_000, ge=1, le=64_000_000)
    max_result_content_blocks: int = Field(default=1_000, ge=1, le=100_000)

    @model_validator(mode="after")
    def validate_upstreams(self) -> "MCPProxyConfig":
        if self.upstream is not None and self.upstreams:
            raise ValueError("Configure either upstream or upstreams, not both")
        configured = self.upstream_configs
        if not configured:
            raise ValueError("At least one upstream MCP server is required")
        if len(configured) > self.max_upstreams:
            raise ValueError("Configured upstream count exceeds max_upstreams")
        server_ids = [item.server_id for item in configured]
        if len(server_ids) != len(set(server_ids)):
            raise ValueError("Every upstream MCP server_id must be unique")
        scoped_keys = (
            set(self.resource_fields)
            | set(self.destination_fields)
            | set(self.allowed_resources_by_tool)
            | set(self.allowed_destinations_by_tool)
            | set(self.grounding_terms_by_tool)
        )
        if any(":" not in key for key in scoped_keys):
            raise ValueError("Resource and destination policies require qualified server:tool keys")
        if self.allowed_resources or self.allowed_destinations:
            raise ValueError(
                "MCP scope policy must use allowed_resources_by_tool and "
                "allowed_destinations_by_tool, not global allowlists"
            )
        if set(self.resource_fields) != set(self.allowed_resources_by_tool):
            raise ValueError(
                "Every resource_fields entry needs one allowed_resources_by_tool entry"
            )
        if set(self.destination_fields) != set(self.allowed_destinations_by_tool):
            raise ValueError(
                "Every destination_fields entry needs one allowed_destinations_by_tool entry"
            )
        if any(not values for values in self.allowed_resources_by_tool.values()):
            raise ValueError("Per-tool allowed resource sets cannot be empty")
        if any(not values for values in self.allowed_destinations_by_tool.values()):
            raise ValueError("Per-tool allowed destination lists cannot be empty")
        if any(catch_all_destination(p) for values in self.allowed_destinations_by_tool.values() for p in values):
            raise ValueError("Per-tool allowed destination lists must not contain a catch-all pattern")
        if any(not values for values in self.grounding_terms_by_tool.values()):
            raise ValueError("Per-tool grounding term sets cannot be empty")
        return self

    @property
    def upstream_configs(self) -> list[MCPUpstreamConfig]:
        return self.upstreams or ([self.upstream] if self.upstream is not None else [])

    @classmethod
    def from_file(cls, path: str | Path) -> "MCPProxyConfig":
        return cls.model_validate(json.loads(Path(path).read_text()))

    @staticmethod
    def _matches(name: str, patterns: list[str]) -> bool:
        # Patterns are intentionally matched against qualified names only.
        # An unqualified ``read`` rule must not accidentally authorize the same
        # raw tool name on every connected server.
        return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)

    def is_pinned(self, name: str) -> bool:
        return self._matches(name, self.pinned_tools)

    def is_allowed(self, name: str) -> bool:
        return self._matches(name, self.allowed_tools)

    def is_prohibited(self, name: str) -> bool:
        return self._matches(name, self.prohibited_tools)

    def is_read_only(self, name: str) -> bool:
        # MCP annotations are untrusted hints. Read-only status must come from
        # this operator-owned configuration.
        return self._matches(name, self.read_only_tools)


def _fingerprint(tool: MCPTool) -> str:
    return stable_hash(tool.model_dump(
        mode="json", include={"title", "description", "input_schema", "output_schema", "annotations"}
    ))


class MCPRemoteToolError(RuntimeError):
    """An upstream tool returned an MCP-level error result."""


_SCHEMA_ANNOTATIONS = {
    "title", "description", "$comment", "examples", "default",
    "deprecated", "readOnly", "writeOnly",
}
_SAFE_TOOL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


# JSON Schema keywords that carry validation structure (2020-12, plus draft-07's dependencies,
# additionalItems and definitions, and OpenAPI's nullable). Anything else an upstream server adds,
# x-* keys and unknown keywords included, is free text the agent would read unscanned.
_SCHEMA_KEYWORDS = frozenset({
    "type", "enum", "const", "properties", "patternProperties", "additionalProperties", "required",
    "items", "prefixItems", "additionalItems", "contains", "minContains", "maxContains", "minItems",
    "maxItems", "uniqueItems", "minLength", "maxLength", "pattern", "format", "minimum", "maximum",
    "exclusiveMinimum", "exclusiveMaximum", "multipleOf", "minProperties", "maxProperties",
    "dependentRequired", "dependentSchemas", "dependencies", "propertyNames", "allOf", "anyOf", "oneOf",
    "not", "if", "then", "else", "$ref", "$defs", "definitions", "$schema", "$id", "$anchor",
    "$dynamicRef", "$dynamicAnchor", "unevaluatedItems", "unevaluatedProperties", "contentEncoding",
    "contentMediaType", "contentSchema", "nullable",
})


def _public_schema(schema: dict[str, Any], annotations: bool = False) -> dict[str, Any]:
    """Validation structure only: an allowlist, so text in a keyword nobody scans never reaches
    the agent. ``annotations`` keeps the ones ``tool_text`` scanned (transparent mode shows them)."""
    result: dict[str, Any] = {}
    schema_maps = {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}
    schema_lists = {"allOf", "anyOf", "oneOf", "prefixItems", "items"}
    for key, value in schema.items():
        if key in _SCHEMA_ANNOTATIONS:
            if annotations:
                result[key] = value
        elif key not in _SCHEMA_KEYWORDS:
            continue
        elif key in schema_maps and isinstance(value, dict):
            result[key] = {
                name: _public_schema(child, annotations) if isinstance(child, dict) else child
                for name, child in value.items()
            }
        elif key in schema_lists and isinstance(value, list):
            result[key] = [
                _public_schema(child, annotations) if isinstance(child, dict) else child for child in value
            ]
        elif isinstance(value, dict) and key not in {"const", "enum"}:
            result[key] = _public_schema(value, annotations)
        else:
            result[key] = value
    return result


class MCPProxyRuntime:
    """Own an upstream connection and a policy service bound to its schemas."""

    def __init__(
        self,
        config: MCPProxyConfig,
        upstream: MCPUpstream | None = None,
        upstreams: dict[str, MCPUpstream] | None = None,
    ) -> None:
        self.config = config
        if upstream is not None and upstreams is not None:
            raise ValueError("Pass upstream or upstreams, not both")
        if upstream is not None:
            server_id = config.upstream_configs[0].server_id
            self.upstreams = {server_id: upstream}
        elif upstreams is not None:
            expected = {item.server_id for item in config.upstream_configs}
            if set(upstreams) != expected:
                raise ValueError("Injected upstreams must exactly match configured server_ids")
            self.upstreams = dict(upstreams)
        else:
            self.upstreams = {
                item.server_id: MCPUpstream(item) for item in config.upstream_configs
            }
        self.service: IntentShieldService | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._tools: list[MCPTool] = []
        self._bound_fingerprints: dict[str, str] = {}
        self._drifted_tools: set[str] = set()
        self._quarantined: dict[str, list[str]] = {}
        self._description_values: dict[str, set[str]] = {}
        # Parameters asking the agent for its model, prompt or conversation: hidden from
        # the agent and always sent upstream empty.
        self._redacted: dict[str, set[str]] = {}
        self._visible_schemas: dict[str, dict[str, Any]] = {}
        # Distinctive values from outputs that carried injection text. Kept for the whole
        # session, not per run: the agent opens runs itself, so a fresh run must not wash
        # a value clean.
        self._tainted: set[str] = set()
        # Runs whose intent repeats a flagged output; the agent wrote that intent, not the user.
        self._untrusted_intents: set[str] = set()
        self._injection_seen = False
        # Recipients, URLs, accounts and paths seen in any tool output, kept for the session
        # like ``_tainted`` (a fresh run must not wash them) and bounded, oldest first out.
        self._observed: dict[str, None] = {}
        self._classifier = (InjectionClassifier(config.injection_classifier_dir)
                            if config.injection_classifier_dir else None)
        if self._classifier and not self._classifier.ready:
            raise ValueError(f"injection_classifier_dir is not usable: {self._classifier.reason}")
        # Learned detectors, in order: (name, flags(text, kind)), kind "description" or "output".
        # Each reads text the rules passed.
        self._detectors: list[tuple[str, Callable[[str, str], bool | None]]] = []
        if self._classifier:
            classifier = self._classifier
            self._detectors.append(("injection_classifier", lambda text, kind: classifier.flags(text)))
        self._prompt_guard: Any = None  # kept so a benchmark can count its errors, like the judge's
        if config.prompt_guard:
            from .prompt_guard import PromptGuard
            guard = self._prompt_guard = PromptGuard(config.prompt_guard)
            self._detectors.append(("prompt_guard", lambda text, kind: guard.flags(text)))
        self._learner: Any = None
        self._rules: Any = None
        self._rule_benign: list[str] = []
        if config.exemplar_index_dir:
            from .exemplars import Embedder, ExemplarIndex
            embedder = Embedder(config.embedder_dir)
            if not embedder.ready:
                raise ValueError(f"embedder_dir is not usable: {embedder.reason}")
            exemplars = ExemplarIndex.load(Path(config.exemplar_index_dir), embedder)
            self._detectors.append(("exemplars", exemplars.flags))
            if config.learning_regression:
                from .learning import Learner, LearningStore, Regression
                rows = [json.loads(line) for path in config.learning_regression
                        for line in Path(path).read_text().splitlines() if line.strip()]
                regression = Regression.from_rows([r for r in rows if r.get("split") == "validation"],
                                                  exemplars, cache=Path(config.exemplar_index_dir))
                self._learner = Learner(exemplars, LearningStore(config.database_path), regression)
                from .signatures import LearnedRules, RuleStore
                self._rules = LearnedRules(RuleStore(config.database_path))
                rules = self._rules
                self._detectors.append(("learned_rules", lambda text, kind: rules.flags(text)))
                # Benign texts a proposed rule must not match: every split but the held-out test.
                self._rule_benign = [r["text"] for r in rows if r.get("label") == "data" and r.get("split") != "test"]
        elif config.learning_regression:
            raise ValueError("learning_regression needs exemplar_index_dir")
        # run_id -> recent tool outputs, so a reviewed call can be linked to the text it reused.
        self._outputs: dict[str, list[dict[str, Any]]] = {}
        self._judge = Judge.from_spec(config.judge) if config.judge else None
        # Tools whose description passed the rules but not the classifier or the judge.
        self._suspect_tools: dict[str, ReasonCode] = {}
        self._suspect_values: set[str] = set()

    async def __aenter__(self) -> "MCPProxyRuntime":
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        await self.close()

    async def connect(self) -> None:
        if self.service is not None:
            return
        self._loop = asyncio.get_running_loop()
        try:
            for upstream in self.upstreams.values():
                await upstream.connect()
            tools = await self._list_all_tools()
            registry = self._build_registry(tools)
        except Exception:
            self._loop = None
            await self._close_upstreams()
            raise
        policy = PolicyConfig(
            allowed_tools={name for name in registry if self.config.is_allowed(name)},
            prohibited_tools={name for name in registry if self.config.is_prohibited(name)},
            allowed_resources=set(),
            allowed_destinations=[],
            call_budget=self.config.call_budget,
            injection_block_threshold=self.config.injection_block_threshold,
            minimum_intent_alignment=self.config.minimum_intent_alignment,
            lenient_reads=self.config.lenient_reads,
            approval_ttl_seconds=self.config.approval_ttl_seconds,
        )
        self._tools = tools
        self._bound_fingerprints = {tool.qualified_name: _fingerprint(tool) for tool in tools}
        self.service = IntentShieldService(
            Storage(self.config.database_path), policy, registry=registry,
            pre_policy_check=self._pre_policy_check, result_inspector=self._inspect_result,
        )
        if self._quarantined:
            self.service.storage.add_event(
                self._ensure_system_run(), "MCP_TOOLS_QUARANTINED", {"tools": self._quarantined}
            )
        if self._redacted:
            self.service.storage.add_event(
                self._ensure_system_run(), "MCP_SELF_DISCLOSURE_FIELDS",
                {"tools": {name: sorted(fields) for name, fields in self._redacted.items()}},
            )

    async def close(self) -> None:
        self.service = None
        self._loop = None
        await self._close_upstreams()

    async def _close_upstreams(self) -> None:
        # MCP transport context managers are task-affine. Close them in the
        # same lifespan task that opened them rather than child gather tasks.
        errors: list[BaseException] = []
        for upstream in reversed(tuple(self.upstreams.values())):
            try:
                await upstream.close()
            except BaseException as exc:
                errors.append(exc)
        if errors:
            raise RuntimeError(f"Failed to close {len(errors)} upstream MCP connection(s)") from errors[0]

    async def _list_all_tools(self) -> list[MCPTool]:
        pages = await asyncio.gather(
            *(upstream.list_tools() for upstream in self.upstreams.values())
        )
        tools = [tool for page in pages for tool in page]
        if len(tools) > self.config.max_total_tools:
            raise ValueError("Combined MCP catalog exceeds max_total_tools")
        total_schema_bytes = sum(
            len(json.dumps(tool.input_schema, separators=(",", ":")).encode())
            for tool in tools
        )
        if total_schema_bytes > self.config.max_total_schema_bytes:
            raise ValueError("Combined MCP catalog exceeds max_total_schema_bytes")
        return tools

    def _build_registry(self, tools: list[MCPTool]) -> dict[str, ToolSpec]:
        registry: dict[str, ToolSpec] = {}
        self._quarantined, self._description_values, self._redacted = {}, {}, {}
        # An instruction split across one server's tools quarantines all of them.
        for server_id in dict.fromkeys(tool.server_id for tool in tools):
            own = [tool for tool in tools if tool.server_id == server_id]
            split = scan_server(tool_text(t.description, t.input_schema, t.title) for t in own)
            if split and self.config.quarantine_poisoned_tools:
                self._quarantined.update({tool.qualified_name: list(split) for tool in own})
        for tool in tools:
            qualified = tool.qualified_name
            # Untrusted text: scanned for poisoning; a reference to another
            # server's tool name is shadowing.
            text = tool_text(tool.description, tool.input_schema, tool.title)
            if extra := schema_text(tool.input_schema):
                text = f"{text}\n{extra}"
            own = {other.name for other in tools if other.server_id == tool.server_id}
            findings = scan_description(
                text, {other.name for other in tools if other.server_id != tool.server_id} - own
            )
            if findings and self.config.quarantine_poisoned_tools:
                self._quarantined[qualified] = [*self._quarantined.get(qualified, []), *findings]
            if not findings and qualified not in self._quarantined:
                if self._semantic_flag(text, "description"):
                    self._suspect_tools[qualified] = ReasonCode.REVIEW_CLASSIFIER_FLAGGED
                elif self._judge and self._judge.tool(qualified, text):
                    self._suspect_tools[qualified] = ReasonCode.REVIEW_JUDGE_FLAGGED
            self._description_values[qualified] = distinctive_values(text)
            hidden = self_disclosure_fields(tool.input_schema)
            if hidden:
                self._redacted[qualified] = hidden
            visible = tool.input_schema if not hidden else {
                **tool.input_schema,
                "properties": {k: v for k, v in tool.input_schema["properties"].items() if k not in hidden},
                **({"required": [k for k in tool.input_schema["required"] if k not in hidden]}
                   if isinstance(tool.input_schema.get("required"), list) else {}),
            }
            self._visible_schemas[qualified] = visible
            if not _SAFE_TOOL_NAME.fullmatch(tool.name) or qualified in registry:
                raise ValueError(f"Invalid or duplicate upstream MCP tool: {qualified!r}")
            Draft202012Validator.check_schema(tool.input_schema)
            validator = Draft202012Validator(tool.input_schema)

            def validate(arguments: dict[str, Any], *, current=validator) -> None:
                errors = sorted(current.iter_errors(arguments), key=lambda item: list(item.path))
                if errors:
                    path = ".".join(str(part) for part in errors[0].path) or "arguments"
                    raise ValueError(f"{path}: {errors[0].message}")

            def execute(parsed: BaseModel, *, current=tool) -> dict[str, Any]:
                if self._loop is None:
                    raise RuntimeError("MCP proxy is not connected")
                upstream = self.upstreams[current.server_id]
                future = asyncio.run_coroutine_threadsafe(
                    upstream.call_tool(current.name, parsed.model_dump(mode="json")),
                    self._loop,
                )
                result: MCPCallResult = future.result(
                    timeout=upstream.config.read_timeout_seconds
                )
                if result.is_error:
                    message = result.error.message if result.error else "Upstream MCP tool failed"
                    raise MCPRemoteToolError(message)
                normalized_result = self._bounded(result)
                return {
                    "trust": "UNTRUSTED_MCP_OUTPUT",
                    "upstream": normalized_result,
                }

            registry[qualified] = ToolSpec(
                name=qualified,
                description=(
                    f"Quarantined MCP tool {qualified}; upstream description matched poisoning rules."
                    if qualified in self._quarantined
                    else tool.description
                    if self.config.expose_upstream_descriptions and tool.description
                    and qualified not in self._suspect_tools
                    else f"Guarded MCP tool {qualified}; upstream description withheld as untrusted."
                ),
                args_model=MCPArguments,
                mutation=not self.config.is_read_only(qualified),
                destination_field=(
                    self.config.destination_fields.get(qualified)
                ),
                executor=execute,
                schema_override=tool.input_schema,
                public_schema_override=_public_schema(visible),
                argument_validator=validate,
                upstream_id=tool.server_id,
                upstream_tool_name=tool.name,
                resource_field=self.config.resource_fields.get(qualified),
                allowed_resources_override=self.config.allowed_resources_by_tool.get(qualified),
                allowed_destinations_override=self.config.allowed_destinations_by_tool.get(qualified),
                grounding_terms=tuple(
                    sorted(self.config.grounding_terms_by_tool.get(qualified, set()))
                ),
            )
            if self.config.is_allowed(qualified) and not registry[qualified].grounding_terms:
                raise ValueError(
                    f"Allowed MCP tool requires grounding_terms_by_tool: {qualified}"
                )
        return registry

    def _bounded(self, result: MCPCallResult) -> dict[str, Any]:
        normalized = result.model_dump(mode="json")
        if len(result.content) > self.config.max_result_content_blocks:
            raise MCPRemoteToolError("Upstream MCP result exceeded the content-block limit")
        if len(json.dumps(normalized, separators=(",", ":")).encode()) > self.config.max_result_bytes:
            raise MCPRemoteToolError("Upstream MCP result exceeded the byte limit")
        return normalized

    def _service(self) -> IntentShieldService:
        if self.service is None:
            raise RuntimeError("MCP proxy is not connected")
        return self.service

    async def create_run(self, user_intent: str) -> str:
        run_id = await asyncio.to_thread(self._service().create_run, user_intent)
        # The intent exempts what it names from detection and provenance. An intent that
        # repeats a value or instruction from a flagged output is the injection speaking.
        flagged = self._tainted | self._suspect_values
        if distinctive_values(user_intent) & flagged or (self._injection_seen and scan_output(user_intent)):
            self._untrusted_intents.add(run_id)
            self._service().storage.add_event(run_id, "MCP_INTENT_FROM_OUTPUT", {})
        return run_id

    async def tool_catalog(self, *, refresh: bool = True) -> list[dict[str, Any]]:
        if refresh:
            await self._refresh_catalog()
        catalog = self._service().tool_catalog()
        for item in catalog:
            item["available"] = not (
                item["name"] in self._drifted_tools or item["name"] in self._quarantined
            )
            item["schema_drift"] = item["name"] in self._drifted_tools
            item["quarantined"] = item["name"] in self._quarantined
            item["poisoning_findings"] = self._quarantined.get(item["name"], [])
            item["redacted_fields"] = sorted(self._redacted.get(item["name"], ()))
            item["classifier_flagged"] = self._suspect_tools.get(item["name"]) == ReasonCode.REVIEW_CLASSIFIER_FLAGGED
            item["judge_flagged"] = self._suspect_tools.get(item["name"]) == ReasonCode.REVIEW_JUDGE_FLAGGED
        return catalog

    async def _refresh_catalog(self) -> None:
        discovered = await self._list_all_tools()
        # Rug pull: any change to schema, description, title or annotations
        # after connect fails closed, not only schema changes.
        current = {tool.qualified_name: _fingerprint(tool) for tool in discovered}
        changed = {
            name for name in set(current) | set(self._bound_fingerprints)
            if current.get(name) != self._bound_fingerprints.get(name)
        }
        newly_drifted = changed - self._drifted_tools
        self._drifted_tools.update(changed)
        if newly_drifted:
            self._service().storage.add_event(
                self._ensure_system_run(),
                "MCP_CATALOG_DRIFT",
                {"tools": sorted(newly_drifted)},
            )

    def _pre_policy_check(self, run_id: str, user_intent: str, call: ToolCall) -> ReasonCode | None:
        verdict = self._rule_check(run_id, user_intent, call)
        # The judge only sees calls that would run: blocked ones are blocked, and
        # mutations already wait on a human.
        if verdict is None and self._judge and self.config.is_read_only(call.tool_name):
            objection = self._judge.call(user_intent, call.tool_name, call.arguments)
            if objection:
                self._service().storage.add_event(run_id, "MCP_JUDGE_FLAGGED",
                                                  {"tool_name": call.tool_name, "reason": objection})
                return ReasonCode.REVIEW_JUDGE_FLAGGED
        return verdict

    def _rule_check(self, run_id: str, user_intent: str, call: ToolCall) -> ReasonCode | None:
        if call.tool_name in self._quarantined:
            return ReasonCode.BLOCK_TOOL_QUARANTINED
        if run_id in self._untrusted_intents:
            return ReasonCode.REVIEW_UNTRUSTED_ARGUMENT_SOURCE
        # Argument provenance: a distinctive value (email, URL, account, path, id)
        # the user never gave must not come from an injected output in this run
        # or from another tool's description.
        values = distinctive_values(call.arguments) - distinctive_values(user_intent)
        if not values:
            return self._suspect_tools.get(call.tool_name)
        if values & self._tainted:
            return ReasonCode.BLOCK_UNTRUSTED_ARGUMENT_SOURCE
        for name, described in self._description_values.items():
            if name != call.tool_name and values & described:
                return ReasonCode.BLOCK_UNTRUSTED_ARGUMENT_SOURCE
        if call.tool_name in self._suspect_tools:
            return self._suspect_tools[call.tool_name]
        if values & self._suspect_values:
            return ReasonCode.REVIEW_CLASSIFIER_FLAGGED
        # Detection is not the gate: a value the scanners missed still came from a tool.
        if self.config.review_output_sourced_arguments and sourced_from(
            authority_values(call.arguments), self._observed.keys(),
            distinctive_values(user_intent),
        ):
            return ReasonCode.REVIEW_UNTRUSTED_ARGUMENT_SOURCE
        return None

    def _semantic_flag(self, text: str, kind: str) -> str | None:
        """The first learned detector that flags ``text`` (a ``description`` or an ``output``), or None.
        Evidence only."""
        for name, flags in self._detectors:
            if flags(text, kind):
                return name
        return None

    def _inspect_result(self, run_id: str, call: ToolCall, result: dict[str, Any]) -> dict[str, Any]:
        upstream = result.get("upstream", result)
        self._observed.update(dict.fromkeys(authority_values(upstream)))
        for stale in list(itertools.islice(self._observed, max(0, len(self._observed) - 50_000))):
            del self._observed[stale]
        findings = scan_output(upstream)
        text = upstream if isinstance(upstream, str) else json.dumps(upstream, ensure_ascii=False)
        detector = None if findings else (
            "line_split_rules" if scan_output_collapsed(upstream) else self._semantic_flag(text, "output"))
        if self._learner is not None:  # only learning links a reviewed call to the text it reused
            outputs = self._outputs.setdefault(run_id, [])
            outputs.append({"tool_name": call.tool_name, "text": text[:20_000],
                            "values": distinctive_values(upstream), "flagged": bool(findings or detector)})
            del outputs[:-32]
            for stale in list(itertools.islice(self._outputs, max(0, len(self._outputs) - 64))):
                del self._outputs[stale]
        if not findings:
            if detector:
                self._injection_seen = True
                self._suspect_values.update(distinctive_values(upstream))
                self._service().storage.add_event(run_id, "MCP_OUTPUT_SUSPECTED",
                                                  {"tool_name": call.tool_name, "detector": detector})
                return {**result, "injection_suspected": True, "injection_findings": ["semantic_instruction"]}
            return result
        values = distinctive_values(result.get("upstream", result))
        self._injection_seen = True
        self._tainted.update(values)
        self._service().storage.add_event(run_id, "MCP_OUTPUT_INJECTION", {
            "tool_name": call.tool_name, "findings": findings, "tainted_values": len(values),
        })
        return {**result, "injection_detected": True, "injection_findings": findings}

    def _redact(self, call: ToolCall) -> ToolCall:
        hidden = self._redacted.get(call.tool_name)
        if not hidden:
            return call
        schema = next(t.input_schema for t in self._tools if t.qualified_name == call.tool_name)
        required = set(schema.get("required") or ())
        arguments = {k: v for k, v in call.arguments.items() if k not in hidden}
        for name in hidden & required:
            # Only an empty string can stand in for a required value; other types fail validation.
            arguments[name] = ""
        return call.model_copy(update={"arguments": arguments})

    def _ensure_system_run(self) -> str:
        return self._service().create_run("Monitor upstream MCP tool catalog", "mcp-catalog")

    async def evaluate_and_execute(self, run_id: str, call: ToolCall) -> GatewayResult:
        service = self._service()
        await self._refresh_catalog()
        call = self._redact(call)
        if call.tool_name in self._drifted_tools:
            # Force the existing pure policy engine down its schema-drift path.
            # The upstream executor remains unreachable.
            call = call.model_copy(update={"schema_hash": "mcp-catalog-drift"})
        # Execution must run off the event loop because the synchronous policy
        # engine may wait for an upstream coroutine scheduled onto this loop.
        return await asyncio.to_thread(service.evaluate_and_execute, run_id, "", call)

    async def transparent_tools(self) -> list[tuple[MCPTool, dict[str, Any]]]:
        """Upstream tools an MCP client may see directly: not quarantined, not drifted, with
        self-disclosure parameters removed from the schema."""
        await self._refresh_catalog()
        withheld = "Description withheld by IntentShield: it may try to instruct the agent."
        shown = []
        for tool in self._tools:
            name = tool.qualified_name
            if name in self._quarantined or name in self._drifted_tools:
                continue
            visible = self._visible_schemas[name]
            if name in self._suspect_tools:  # a flagged tool keeps no free text at all
                shown.append((tool.model_copy(update={"description": withheld, "title": None}),
                              _public_schema(visible)))
            else:
                shown.append((tool, _public_schema(visible, annotations=True)))
        return shown

    def _blocked_reason(self, name: str) -> str | None:
        if name in self._quarantined:
            return f"{name} is quarantined: its description matched poisoning rules"
        if name in self._drifted_tools:
            return f"{name} changed after connect (possible rug pull) and is blocked"
        return None

    async def hidden_tools(self) -> list[tuple[MCPTool, str]]:
        """Tools ``transparent_tools`` leaves out, with the reason a call to one is refused.
        A drifted tool stays blocked for the rest of the session, even if the upstream
        later restores it: the fingerprint is bound once at connect and never re-bound."""
        await self._refresh_catalog()
        return [(tool, reason) for tool in self._tools if (reason := self._blocked_reason(tool.qualified_name))]

    async def forward(self, name: str, arguments: dict[str, Any]) -> tuple[MCPCallResult, list[str]]:
        """Transparent mode: call an upstream tool on the catalog layer's terms only. The
        intent-bound call policy runs in the harness hooks, which see the user's prompt."""
        await self._refresh_catalog()
        if reason := self._blocked_reason(name):
            raise MCPRemoteToolError(reason)
        tool = next((t for t in self._tools if t.qualified_name == name), None)
        if tool is None:
            raise MCPRemoteToolError(f"Unknown tool {name}")
        call = self._redact(ToolCall(tool_name=name, arguments=arguments, schema_hash="transparent"))
        result = await self.upstreams[tool.server_id].call_tool(tool.name, call.arguments)
        self._bounded(result)
        shown = result.model_dump(mode="json", include={"content", "structured_content"})
        return result, scan_output(shown) or scan_output_collapsed(shown)

    async def evaluate_only(self, run_id: str, call: ToolCall) -> GatewayResult:
        """Evaluate a proposed call without execution or approval persistence."""
        await self._refresh_catalog()
        call = self._redact(call)
        if call.tool_name in self._drifted_tools:
            call = call.model_copy(update={"schema_hash": "mcp-catalog-drift"})
        return await asyncio.to_thread(self._service().evaluate_only, run_id, call)

    async def decide_approval(self, approval_id: str, approve: bool) -> GatewayResult:
        service = self._service()
        approval = await asyncio.to_thread(service.storage.get_approval, approval_id)
        if not approval:
            raise KeyError(approval_id)
        await self._refresh_catalog()
        if approve and approval["tool_name"] in self._drifted_tools:
            # A human approved the previously displayed operation, not a
            # replacement schema supplied later by the upstream server.
            return await asyncio.to_thread(service.decide_approval, approval_id, False)
        return await asyncio.to_thread(service.decide_approval, approval_id, approve)

    async def decide_and_learn(self, approval_id: str, approve: bool,
                               learn: str | None) -> tuple[GatewayResult, list[dict[str, Any]]]:
        """Decide an approval and, when the operator says so, learn from the outputs the call reused.

        ``learn`` is ``injection`` (only with a rejection: the call was induced by injected text) or
        ``benign`` (only with an approval). Only outputs whose values the call reused are learned, or
        for ``injection`` any flagged output of the run when none was reused; an approval never
        teaches a flagged output as benign."""
        if not (learn is None or (learn == "injection" and not approve) or (learn == "benign" and approve)):
            raise ValueError("learn must be 'injection' with a rejection or 'benign' with an approval")
        if learn and self._learner is None:
            raise ValueError("learning is not enabled (needs exemplar_index_dir and learning_regression)")
        result = await self.decide_approval(approval_id, approve)
        if not learn:
            return result, []
        return result, await asyncio.to_thread(self._learn_from_approval, approval_id, learn)

    def _learn_from_approval(self, approval_id: str, learn: str) -> list[dict[str, Any]]:
        from .learning import linked_excerpt

        storage = self._service().storage
        approval = storage.get_approval(approval_id) or {}
        run = storage.get_run(approval.get("run_id", "")) or {}
        values = distinctive_values(json.loads(approval.get("args_json") or "{}")) - distinctive_values(
            run.get("user_intent", ""))
        outputs = self._outputs.get(approval.get("run_id", ""), [])
        linked = [o for o in outputs if values & o["values"]]
        if learn == "injection":
            linked = linked or [o for o in outputs if o["flagged"]]
        else:
            linked = [o for o in linked if not o["flagged"]]
        learned = []
        for output in linked:
            text = linked_excerpt(output["text"], values & output["values"]) if values & output["values"] \
                else output["text"]
            learned.append(self._learner.learn(
                text, "instruction" if learn == "injection" else "data",
                "review_reject" if learn == "injection" else "review_approve",
                run_id=approval.get("run_id"), approval_id=approval_id, tool_name=output["tool_name"]))
        storage.add_event(approval["run_id"], "MCP_LEARNED", {
            "approval_id": approval_id, "learn": learn,
            "examples": [{"id": e["id"], "status": e["status"]} for e in learned]})
        return learned

    async def learn_example(self, text: str, label: str) -> dict[str, Any]:
        """Operator-labelled text: ``injection`` or ``benign``."""
        if self._learner is None:
            raise ValueError("learning is not enabled (needs exemplar_index_dir and learning_regression)")
        if label not in ("injection", "benign"):
            raise ValueError("label must be 'injection' or 'benign'")
        return await asyncio.to_thread(self._learner.learn, text,
                                       "instruction" if label == "injection" else "data", "operator")

    async def propose_rules(self, example_id: str) -> list[dict[str, Any]]:
        """Ask the signature model for rules for one active injection example; gated ones wait as pending."""
        if self._rules is None or not self.config.signature_model:
            raise ValueError("rule induction is not enabled (needs learning and signature_model)")
        from .signatures import induce, ollama

        example = next((r for r in self._learner.store.examples("active") if r["id"] == example_id), None)
        if example is None or example["label"] != "instruction":
            raise KeyError(example_id)
        return await asyncio.to_thread(induce, ollama(self.config.signature_model, self.config.signature_host),
                                       self._rules.store, example["text"], self._rule_benign, example_id)

    async def decide_rule(self, rule_id: str, approve: bool) -> dict[str, Any]:
        if self._rules is None:
            raise ValueError("learning is not enabled (needs exemplar_index_dir and learning_regression)")
        row = await asyncio.to_thread(self._rules.store.decide, rule_id, approve)
        self._rules.reload()
        return row

    async def rules_status(self) -> dict[str, Any]:
        if self._rules is None:
            return {"enabled": False}
        rows = await asyncio.to_thread(self._rules.store.rules)
        return {"enabled": True, "proposals": bool(self.config.signature_model),
                "rules": [{**r, "gate": json.loads(r.pop("gate_json"))} for r in rows]}

    async def learning_status(self) -> dict[str, Any]:
        if self._learner is None:
            return {"enabled": False}
        rows = await asyncio.to_thread(self._learner.store.examples)
        sizes = self._learner.index.sizes()
        return {"enabled": True, "index": {"instruction_chunks": sizes[0], "data_chunks": sizes[1]},
                "examples": [{**{k: r[k] for k in ("id", "label", "origin", "status", "tool_name", "created_at")},
                              "text": r["text"][:300], "gate": json.loads(r["gate_json"])} for r in rows]}

    async def get_run(self, run_id: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self._service().storage.get_run, run_id)

    async def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        storage = self._service().storage
        approval = await asyncio.to_thread(storage.get_approval, approval_id)
        if approval is None:
            return None
        completion = await asyncio.to_thread(storage.get_approval_result, approval_id)
        return {**approval, "ready": completion is not None, "completion": completion}
