"""The proxy's settings: upstreams, allow, prohibit, pin and read-only lists and limits, read from a JSON file."""
from __future__ import annotations

import fnmatch
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

from intentshield.mcp_upstream import MCPUpstreamConfig
from intentshield.storage import default_database
from intentshield.tools import catch_all_destination


class MCPProxyConfig(BaseModel):
    """Local trust policy plus connection details for one upstream server."""

    model_config = ConfigDict(extra="forbid")

    # ``upstream`` remains accepted for existing single-server configs.
    upstream: MCPUpstreamConfig | None = None
    upstreams: list[MCPUpstreamConfig] = Field(default_factory=list)
    database_path: str = Field(default_factory=lambda: default_database("intentshield-mcp.db"))
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
    # Qualified ``server:tool`` names whose description may name a key, a credential or a secrets file (a tool that reads the
    # project's ``.env``, a tool that returns the public key): the ``sensitive_target`` rule alone does not hide them. Every other
    # rule still does, and the description is still pinned by its hash.
    trusted_tools: list[str] = Field(default_factory=list)
    # A recipient, URL, account or path whose only source is a tool output sends the
    # call to review, whether or not the scanners flagged that output. A side-effecting
    # call always does; this setting decides it for reads.
    review_output_sourced_arguments: bool = True
    # Whether a run's ``user_intent`` comes from a channel the agent cannot write to (an operator, a
    # harness hook, a benchmark runner). The gateway's ``intentshield_create_run`` is agent-callable,
    # so by default a value the intent names that a tool output had already shown is not the user's
    # word and earns no exemption from the provenance review. Set true only when something other
    # than the monitored agent writes the intent.
    trusted_intent: bool = False
    # Optional local classifier (``intentshield.injection_training``) run on descriptions
    # and outputs the rules pass. A hit withholds the description or flags the output
    # and sends affected calls to review; it never allows anything.
    injection_classifier_dir: str | None = None
    # Optional LLM judge (``judge.py``): "groq" or "gemini", optionally ":model". It reads
    # descriptions the rules pass, and each read-only call that would otherwise run against
    # the user's request; an objection withholds the tool or sends the call to review.
    # It never allows anything. The key comes from GROQ_API_KEY or GEMINI_API_KEY.
    judge: str | None = None
    # Time the judge may spend on descriptions at connect, which runs before the proxy answers the
    # client's ``initialize`` (clients give up after about 30 s). A call already started may run past
    # it by up to 30 s. Tools not reached get no opinion, as on a judge error; they are logged and
    # listed in an ``MCP_JUDGE_BUDGET_SPENT`` event.
    judge_catalog_budget_seconds: float = Field(default=20, gt=0)
    # Whether the judge also reads each tool result no rule or detector flagged, for plain-language
    # injections: one request per result, so latency and free-tier quota. A flagged result is suspected,
    # not tainted: its values go to review.
    judge_outputs: bool = False
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
    # The agent opens runs itself, and each run has its own call budget: a cap per proxy session, and
    # a cap on dry-run evaluations per run (each one tells the agent the exact reason code).
    max_runs: int = Field(default=50, ge=1)
    max_dry_runs_per_run: int = Field(default=20, ge=0)
    injection_block_threshold: float = Field(default=0.75, ge=0, le=1)
    minimum_intent_alignment: float = Field(default=0.60, ge=0, le=1)
    # Ungrounded reads pass (evidence, not a veto); mutations and negated reads stay strict.
    lenient_reads: bool = False
    # Adaptive threat memory (``threat_memory``): what rule-confirmed attacks used (addresses, wording,
    # sources), kept across runs and processes and given back as evidence. On by default; the file
    # defaults to ``threats.db`` next to ``database_path``. ``threat_packs_dir`` adds signed threat
    # packs (``rule_packs``), verified with the INTENTSHIELD_PACK_* settings and hot-reloaded.
    threat_memory: bool = True
    threat_memory_path: str | None = None
    threat_packs_dir: str | None = None
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
        if any(":" not in name for name in self.trusted_tools):
            raise ValueError("trusted_tools needs qualified server:tool names")
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
        return cls.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))

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
