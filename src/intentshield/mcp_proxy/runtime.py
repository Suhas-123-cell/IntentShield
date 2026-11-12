"""The proxy runtime: the connection to the upstream servers, runs, and the path of a call through the checks."""
from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from intentshield.judge import Judge
from intentshield.mcp_inspect import distinctive_values, scan_output
from intentshield.mcp_upstream import MCPCallResult, MCPTool, MCPUpstream
from intentshield.models import GatewayResult, ReasonCode, ToolCall
from intentshield.policy import PolicyConfig
from intentshield.service import IntentShieldService
from intentshield.storage import Storage
from intentshield.threat_memory import GuardedMemory

from .approvals import _Approvals
from .catalog import _Catalog, _fingerprint
from .checks import _Checks
from .config import MCPProxyConfig
from .errors import MCPRemoteToolError, RunLimitError
from .hosts import _host_overlap, _network_values
from .judging import _Judging
from .log import logger
from .schema import _exceeds_bytes
from .taint import _RecentSet

if TYPE_CHECKING:
    from intentshield.threat_memory import ThreatMemory


class MCPProxyRuntime(_Catalog, _Checks, _Judging, _Approvals):
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
        self._said_hidden: set[tuple[str, tuple[str, ...]]] = set()
        self._left_out: dict[str, str] = {}  # tools the proxy cannot serve (bad name or schema): never shown
        self._failed_upstreams: dict[str, str] = {}  # servers that could not list their tools: none of theirs served
        self._description_values: dict[str, set[str]] = {}
        # Parameters asking the agent for its model, prompt or conversation: hidden from
        # the agent and always sent upstream empty.
        self._redacted: dict[str, set[str]] = {}
        self._unjudged: list[str] = []  # descriptions the judge's connect budget did not reach
        self._unjudged_text: dict[str, str] = {}
        self._visible_schemas: dict[str, dict[str, Any]] = {}
        # Distinctive values from outputs that carried injection text. Kept for the whole
        # session, not per run: the agent opens runs itself, so a fresh run must not wash
        # a value clean.
        self._tainted: _RecentSet = _RecentSet()
        # Hosts and mailboxes of those outputs, canonicalised (see ``_network_values``): a read that only
        # reuses the host of an injected address is still the injection's.
        self._tainted_hosts: _RecentSet = _RecentSet()
        self._tainted_boxes: _RecentSet = _RecentSet()
        self._runs = 0
        self._transparent_run: str | None = None
        self._judge_errors_seen = 0
        self._judge_error_logged = float("-inf")
        self._judge_retry_at = float("-inf")  # earliest next pass over descriptions the judge failed to read
        self._judging = threading.Lock()
        self._pending_judge_error: tuple[int, str] | None = None
        # Runs whose intent repeats a flagged output; the agent wrote that intent, not the user.
        self._untrusted_intents: set[str] = set()
        # Values an agent-written intent names that the proxy had already seen in a tool output when
        # the run was created: the agent could only have learned them from a tool, so they do not
        # earn the exemption the user's own words get. A hook's intent is the user's; a gateway's
        # intent is written by the monitored agent.
        self._intent_from_outputs: dict[str, set[str]] = {}
        self._injection_seen = False
        # Recipients, URLs, accounts and paths seen in any tool output, kept for the session
        # like ``_tainted`` (a fresh run must not wash them) and bounded, oldest first out.
        self._observed: dict[str, None] = {}
        # The session sets above are read and written from the event loop (``create_run``,
        # ``_refresh_catalog``) and from ``asyncio.to_thread`` workers (``_rule_check``,
        # ``_inspect_result``); one lock keeps every update whole.
        self._lock = threading.RLock()
        from intentshield.injection_classifier import InjectionClassifier  # torch only when configured
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
            from intentshield.prompt_guard import PromptGuard
            # Bounded like the judge: the call holds the agent, so one short try, then no opinion.
            guard = self._prompt_guard = PromptGuard(config.prompt_guard, timeout=15, retries=1)
            self._detectors.append(("prompt_guard", lambda text, kind: guard.flags(text)))
        self._learner: Any = None
        self._rules: Any = None
        self._rule_benign: list[str] = []
        if config.exemplar_index_dir:
            from intentshield.exemplars import Embedder, ExemplarIndex
            embedder = Embedder(config.embedder_dir)
            if not embedder.ready:
                raise ValueError(f"embedder_dir is not usable: {embedder.reason}")
            exemplars = ExemplarIndex.load(Path(config.exemplar_index_dir), embedder)
            self._detectors.append(("exemplars", exemplars.flags))
            if config.learning_regression:
                from intentshield.learning import Learner, LearningStore, Regression
                rows = [json.loads(line) for path in config.learning_regression
                        for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
                regression = Regression.from_rows([r for r in rows if r.get("split") == "validation"],
                                                  exemplars, cache=Path(config.exemplar_index_dir))
                self._learner = Learner(exemplars, LearningStore(config.database_path), regression)
                from intentshield.signatures import LearnedRules, RuleStore
                self._rules = LearnedRules(RuleStore(config.database_path))
                rules = self._rules
                self._detectors.append(("learned_rules", lambda text, kind: rules.flags(text)))
                # Benign texts a proposed rule must not match: every split but the held-out test.
                self._rule_benign = [r["text"] for r in rows if r.get("label") == "data" and r.get("split") != "test"]
        elif config.learning_regression:
            raise ValueError("learning_regression needs exemplar_index_dir")
        # run_id -> recent tool outputs, so a reviewed call can be linked to the text it reused.
        self._outputs: dict[str, list[dict[str, Any]]] = {}
        # A proxy call holds the agent: one short try, then no opinion, never minutes of back-off.
        self._judge = Judge.from_spec(config.judge, timeout=15, retries=1, budget=30) if config.judge else None
        # Tools whose description passed the rules but not the classifier or the judge.
        self._suspect_tools: dict[str, ReasonCode] = {}
        self._suspect_values: _RecentSet = _RecentSet()
        self._taint_incomplete = False  # a cap dropped tainted values: see MAX_TAINTED
        self._memory: ThreatMemory | None = None
        if config.threat_memory:
            from intentshield.rule_packs import PackSet
            from intentshield.threat_memory import ThreatMemory
            try:
                self._memory = ThreatMemory(
                    config.threat_memory_path or Path(config.database_path).with_name("threats.db"),
                    packs=PackSet(config.threat_packs_dir) if config.threat_packs_dir else None)
            except Exception as exc:  # a corrupt file costs the memory, not the proxy
                logger.warning("threat memory disabled", extra={"error": f"{type(exc).__name__}: {exc}"})
        self._recall = GuardedMemory(self._memory, self._memory_failed)

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
            error_inspector=self._inspect_error, dry_run_limit=self.config.max_dry_runs_per_run,
        )
        if self._quarantined:
            self.service.storage.add_event(
                self._ensure_system_run(), "MCP_TOOLS_QUARANTINED", {"tools": self._quarantined}
            )
        if self._failed_upstreams:
            self.service.storage.add_event(
                self._ensure_system_run(), "MCP_UPSTREAMS_LEFT_OUT", {"upstreams": self._failed_upstreams}
            )
        if self._unjudged:
            logger.warning("the judge did not read every description (its budget ran out or it was unavailable)",
                           extra={"unjudged": len(self._unjudged)})
            self.service.storage.add_event(
                self._ensure_system_run(), "MCP_JUDGE_BUDGET_SPENT", {"tools": self._unjudged}
            )
        if self._pending_judge_error:
            self.service.storage.add_event(self._ensure_system_run(), "MCP_JUDGE_ERROR", {
                "new_errors": self._pending_judge_error[0], "last_error": self._pending_judge_error[1]})
            self._pending_judge_error = None
        if self._redacted:
            self.service.storage.add_event(
                self._ensure_system_run(), "MCP_SELF_DISCLOSURE_FIELDS",
                {"tools": {name: sorted(fields) for name, fields in self._redacted.items()}},
            )

    async def close(self) -> None:
        service, self.service = self.service, None
        self._loop = None
        try:
            await self._close_upstreams()
        finally:
            if service is not None:
                service.security_supervisor.close()
            self._recall.close()

    async def _close_upstreams(self) -> None:
        # MCP transport context managers are task-affine. Close them in the
        # same lifespan task that opened them rather than child gather tasks.
        errors: list[Exception] = []
        interrupted: BaseException | None = None
        for upstream in reversed(tuple(self.upstreams.values())):
            try:
                await upstream.close()
            except Exception as exc:
                errors.append(exc)
            except BaseException as exc:  # cancellation: close the rest, then let it propagate as itself
                interrupted = interrupted or exc
        if interrupted is not None:
            for error in errors:  # not lost behind the cancellation
                logger.warning("upstream close failed", extra={"error": type(error).__name__})
            raise interrupted
        if errors:
            raise RuntimeError(f"Failed to close {len(errors)} upstream MCP connection(s)") from errors[0]

    def _bounded(self, result: MCPCallResult) -> dict[str, Any]:
        """The result as JSON, or a refusal. The limit holds back delivery: the SDK has read the whole reply by
        now, so what is spared here is the copies (the dump and its JSON text) a hostile size would multiply."""
        if len(result.content) > self.config.max_result_content_blocks:
            raise MCPRemoteToolError("Upstream MCP result exceeded the content-block limit")
        if _exceeds_bytes((result.content, result.structured_content, result.meta, result.error),
                          self.config.max_result_bytes):
            raise MCPRemoteToolError("Upstream MCP result exceeded the byte limit")
        normalized = result.model_dump(mode="json")
        if len(json.dumps(normalized, separators=(",", ":")).encode()) > self.config.max_result_bytes:
            raise MCPRemoteToolError("Upstream MCP result exceeded the byte limit")
        return normalized

    def _service(self) -> IntentShieldService:
        if self.service is None:
            raise RuntimeError("MCP proxy is not connected")
        return self.service

    async def create_run(self, user_intent: str) -> str:
        with self._lock:  # the agent opens runs itself, and every run starts a fresh call budget
            if self._runs >= self.config.max_runs:
                raise RunLimitError(f"This proxy session has opened its {self.config.max_runs} runs; restart it "
                                    "(or raise max_runs) to open more")
            self._runs += 1
        run_id = await asyncio.to_thread(self._service().create_run, user_intent)
        # The intent exempts what it names from detection and provenance. An intent that
        # repeats a value or instruction from a flagged output is the injection speaking.
        named = distinctive_values(user_intent)
        watching = bool(self._tainted_hosts or self._taint_incomplete)
        named_hosts, named_boxes = _network_values(user_intent) if watching else (set(), set())
        event: tuple[str, dict[str, Any]] | None = None
        with self._lock:  # decided under the lock, written after it and off the event loop
            flagged = self._tainted | self._suspect_values
            if (named & flagged or (self._injection_seen and scan_output(user_intent))
                    or _host_overlap(named_hosts, self._tainted_hosts)
                    or (self._taint_incomplete and (named or named_hosts or named_boxes))):
                self._untrusted_intents.add(run_id)
                event = ("MCP_INTENT_FROM_OUTPUT", {})
            elif not self.config.trusted_intent and (learned := named & self._observed.keys()):
                self._intent_from_outputs[run_id] = learned
                event = ("MCP_INTENT_NAMES_OBSERVED_VALUES", {"values": sorted(learned)[:20]})
        if event:
            await asyncio.to_thread(self._service().storage.add_event, run_id, *event)
        return run_id

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

    async def forward(self, name: str, arguments: dict[str, Any], *,
                      refresh: bool = True) -> tuple[MCPCallResult, list[str]]:
        """Transparent mode: call an upstream tool on the catalog layer's terms only. The
        intent-bound call policy runs in the harness hooks, which see the user's prompt. The result gets
        the gateway's inspection (rules, tracked values, detectors, judge); what it finds comes back as
        the second item, for the warning in front of the result. A caller that has just listed the tools
        (``transparent_tools``) passes ``refresh=False``: one catalog listing per call, not two."""
        if refresh:
            await self._refresh_catalog()
        if reason := self._blocked_reason(name):
            raise MCPRemoteToolError(reason)
        tool = next((t for t in self._tools if t.qualified_name == name), None)
        if tool is None:
            raise MCPRemoteToolError(f"Unknown tool {name}")
        if name in self._suspect_tools:  # no review queue here: a tool whose description was withheld is not called
            raise MCPRemoteToolError(f"{name} is withheld by IntentShield: its description was flagged as a possible "
                                     "injection, and transparent mode has no review step")
        call = self._redact(ToolCall(tool_name=name, arguments=arguments, schema_hash="transparent"))
        result = await self.upstreams[tool.server_id].call_tool(tool.name, call.arguments)
        self._bounded(result)
        shown = result.model_dump(mode="json", include={"content", "structured_content"})
        run_id = await asyncio.to_thread(self._transparent_run_id)
        inspected = await asyncio.to_thread(
            self._inspect_result, run_id, call, {"trust": "UNTRUSTED_MCP_OUTPUT", "upstream": shown})
        return result, list(inspected.get("injection_findings", []))

    def _transparent_run_id(self) -> str:
        """The one run transparent-mode results are audited under: there is no per-prompt run here."""
        with self._lock:
            if self._transparent_run is None:
                self._transparent_run = self._service().create_run(
                    "Transparent MCP session (results inspected, calls judged by the harness hooks)", "mcp-transparent")
            return self._transparent_run

    async def evaluate_only(self, run_id: str, call: ToolCall) -> GatewayResult:
        """Evaluate a proposed call without execution or approval persistence."""
        await self._refresh_catalog()
        call = self._redact(call)
        if call.tool_name in self._drifted_tools:
            call = call.model_copy(update={"schema_hash": "mcp-catalog-drift"})
        return await asyncio.to_thread(self._service().evaluate_only, run_id, call)
