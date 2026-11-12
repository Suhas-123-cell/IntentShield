"""The state a proxy runtime keeps, declared once for the modules that share it."""
from __future__ import annotations

import asyncio
import threading
from typing import TYPE_CHECKING, Any, Callable

from intentshield.judge import Judge
from intentshield.mcp_upstream import MCPCallResult, MCPTool, MCPUpstream
from intentshield.models import ReasonCode
from intentshield.service import IntentShieldService
from intentshield.threat_memory import GuardedMemory

from .config import MCPProxyConfig
from .taint import _RecentSet

if TYPE_CHECKING:
    from intentshield.injection_classifier import InjectionClassifier
    from intentshield.threat_memory import ThreatMemory


class _State:
    """What every part of the runtime reads: set by ``MCPProxyRuntime.__init__``."""

    config: MCPProxyConfig
    upstreams: dict[str, MCPUpstream]
    service: IntentShieldService | None
    _loop: asyncio.AbstractEventLoop | None
    _tools: list[MCPTool]
    _bound_fingerprints: dict[str, str]
    _drifted_tools: set[str]
    _quarantined: dict[str, list[str]]
    _said_hidden: set[tuple[str, tuple[str, ...]]]
    _left_out: dict[str, str]
    _failed_upstreams: dict[str, str]
    _description_values: dict[str, set[str]]
    _redacted: dict[str, set[str]]
    _unjudged: list[str]
    _unjudged_text: dict[str, str]
    _visible_schemas: dict[str, dict[str, Any]]
    _tainted: _RecentSet
    _tainted_hosts: _RecentSet
    _tainted_boxes: _RecentSet
    _runs: int
    _transparent_run: str | None
    _judge_errors_seen: int
    _judge_error_logged: float
    _judge_retry_at: float
    _judging: threading.Lock
    _pending_judge_error: tuple[int, str] | None
    _untrusted_intents: set[str]
    _intent_from_outputs: dict[str, set[str]]
    _injection_seen: bool
    _observed: dict[str, None]
    _lock: threading.RLock
    _classifier: InjectionClassifier | None
    _detectors: list[tuple[str, Callable[[str, str], bool | None]]]
    _prompt_guard: Any
    _learner: Any
    _rules: Any
    _rule_benign: list[str]
    _outputs: dict[str, list[dict[str, Any]]]
    _judge: Judge | None
    _suspect_tools: dict[str, ReasonCode]
    _suspect_values: _RecentSet
    _taint_incomplete: bool
    _memory: ThreatMemory | None
    _recall: GuardedMemory

    if TYPE_CHECKING:  # the methods of the other parts, as the type checker needs to know them

        def _bounded(self, result: MCPCallResult) -> dict[str, Any]: ...

        def _service(self) -> IntentShieldService: ...

        async def _refresh_catalog(self) -> None: ...

        def _judge_failed(self, exc: Exception) -> None: ...

        def _note_judge_errors(self, run_id: str | None = None) -> None: ...

        def _judge_descriptions(self, pending: dict[str, str]) -> None: ...

        def _judge_retry_due(self) -> bool: ...

        def _judge_pending(self) -> None: ...

        def _judge_output(self, run_id: str, tool: str, text: str) -> str | None: ...

        def _semantic_flag(self, text: str, kind: str, run_id: str | None = None) -> str | None: ...

        def _ensure_system_run(self) -> str: ...
