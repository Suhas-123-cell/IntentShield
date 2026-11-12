"""The judge's reading of tool descriptions and tool outputs, and what the proxy does with its errors."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from time import monotonic as _mono  # a name of its own: tests replace this module's ``time``

from intentshield.models import ReasonCode

from .log import logger
from .schema import _public_schema, _withheld_schema
from .state import _State

_JUDGE_WORKERS = 4
_JUDGE_RETRY_SECONDS = 60


class _Judging(_State):
    """The judge's reading of descriptions and outputs."""

    def _judge_failed(self, exc: Exception) -> None:
        logger.warning("judge raised: no opinion", extra={"error": type(exc).__name__})

    def _note_judge_errors(self, run_id: str | None = None) -> None:
        """A judge error is no opinion, so it is invisible unless said: an ``MCP_JUDGE_ERROR`` event whenever
        the judge's error count has grown since the last check, and a warning at most once a minute."""
        judge = self._judge
        if judge is None:
            return
        with self._lock:
            total = int(getattr(judge, "errors", 0) or 0)
            new, self._judge_errors_seen = total - self._judge_errors_seen, total
            if new <= 0:
                return
            detail = str(getattr(judge, "last_error", "") or "")[:200]
            log = _mono() - self._judge_error_logged >= 60
            if log:
                self._judge_error_logged = _mono()
        if log:
            logger.warning("judge errors: its answers count as no opinion", extra={"new_errors": new, "error": detail})
        if self.service is None:  # still connecting: ``connect`` writes it once the audit log is open
            self._pending_judge_error = ((self._pending_judge_error or (0, ""))[0] + new, detail)
            return
        self.service.storage.add_event(run_id or self._ensure_system_run(), "MCP_JUDGE_ERROR",
                                       {"new_errors": new, "last_error": detail})

    def _judge_descriptions(self, pending: dict[str, str]) -> None:
        """The judge reads ``pending`` descriptions on a few threads at once, for ``judge_catalog_budget_seconds``.
        A hostile server can list decoys first, so a tool the judge did not reach is not judged clean: it stays
        in ``_unjudged``, its free text withheld, until a later pass reads it."""
        judge = self._judge
        if judge is None or not pending:
            return
        deadline = time.monotonic() + self.config.judge_catalog_budget_seconds
        slots = threading.Semaphore(_JUDGE_WORKERS)
        verdicts: dict[str, str | None] = {}
        unreached: list[str] = []

        def read(name: str, text: str) -> None:
            try:
                verdicts[name] = judge.tool(name, text)
                # An answer the judge could not get (down, rate-limited, no verdict) is no reading: the tool stays
                # unjudged and the next pass asks again. Judges that keep no per-call count have no way to say.
                if getattr(judge, "call_stats", lambda: (0, 0))()[0] and not verdicts[name]:
                    unreached.append(name)
            except Exception as exc:
                verdicts[name] = None
                unreached.append(name)
                self._judge_failed(exc)
            finally:
                slots.release()

        with ThreadPoolExecutor(max_workers=_JUDGE_WORKERS) as pool:
            for name, text in pending.items():
                slots.acquire()  # a free worker, or the budget runs out while waiting
                if time.monotonic() >= deadline:
                    slots.release()
                    unreached.append(name)
                    continue
                pool.submit(read, name, text)
        with self._lock:
            self._suspect_tools.update({name: ReasonCode.REVIEW_JUDGE_FLAGGED for name, flagged in verdicts.items()
                                        if flagged})
            self._unjudged = unreached
            self._sync_registry_views()
            # A judge that failed is asked again later, not by every call: each pass waits on it.
            self._judge_retry_at = _mono() + _JUDGE_RETRY_SECONDS if any(name in verdicts for name in unreached) \
                else float("-inf")
            self._unjudged_text = {name: pending[name] for name in unreached}
        self._note_judge_errors()

    def _sync_registry_views(self) -> None:
        """Bring the registry's public schemas and descriptions (what the model gateway shows) in line with the
        judge's latest verdicts: a tool flagged or read after connect must not keep what it showed before."""
        if self.service is None:
            return
        by_name = {tool.qualified_name: tool for tool in self._tools}
        for name, spec in list(self.service.registry.items()):
            tool, visible = by_name.get(name), self._visible_schemas.get(name)
            if tool is None or visible is None or name in self._quarantined:
                continue
            withheld = name in self._suspect_tools or name in self._unjudged
            schema = _withheld_schema(visible, flagged=name in self._suspect_tools) if withheld \
                else _public_schema(visible)
            description = tool.description if (self.config.expose_upstream_descriptions and tool.description
                                               and not withheld) \
                else f"Guarded MCP tool {name}; upstream description withheld as untrusted."
            if schema != spec.public_schema_override or description != spec.description:
                self.service.registry[name] = replace(spec, public_schema_override=schema, description=description)

    def _judge_retry_due(self) -> bool:
        """Whether there are descriptions the judge did not read and its pause after a failure is over."""
        return bool(self._unjudged and self._judge and _mono() >= self._judge_retry_at)

    def _judge_pending(self) -> None:
        """Another pass over the descriptions an earlier one did not reach (each list and call asks)."""
        if not self._judging.acquire(blocking=False):
            return
        try:
            with self._lock:
                pending = dict(self._unjudged_text)
            self._judge_descriptions(pending)
        finally:
            self._judging.release()

    def _judge_output(self, run_id: str, tool: str, text: str) -> str | None:
        """``judge`` when the LLM judge reads the result as steering the agent; last, as the costliest check,
        and only with ``judge_outputs``. Plain-language injections carry no marker a rule can match."""
        if self._judge is None or not self.config.judge_outputs:
            return None
        # The transparent run's "intent" is a label, not the user's request, which this proxy never sees.
        intent = "" if run_id == self._transparent_run else (
            self._service().storage.get_run(run_id) or {}).get("user_intent", "")
        unread = int(getattr(self._judge, "unread", 0) or 0)
        try:
            flagged = self._judge.output(intent, tool, text)
        except Exception as exc:
            flagged = None
            self._judge_failed(exc)
        self._note_judge_errors(run_id)
        # This call's own count (same thread): the shared total also moves with every other result being judged.
        stats = getattr(self._judge, "call_stats", None)
        skipped = stats()[1] if stats else int(getattr(self._judge, "unread", 0) or 0) - unread
        if not flagged and skipped > 0:  # a long result's least suspect parts went unread: say so in the log
            self._service().storage.add_event(run_id, "MCP_JUDGE_PARTIAL", {"tool_name": tool, "skipped": skipped})
        return "judge" if flagged else None

    def _semantic_flag(self, text: str, kind: str, run_id: str | None = None) -> str | None:
        """The first learned detector that flags ``text`` (a ``description`` or an ``output``), or None.
        Evidence only: a detector that raises has no opinion, which is logged and, for an output, an event."""
        for name, flags in self._detectors:
            try:
                if flags(text, kind):
                    return name
            except Exception as exc:
                logger.warning("detector failed: no opinion", extra={"detector": name, "error": type(exc).__name__})
                if run_id is not None and self.service is not None:
                    self.service.storage.add_event(run_id, "MCP_DETECTOR_ERROR", {
                        "detector": name, "kind": kind, "error": f"{type(exc).__name__}: {exc}"[:200]})
        return None
