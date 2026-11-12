"""The checks of a call before it runs and of its result after."""
from __future__ import annotations

import itertools
import json
from typing import Any

from intentshield import credentials
from intentshield.mcp_inspect import (
    authority_values,
    distinctive_values,
    scan_output,
    scan_output_collapsed,
    sourced_from,
    traced_urls,
)
from intentshield.models import ReasonCode, ToolCall

from .errors import MCPRemoteToolError, _marker
from .hosts import _host_overlap, _network_values
from .log import logger
from .state import _State
from .taint import MAX_OUTPUT_TAINT, _newest


class _Checks(_State):
    """The checks of a call before it runs and of its result after."""

    def _pre_policy_check(self, run_id: str, user_intent: str, call: ToolCall) -> ReasonCode | None:
        verdict = self._rule_check(run_id, user_intent, call)
        # The judge only sees calls that would run: blocked ones are blocked, and
        # mutations already wait on a human.
        if verdict is None and self._judge and self.config.is_read_only(call.tool_name):
            try:
                objection = self._judge.call(user_intent, call.tool_name, call.arguments)
            except Exception as exc:  # the judge is evidence only: its failure is no opinion
                objection = None
                self._judge_failed(exc)
            self._note_judge_errors(run_id)
            if objection:
                self._service().storage.add_event(run_id, "MCP_JUDGE_FLAGGED",
                                                  {"tool_name": call.tool_name, "reason": objection})
                return ReasonCode.REVIEW_JUDGE_FLAGGED
        return verdict

    def _rule_check(self, run_id: str, user_intent: str, call: ToolCall) -> ReasonCode | None:
        known = self._known_threat(user_intent, call)  # a SQLite read: outside the lock
        with self._lock:
            return self._rule_check_locked(run_id, user_intent, call, known)

    def _rule_check_locked(self, run_id: str, user_intent: str, call: ToolCall,
                           known: str | None) -> ReasonCode | None:
        if call.tool_name in self._quarantined:
            return ReasonCode.BLOCK_TOOL_QUARANTINED
        if run_id in self._untrusted_intents:
            return ReasonCode.REVIEW_UNTRUSTED_ARGUMENT_SOURCE
        # A credential the user did not give, leaving in an argument: what an injection that got the agent to
        # read a token or a key file sends.
        if any(credential not in user_intent for credential in credentials.find(call.arguments)):
            return ReasonCode.BLOCK_CREDENTIAL_EGRESS if self._tainted else ReasonCode.REVIEW_CREDENTIAL_EGRESS
        # Argument provenance: a distinctive value (email, URL, account, path, id)
        # the user never gave must not come from an injected output in this run
        # or from another tool's description.
        users_own = distinctive_values(user_intent) - self._intent_from_outputs.get(run_id, set())
        values = distinctive_values(call.arguments) - users_own
        if values & self._tainted or (values and self._taint_incomplete):
            return ReasonCode.BLOCK_UNTRUSTED_ARGUMENT_SOURCE
        # A URL built on a tainted one: the injected address with the data appended.
        traced = traced_urls(values, self._tainted, users_own)
        if "path" in traced.values():
            return ReasonCode.BLOCK_UNTRUSTED_ARGUMENT_SOURCE
        if traced:
            return ReasonCode.REVIEW_UNTRUSTED_ARGUMENT_SOURCE
        # The host or mailbox of an injected address in another spelling (a bare host, a +tag, another
        # case, another path): not the same string, so not in ``_tainted``, but the same destination.
        if (self._tainted_hosts or self._tainted_boxes or self._taint_incomplete) and self._reuses_tainted_host(
                user_intent, call):
            return ReasonCode.REVIEW_UNTRUSTED_ARGUMENT_SOURCE
        if not values:
            return self._known_reason(known) or self._suspect_tools.get(call.tool_name)
        for name, described in self._description_values.items():
            if name != call.tool_name and values & described:
                return ReasonCode.BLOCK_UNTRUSTED_ARGUMENT_SOURCE
        if known:  # an address a rule-confirmed attack used before, in any run or process, or a pack rule
            return self._known_reason(known)
        if call.tool_name in self._suspect_tools:
            return self._suspect_tools[call.tool_name]
        if values & self._suspect_values:
            return ReasonCode.REVIEW_CLASSIFIER_FLAGGED
        # Detection is not the gate: a value the scanners missed still came from a tool.
        reads_too = self.config.review_output_sourced_arguments
        if (reads_too or not self.config.is_read_only(call.tool_name)) and sourced_from(
            authority_values(call.arguments), self._observed.keys(), users_own,
        ):
            return ReasonCode.REVIEW_UNTRUSTED_ARGUMENT_SOURCE
        return None

    def _reuses_tainted_host(self, user_intent: str, call: ToolCall) -> bool:
        hosts, boxes = _network_values(call.arguments)
        if not (hosts or boxes):
            return False
        users_hosts, users_boxes = _network_values(user_intent)
        fresh = {h for h in hosts if h not in users_hosts and not _host_overlap({h}, users_hosts)}
        # After a cap dropped tainted values the sets cannot say which hosts are clean (a host that is no
        # distinctive value, a bare or internationalised one, is not caught by the value rule either): one the user
        # did not give is not trusted.
        if self._taint_incomplete and (fresh or boxes - users_boxes):
            return True
        return bool((boxes - users_boxes) & self._tainted_boxes or _host_overlap(fresh, self._tainted_hosts))

    def _known_threat(self, user_intent: str, call: ToolCall) -> str | None:
        """``block`` or ``review`` when the threat memory knows a value of the call (the user's own
        values exempt) or a pack rule for arguments matches it; None otherwise or when it fails."""
        if self._memory is None:
            return None
        # A failure of the memory is reported and ignored.
        values = distinctive_values(call.arguments) - distinctive_values(user_intent)
        known = self._recall.check_values(values, trusted=user_intent)
        levels = [known.level] if known else []
        levels += [hit["level"] for hit in self._recall.text_matches(call.arguments, target="argument")]
        return "block" if "block" in levels else "review" if levels else None

    @staticmethod
    def _known_reason(level: str | None) -> ReasonCode | None:
        return {"block": ReasonCode.BLOCK_KNOWN_THREAT, "review": ReasonCode.REVIEW_KNOWN_THREAT}.get(level or "")

    def _memory_failed(self, method: str, exc: Exception) -> None:
        logger.warning("threat memory failed", extra={"method": method, "error": type(exc).__name__})

    def _inspect_error(self, run_id: str, call: ToolCall, exc: Exception) -> Exception:
        """An upstream's error text reaches the agent as an output does: it gets the same inspection (rules,
        tracked values, detectors, judge) and, when flagged, the same marker in front of it."""
        if not (isinstance(exc, MCPRemoteToolError) and exc.upstream):
            return exc
        flagged = self._inspect_result(run_id, call, {"upstream": str(exc)})
        if not flagged.get("injection_findings"):
            return exc
        return MCPRemoteToolError(f"{_marker(flagged['injection_findings'], 'error')}\n{exc}", upstream=True)

    def _inspect_result(self, run_id: str, call: ToolCall, result: dict[str, Any]) -> dict[str, Any]:
        upstream = result.get("upstream", result)
        # Scanning, the learned detectors and the threat-memory lookups run outside the lock: a
        # hosted detector can take seconds, and the event loop takes the same lock in create_run.
        findings = scan_output(upstream)
        text = upstream if isinstance(upstream, str) else json.dumps(upstream, ensure_ascii=False)
        known = [] if findings else self._recall.text_matches(upstream)
        if any(hit["level"] == "block" for hit in known):
            # A rule from a pack the operator trusts at block level counts like a built-in rule hit
            # (taints the output's values), but teaches the memory nothing.
            findings = [hit["name"] for hit in known]
        values = distinctive_values(upstream)
        hosts, boxes = _network_values(upstream) if findings else (set(), set())
        with self._lock:
            # Provenance first: a detector or judge that fails or hangs below must not leave the values of
            # this output unrecorded.
            for value in authority_values(upstream):  # a re-seen value moves to the end, so eviction never drops a fresh one
                self._observed.pop(value, None)
                self._observed[value] = None
            for stale in list(itertools.islice(self._observed, max(0, len(self._observed) - 50_000))):
                del self._observed[stale]
            if findings:
                self._injection_seen = True
                for taint, found in ((self._tainted, values), (self._tainted_hosts, hosts),
                                     (self._tainted_boxes, boxes)):
                    self._taint_incomplete = self._taint_incomplete or len(found) > MAX_OUTPUT_TAINT
                    taint.update(_newest(found))
                    self._taint_incomplete = self._taint_incomplete or taint.evicted
        collapsed = [] if findings else scan_output_collapsed(upstream)
        detector = None if findings else (
            "line_split_rules" if collapsed
            else "threat_memory" if known or self._recall.hostile(call.tool_name.partition(":")[0])
            else self._semantic_flag(text, "output", run_id) or self._judge_output(run_id, call.tool_name, text))
        with self._lock:
            if self._learner is not None:  # only learning links a reviewed call to the text it reused
                outputs = self._outputs.setdefault(run_id, [])
                outputs.append({"tool_name": call.tool_name, "text": text[:20_000],
                                "values": values, "flagged": bool(findings or detector)})
                del outputs[:-32]
                for stale in list(itertools.islice(self._outputs, max(0, len(self._outputs) - 64))):
                    del self._outputs[stale]
            if detector:
                self._injection_seen = True
                self._taint_incomplete = self._taint_incomplete or len(values) > MAX_OUTPUT_TAINT
                self._suspect_values.update(_newest(values))
                self._taint_incomplete = self._taint_incomplete or self._suspect_values.evicted
        if not findings:
            if detector:
                self._service().storage.add_event(run_id, "MCP_OUTPUT_SUSPECTED",
                                                  {"tool_name": call.tool_name, "detector": detector})
                return {**result, "injection_suspected": True,
                        "injection_findings": collapsed or ["semantic_instruction"]}
            return result
        if self._memory and not known:  # only rule-confirmed text teaches it, never a pack's or its own
            run = self._service().storage.get_run(run_id) or {}
            self._recall.record_attack(upstream, findings, source=call.tool_name.partition(":")[0], run_key=run_id,
                                       trusted=run.get("user_intent", ""))
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
