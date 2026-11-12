"""Approvals of held calls, and learning from them."""
from __future__ import annotations

import asyncio
import json
from typing import Any

from intentshield.mcp_inspect import distinctive_values
from intentshield.models import GatewayResult

from .state import _State


class _Approvals(_State):
    """Approvals of held calls, and learning from them."""

    async def decide_approval(self, approval_id: str, approve: bool, trust_source: bool = False) -> GatewayResult:
        service = self._service()
        approval = await asyncio.to_thread(service.storage.get_approval, approval_id)
        if not approval:
            raise KeyError(approval_id)
        await self._refresh_catalog()
        if approve and approval["tool_name"] in self._drifted_tools:
            # A human approved the previously displayed operation, not a
            # replacement schema supplied later by the upstream server.
            return await asyncio.to_thread(service.decide_approval, approval_id, False)
        result = await asyncio.to_thread(service.decide_approval, approval_id, approve)
        if approve and trust_source:  # only an operator who says so vouches for the server: approving one call does not
            await asyncio.to_thread(self._recall.clear_source, approval["tool_name"].partition(":")[0])
        return result

    async def decide_and_learn(self, approval_id: str, approve: bool,
                               learn: str | None, trust_source: bool = False) -> tuple[GatewayResult, list[dict[str, Any]]]:
        """Decide an approval and, when the operator says so, learn from the outputs the call reused.

        ``learn`` is ``injection`` (only with a rejection: the call was induced by injected text) or
        ``benign`` (only with an approval). Only outputs whose values the call reused are learned, or
        for ``injection`` any flagged output of the run when none was reused; an approval never
        teaches a flagged output as benign."""
        if not (learn is None or (learn == "injection" and not approve) or (learn == "benign" and approve)):
            raise ValueError("learn must be 'injection' with a rejection or 'benign' with an approval")
        if learn and self._learner is None:
            raise ValueError("learning is not enabled (needs exemplar_index_dir and learning_regression)")
        result = await self.decide_approval(approval_id, approve, trust_source)
        if not learn:
            return result, []
        return result, await asyncio.to_thread(self._learn_from_approval, approval_id, learn)

    def _learn_from_approval(self, approval_id: str, learn: str) -> list[dict[str, Any]]:
        from intentshield.learning import linked_excerpt

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

    async def learn_example(self, text: str, label: object) -> dict[str, Any]:
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
        from intentshield.signatures import induce, ollama

        example = next((r for r in self._learner.store.examples("active") if r["id"] == example_id), None)
        if example is None or example["label"] != "instruction":
            raise KeyError(example_id)
        return await asyncio.to_thread(induce, ollama(self.config.signature_model, self.config.signature_host),
                                       self._rules.store, example["text"], self._rule_benign, example_id)

    async def decide_rule(self, rule_id: str, approve: bool) -> dict[str, Any]:
        if self._rules is None:
            raise ValueError("learning is not enabled (needs exemplar_index_dir and learning_regression)")
        row: dict[str, Any] = await asyncio.to_thread(self._rules.store.decide, rule_id, approve)
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
