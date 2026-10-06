from __future__ import annotations

import fnmatch
import re
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from enum import StrEnum
from threading import BoundedSemaphore
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from .models import ToolCall
from .tools import ToolSpec, canonical_json


class EvidenceReason(StrEnum):
    NO_INJECTION_INDICATORS = "NO_INJECTION_INDICATORS"
    PROMPT_INJECTION_PATTERN = "PROMPT_INJECTION_PATTERN"
    EXFILTRATION_PATTERN = "EXFILTRATION_PATTERN"
    TOOL_METADATA_MATCH = "TOOL_METADATA_MATCH"
    TOOL_METADATA_MISMATCH = "TOOL_METADATA_MISMATCH"
    SCHEMA_HASH_MATCH = "SCHEMA_HASH_MATCH"
    SCHEMA_HASH_MISMATCH = "SCHEMA_HASH_MISMATCH"
    ACTION_GROUNDED = "ACTION_GROUNDED"
    ACTION_NOT_GROUNDED = "ACTION_NOT_GROUNDED"
    ACTION_EXPLICITLY_NEGATED = "ACTION_EXPLICITLY_NEGATED"
    RESOURCE_IN_SCOPE = "RESOURCE_IN_SCOPE"
    RESOURCE_OUT_OF_SCOPE = "RESOURCE_OUT_OF_SCOPE"
    DESTINATION_GROUNDED = "DESTINATION_GROUNDED"
    DESTINATION_NOT_GROUNDED = "DESTINATION_NOT_GROUNDED"
    DESTINATION_OUT_OF_SCOPE = "DESTINATION_OUT_OF_SCOPE"
    LOCAL_CLASSIFIER_USED = "LOCAL_CLASSIFIER_USED"
    LOCAL_CLASSIFIER_FAILED = "LOCAL_CLASSIFIER_FAILED"
    AGENT_TIMEOUT = "AGENT_TIMEOUT"
    AGENT_FAILURE = "AGENT_FAILURE"
    MUTATION_REQUIRES_POLICY_REVIEW = "MUTATION_REQUIRES_POLICY_REVIEW"
    CONSENSUS_CLEAR = "CONSENSUS_CLEAR"
    CONSENSUS_REVIEW = "CONSENSUS_REVIEW"
    CONSENSUS_BLOCK = "CONSENSUS_BLOCK"


class EvidenceStatus(StrEnum):
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"


class SecurityDisposition(StrEnum):
    """Advisory disposition; deliberately has no ALLOW/EXECUTE state."""

    CLEAR_FOR_POLICY = "CLEAR_FOR_POLICY"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class TrustedToolMetadata(BaseModel):
    """Minimal registry facts agents may trust while analysing a proposed call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=300)
    schema_hash: str = Field(min_length=1, max_length=128)
    mutation: bool
    resource_field: str | None = Field(default=None, min_length=1, max_length=100)
    destination_field: str | None = Field(default=None, min_length=1, max_length=100)
    allowed_resources: tuple[str, ...] = ()
    allowed_destinations: tuple[str, ...] = ()
    grounding_terms: tuple[str, ...] = ()

    @classmethod
    def from_spec(
        cls,
        spec: ToolSpec,
        *,
        allowed_resources: set[str] | tuple[str, ...] = (),
        allowed_destinations: list[str] | tuple[str, ...] = (),
    ) -> "TrustedToolMetadata":
        resources = (
            spec.allowed_resources_override
            if spec.allowed_resources_override is not None
            else allowed_resources
        )
        destinations = (
            spec.allowed_destinations_override
            if spec.allowed_destinations_override is not None
            else allowed_destinations
        )
        return cls(
            name=spec.name,
            schema_hash=spec.schema_hash,
            mutation=spec.mutation,
            resource_field=spec.resource_field,
            destination_field=spec.destination_field,
            allowed_resources=tuple(sorted(resources)),
            allowed_destinations=tuple(destinations),
            grounding_terms=tuple(sorted(set(spec.grounding_terms))),
        )


class IntentClassifierResult(BaseModel):
    """Narrow output contract for a local classifier such as DeBERTa."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    alignment_score: float = Field(ge=0.0, le=1.0)
    label: str = Field(min_length=1, max_length=100)


@runtime_checkable
class LocalIntentClassifier(Protocol):
    def predict(
        self,
        user_intent: str,
        call: ToolCall,
        metadata: TrustedToolMetadata,
    ) -> IntentClassifierResult: ...


class DetectionEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent: Literal["detection"] = "detection"
    status: EvidenceStatus
    injection_score: float = Field(ge=0.0, le=1.0)
    reason_codes: tuple[EvidenceReason, ...] = Field(min_length=1)
    matched_rules: tuple[str, ...] = ()
    elapsed_ms: float = Field(default=0.0, ge=0.0)


class GroundingEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent: Literal["grounding"] = "grounding"
    status: EvidenceStatus
    intent_alignment: float = Field(ge=0.0, le=1.0)
    scope_score: float = Field(ge=0.0, le=1.0)
    classifier_score: float | None = Field(default=None, ge=0.0, le=1.0)
    classifier_label: str | None = Field(default=None, min_length=1, max_length=100)
    reason_codes: tuple[EvidenceReason, ...] = Field(min_length=1)
    elapsed_ms: float = Field(default=0.0, ge=0.0)


class SecurityAssessment(BaseModel):
    """Validated evidence for policy consumption, never an execution permit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    disposition: SecurityDisposition
    injection_score: float = Field(ge=0.0, le=1.0)
    intent_alignment: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=1.0)
    reason_codes: tuple[EvidenceReason, ...] = Field(min_length=1)
    detection: DetectionEvidence
    grounding: GroundingEvidence
    fail_closed: bool
    execution_authorized: Literal[False] = False
    policy_evaluation_required: Literal[True] = True


class SecuritySupervisorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    timeout_ms: int = Field(default=250, ge=1, le=30_000)
    injection_block_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    minimum_intent_alignment: float = Field(default=0.60, ge=0.0, le=1.0)
    mutation_risk_floor: float = Field(default=0.35, ge=0.0, le=1.0)
    lenient_reads: bool = False


class AnalysisAgent(Protocol):
    def analyze(
        self,
        user_intent: str,
        call: ToolCall,
        metadata: TrustedToolMetadata,
    ) -> DetectionEvidence | GroundingEvidence: ...


_INJECTION_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?", re.I),
    ),
    (
        "authority_impersonation",
        re.compile(r"(?:system|developer)\s+(?:prompt|message|instructions?)", re.I),
    ),
    (
        "exfiltration",
        re.compile(
            r"(?:reveal|steal|exfiltrat\w*|leak|upload)\s+(?:the\s+)?"
            r"(?:secret|credential|token|password|private\s+key|data)",
            re.I,
        ),
    ),
    (
        "unauthorized_recipient",
        re.compile(r"(?:send|forward|email)\b[^.!?]{0,120}\b(?:attacker|evil|unauthori[sz]ed)", re.I),
    ),
)

_READ_ACTIONS = frozenset({
    "read", "get", "list", "search", "find", "show", "view", "fetch", "check",
    "summarize", "summarise", "inspect", "retrieve",
})
_GENERIC_TERMS = _READ_ACTIONS | frozenset({
    "user", "users", "details", "detail", "info", "information", "all", "data", "item", "items", "to",
    # Stopwords: tool names like The23andMe split into "the", "and", "me".
    "the", "a", "an", "and", "or", "of", "for", "in", "on", "at", "by", "with", "from", "me", "my",
    "i", "you", "your", "it", "is", "be", "can", "please",
})
_WRITE_ACTIONS = frozenset(
    {
        "append",
        "approve",
        "assign",
        "cancel",
        "close",
        "create",
        "delete",
        "email",
        "forward",
        "move",
        "post",
        "remove",
        "rename",
        "send",
        "update",
        "upload",
        "write",
        # Common MCP mutation verbs. Grounding a mutation only lets it reach
        # human review; it never authorizes execution.
        "add", "edit", "replace", "insert", "modify", "change", "set", "save", "put", "push",
        "commit", "merge", "install", "publish", "schedule", "book", "pay", "transfer", "mark",
        "abort", "start", "restart", "deploy", "invite", "reply", "share", "archive",
    }
)


def _elapsed_ms(start: float) -> float:
    return round((time.monotonic() - start) * 1000, 3)


def _tokens(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", value.lower()))


def _explicitly_negates(intent: str, actions: set[str]) -> bool:
    if not actions:
        return False
    alternatives = "|".join(re.escape(action) for action in sorted(actions))
    return bool(
        re.search(
            rf"\b(?:do\s+not|don't|never|must\s+not|stop)\b[^.!?]{{0,80}}\b(?:{alternatives})\w*\b",
            intent,
            re.I,
        )
    )


class DeterministicDetectionAgent:
    """Detects prompt-injection/exfiltration indicators without network access."""

    def analyze(
        self,
        user_intent: str,
        call: ToolCall,
        metadata: TrustedToolMetadata,
    ) -> DetectionEvidence:
        del metadata
        started = time.monotonic()
        # Arguments are the indirect-prompt-injection boundary. Text the user typed
        # verbatim is the user's own request ("forward this: ignore previous
        # instructions..."), so a match the intent already contains does not count.
        content = f"{call.tool_name}\n{canonical_json(call.arguments)}"
        intent = " ".join(user_intent.lower().split())
        matched = tuple(
            name for name, pattern in _INJECTION_RULES
            if any(" ".join(m.group(0).lower().split()) not in intent for m in pattern.finditer(content))
        )
        if not matched:
            return DetectionEvidence(
                status=EvidenceStatus.COMPLETE,
                injection_score=0.02,
                reason_codes=(EvidenceReason.NO_INJECTION_INDICATORS,),
                elapsed_ms=_elapsed_ms(started),
            )
        reasons = [EvidenceReason.PROMPT_INJECTION_PATTERN]
        if "exfiltration" in matched or "unauthorized_recipient" in matched:
            reasons.append(EvidenceReason.EXFILTRATION_PATTERN)
        return DetectionEvidence(
            status=EvidenceStatus.COMPLETE,
            injection_score=min(0.99, 0.52 + (0.23 * len(matched))),
            reason_codes=tuple(reasons),
            matched_rules=matched,
            elapsed_ms=_elapsed_ms(started),
        )


class DeterministicGroundingAgent:
    """Grounds tool, schema, action, resource and destination to trusted facts."""

    def __init__(self, classifier: LocalIntentClassifier | None = None) -> None:
        self.classifier = classifier

    def analyze(
        self,
        user_intent: str,
        call: ToolCall,
        metadata: TrustedToolMetadata,
    ) -> GroundingEvidence:
        started = time.monotonic()
        reasons: list[EvidenceReason] = []
        hard_failure = False
        scope_score = 1.0

        if call.tool_name == metadata.name:
            reasons.append(EvidenceReason.TOOL_METADATA_MATCH)
        else:
            reasons.append(EvidenceReason.TOOL_METADATA_MISMATCH)
            hard_failure = True
        if call.schema_hash == metadata.schema_hash:
            reasons.append(EvidenceReason.SCHEMA_HASH_MATCH)
        else:
            reasons.append(EvidenceReason.SCHEMA_HASH_MISMATCH)
            hard_failure = True

        # Read/mutation classification is operator-owned ToolSpec metadata.
        # The upstream tool name can add no authority and is not trusted to
        # define the expected action family.
        intent_action_family = set(
            _WRITE_ACTIONS if metadata.mutation else _READ_ACTIONS
        )
        intent_tokens = _tokens(user_intent)
        # Generic verbs ("get", "list") in a tool name must not count as grounding,
        # or any "get ..." request would ground every Get* tool.
        specific_terms = _tokens(" ".join(metadata.grounding_terms)) - _GENERIC_TERMS
        if _explicitly_negates(user_intent, intent_action_family):
            deterministic_alignment = 0.0
            reasons.append(EvidenceReason.ACTION_EXPLICITLY_NEGATED)
        elif (
            intent_action_family & intent_tokens and specific_terms & intent_tokens
        ) or (
            # Reads need only specific entity overlap ("give me the GitHub user
            # details" has no listed verb). Mutations still need an explicit verb.
            not metadata.mutation and specific_terms & intent_tokens
        ):
            deterministic_alignment = 0.95
            reasons.append(EvidenceReason.ACTION_GROUNDED)
        else:
            deterministic_alignment = 0.30
            reasons.append(EvidenceReason.ACTION_NOT_GROUNDED)

        if metadata.resource_field:
            resource = call.arguments.get(metadata.resource_field)
            if isinstance(resource, str) and (
                not metadata.allowed_resources or resource in metadata.allowed_resources
            ):
                reasons.append(EvidenceReason.RESOURCE_IN_SCOPE)
            else:
                reasons.append(EvidenceReason.RESOURCE_OUT_OF_SCOPE)
                scope_score = 0.0
                hard_failure = True

        if metadata.destination_field:
            destination = call.arguments.get(metadata.destination_field)
            if not isinstance(destination, str) or not destination.strip() or not any(
                fnmatch.fnmatchcase(destination, pattern)
                for pattern in metadata.allowed_destinations
            ):
                reasons.append(EvidenceReason.DESTINATION_OUT_OF_SCOPE)
                scope_score = 0.0
                hard_failure = True
            else:
                destination_tokens = _tokens(destination.split("@", 1)[0])
                # When the user names addresses, only those exact addresses ground;
                # token overlap would accept alice.archive@ for alice@.
                named = {a.lower() for a in re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", user_intent)}
                if destination.lower() in named if named else destination_tokens & intent_tokens:
                    reasons.append(EvidenceReason.DESTINATION_GROUNDED)
                    if (
                        deterministic_alignment == 0.30
                        and intent_action_family & intent_tokens
                    ):
                        reasons = [
                            reason
                            for reason in reasons
                            if reason is not EvidenceReason.ACTION_NOT_GROUNDED
                        ]
                        reasons.append(EvidenceReason.ACTION_GROUNDED)
                        deterministic_alignment = 0.95
                else:
                    reasons.append(EvidenceReason.DESTINATION_NOT_GROUNDED)
                    deterministic_alignment = min(deterministic_alignment, 0.55)

        classifier_score: float | None = None
        classifier_label: str | None = None
        if self.classifier is not None:
            try:
                prediction = IntentClassifierResult.model_validate(
                    self.classifier.predict(user_intent, call, metadata)
                )
            except Exception:
                # Classifier code is a plug-in boundary. Invalid output and
                # runtime errors are security failures, not soft fallbacks.
                return GroundingEvidence(
                    status=EvidenceStatus.FAILED,
                    intent_alignment=0.0,
                    scope_score=0.0,
                    reason_codes=(EvidenceReason.LOCAL_CLASSIFIER_FAILED,),
                    elapsed_ms=_elapsed_ms(started),
                )
            classifier_score = prediction.alignment_score
            classifier_label = prediction.label
            reasons.append(EvidenceReason.LOCAL_CLASSIFIER_USED)

        if hard_failure:
            alignment = 0.0
        elif classifier_score is None:
            alignment = deterministic_alignment
        else:
            # A learned classifier can make grounding more conservative, but it
            # cannot wash out deterministic constraints or explicit negation.
            alignment = min(deterministic_alignment, classifier_score)

        return GroundingEvidence(
            status=EvidenceStatus.COMPLETE,
            intent_alignment=round(alignment, 4),
            scope_score=scope_score,
            classifier_score=classifier_score,
            classifier_label=classifier_label,
            reason_codes=tuple(reasons),
            elapsed_ms=_elapsed_ms(started),
        )


class SecurityAnalysisSupervisor:
    """Runs two bounded evidence agents and combines them conservatively."""

    def __init__(
        self,
        *,
        config: SecuritySupervisorConfig | None = None,
        detection_agent: AnalysisAgent | None = None,
        grounding_agent: AnalysisAgent | None = None,
        classifier: LocalIntentClassifier | None = None,
    ) -> None:
        self.config = config or SecuritySupervisorConfig()
        self.detection_agent = detection_agent or DeterministicDetectionAgent()
        self.grounding_agent = grounding_agent or DeterministicGroundingAgent(classifier)
        self._executor = ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="intentshield-security"
        )
        self._slots = BoundedSemaphore(2)

    def _submit(
        self,
        agent: AnalysisAgent,
        user_intent: str,
        call: ToolCall,
        metadata: TrustedToolMetadata,
    ) -> Future[DetectionEvidence | GroundingEvidence] | None:
        if not self._slots.acquire(blocking=False):
            return None

        def run() -> DetectionEvidence | GroundingEvidence:
            try:
                return agent.analyze(
                    user_intent,
                    call.model_copy(deep=True),
                    metadata.model_copy(deep=True),
                )
            finally:
                self._slots.release()

        return self._executor.submit(run)

    def analyze(
        self,
        user_intent: str,
        call: ToolCall,
        metadata: TrustedToolMetadata,
    ) -> SecurityAssessment:
        if not user_intent.strip():
            raise ValueError("user_intent must not be blank")

        futures: dict[str, Future[DetectionEvidence | GroundingEvidence] | None] = {
            "detection": self._submit(
                self.detection_agent, user_intent, call, metadata
            ),
            "grounding": self._submit(
                self.grounding_agent, user_intent, call, metadata
            ),
        }
        active = {future for future in futures.values() if future is not None}
        done, pending = wait(active, timeout=self.config.timeout_ms / 1000)
        for future in pending:
            future.cancel()

        detection = self._detection_result(futures["detection"], done)
        grounding = self._grounding_result(futures["grounding"], done)
        return self._combine(detection, grounding, metadata)

    @staticmethod
    def _detection_result(
        future: Future[DetectionEvidence | GroundingEvidence] | None,
        done: set[Future[DetectionEvidence | GroundingEvidence]],
    ) -> DetectionEvidence:
        if future is None or future not in done:
            return DetectionEvidence(
                status=EvidenceStatus.TIMED_OUT,
                injection_score=1.0,
                reason_codes=(EvidenceReason.AGENT_TIMEOUT,),
            )
        try:
            return DetectionEvidence.model_validate(future.result())
        except Exception:
            return DetectionEvidence(
                status=EvidenceStatus.FAILED,
                injection_score=1.0,
                reason_codes=(EvidenceReason.AGENT_FAILURE,),
            )

    @staticmethod
    def _grounding_result(
        future: Future[DetectionEvidence | GroundingEvidence] | None,
        done: set[Future[DetectionEvidence | GroundingEvidence]],
    ) -> GroundingEvidence:
        if future is None or future not in done:
            return GroundingEvidence(
                status=EvidenceStatus.TIMED_OUT,
                intent_alignment=0.0,
                scope_score=0.0,
                reason_codes=(EvidenceReason.AGENT_TIMEOUT,),
            )
        try:
            return GroundingEvidence.model_validate(future.result())
        except Exception:
            return GroundingEvidence(
                status=EvidenceStatus.FAILED,
                intent_alignment=0.0,
                scope_score=0.0,
                reason_codes=(EvidenceReason.AGENT_FAILURE,),
            )

    def _combine(
        self,
        detection: DetectionEvidence,
        grounding: GroundingEvidence,
        metadata: TrustedToolMetadata,
    ) -> SecurityAssessment:
        failed = (
            detection.status is not EvidenceStatus.COMPLETE
            or grounding.status is not EvidenceStatus.COMPLETE
        )
        injection = detection.injection_score
        alignment = grounding.intent_alignment
        risk = max(
            injection,
            1.0 - alignment,
            self.config.mutation_risk_floor if metadata.mutation else 0.0,
        )
        reasons = list(dict.fromkeys((*detection.reason_codes, *grounding.reason_codes)))
        # A mutation whose only gap is vocabulary ("click the #submit button" names no
        # listed verb) goes to human review: it can never run unapproved anyway. An
        # ungrounded recipient, negation or hard failure (alignment 0) still blocks.
        unmatched_mutation = (
            metadata.mutation
            and alignment > 0.0
            and EvidenceReason.ACTION_NOT_GROUNDED in grounding.reason_codes
            and EvidenceReason.DESTINATION_NOT_GROUNDED not in grounding.reason_codes
        )

        if (
            failed
            or injection >= self.config.injection_block_threshold
            or grounding.scope_score == 0.0
            or (
                alignment < self.config.minimum_intent_alignment
                and not unmatched_mutation
                # Lenient reads: an ungrounded read is evidence, not a veto. Negated
                # or failed grounding (alignment 0) stays strict.
                and (metadata.mutation or not self.config.lenient_reads or alignment == 0.0)
            )
        ):
            disposition = SecurityDisposition.BLOCK
            reasons.append(EvidenceReason.CONSENSUS_BLOCK)
        elif metadata.mutation:
            disposition = SecurityDisposition.REVIEW
            reasons.extend(
                (EvidenceReason.MUTATION_REQUIRES_POLICY_REVIEW, EvidenceReason.CONSENSUS_REVIEW)
            )
        else:
            disposition = SecurityDisposition.CLEAR_FOR_POLICY
            reasons.append(EvidenceReason.CONSENSUS_CLEAR)

        return SecurityAssessment(
            disposition=disposition,
            injection_score=round(injection, 4),
            intent_alignment=round(alignment, 4),
            risk_score=round(risk, 4),
            reason_codes=tuple(dict.fromkeys(reasons)),
            detection=detection,
            grounding=grounding,
            fail_closed=failed,
        )
