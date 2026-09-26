"""Local DeBERTa intent classification with an explicit fail-closed boundary.

The module deliberately has no import-time dependency on PyTorch or
Transformers. IntentShield can therefore start normally before a model has
been trained; callers receive an unavailable UNKNOWN abstention rather than a
crash or an optimistic classification.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from enum import StrEnum
from pathlib import Path
from threading import Lock
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field

from .models import ToolCall
from .security_agents import IntentClassifierResult, TrustedToolMetadata


ARTIFACT_SCHEMA_VERSION = 1
DEFAULT_ARTIFACT_DIR = Path("artifacts/intent-deberta-v3-small")
TRAINED_LABELS = ("read", "mutation", "no_action")


class IntentClass(StrEnum):
    READ = "read"
    MUTATION = "mutation"
    NO_ACTION = "no_action"
    UNKNOWN = "unknown"


class ClassifierStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ready: bool
    artifact_dir: str
    model_name: str | None = None
    reason: str | None = None


class IntentPrediction(BaseModel):
    """A prediction suitable for a security decision.

    ``available=False`` always carries ``unknown``, zero confidence and
    ``fail_closed=True``. The classifier is advisory intent evidence, not a
    prompt-injection detector or an authorization decision.
    """

    model_config = ConfigDict(extra="forbid")

    label: IntentClass
    confidence: float = Field(ge=0.0, le=1.0)
    scores: dict[IntentClass, float]
    available: bool
    fail_closed: bool
    reason: str | None = None
    model_name: str | None = None


ModelLoader = Callable[[Path], tuple[Any, Any, Any]]


def _load_transformers_model(artifact_dir: Path) -> tuple[Any, Any, Any]:
    """Load only local artifacts and return tokenizer, model, and torch."""
    import torch  # type: ignore[import-not-found]
    from transformers import (  # type: ignore[import-not-found]
        AutoModelForSequenceClassification,
        AutoTokenizer,
    )

    tokenizer = AutoTokenizer.from_pretrained(
        artifact_dir,
        local_files_only=True,
        trust_remote_code=False,
        fix_mistral_regex=True,
    )
    model = AutoModelForSequenceClassification.from_pretrained(
        artifact_dir, local_files_only=True, trust_remote_code=False,
        use_safetensors=True,
    )
    model.eval()
    return tokenizer, model, torch


class DebertaIntentClassifier:
    """Lazy, local-only runtime adapter for a trained classifier artifact."""

    def __init__(
        self,
        artifact_dir: str | Path = DEFAULT_ARTIFACT_DIR,
        *,
        loader: ModelLoader | None = None,
    ) -> None:
        self.artifact_dir = Path(artifact_dir)
        self._loader = loader or _load_transformers_model
        self._uses_default_loader = loader is None
        self._lock = Lock()
        self._loaded: tuple[Any, Any, Any] | None = None
        self._metadata: dict[str, Any] | None = None
        self._load_error: str | None = None

    def _read_metadata(self) -> dict[str, Any]:
        if self._metadata is not None:
            return self._metadata
        path = self.artifact_dir / "intent_metadata.json"
        if not path.is_file():
            raise RuntimeError(f"classifier artifact metadata is missing: {path}")
        try:
            metadata = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("classifier artifact metadata is unreadable") from exc
        if metadata.get("schema_version") != ARTIFACT_SCHEMA_VERSION:
            raise RuntimeError("unsupported classifier artifact schema")
        id2label = metadata.get("id2label")
        expected = {str(index): label for index, label in enumerate(TRAINED_LABELS)}
        if id2label != expected:
            raise RuntimeError("classifier artifact label mapping is invalid")
        if not isinstance(metadata.get("base_model"), str):
            raise RuntimeError("classifier artifact base model is missing")
        if not isinstance(metadata.get("base_model_revision"), str):
            raise RuntimeError("classifier artifact base model revision is missing")
        max_length = metadata.get("max_length")
        if not isinstance(max_length, int) or not 8 <= max_length <= 4096:
            raise RuntimeError("classifier artifact max_length is invalid")
        minimum_confidence = metadata.get("minimum_confidence")
        if not isinstance(minimum_confidence, (int, float)) or not 0 < minimum_confidence <= 1:
            raise RuntimeError("classifier artifact confidence threshold is invalid")
        release = metadata.get("release")
        if not isinstance(release, dict) or release.get("qualified") is not True:
            raise RuntimeError("classifier artifact did not pass its release gates")
        self._metadata = metadata
        return metadata

    def _verify_files(self, metadata: dict[str, Any]) -> None:
        files = metadata.get("files")
        if not isinstance(files, dict) or not files:
            raise RuntimeError("classifier artifact file manifest is missing")
        required = {"config.json", "tokenizer_config.json", "model.safetensors"}
        if not required.issubset(files):
            raise RuntimeError("classifier artifact file manifest is incomplete")
        for name, expected_hash in files.items():
            if not isinstance(name, str) or Path(name).name != name:
                raise RuntimeError("classifier artifact file manifest is invalid")
            path = self.artifact_dir / name
            if not path.is_file():
                raise RuntimeError(f"classifier artifact file is missing: {name}")
            actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual_hash != expected_hash:
                raise RuntimeError(f"classifier artifact hash mismatch: {name}")

    def status(self) -> ClassifierStatus:
        try:
            metadata = self._read_metadata()
            self._verify_files(metadata)
            if self._uses_default_loader:
                absent = [
                    package
                    for package in ("torch", "transformers")
                    if importlib.util.find_spec(package) is None
                ]
                if absent:
                    raise RuntimeError(
                        "classifier dependencies are missing: " + ", ".join(absent)
                    )
            if self._load_error:
                raise RuntimeError(self._load_error)
            return ClassifierStatus(
                ready=True,
                artifact_dir=str(self.artifact_dir),
                model_name=metadata["base_model"],
            )
        except RuntimeError as exc:
            return ClassifierStatus(
                ready=False,
                artifact_dir=str(self.artifact_dir),
                model_name=(self._metadata or {}).get("base_model"),
                reason=str(exc),
            )

    def _ensure_loaded(self) -> tuple[Any, Any, Any]:
        if self._loaded is not None:
            return self._loaded
        with self._lock:
            if self._loaded is not None:
                return self._loaded
            self._read_metadata()
            self._verify_files(self._metadata or {})
            try:
                self._loaded = self._loader(self.artifact_dir)
            except Exception as exc:  # model backends raise many library-specific errors
                self._load_error = f"classifier could not be loaded: {type(exc).__name__}"
                raise RuntimeError(self._load_error) from exc
            return self._loaded

    def predict(self, text: str) -> IntentPrediction:
        if not text or not text.strip():
            return self._fail_closed("classifier input is empty")
        try:
            metadata = self._read_metadata()
            tokenizer, model, torch = self._ensure_loaded()
            encoded = tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=metadata["max_length"],
            )
            with torch.no_grad():
                output = model(**encoded)
                probabilities = torch.softmax(output.logits, dim=-1)[0].tolist()
            if len(probabilities) != len(TRAINED_LABELS):
                raise RuntimeError("classifier returned an invalid score vector")
            scores = {
                IntentClass(label): round(float(probability), 6)
                for label, probability in zip(TRAINED_LABELS, probabilities, strict=True)
            }
            label = max(scores, key=scores.get)  # type: ignore[arg-type]
            minimum_confidence = float(metadata["minimum_confidence"])
            if scores[label] < minimum_confidence:
                return IntentPrediction(
                    label=IntentClass.UNKNOWN,
                    confidence=scores[label],
                    scores=scores,
                    available=True,
                    fail_closed=True,
                    reason="classifier confidence is below the abstention threshold",
                    model_name=metadata["base_model"],
                )
            return IntentPrediction(
                label=label,
                confidence=scores[label],
                scores=scores,
                available=True,
                fail_closed=False,
                model_name=metadata["base_model"],
            )
        except Exception as exc:
            reason = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
            return self._fail_closed(reason)

    def _fail_closed(self, reason: str) -> IntentPrediction:
        return IntentPrediction(
            label=IntentClass.UNKNOWN,
            confidence=0.0,
            scores={IntentClass(label): 0.0 for label in TRAINED_LABELS},
            available=False,
            fail_closed=True,
            reason=reason,
            model_name=(self._metadata or {}).get("base_model"),
        )


class DebertaGroundingAdapter:
    """Adapt intent-family predictions to the grounding-agent protocol.

    The adapter compares DeBERTa output only with operator-owned mutation
    metadata. It cannot authorize execution, and UNKNOWN/unavailable/no-action
    predictions deliberately contribute zero alignment.
    """

    def __init__(self, classifier: DebertaIntentClassifier) -> None:
        self.classifier = classifier

    def predict(
        self,
        user_intent: str,
        call: ToolCall,
        metadata: TrustedToolMetadata,
    ) -> IntentClassifierResult:
        del call
        prediction = self.classifier.predict(user_intent)
        expected = IntentClass.MUTATION if metadata.mutation else IntentClass.READ
        aligned = prediction.available and not prediction.fail_closed and prediction.label is expected
        return IntentClassifierResult(
            alignment_score=prediction.confidence if aligned else 0.0,
            label=prediction.label.value,
        )
