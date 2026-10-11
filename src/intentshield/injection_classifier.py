"""Local second-stage check: does this text try to instruct the agent?

Runs only on descriptions and outputs the rules pass, catching plain-language and
non-English injections the regexes miss. It is evidence: a hit can send a call to
review, never authorize one. Like the intent classifier it loads local, hash-checked,
safetensors files only, imports PyTorch lazily, and reports unavailable instead of
guessing when anything is wrong.

Train an artifact with ``python -m intentshield.injection_training``.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from threading import Lock
from typing import Any

from .intent_classifier import _load_transformers_model

LABELS = ("data", "instruction")
METADATA = "injection_metadata.json"
# Long outputs are read in overlapping windows; past this many the rest is not scored.
MAX_WINDOWS = 32


class InjectionClassifier:
    def __init__(self, artifact_dir: str | Path) -> None:
        self.artifact_dir = Path(artifact_dir)
        self._lock = Lock()
        self._loaded: tuple[Any, Any, Any] | None = None
        self.metadata: dict[str, Any] = {}
        self.reason: str | None = None
        try:
            self.metadata = self._verified_metadata()
        except (OSError, ValueError, RuntimeError) as exc:
            self.reason = str(exc)

    @property
    def ready(self) -> bool:
        return self.reason is None

    def _verified_metadata(self) -> dict[str, Any]:
        metadata = json.loads((self.artifact_dir / METADATA).read_text(encoding="utf-8"))
        if metadata.get("id2label") != {str(i): label for i, label in enumerate(LABELS)}:
            raise RuntimeError("injection classifier label mapping is invalid")
        if not 0 < float(metadata.get("threshold", 0)) < 1 or not 8 <= int(metadata.get("max_length", 0)) <= 4096:
            raise RuntimeError("injection classifier threshold or max_length is invalid")
        files = metadata.get("files") or {}
        if not {"config.json", "tokenizer_config.json", "model.safetensors"} <= set(files):
            raise RuntimeError("injection classifier file manifest is incomplete")
        for name, digest in files.items():
            path = self.artifact_dir / Path(name).name
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise RuntimeError(f"injection classifier hash mismatch: {name}")
        return metadata

    def score(self, text: str) -> float:
        """Highest probability of ``instruction`` over the text's windows; 0.0 if unavailable."""
        if not self.ready or not text.strip():
            return 0.0
        try:
            with self._lock:
                if self._loaded is None:
                    self._loaded = _load_transformers_model(self.artifact_dir)
            tokenizer, model, torch = self._loaded
            encoded = tokenizer(text, truncation=True, max_length=self.metadata["max_length"], stride=32,
                                return_overflowing_tokens=True, padding=True, return_tensors="pt")
            inputs = {k: v[:MAX_WINDOWS] for k, v in encoded.items() if k in ("input_ids", "attention_mask")}
            with torch.no_grad():
                probabilities = torch.softmax(model(**inputs).logits, dim=-1)[:, 1]
            return round(float(probabilities.max()), 6)
        except Exception as exc:  # model backends raise many library-specific errors
            self.reason = f"injection classifier failed: {type(exc).__name__}"
            return 0.0

    def flags(self, text: str) -> bool:
        return self.score(text) >= float(self.metadata.get("threshold", 1.0))
