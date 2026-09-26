import hashlib
import json
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from intentshield.intent_classifier import (
    DebertaGroundingAdapter,
    DebertaIntentClassifier,
    IntentClass,
    TRAINED_LABELS,
)
from intentshield.models import ToolCall
from intentshield.security_agents import TrustedToolMetadata
from intentshield.intent_training import DEFAULT_DATASET, dataset_sha256, load_examples


def _artifact(path: Path, *, minimum_confidence: float = 0.65) -> None:
    files = {
        "config.json": b"{}",
        "tokenizer_config.json": b"{}",
        "model.safetensors": b"safe weights",
    }
    for name, content in files.items():
        (path / name).write_bytes(content)
    metadata = {
        "schema_version": 1,
        "base_model": "microsoft/deberta-v3-small",
        "base_model_revision": "0123456789abcdef",
        "id2label": {str(index): label for index, label in enumerate(TRAINED_LABELS)},
        "max_length": 192,
        "minimum_confidence": minimum_confidence,
        "release": {"qualified": True},
        "files": {
            name: hashlib.sha256(content).hexdigest() for name, content in files.items()
        },
    }
    (path / "intent_metadata.json").write_text(json.dumps(metadata), encoding="utf-8")


class _Probabilities:
    def __init__(self, values):
        self.values = values

    def __getitem__(self, _index):
        return self

    def tolist(self):
        return self.values


class _Torch:
    @staticmethod
    def no_grad():
        return nullcontext()

    @staticmethod
    def softmax(logits, dim):
        assert dim == -1
        return _Probabilities(logits)


class _Tokenizer:
    def __call__(self, text, **kwargs):
        assert text
        assert kwargs == {"return_tensors": "pt", "truncation": True, "max_length": 192}
        return {"input_ids": [1, 2, 3]}


class _Model:
    def __init__(self, probabilities):
        self.probabilities = probabilities

    def __call__(self, **encoded):
        assert encoded == {"input_ids": [1, 2, 3]}
        return SimpleNamespace(logits=self.probabilities)


def test_checked_in_dataset_is_balanced_and_group_isolated():
    examples = load_examples(DEFAULT_DATASET)
    labels_by_split = {
        split: {label: sum(e.split == split and e.label == label for e in examples) for label in TRAINED_LABELS}
        for split in ("train", "validation")
    }

    assert labels_by_split["train"] == {label: 20 for label in TRAINED_LABELS}
    assert labels_by_split["validation"] == {label: 6 for label in TRAINED_LABELS}
    assert all(len({e.split for e in examples if e.group == group}) == 1 for group in {e.group for e in examples})
    assert len(dataset_sha256(DEFAULT_DATASET)) == 64


def test_missing_artifact_fails_closed_without_importing_ml_dependencies(tmp_path: Path):
    classifier = DebertaIntentClassifier(tmp_path / "missing")

    assert classifier.status().ready is False
    prediction = classifier.predict("Read my inbox")
    assert prediction.label is IntentClass.UNKNOWN
    assert prediction.confidence == 0.0
    assert prediction.available is False
    assert prediction.fail_closed is True
    assert "metadata is missing" in prediction.reason


def test_local_artifact_prediction_uses_explicit_label_mapping(tmp_path: Path):
    _artifact(tmp_path)
    classifier = DebertaIntentClassifier(
        tmp_path,
        loader=lambda _path: (_Tokenizer(), _Model([0.03, 0.94, 0.03]), _Torch()),
    )

    assert classifier.status().ready is True
    prediction = classifier.predict("Send the report")
    assert prediction.label is IntentClass.MUTATION
    assert prediction.confidence == 0.94
    assert prediction.available is True
    assert prediction.fail_closed is False


def test_low_confidence_prediction_abstains(tmp_path: Path):
    _artifact(tmp_path, minimum_confidence=0.7)
    classifier = DebertaIntentClassifier(
        tmp_path,
        loader=lambda _path: (_Tokenizer(), _Model([0.40, 0.35, 0.25]), _Torch()),
    )

    prediction = classifier.predict("Maybe do something with the record")
    assert prediction.label is IntentClass.UNKNOWN
    assert prediction.confidence == 0.4
    assert prediction.available is True
    assert prediction.fail_closed is True
    assert "abstention" in prediction.reason


def test_tampered_artifact_is_degraded_and_never_loaded(tmp_path: Path):
    _artifact(tmp_path)
    (tmp_path / "model.safetensors").write_bytes(b"tampered")
    classifier = DebertaIntentClassifier(
        tmp_path,
        loader=lambda _path: pytest.fail("tampered model must not load"),
    )

    assert classifier.status().ready is False
    prediction = classifier.predict("Delete the record")
    assert prediction.label is IntentClass.UNKNOWN
    assert prediction.available is False
    assert prediction.confidence == 0.0
    assert "hash mismatch" in prediction.reason


def test_unqualified_checkpoint_is_not_available(tmp_path: Path):
    _artifact(tmp_path)
    metadata_path = tmp_path / "intent_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["release"]["qualified"] = False
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    classifier = DebertaIntentClassifier(tmp_path, loader=lambda _path: pytest.fail("must not load"))
    assert classifier.status().ready is False
    assert "release gates" in classifier.predict("Read inbox").reason


def test_grounding_adapter_compares_against_trusted_tool_family(tmp_path: Path):
    _artifact(tmp_path)
    classifier = DebertaIntentClassifier(
        tmp_path,
        loader=lambda _path: (_Tokenizer(), _Model([0.03, 0.94, 0.03]), _Torch()),
    )
    adapter = DebertaGroundingAdapter(classifier)
    call = ToolCall(tool_name="send_email", arguments={}, schema_hash="trusted")
    mutation = TrustedToolMetadata(name="send_email", schema_hash="trusted", mutation=True)
    read = mutation.model_copy(update={"mutation": False})

    assert adapter.predict("Send an email", call, mutation).alignment_score == 0.94
    assert adapter.predict("Send an email", call, read).alignment_score == 0.0


def test_dataset_loader_rejects_template_group_leakage(tmp_path: Path):
    rows = [
        {"text": "Read A", "label": "read", "action": "x", "split": "train", "group": "leak"},
        {"text": "Read B", "label": "read", "action": "x", "split": "validation", "group": "leak"},
    ]
    for split in ("train", "validation"):
        for label in ("mutation", "no_action"):
            rows.append({
                "text": f"{split} {label}", "label": label, "action": "x", "split": split,
                "group": f"{split}-{label}",
            })
    path = tmp_path / "leaky.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")

    with pytest.raises(ValueError, match="groups span splits"):
        load_examples(path)
