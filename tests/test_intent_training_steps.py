"""The steps of ``intent_training.train``, run without PyTorch: stand-ins for torch and transformers sit in ``sys.modules``."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from intentshield import intent_training
from intentshield.intent_classifier import TRAINED_LABELS


def _hash(text: str) -> int:
    return int(hashlib.sha256(text.encode()).hexdigest()[:8], 16)


class _Values:
    """A list that behaves as the few tensor operations the training reads."""

    def __init__(self, values: Any) -> None:
        self.values = list(values)

    def __len__(self) -> int:
        return len(self.values)

    def __eq__(self, other: object) -> _Values:
        return _Values(a == b for a, b in zip(self.values, other.values, strict=True))

    def sum(self) -> _Values:
        return _Values([sum(self.values)])

    def item(self) -> Any:
        return self.values[0]

    def cpu(self) -> _Values:
        return self

    def to(self, _device: Any) -> _Values:
        return self

    def tolist(self) -> list[Any]:
        return list(self.values)

    def argmax(self, dim: int = -1) -> _Values:
        return _Values(max(range(len(row)), key=row.__getitem__) for row in self.values)


class _Output:
    def __init__(self, logits: list[list[float]]) -> None:
        self.logits = _Values(logits)
        self.loss = types.SimpleNamespace(item=lambda: sum(map(sum, logits)) / len(logits), backward=lambda: None)


class _Model:
    config = types.SimpleNamespace(_commit_hash="0123abc")

    def __init__(self, labels: int) -> None:
        self.labels = labels

    def to(self, _device: Any) -> _Model:
        return self

    def parameters(self) -> list[Any]:
        return []

    def train(self) -> None:
        pass

    def eval(self) -> None:
        pass

    def __call__(self, input_ids: _Values, labels: _Values, **_: Any) -> _Output:
        return _Output([[(_hash(f"{row}{i}") % 97) / 97 for i in range(self.labels)] for row in input_ids.values])

    def save_pretrained(self, directory: Path, safe_serialization: bool = False) -> None:
        (Path(directory) / "model.safetensors").write_text(f"weights {safe_serialization}", encoding="utf-8")


class _Tokenizer:
    def __call__(self, texts: list[str], **_: Any) -> dict[str, _Values]:
        ids = _Values([[_hash(t) % 1000, len(t)] for t in texts])
        return {"input_ids": ids, "attention_mask": _Values([[1, 1]] * len(texts))}

    def save_pretrained(self, directory: Path) -> None:
        (Path(directory) / "tokenizer.json").write_text("{}", encoding="utf-8")


class _Loader:
    def __init__(self, data: list[tuple[str, int]], batch_size: int, shuffle: bool, collate_fn: Any,
                 generator: Any = None) -> None:
        self.data, self.size, self.shuffle, self.collate, self.generator = data, batch_size, shuffle, collate_fn, generator

    def __len__(self) -> int:
        return (len(self.data) + self.size - 1) // self.size

    def __iter__(self) -> Any:
        data = list(self.data)
        if self.shuffle:
            data.sort(key=lambda row: _hash(row[0] + str(self.generator.seed)))
        for start in range(0, len(data), self.size):
            yield self.collate(data[start:start + self.size])


@pytest.fixture
def fake_stack(monkeypatch) -> list[Any]:
    """torch and transformers stand-ins; the list collects what the training asked of them."""
    calls: list[Any] = []
    torch = types.ModuleType("torch")
    torch.__version__ = "0.0-stub"
    torch.manual_seed = lambda seed: calls.append(("seed", seed))
    torch.cuda = types.SimpleNamespace(is_available=lambda: False)
    torch.use_deterministic_algorithms = lambda *a, **k: None
    torch.device = lambda name: name
    torch.Generator = lambda: types.SimpleNamespace(manual_seed=lambda s: types.SimpleNamespace(seed=s))
    torch.tensor = lambda values, dtype=None: _Values(values)
    torch.long = "long"
    torch.no_grad = lambda: __import__("contextlib").nullcontext()
    torch.nn = types.SimpleNamespace(
        utils=types.SimpleNamespace(clip_grad_norm_=lambda params, limit: calls.append(("clip", limit))))

    class AdamW:
        def __init__(self, params: Any, lr: float) -> None:
            calls.append(("lr", lr))

        def zero_grad(self, set_to_none: bool) -> None:
            pass

        def step(self) -> None:
            calls.append("step")

    torch.optim = types.SimpleNamespace(AdamW=AdamW)
    data = types.ModuleType("torch.utils.data")
    data.DataLoader = _Loader
    utils = types.ModuleType("torch.utils")
    utils.data = data
    torch.utils = utils
    transformers = types.ModuleType("transformers")
    transformers.__version__ = "0.0-stub"
    def load_model(name: str, **kw: Any) -> _Model:
        calls.append(("model", name, kw["revision"], kw["trust_remote_code"]))
        return _Model(kw["num_labels"])

    transformers.AutoModelForSequenceClassification = types.SimpleNamespace(
        from_pretrained=load_model)
    transformers.AutoTokenizer = types.SimpleNamespace(
        from_pretrained=lambda name, **kw: calls.append(("tokenizer", name)) or _Tokenizer())
    transformers.get_linear_schedule_with_warmup = lambda optimizer, num_warmup_steps, num_training_steps: (
        calls.append(("schedule", num_warmup_steps, num_training_steps)) or types.SimpleNamespace(step=lambda: None))
    for name, module in (("torch", torch), ("torch.utils", utils), ("torch.utils.data", data), ("transformers", transformers)):
        monkeypatch.setitem(sys.modules, name, module)
    return calls


def _args(tmp_path: Path, **override: Any) -> argparse.Namespace:
    values: dict[str, Any] = {
        "dataset": str(intent_training.DEFAULT_DATASET), "output": str(tmp_path / "artifact"), "base_model": "stub/base",
        "base_model_revision": "main", "epochs": 2, "batch_size": 8, "learning_rate": 2e-5, "warmup_ratio": 0.1,
        "max_grad_norm": 1.0, "max_length": 192, "minimum_confidence": 0.65, "minimum_macro_f1": 0.0,
        "minimum_class_recall": 0.0, "seed": 1729, "overwrite": False}
    return argparse.Namespace(**{**values, **override})


def test_train_writes_the_artifact_and_its_record(tmp_path: Path, fake_stack):
    metadata = intent_training.train(_args(tmp_path))
    out = tmp_path / "artifact"
    assert sorted(p.name for p in out.iterdir()) == [
        "evaluation_report.json", "intent_metadata.json", "label_map.json", "model.safetensors", "tokenizer.json"]
    saved = json.loads((out / "intent_metadata.json").read_text(encoding="utf-8"))
    assert saved == json.loads(json.dumps(metadata))
    assert saved["base_model_revision"] == "0123abc" and saved["dependencies"]["torch"] == "0.0-stub"
    assert set(saved["files"]) == {"evaluation_report.json", "label_map.json", "model.safetensors", "tokenizer.json"}
    assert saved["files"]["model.safetensors"] == hashlib.sha256((out / "model.safetensors").read_bytes()).hexdigest()
    assert (out / "model.safetensors").read_text(encoding="utf-8") == "weights True", "weights are saved as safetensors"
    assert json.loads((out / "label_map.json").read_text(encoding="utf-8"))["abstention_label"] == "unknown"
    assert set(saved["metrics"]["per_class"]) == set(TRAINED_LABELS)
    assert saved["release"]["qualified"] is True
    assert ("seed", 1729) in fake_stack and ("clip", 1.0) in fake_stack and ("lr", 2e-5) in fake_stack
    assert ("model", "stub/base", "main", False) in fake_stack, "remote code is never trusted"


def test_the_release_gate_follows_the_thresholds(tmp_path: Path, fake_stack):
    assert intent_training.train(_args(tmp_path, minimum_macro_f1=0.999))["release"]["qualified"] is False
    assert intent_training.train(_args(tmp_path, minimum_class_recall=1.0, overwrite=True))["release"]["qualified"] is False


def test_an_existing_output_is_refused_after_training_unless_overwrite_is_given(tmp_path: Path, fake_stack):
    intent_training.train(_args(tmp_path))
    with pytest.raises(RuntimeError, match="output already exists"):
        intent_training.train(_args(tmp_path))
    intent_training.train(_args(tmp_path, overwrite=True))
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".artifact-")], "no temporary directory is left"


def test_an_unpinned_base_model_without_a_reported_revision_is_refused(tmp_path: Path, fake_stack, monkeypatch):
    monkeypatch.setattr(_Model, "config", types.SimpleNamespace())
    with pytest.raises(RuntimeError, match="immutable base revision"):
        intent_training.train(_args(tmp_path))
    assert not (tmp_path / "artifact").exists()
    assert intent_training.train(_args(tmp_path, base_model_revision="a1b2c3"))["base_model_revision"] == "a1b2c3"


def test_missing_training_dependencies_say_where_to_get_them(tmp_path: Path, monkeypatch):
    monkeypatch.setitem(sys.modules, "torch", None)
    with pytest.raises(RuntimeError, match="requirements-ml.txt"):
        intent_training.train(_args(tmp_path))


def test_per_class_scores():
    label2id = {"a": 0, "b": 1, "c": 2}
    report = intent_training._per_class(label2id, [0, 0, 1, 1, 2], [0, 1, 1, 1, 0])
    assert report["a"] == {"support": 2, "precision": 0.5, "recall": 0.5, "f1": 0.5}
    assert report["b"]["precision"] == round(2 / 3, 6) and report["b"]["recall"] == 1.0
    assert report["c"] == {"support": 1, "precision": 0.0, "recall": 0.0, "f1": 0.0}
