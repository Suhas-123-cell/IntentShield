"""Reproducible fine-tuning CLI for the IntentShield intent classifier."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import shutil
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .intent_classifier import ARTIFACT_SCHEMA_VERSION, TRAINED_LABELS


DEFAULT_BASE_MODEL = "microsoft/deberta-v3-small"
DEFAULT_DATASET = Path(__file__).with_name("data") / "intent_training.jsonl"


@dataclass(frozen=True)
class Example:
    text: str
    label: str
    action: str
    split: str
    group: str


def load_examples(path: Path) -> list[Example]:
    examples: list[Example] = []
    seen: set[str] = set()
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw_line.strip():
            continue
        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON on dataset line {line_number}") from exc
        try:
            example = Example(
                text=record["text"].strip(),
                label=record["label"],
                action=record["action"],
                split=record["split"],
                group=record["group"],
            )
        except (KeyError, AttributeError) as exc:
            raise ValueError(f"invalid example on dataset line {line_number}") from exc
        if not example.text:
            raise ValueError(f"empty text on dataset line {line_number}")
        if example.label not in TRAINED_LABELS:
            raise ValueError(f"unknown label on dataset line {line_number}: {example.label}")
        if example.split not in {"train", "validation"}:
            raise ValueError(f"unknown split on dataset line {line_number}: {example.split}")
        normalized = " ".join(example.text.lower().split())
        if normalized in seen:
            raise ValueError(f"duplicate text on dataset line {line_number}")
        seen.add(normalized)
        examples.append(example)
    counts = Counter((example.split, example.label) for example in examples)
    group_splits: dict[str, set[str]] = {}
    for example in examples:
        group_splits.setdefault(example.group, set()).add(example.split)
    leaked = sorted(group for group, splits in group_splits.items() if len(splits) > 1)
    if leaked:
        raise ValueError("dataset groups span splits: " + ", ".join(leaked))
    missing = [
        f"{split}/{label}"
        for split in ("train", "validation")
        for label in TRAINED_LABELS
        if counts[(split, label)] == 0
    ]
    if missing:
        raise ValueError("dataset has empty classes: " + ", ".join(missing))
    return examples


def dataset_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _set_determinism(seed: int, torch: Any) -> None:
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    torch.use_deterministic_algorithms(True, warn_only=True)


def train(args: argparse.Namespace) -> dict[str, Any]:
    try:
        import torch
        from torch.utils.data import DataLoader, Dataset
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            get_linear_schedule_with_warmup,
        )
    except ImportError as exc:
        raise RuntimeError(
            "training dependencies are missing; install requirements-ml.txt"
        ) from exc

    dataset_path = Path(args.dataset).resolve()
    output_dir = Path(args.output).resolve()
    examples = load_examples(dataset_path)
    train_examples = [example for example in examples if example.split == "train"]
    validation_examples = [example for example in examples if example.split == "validation"]
    label2id = {label: index for index, label in enumerate(TRAINED_LABELS)}
    id2label = {index: label for label, index in label2id.items()}
    _set_determinism(args.seed, torch)

    class IntentDataset(Dataset):
        def __init__(self, rows: list[Example]) -> None:
            self.rows = rows

        def __len__(self) -> int:
            return len(self.rows)

        def __getitem__(self, index: int) -> tuple[str, int]:
            row = self.rows[index]
            return row.text, label2id[row.label]

    tokenizer = AutoTokenizer.from_pretrained(
        args.base_model,
        revision=args.base_model_revision,
        trust_remote_code=False,
        fix_mistral_regex=True,
    )
    model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model,
        revision=args.base_model_revision,
        trust_remote_code=False,
        num_labels=len(TRAINED_LABELS),
        label2id=label2id,
        id2label=id2label,
    )
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    def collate(batch: list[tuple[str, int]]) -> dict[str, Any]:
        texts, labels = zip(*batch, strict=True)
        encoded = tokenizer(
            list(texts),
            padding=True,
            truncation=True,
            max_length=args.max_length,
            return_tensors="pt",
        )
        encoded["labels"] = torch.tensor(labels, dtype=torch.long)
        return encoded

    generator = torch.Generator().manual_seed(args.seed)
    training_loader = DataLoader(
        IntentDataset(train_examples),
        batch_size=args.batch_size,
        shuffle=True,
        generator=generator,
        collate_fn=collate,
    )
    validation_loader = DataLoader(
        IntentDataset(validation_examples),
        batch_size=args.batch_size,
        shuffle=False,
        collate_fn=collate,
    )
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate)
    total_steps = max(1, len(training_loader) * args.epochs)
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=int(total_steps * args.warmup_ratio),
        num_training_steps=total_steps,
    )

    for _epoch in range(args.epochs):
        model.train()
        for batch in training_loader:
            batch = {key: value.to(device) for key, value in batch.items()}
            optimizer.zero_grad(set_to_none=True)
            loss = model(**batch).loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), args.max_grad_norm)
            optimizer.step()
            scheduler.step()

    model.eval()
    correct = 0
    total = 0
    validation_loss = 0.0
    expected_labels: list[int] = []
    predicted_labels: list[int] = []
    with torch.no_grad():
        for batch in validation_loader:
            batch = {key: value.to(device) for key, value in batch.items()}
            output = model(**batch)
            validation_loss += float(output.loss.item()) * len(batch["labels"])
            predictions = output.logits.argmax(dim=-1)
            correct += int((predictions == batch["labels"]).sum().item())
            total += len(batch["labels"])
            expected_labels.extend(batch["labels"].cpu().tolist())
            predicted_labels.extend(predictions.cpu().tolist())

    per_class: dict[str, dict[str, float | int]] = {}
    for label, label_id in label2id.items():
        true_positive = sum(
            expected == label_id and predicted == label_id
            for expected, predicted in zip(expected_labels, predicted_labels, strict=True)
        )
        false_positive = sum(
            expected != label_id and predicted == label_id
            for expected, predicted in zip(expected_labels, predicted_labels, strict=True)
        )
        false_negative = sum(
            expected == label_id and predicted != label_id
            for expected, predicted in zip(expected_labels, predicted_labels, strict=True)
        )
        precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
        recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_class[label] = {
            "support": sum(expected == label_id for expected in expected_labels),
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
        }

    resolved_revision = getattr(model.config, "_commit_hash", None)
    if not resolved_revision and args.base_model_revision == "main":
        raise RuntimeError("the model registry did not report an immutable base revision")
    metadata = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "task": "intent_classification",
        "base_model": args.base_model,
        "base_model_revision": resolved_revision or args.base_model_revision,
        "id2label": {str(index): label for index, label in id2label.items()},
        "label2id": label2id,
        "max_length": args.max_length,
        "minimum_confidence": args.minimum_confidence,
        "dataset": str(dataset_path),
        "dataset_sha256": dataset_sha256(dataset_path),
        "action_labels": sorted({example.action for example in examples}),
        "seed": args.seed,
        "dependencies": {
            "python": platform.python_version(),
            "torch": torch.__version__,
            "transformers": __import__("transformers").__version__,
        },
        "hyperparameters": {
            "epochs": args.epochs,
            "batch_size": args.batch_size,
            "learning_rate": args.learning_rate,
            "warmup_ratio": args.warmup_ratio,
            "max_grad_norm": args.max_grad_norm,
        },
        "examples": {
            "train": len(train_examples),
            "validation": len(validation_examples),
        },
        "metrics": {
            "validation_accuracy": round(correct / total, 6),
            "validation_loss": round(validation_loss / total, 6),
            "macro_f1": round(
                sum(float(values["f1"]) for values in per_class.values()) / len(per_class), 6
            ),
            "per_class": per_class,
        },
    }
    macro_f1 = float(metadata["metrics"]["macro_f1"])
    lowest_recall = min(float(values["recall"]) for values in per_class.values())
    metadata["release"] = {
        "qualified": macro_f1 >= args.minimum_macro_f1
        and lowest_recall >= args.minimum_class_recall,
        "minimum_macro_f1": args.minimum_macro_f1,
        "minimum_class_recall": args.minimum_class_recall,
        "observed_lowest_class_recall": lowest_recall,
    }

    if output_dir.exists() and not args.overwrite:
        raise RuntimeError(f"output already exists: {output_dir}; pass --overwrite")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=output_dir.parent))
    try:
        model.save_pretrained(temporary, safe_serialization=True)
        tokenizer.save_pretrained(temporary)
        (temporary / "label_map.json").write_text(
            json.dumps(
                {
                    "id2label": metadata["id2label"],
                    "label2id": metadata["label2id"],
                    "abstention_label": "unknown",
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (temporary / "evaluation_report.json").write_text(
            json.dumps(metadata["metrics"], indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        artifact_names = [
            path.name
            for path in temporary.iterdir()
            if path.is_file() and path.name != "intent_metadata.json"
        ]
        metadata["files"] = {
            name: hashlib.sha256((temporary / name).read_bytes()).hexdigest()
            for name in sorted(artifact_names)
        }
        (temporary / "intent_metadata.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        if output_dir.exists():
            shutil.rmtree(output_dir)
        temporary.replace(output_dir)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return metadata


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
    parser.add_argument("--output", default="artifacts/intent-deberta-v3-small")
    parser.add_argument("--base-model", default=DEFAULT_BASE_MODEL)
    parser.add_argument("--base-model-revision", default="main")
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--warmup-ratio", type=float, default=0.1)
    parser.add_argument("--max-grad-norm", type=float, default=1.0)
    parser.add_argument("--max-length", type=int, default=192)
    parser.add_argument("--minimum-confidence", type=float, default=0.65)
    parser.add_argument("--minimum-macro-f1", type=float, default=0.90)
    parser.add_argument("--minimum-class-recall", type=float, default=0.80)
    parser.add_argument("--seed", type=int, default=1729)
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.epochs < 1 or args.batch_size < 1 or args.max_length < 8:
        raise SystemExit("epochs, batch size, and max length must be positive")
    if not 0.0 <= args.warmup_ratio < 1.0:
        raise SystemExit("warmup ratio must be at least zero and less than one")
    if not 0.0 < args.minimum_confidence <= 1.0:
        raise SystemExit("minimum confidence must be greater than zero and at most one")
    if not 0.0 <= args.minimum_macro_f1 <= 1.0:
        raise SystemExit("minimum macro F1 must be between zero and one")
    if not 0.0 <= args.minimum_class_recall <= 1.0:
        raise SystemExit("minimum class recall must be between zero and one")
    metadata = train(args)
    print(json.dumps(metadata, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
