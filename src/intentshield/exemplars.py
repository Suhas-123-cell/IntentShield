"""Learned injection exemplars: a local embedding nearest-neighbour detector that can grow.

A text is cut into overlapping chunks (about 48 words, or 160 characters for unspaced scripts) and
each chunk is embedded with a local multilingual model (intfloat/multilingual-e5-small). A chunk
scores the similarity-weighted share of known injection chunks among its ``k`` nearest neighbours,
each class weighted by the inverse of its size so the larger class does not win by count; a text
scores its worst chunk and is flagged at ``threshold``. A vote rather than the nearest neighbour,
because this embedder puts nearly every pair between 0.7 and 0.9 (on validation the vote found three
times the injections at the same false-flag rate). A new exemplar changes the votes at once, with no
retraining. Evidence only, like every learned detector here: a flag can send a call to review, never
authorize one.

Known injections are mostly benign text with an attack woven in. Storing them whole would teach the
index that the benign part is an attack, so an injection's chunks are kept only when no benign chunk
is a near-duplicate (``DUPLICATE``). Benign chunks are added first for that reason.

The embedder loads local, hash-checked safetensors files only, imports PyTorch lazily, and reports
unavailable instead of guessing. Build the artifacts with:

    .venv/bin/python -m intentshield.exemplars download --out artifacts/embedder-e5-small
    .venv/bin/python -m intentshield.exemplars seed --embedder artifacts/embedder-e5-small --out artifacts/exemplars
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from threading import Lock
from typing import Any, Iterable

import numpy as np

MODEL = "intfloat/multilingual-e5-small"
METADATA = "embedder_metadata.json"
FILES = ("config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json",
         "special_tokens_map.json", "sentencepiece.bpe.model")
CHUNK_WORDS, CHUNK_STRIDE, CHUNK_CHARS, CHAR_STRIDE, MAX_CHUNKS = 48, 32, 160, 110, 32
K_CHOICES = (15, 30, 50, 100)
# An injection chunk at least this similar to a benign chunk is the benign part of the text.
DUPLICATE = 0.92


def chunks(text: str) -> list[str]:
    """Overlapping word windows; character windows for scripts written without spaces."""
    text = " ".join(text.split())
    if not text:
        return []
    words = text.split(" ")
    if len(words) * 12 < len(text):  # few spaces for the length: Chinese, Japanese, Thai
        starts = range(0, max(len(text) - (CHUNK_CHARS - CHAR_STRIDE), 1), CHAR_STRIDE)
        return [text[i:i + CHUNK_CHARS] for i in starts][:MAX_CHUNKS]
    starts = range(0, max(len(words) - (CHUNK_WORDS - CHUNK_STRIDE), 1), CHUNK_STRIDE)
    return [" ".join(words[i:i + CHUNK_WORDS]) for i in starts][:MAX_CHUNKS]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def download(out: Path) -> dict[str, Any]:
    """Fetch the embedder's files once and record their hashes; later loads are offline."""
    from huggingface_hub import hf_hub_download

    out.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        hf_hub_download(MODEL, name, local_dir=out)
    metadata = {"model": MODEL, "files": {name: _sha256(out / name) for name in FILES}}
    (out / METADATA).write_text(json.dumps(metadata, indent=2))
    return metadata


class Embedder:
    def __init__(self, artifact_dir: str | Path) -> None:
        self.artifact_dir = Path(artifact_dir)
        self._lock = Lock()
        self._loaded: tuple[Any, Any, Any] | None = None
        self.metadata: dict[str, Any] = {}
        self.reason: str | None = None
        try:
            metadata = json.loads((self.artifact_dir / METADATA).read_text())
            if metadata.get("model") != MODEL or set(metadata.get("files") or {}) != set(FILES):
                raise RuntimeError("embedder metadata does not match the expected model and files")
            for name, digest in metadata["files"].items():
                if _sha256(self.artifact_dir / name) != digest:
                    raise RuntimeError(f"embedder hash mismatch: {name}")
            self.metadata = metadata
        except (OSError, ValueError, RuntimeError) as exc:
            self.reason = str(exc)

    @property
    def ready(self) -> bool:
        return self.reason is None

    def embed(self, texts: list[str], batch: int = 32) -> np.ndarray:
        """L2-normalized embeddings, one row per text (mean pooling, as the model is trained)."""
        if not self.ready:
            raise RuntimeError(f"embedder unavailable: {self.reason}")
        with self._lock:
            if self._loaded is None:
                import torch
                from transformers import AutoModel, AutoTokenizer

                tokenizer = AutoTokenizer.from_pretrained(self.artifact_dir, local_files_only=True,
                                                          trust_remote_code=False)
                model = AutoModel.from_pretrained(self.artifact_dir, local_files_only=True,
                                                  trust_remote_code=False, use_safetensors=True)
                model.eval()
                self._loaded = (tokenizer, model, torch)
        tokenizer, model, torch = self._loaded
        out = []
        for i in range(0, len(texts), batch):
            encoded = tokenizer([f"query: {t}" for t in texts[i:i + batch]], padding=True, truncation=True,
                                max_length=512, return_tensors="pt")
            with torch.no_grad():
                hidden = model(**encoded).last_hidden_state
            mask = encoded["attention_mask"].unsqueeze(-1).to(hidden.dtype)
            pooled = (hidden * mask).sum(1) / mask.sum(1).clamp(min=1)
            out.append(torch.nn.functional.normalize(pooled, dim=-1).numpy())
        return np.concatenate(out) if out else np.zeros((0, 384), dtype=np.float32)


class ExemplarIndex:
    def __init__(self, embedder: Embedder, threshold: float = 0.9, k: int = 50) -> None:
        self.embedder, self.threshold, self.k = embedder, threshold, k
        self.vectors: dict[str, np.ndarray] = {"instruction": np.zeros((0, 384), np.float32),
                                               "data": np.zeros((0, 384), np.float32)}
        self.texts: dict[str, list[str]] = {"instruction": [], "data": []}

    def add(self, texts: Iterable[str], label: str) -> list[str]:
        """Add texts' chunks under ``label``; returns the chunks kept. Add benign texts first."""
        pieces = list(dict.fromkeys(c for t in texts for c in chunks(t)))
        return self.add_vectors(pieces, self.embedder.embed(pieces) if pieces else None, label)

    def add_vectors(self, pieces: list[str], vectors: np.ndarray | None, label: str) -> list[str]:
        """``add`` for chunks already embedded; injection chunks that duplicate a benign one are dropped."""
        if label not in self.vectors:
            raise ValueError("label must be 'instruction' or 'data'")
        if not pieces or vectors is None:
            return []
        if label == "instruction" and len(self.vectors["data"]):
            keep = (vectors @ self.vectors["data"].T).max(axis=1) < DUPLICATE
            pieces, vectors = [p for p, k in zip(pieces, keep) if k], vectors[keep]
        self.vectors[label] = np.concatenate([self.vectors[label], vectors.astype(np.float32)])
        self.texts[label] = self.texts[label] + pieces
        return pieces

    def copy(self) -> "ExemplarIndex":
        """A copy that can be added to without changing this index (arrays are replaced, not mutated)."""
        twin = ExemplarIndex(self.embedder, self.threshold, self.k)
        twin.vectors, twin.texts = dict(self.vectors), {k: list(v) for k, v in self.texts.items()}
        return twin

    def embed_text(self, text: str) -> np.ndarray:
        pieces = chunks(text)
        return self.embedder.embed(pieces) if pieces else np.zeros((0, 384), np.float32)

    def neighbours(self, text: str, k: int) -> tuple[np.ndarray, np.ndarray]:
        """Per chunk, the k nearest exemplars: (similarities, is-injection), both chunks x k."""
        return self.neighbours_of(self.embed_text(text), k)

    def neighbours_of(self, vectors: np.ndarray, k: int) -> tuple[np.ndarray, np.ndarray]:
        if not len(vectors) or not len(self.vectors["instruction"]) or not len(self.vectors["data"]):
            return np.zeros((0, 0), np.float32), np.zeros((0, 0), bool)
        sims = vectors @ np.concatenate([self.vectors["instruction"], self.vectors["data"]]).T
        top = np.argsort(-sims, axis=1)[:, :k]
        return np.take_along_axis(sims, top, axis=1), top < len(self.vectors["instruction"])

    def score_vectors(self, vectors: np.ndarray) -> float:
        return self.vote(*self.neighbours_of(vectors, self.k), self.k, self.sizes())

    def sizes(self) -> tuple[int, int]:
        return len(self.vectors["instruction"]), len(self.vectors["data"])

    @staticmethod
    def vote(sims: np.ndarray, injection: np.ndarray, k: int, sizes: tuple[int, int]) -> float:
        """The worst chunk's class-balanced, similarity-weighted share of injections among k neighbours."""
        if not sims.size:
            return 0.0
        sims, injection = np.clip(sims[:, :k], 0, None), injection[:, :k]
        attack = (sims * injection).sum(axis=1) / max(sizes[0], 1)
        benign = (sims * ~injection).sum(axis=1) / max(sizes[1], 1)
        return float((attack / np.maximum(attack + benign, 1e-12)).max())

    def score(self, text: str) -> float:
        return self.vote(*self.neighbours(text, self.k), self.k, self.sizes())

    def flags(self, text: str) -> bool:
        return self.score(text) >= self.threshold

    def save(self, out: Path) -> None:
        out.mkdir(parents=True, exist_ok=True)
        np.savez(out / "index.npz", instruction=self.vectors["instruction"], data=self.vectors["data"])
        (out / "index.json").write_text(json.dumps({
            "threshold": self.threshold, "k": self.k, "embedder": self.embedder.metadata,
            "instruction_texts": self.texts["instruction"], "data_texts": self.texts["data"]}, ensure_ascii=False))

    @classmethod
    def load(cls, path: Path, embedder: Embedder) -> "ExemplarIndex":
        meta = json.loads((path / "index.json").read_text())
        if meta["embedder"] != embedder.metadata:
            raise RuntimeError("exemplar index was built with a different embedder")
        index = cls(embedder, meta["threshold"], meta["k"])
        arrays = np.load(path / "index.npz")
        for label in ("instruction", "data"):
            index.vectors[label], index.texts[label] = arrays[label], meta[f"{label}_texts"]
        return index


def threshold_for(benign: list[float], max_fpr: float) -> float:
    """The lowest threshold that flags at most ``max_fpr`` of the benign scores."""
    ranked, allowed = sorted(benign, reverse=True), int(max_fpr * len(benign))
    return max(ranked[allowed] + 1e-6 if allowed < len(ranked) else 0.0, 1e-6)


def tune(index: ExemplarIndex, rows: list[tuple[str, bool]], max_fpr: float,
         ks: tuple[int, ...] = K_CHOICES) -> tuple[float, int, float, float]:
    """The (threshold, k) with the best recall whose benign flag rate is at most ``max_fpr``.

    ``rows`` holds validation texts and whether each is an injection. Neighbours are found once
    for the largest k. Returns (threshold, k, recall, benign flag rate)."""
    found = [(index.neighbours(text, max(ks)), injection) for text, injection in rows]
    best = (1.01, ks[0], 0.0, 0.0)
    for k in ks:
        scores = [(ExemplarIndex.vote(*n, k, index.sizes()), injection) for n, injection in found]
        threshold = threshold_for([s for s, inj in scores if not inj], max_fpr)
        flagged = lambda inj: [s >= threshold for s, i in scores if i == inj]
        recall = sum(flagged(True)) / max(len(flagged(True)), 1)
        fpr = sum(flagged(False)) / max(len(flagged(False)), 1)
        if recall > best[2]:
            best = (threshold, k, recall, fpr)
    return best


def _rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m intentshield.exemplars")
    sub = parser.add_subparsers(dest="command", required=True)
    get = sub.add_parser("download", help="fetch the embedder and record its hashes")
    get.add_argument("--out", type=Path, default=Path("artifacts/embedder-e5-small"))
    seed = sub.add_parser("seed", help="build the index from training rows and tune it on validation rows")
    seed.add_argument("--embedder", type=Path, default=Path("artifacts/embedder-e5-small"))
    seed.add_argument("--dataset", type=Path, default=Path("artifacts/injection/dataset.jsonl"))
    seed.add_argument("--hard", type=Path, default=Path("artifacts/injection/hard_negatives.jsonl"))
    seed.add_argument("--max-fpr", type=float, default=0.01, help="benign flag rate allowed on validation")
    seed.add_argument("--out", type=Path, default=Path("artifacts/exemplars"))
    args = parser.parse_args(argv)
    if args.command == "download":
        print(json.dumps(download(args.out), indent=2))
        return
    embedder = Embedder(args.embedder)
    if not embedder.ready:
        raise SystemExit(f"embedder unavailable: {embedder.reason}")
    rows = _rows(args.dataset) + _rows(args.hard)
    train = [r for r in rows if r["split"] == "train"]
    index = ExemplarIndex(embedder)
    index.add((r["text"] for r in train if r["label"] == "data"), "data")
    index.add((r["text"] for r in train if r["label"] == "instruction"), "instruction")
    validation = [r for r in rows if r["split"] == "validation"]
    index.threshold, index.k, recall, fpr = tune(
        index, [(r["text"], r["label"] == "instruction") for r in validation], args.max_fpr)
    index.save(args.out)
    print(json.dumps({"instruction_chunks": len(index.texts["instruction"]), "data_chunks": len(index.texts["data"]),
                      "validation_rows": len(validation), "threshold": round(index.threshold, 4),
                      "k": index.k, "validation_recall": round(recall, 4),
                      "validation_benign_flagged": round(fpr, 4)}, indent=2))


if __name__ == "__main__":
    main()
