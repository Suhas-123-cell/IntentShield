"""Learning injection exemplars from operator labels, behind a regression gate.

Who may teach: only the operator, through the authenticated control plane. A label comes from an
explicit ``learn`` on an approval decision (``injection`` with a rejection, ``benign`` with an
approval) or from labelling a text directly. Tool output and tool descriptions never create a label;
they are only what gets labelled.

What a label may change: only the exemplar detector (``exemplars.ExemplarIndex``). Rules, the
quarantine and the review of mutations are untouched, so an approval can never lift a rule flag.

The gate: a new injection exemplar goes live only if no benign text of the regression set becomes
flagged; a new benign exemplar only if no injection of the regression set stops being flagged. A
rejected example is kept with its gate result for audit. Every example is stored in SQLite and
replayed into the index at start.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

import numpy as np

from .exemplars import ExemplarIndex, chunks, kind_of

LABELS = ("instruction", "data")
ORIGINS = ("operator", "review_reject", "review_approve")
MAX_TEXT = 20_000


class LearningStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        with self.connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS learned_examples (
                    id TEXT PRIMARY KEY,
                    text TEXT NOT NULL,
                    label TEXT NOT NULL,
                    origin TEXT NOT NULL,
                    status TEXT NOT NULL,
                    gate_json TEXT NOT NULL,
                    run_id TEXT,
                    approval_id TEXT,
                    tool_name TEXT,
                    created_at TEXT NOT NULL
                )""")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def add(self, row: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO learned_examples VALUES (:id,:text,:label,:origin,:status,:gate_json,"
                       ":run_id,:approval_id,:tool_name,:created_at)", row)

    def examples(self, status: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as db:
            query = "SELECT * FROM learned_examples" + (" WHERE status=?" if status else "") + " ORDER BY created_at"
            return [dict(r) for r in db.execute(query, (status,) if status else ())]


class Regression:
    """Benign and injection texts the gate re-scores, embedded once (chunk vectors per text), each
    judged at the threshold of its kind (output or description)."""

    def __init__(self, benign: list[tuple[np.ndarray, str]], injections: list[tuple[np.ndarray, str]]) -> None:
        self.benign, self.injections = benign, injections

    @classmethod
    def from_rows(cls, rows: list[dict[str, Any]], index: ExemplarIndex, cache: Path | None = None) -> "Regression":
        texts = sorted({(r["text"], r["label"], kind_of(r.get("source", ""))) for r in rows if r.get("label") in LABELS})
        key = hashlib.sha256(json.dumps([texts, index.embedder.metadata]).encode()).hexdigest()[:16]
        path = cache / f"regression-{key}.npz" if cache else None
        if path and path.exists():
            stored = np.load(path)
            vectors = [stored[f"t{i}"] for i in range(len(texts))]
        else:
            vectors = [index.embed_text(text) for text, _, _ in texts]
            if path:
                path.parent.mkdir(parents=True, exist_ok=True)
                np.savez(path, **{f"t{i}": v for i, v in enumerate(vectors)})
        return cls([(v, kind) for v, (_, label, kind) in zip(vectors, texts) if label == "data"],
                   [(v, kind) for v, (_, label, kind) in zip(vectors, texts) if label == "instruction"])

    def flagged(self, index: ExemplarIndex) -> tuple[int, int]:
        """(benign texts flagged, injections flagged) under ``index``."""
        flag = lambda item: index.score_vectors(item[0]) >= index.thresholds[item[1]]
        return sum(map(flag, self.benign)), sum(map(flag, self.injections))


class Learner:
    def __init__(self, index: ExemplarIndex, store: LearningStore, regression: Regression) -> None:
        self.index, self.store, self.regression = index, store, regression
        self.replayed = self.replay()

    def replay(self) -> int:
        """Re-add every stored example that passed its gate, in the order it was learned."""
        active = self.store.examples("active")
        for row in active:
            self.index.add([row["text"]], row["label"])
        return len(active)

    def learn(self, text: str, label: str, origin: str, *, run_id: str | None = None,
              approval_id: str | None = None, tool_name: str | None = None) -> dict[str, Any]:
        if label not in LABELS or origin not in ORIGINS:
            raise ValueError("unknown label or origin")
        text = text[:MAX_TEXT]
        if not chunks(text):
            raise ValueError("nothing to learn from an empty text")
        trial = self.index.copy()
        kept = trial.add([text], label)
        before, after = self.regression.flagged(self.index), self.regression.flagged(trial)
        gate = {"kept_chunks": len(kept), "benign_flagged": [before[0], after[0]],
                "injections_flagged": [before[1], after[1]], "benign_n": len(self.regression.benign),
                "injections_n": len(self.regression.injections)}
        if not kept:
            status, gate["reason"] = "rejected_by_gate", "every chunk duplicates a known benign chunk"
        elif label == "instruction" and after[0] > before[0]:
            status, gate["reason"] = "rejected_by_gate", "it would flag benign regression texts"
        elif label == "data" and after[1] < before[1]:
            status, gate["reason"] = "rejected_by_gate", "it would unflag regression injections"
        else:
            status = "active"
            self.index.vectors, self.index.texts = trial.vectors, trial.texts
        row = {"id": uuid.uuid4().hex, "text": text, "label": label, "origin": origin, "status": status,
               "gate_json": json.dumps(gate), "run_id": run_id, "approval_id": approval_id,
               "tool_name": tool_name, "created_at": datetime.now(UTC).isoformat(timespec="seconds")}
        self.store.add(row)
        return {k: row[k] for k in ("id", "label", "origin", "status")} | {"gate": gate}


def linked_excerpt(text: str, values: set[str]) -> str:
    """The chunks of ``text`` that contain any of ``values`` (the part a reviewed call reused), or the
    whole text when none does."""
    hits = [c for c in chunks(text) if any(v.lower() in c.lower() for v in values)]
    return " ".join(dict.fromkeys(hits)) if hits else text
