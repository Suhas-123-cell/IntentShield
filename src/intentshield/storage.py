from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class Storage:
    def __init__(self, path: str | Path = "intentshield.db") -> None:
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def initialize(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY,
                    user_intent TEXT NOT NULL,
                    scenario TEXT,
                    status TEXT NOT NULL,
                    call_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL REFERENCES runs(id),
                    sequence INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(run_id, sequence)
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES runs(id),
                    tool_name TEXT NOT NULL,
                    args_json TEXT NOT NULL,
                    call_fingerprint TEXT NOT NULL,
                    call_json TEXT NOT NULL,
                    call_index INTEGER NOT NULL DEFAULT 1,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    decided_at TEXT,
                    result_json TEXT
                );
                CREATE TABLE IF NOT EXISTS executions (
                    idempotency_key TEXT PRIMARY KEY,
                    call_fingerprint TEXT NOT NULL,
                    run_id TEXT NOT NULL REFERENCES runs(id),
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS idempotency_reservations (
                    idempotency_key TEXT PRIMARY KEY,
                    call_fingerprint TEXT NOT NULL,
                    run_id TEXT NOT NULL REFERENCES runs(id),
                    status TEXT NOT NULL,
                    result_json TEXT,
                    error_json TEXT,
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );
                """
            )
            run_columns = {row[1] for row in db.execute("PRAGMA table_info(runs)").fetchall()}
            if "call_count" not in run_columns:
                db.execute("ALTER TABLE runs ADD COLUMN call_count INTEGER NOT NULL DEFAULT 0")
            approval_columns = {row[1] for row in db.execute("PRAGMA table_info(approvals)").fetchall()}
            if "call_index" not in approval_columns:
                db.execute("ALTER TABLE approvals ADD COLUMN call_index INTEGER NOT NULL DEFAULT 1")
            if "result_json" not in approval_columns:
                db.execute("ALTER TABLE approvals ADD COLUMN result_json TEXT")
            reservation_columns = {
                row[1] for row in db.execute("PRAGMA table_info(idempotency_reservations)").fetchall()
            }
            if "error_json" not in reservation_columns:
                db.execute("ALTER TABLE idempotency_reservations ADD COLUMN error_json TEXT")
            # Preserve pre-reservation idempotency records conservatively. Their
            # old fingerprints will conflict rather than permit a duplicate side effect.
            db.execute(
                """INSERT OR IGNORE INTO idempotency_reservations
                   (idempotency_key,call_fingerprint,run_id,status,result_json,created_at,completed_at)
                   SELECT idempotency_key,call_fingerprint,run_id,'COMPLETED',result_json,created_at,created_at
                   FROM executions"""
            )

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row else None

    def create_run(self, run_id: str, user_intent: str, scenario: str | None) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO runs(id,user_intent,scenario,status,created_at) VALUES(?,?,?,?,?)",
                (run_id, user_intent, scenario, "RUNNING", utc_now()),
            )

    def finish_run(self, run_id: str, status: str) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE runs SET status=?, completed_at=? WHERE id=?",
                (status, utc_now(), run_id),
            )

    def reserve_call(self, run_id: str) -> int:
        """Atomically count a fresh model proposal and return its one-based index."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "UPDATE runs SET call_count=call_count+1 WHERE id=? RETURNING call_count", (run_id,)
            ).fetchone()
            if not row:
                raise KeyError(run_id)
            return int(row[0])

    def add_event(self, run_id: str, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            return self._insert_event(db, run_id, kind, payload)

    @staticmethod
    def _insert_event(
        db: sqlite3.Connection, run_id: str, kind: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        sequence = db.execute(
            "SELECT COALESCE(MAX(sequence),0)+1 FROM events WHERE run_id=?", (run_id,)
        ).fetchone()[0]
        timestamp = utc_now()
        cursor = db.execute(
            "INSERT INTO events(run_id,sequence,kind,payload_json,created_at) VALUES(?,?,?,?,?)",
            (run_id, sequence, kind, json.dumps(payload, sort_keys=True), timestamp),
        )
        return {"id": cursor.lastrowid, "run_id": run_id, "sequence": sequence, "kind": kind,
                "payload": payload, "created_at": timestamp}

    def list_runs(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return self._row(row)

    def list_events(self, run_id: str) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM events WHERE run_id=? ORDER BY sequence", (run_id,)).fetchall()
        return [{**dict(row), "payload": json.loads(row["payload_json"])} for row in rows]

    def create_approval(self, approval: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                """INSERT INTO approvals(id,run_id,tool_name,args_json,call_fingerprint,call_json,call_index,
                   expires_at,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (approval["id"], approval["run_id"], approval["tool_name"], approval["args_json"],
                 approval["call_fingerprint"], approval["call_json"], approval["call_index"],
                 approval["expires_at"], "PENDING", utc_now()),
            )

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
        return self._row(row)

    def save_approval_result(self, approval_id: str, result: dict[str, Any]) -> None:
        """Persist the terminal gateway result for safe post-approval polling."""
        with self.connect() as db:
            cursor = db.execute(
                "UPDATE approvals SET result_json=? WHERE id=? AND status!='PENDING'",
                (json.dumps(result, sort_keys=True), approval_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(approval_id)

    def get_approval_result(self, approval_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT result_json FROM approvals WHERE id=?", (approval_id,)
            ).fetchone()
        if not row or not row["result_json"]:
            return None
        return json.loads(row["result_json"])

    def list_approvals(self, status: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as db:
            if status:
                rows = db.execute("SELECT * FROM approvals WHERE status=? ORDER BY created_at DESC", (status,)).fetchall()
            else:
                rows = db.execute("SELECT * FROM approvals ORDER BY created_at DESC").fetchall()
        return [dict(row) for row in rows]

    def decide_approval(self, approval_id: str, status: str) -> bool:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute(
                "UPDATE approvals SET status=?, decided_at=? WHERE id=? AND status='PENDING'",
                (status, utc_now(), approval_id),
            )
            return cursor.rowcount == 1

    def decide_approval_with_event(
        self, approval_id: str, status: str, run_id: str, payload: dict[str, Any]
    ) -> bool:
        """Compare-and-swap an approval and append its audit event atomically."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute(
                "UPDATE approvals SET status=?, decided_at=? WHERE id=? AND run_id=? AND status='PENDING'",
                (status, utc_now(), approval_id, run_id),
            )
            if cursor.rowcount != 1:
                return False
            self._insert_event(db, run_id, "APPROVAL_DECIDED", payload)
            return True

    def consume_approval(self, approval_id: str, fingerprint: str) -> bool:
        """Atomically consume an approved, exact-bound authorization once."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute(
                """UPDATE approvals SET status='CONSUMED', decided_at=?
                   WHERE id=? AND status='APPROVED' AND call_fingerprint=? AND expires_at>?""",
                (utc_now(), approval_id, fingerprint, utc_now()),
            )
            if cursor.rowcount == 1:
                row = db.execute("SELECT run_id FROM approvals WHERE id=?", (approval_id,)).fetchone()
                self._insert_event(db, row["run_id"], "APPROVAL_CONSUMED", {"approval_id": approval_id})
            return cursor.rowcount == 1

    def get_execution(self, idempotency_key: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM executions WHERE idempotency_key=?", (idempotency_key,)).fetchone()
        return self._row(row)

    def save_execution(self, key: str, fingerprint: str, run_id: str, result: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO executions VALUES(?,?,?,?,?)",
                (key, fingerprint, run_id, json.dumps(result, sort_keys=True), utc_now()),
            )

    def reserve_idempotency(self, key: str, fingerprint: str, run_id: str) -> tuple[str, dict[str, Any] | None]:
        """Reserve a mutation key atomically.

        Returns RESERVED for the sole executor, REPLAY for an identical completed
        call, CONFLICT for a changed call, or IN_PROGRESS for a concurrent caller.
        """
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM idempotency_reservations WHERE idempotency_key=?", (key,)
            ).fetchone()
            if row:
                if row["call_fingerprint"] != fingerprint:
                    return "CONFLICT", None
                if row["status"] == "COMPLETED":
                    return "REPLAY", json.loads(row["result_json"])
                if row["status"] == "IN_DOUBT":
                    return "IN_DOUBT", None
                return "IN_PROGRESS", None
            db.execute(
                """INSERT INTO idempotency_reservations
                   (idempotency_key,call_fingerprint,run_id,status,created_at)
                   VALUES(?,?,?,?,?)""",
                (key, fingerprint, run_id, "RESERVED", utc_now()),
            )
            return "RESERVED", None

    def inspect_idempotency(self, key: str, fingerprint: str) -> str:
        """Return ABSENT, MATCH, IN_PROGRESS, or CONFLICT without reserving."""
        with self.connect() as db:
            row = db.execute(
                "SELECT call_fingerprint,status FROM idempotency_reservations WHERE idempotency_key=?",
                (key,),
            ).fetchone()
        if not row:
            return "ABSENT"
        if row["call_fingerprint"] != fingerprint:
            return "CONFLICT"
        if row["status"] == "RESERVED":
            return "IN_PROGRESS"
        if row["status"] == "IN_DOUBT":
            return "IN_DOUBT"
        return "MATCH"

    def complete_idempotency(self, key: str, fingerprint: str, result: dict[str, Any]) -> bool:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute(
                """UPDATE idempotency_reservations
                   SET status='COMPLETED', result_json=?, completed_at=?
                   WHERE idempotency_key=? AND call_fingerprint=? AND status='RESERVED'""",
                (json.dumps(result, sort_keys=True), utc_now(), key, fingerprint),
            )
            return cursor.rowcount == 1

    def release_idempotency(self, key: str, fingerprint: str) -> None:
        with self.connect() as db:
            db.execute(
                "DELETE FROM idempotency_reservations WHERE idempotency_key=? AND call_fingerprint=? AND status='RESERVED'",
                (key, fingerprint),
            )

    def mark_idempotency_in_doubt(
        self, key: str, fingerprint: str, error: dict[str, Any]
    ) -> bool:
        """Persist an uncertain mutation outcome; this state is never auto-retried."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute(
                """UPDATE idempotency_reservations
                   SET status='IN_DOUBT', error_json=?, completed_at=?
                   WHERE idempotency_key=? AND call_fingerprint=? AND status='RESERVED'""",
                (json.dumps(error, sort_keys=True), utc_now(), key, fingerprint),
            )
            return cursor.rowcount == 1

    def metrics(self) -> dict[str, Any]:
        with self.connect() as db:
            total = db.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            rows = db.execute(
                "SELECT status decision, COUNT(*) count FROM runs "
                "WHERE status IN ('ALLOW','REVIEW','BLOCK') GROUP BY status"
            ).fetchall()
            pending = db.execute("SELECT COUNT(*) FROM approvals WHERE status='PENDING'").fetchone()[0]
            executed = db.execute(
                "SELECT COUNT(*) FROM idempotency_reservations WHERE status='COMPLETED'"
            ).fetchone()[0]
        decisions = {row["decision"]: row["count"] for row in rows if row["decision"]}
        return {"runs": total, "decisions": {k: decisions.get(k, 0) for k in ("ALLOW", "REVIEW", "BLOCK")},
                "pending_approvals": pending, "executions": executed}
