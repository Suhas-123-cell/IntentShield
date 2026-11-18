from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Sequence
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from . import translation


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def add_column(db: sqlite3.Connection, table: str, column: str, kind: str) -> None:
    if column in {row[1] for row in db.execute(f"PRAGMA table_info({table})").fetchall()}:
        return
    try:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")
    except sqlite3.OperationalError as exc:  # a process starting at the same time added it first
        if "duplicate column" not in str(exc):
            raise


# A migration brings a database one version on: ``migrations[n]`` takes version n to n+1, and the version a database is at
# is kept in ``PRAGMA user_version``. The first migration of each database makes the schema as 0.4.4 and earlier built it
# (creating what is missing, adding what is not there yet), so a database from those versions, which carries version 0,
# upgrades with its data as it is. Later migrations only add: a database written by a newer version still works for the
# older code, on the tables and columns it knows.
Migration = Callable[[sqlite3.Connection], None]


def _has_tables(db: sqlite3.Connection, tables: Sequence[str]) -> bool:
    return all(db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).fetchone() for name in tables)


def migrate(db: sqlite3.Connection, migrations: Sequence[Migration], tables: Sequence[str] = ()) -> int:
    """Brings the database to the version of ``migrations`` and returns the version it is at. The migrations run in one
    immediate transaction, so processes that start together (every hook is one) do not both apply one; the version is read
    again once the lock is held. A database at a higher version, written by a newer release, is left as it is and its version
    returned: the caller keeps working on the part it knows and may say so (``newer_schema``).

    ``tables`` are tables the schema must have. When one is missing at a version the database claims, the file was stamped by
    another schema (two modules given the same file), so the migrations run from the start; they only create what is missing,
    and the version never goes down."""
    target = len(migrations)
    found = int(db.execute("PRAGMA user_version").fetchone()[0])
    if found >= target and _has_tables(db, tables):
        return found
    db.execute("BEGIN IMMEDIATE")
    try:
        found = int(db.execute("PRAGMA user_version").fetchone()[0])
        first = found if found < target or _has_tables(db, tables) else 0
        for number in range(first, target):
            migrations[number](db)
            db.execute(f"PRAGMA user_version = {max(number + 1, found)}")
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return max(found, target)


def newer_schema(path: str | Path, known: int) -> int | None:
    """The version of the database at ``path`` when it is higher than ``known`` (written by a newer release), else None. The
    file is opened read-only; a file that is missing or cannot be read gives None."""
    try:
        with closing(sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True, timeout=2)) as db:
            found = int(db.execute("PRAGMA user_version").fetchone()[0])
    except (sqlite3.Error, OSError, ValueError):
        return None
    return found if found > known else None


def default_database(name: str = "intentshield.db") -> str:
    """Where a database goes when nothing names one: ``~/.intentshield/<name>``, as the command line does, and not the working
    directory, where it would end up inside whatever project the caller runs in. A database an older version left in the
    working directory keeps being used, so an upgrade does not silently start from an empty one."""
    if Path(name).is_file():
        return name
    return str(Path.home() / ".intentshield" / name)


_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS runs (
        id TEXT PRIMARY KEY,
        user_intent TEXT NOT NULL,
        scenario TEXT,
        status TEXT NOT NULL,
        call_count INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        completed_at TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL REFERENCES runs(id),
        sequence INTEGER NOT NULL,
        kind TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(run_id, sequence)
    )""",
    """CREATE TABLE IF NOT EXISTS approvals (
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
    )""",
    """CREATE TABLE IF NOT EXISTS executions (
        idempotency_key TEXT PRIMARY KEY,
        call_fingerprint TEXT NOT NULL,
        run_id TEXT NOT NULL REFERENCES runs(id),
        result_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS idempotency_reservations (
        idempotency_key TEXT PRIMARY KEY,
        call_fingerprint TEXT NOT NULL,
        run_id TEXT NOT NULL REFERENCES runs(id),
        status TEXT NOT NULL,
        result_json TEXT,
        error_json TEXT,
        created_at TEXT NOT NULL,
        completed_at TEXT
    )""",
)


def _schema_1(db: sqlite3.Connection) -> None:
    """The schema of 0.4.4 and earlier: the tables, the columns added since the first release, and the old idempotency records."""
    for statement in _SCHEMA:
        db.execute(statement)
    for table, column, kind in (
        ("runs", "call_count", "INTEGER NOT NULL DEFAULT 0"),
        ("approvals", "call_index", "INTEGER NOT NULL DEFAULT 1"),
        ("approvals", "result_json", "TEXT"),
        ("approvals", "reasons_json", "TEXT"),
        ("idempotency_reservations", "error_json", "TEXT"),
    ):
        add_column(db, table, column, kind)
    # Preserve pre-reservation idempotency records conservatively. Their
    # old fingerprints will conflict rather than permit a duplicate side effect.
    db.execute(
        """INSERT OR IGNORE INTO idempotency_reservations
           (idempotency_key,call_fingerprint,run_id,status,result_json,created_at,completed_at)
           SELECT idempotency_key,call_fingerprint,run_id,'COMPLETED',result_json,created_at,created_at
           FROM executions"""
    )


MIGRATIONS: tuple[Migration, ...] = (_schema_1,)
SCHEMA_VERSION = len(MIGRATIONS)


class Storage:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = str(path) if path is not None else default_database()
        translation.private_dir(Path(self.path).parent)
        if not Path(self.path).exists():  # holds executed results and approval arguments: the user's only
            Path(self.path).touch(mode=0o600)
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        # The gateway opens a connection per call from several threads: WAL lets readers and the
        # writer overlap, and the busy timeout turns a brief lock into a wait, not an error.
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA journal_mode = WAL")
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def initialize(self) -> None:
        with self.connect() as db:
            self.schema_version = migrate(db, MIGRATIONS, ('runs', 'events', 'approvals'))

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
                   expires_at,status,created_at,reasons_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (approval["id"], approval["run_id"], approval["tool_name"], approval["args_json"],
                 approval["call_fingerprint"], approval["call_json"], approval["call_index"],
                 approval["expires_at"], "PENDING", utc_now(), json.dumps(approval.get("reasons", []))),
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
        result: dict[str, Any] = json.loads(row["result_json"])
        return result

    def list_approvals(self, status: str | None = None) -> list[dict[str, Any]]:
        # The operator decides with the user's request and the reasons for review in view.
        query = ("SELECT approvals.*, runs.user_intent AS request FROM approvals "
                 "JOIN runs ON runs.id = approvals.run_id")
        with self.connect() as db:
            if status:
                rows = db.execute(f"{query} WHERE approvals.status=? ORDER BY approvals.created_at DESC",
                                  (status,)).fetchall()
            else:
                rows = db.execute(f"{query} ORDER BY approvals.created_at DESC").fetchall()
        return [{**dict(row), "reasons": json.loads(row["reasons_json"] or "[]")} for row in rows]

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
