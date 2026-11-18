"""The versions of the three SQLite databases: ``PRAGMA user_version``, ordered migrations, and a database from another release.

A database written by 0.4.4 or earlier carries version 0 and the schema those releases built. It must open, gain what is
missing and keep every row. A database written by a newer release must never make a hook crash or fail a call.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import closing
from pathlib import Path

import pytest

from intentshield import storage, threat_memory
from intentshield.harness import HarnessGuard, store
from intentshield.storage import Storage, migrate, newer_schema
from intentshield.threat_memory import ThreatMemory

# --- the databases as 0.4.4 and earlier left them --------------------------------------------------------------------------

_LEGACY_GATEWAY = (
    "CREATE TABLE runs (id TEXT PRIMARY KEY, user_intent TEXT NOT NULL, scenario TEXT, status TEXT NOT NULL, "
    "created_at TEXT NOT NULL, completed_at TEXT)",
    "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL REFERENCES runs(id), "
    "sequence INTEGER NOT NULL, kind TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL, "
    "UNIQUE(run_id, sequence))",
    "CREATE TABLE approvals (id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), tool_name TEXT NOT NULL, "
    "args_json TEXT NOT NULL, call_fingerprint TEXT NOT NULL, call_json TEXT NOT NULL, expires_at TEXT NOT NULL, "
    "status TEXT NOT NULL, created_at TEXT NOT NULL, decided_at TEXT)",
    "CREATE TABLE executions (idempotency_key TEXT PRIMARY KEY, call_fingerprint TEXT NOT NULL, "
    "run_id TEXT NOT NULL REFERENCES runs(id), result_json TEXT NOT NULL, created_at TEXT NOT NULL)",
    "CREATE TABLE idempotency_reservations (idempotency_key TEXT PRIMARY KEY, call_fingerprint TEXT NOT NULL, "
    "run_id TEXT NOT NULL REFERENCES runs(id), status TEXT NOT NULL, result_json TEXT, created_at TEXT NOT NULL, "
    "completed_at TEXT)",
    "INSERT INTO runs VALUES ('r1', 'send the report', NULL, 'RUNNING', '2026-01-01', NULL)",
    "INSERT INTO approvals VALUES ('a1', 'r1', 'send_email', '{}', 'fp', '{}', '2030-01-01', 'PENDING', '2026-01-01', NULL)",
    "INSERT INTO executions VALUES ('k1', 'fp1', 'r1', '{\"ok\": true}', '2026-01-02')",
)
_LEGACY_SESSIONS = (
    "CREATE TABLE sessions (id TEXT PRIMARY KEY, intent TEXT NOT NULL, taint TEXT NOT NULL, updated REAL NOT NULL)",
    "INSERT INTO sessions VALUES ('s1', 'tidy the repo', '[\"https://evil.test\"]', {now})",
    "CREATE TABLE harness_events (harness TEXT PRIMARY KEY, last REAL NOT NULL)",
    "INSERT INTO harness_events VALUES ('claude', 5.0)",
)


def _build(path: Path, statements: tuple[str, ...], **fields: float) -> None:
    with closing(sqlite3.connect(path)) as db:
        for statement in statements:
            db.execute(statement.format(**fields) if fields else statement)
        db.commit()


def _legacy_threats(path: Path) -> None:
    """The tables of ``threat_memory._SCHEMA`` without the columns added since (``decided_at``, ``anchor_json``)."""
    with closing(sqlite3.connect(path)) as db:
        for statement in threat_memory._SCHEMA.split(";"):
            if statement.strip():
                db.execute(statement)
        db.execute("INSERT INTO threat_indicators (id, kind, value, domain, status, origin, provenance_json, runs, first_seen, "
                   "last_seen) VALUES ('i1', 'domain', 'evil.test', 'evil.test', 'blocked', 'learned', '[]', 3, 1.0, 2.0)")
        db.execute("INSERT INTO threat_allowlist VALUES ('example.com', 1.0)")
        db.commit()


def _columns(path: Path, table: str) -> set[str]:
    with closing(sqlite3.connect(path)) as db:
        return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}


def _version(path: Path) -> int:
    with closing(sqlite3.connect(path)) as db:
        return int(db.execute("PRAGMA user_version").fetchone()[0])


def _rows(path: Path, query: str) -> list[tuple]:
    with closing(sqlite3.connect(path)) as db:
        return db.execute(query).fetchall()


# --- the machinery ---------------------------------------------------------------------------------------------------------

def test_migrations_run_in_order_and_only_the_missing_ones(tmp_path: Path):
    calls: list[int] = []

    def first(db: sqlite3.Connection) -> None:
        calls.append(1)
        db.execute("CREATE TABLE t (a INTEGER)")

    def second(db: sqlite3.Connection) -> None:
        calls.append(2)
        db.execute("ALTER TABLE t ADD COLUMN b INTEGER")

    path = tmp_path / "m.db"
    db = sqlite3.connect(path)
    assert migrate(db, (first,)) == 1 and calls == [1]
    assert migrate(db, (first,)) == 1 and calls == [1], "a database at the version is not touched"
    assert migrate(db, (first, second)) == 2 and calls == [1, 2], "from version 1 only the second runs"
    assert _columns(path, "t") == {"a", "b"} and _version(path) == 2
    db.close()
    fresh = sqlite3.connect(tmp_path / "n.db")
    assert migrate(fresh, (first, second)) == 2 and calls == [1, 2, 1, 2]
    fresh.close()


def test_a_migration_that_fails_changes_nothing(tmp_path: Path):
    def first(db: sqlite3.Connection) -> None:
        db.execute("CREATE TABLE t (a INTEGER)")

    def broken(db: sqlite3.Connection) -> None:
        db.execute("CREATE TABLE u (a INTEGER)")
        raise RuntimeError("half done")

    path = tmp_path / "m.db"
    db = sqlite3.connect(path)
    migrate(db, (first,))
    with pytest.raises(RuntimeError, match="half done"):
        migrate(db, (first, broken))
    db.close()
    assert _version(path) == 1 and _columns(path, "u") == set(), "the failed step is rolled back, the version stays"


def test_a_database_from_a_newer_release_is_left_alone(tmp_path: Path):
    def first(db: sqlite3.Connection) -> None:
        db.execute("CREATE TABLE t (a INTEGER)")

    path = tmp_path / "m.db"
    db = sqlite3.connect(path)
    db.execute("PRAGMA user_version = 9")
    assert migrate(db, (first,)) == 9
    db.close()
    assert _version(path) == 9 and _columns(path, "t") == set(), "no migration of this release runs on it, none is undone"


def test_a_table_the_schema_needs_is_made_even_when_the_version_says_it_exists(tmp_path: Path):
    def first(db: sqlite3.Connection) -> None:
        db.execute("CREATE TABLE IF NOT EXISTS t (a INTEGER)")

    path = tmp_path / "shared.db"
    db = sqlite3.connect(path)
    db.execute("PRAGMA user_version = 1")  # stamped by another schema that was given the same file
    assert migrate(db, (first,), ("t",)) == 1
    db.close()
    assert _columns(path, "t") == {"a"} and _version(path) == 1


def test_a_hook_guard_and_a_gateway_storage_can_share_one_file_in_either_order(tmp_path: Path):
    """0.4.4 let two schemas live in one file; the replay benchmark names its hook and proxy databases alike."""
    for order, name in ((("hooks", "gateway"), "a.db"), (("gateway", "hooks"), "b.db")):
        path = tmp_path / name
        for kind in order:
            if kind == "hooks":
                HarnessGuard(path).close()
            else:
                Storage(str(path)).initialize()
        with closing(sqlite3.connect(path)) as db:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert {"sessions", "runs", "approvals"} <= tables, order


def test_newer_schema_names_the_version_only_when_it_is_newer(tmp_path: Path):
    path = tmp_path / "v.db"
    assert newer_schema(path, 1) is None, "no such file"
    _build(path, ("CREATE TABLE t (a INTEGER)", "PRAGMA user_version = 1"))
    assert newer_schema(path, 1) is None
    _build(path, ("PRAGMA user_version = 4",))
    assert newer_schema(path, 1) == 4 and newer_schema(path, 4) is None
    (tmp_path / "not-a-db").write_text("this is not sqlite" * 50, encoding="utf-8")
    assert newer_schema(tmp_path / "not-a-db", 1) is None


def test_a_path_with_odd_characters_is_read(tmp_path: Path):
    path = tmp_path / "a b#c?d" / "v.db"
    path.parent.mkdir()
    _build(path, ("CREATE TABLE t (a INTEGER)", "PRAGMA user_version = 3"))
    assert newer_schema(path, 1) == 3


# --- a database that 0.4.4 or earlier wrote --------------------------------------------------------------------------------

def test_the_gateway_database_of_an_older_release_upgrades_with_its_rows(tmp_path: Path):
    path = tmp_path / "gateway.db"
    _build(path, _LEGACY_GATEWAY)
    assert _version(path) == 0
    store_ = Storage(path)
    assert _version(path) == storage.SCHEMA_VERSION == store_.schema_version == 1
    assert "call_count" in _columns(path, "runs")
    assert {"call_index", "result_json", "reasons_json"} <= _columns(path, "approvals")
    assert "error_json" in _columns(path, "idempotency_reservations")
    assert _rows(path, "SELECT id, user_intent FROM runs") == [("r1", "send the report")]
    assert _rows(path, "SELECT id, status FROM approvals") == [("a1", "PENDING")]
    assert _rows(path, "SELECT idempotency_key, status, result_json FROM idempotency_reservations") == [
        ("k1", "COMPLETED", '{"ok": true}')], "the old execution is kept as a completed reservation"
    assert _rows(path, "SELECT idempotency_key FROM executions") == [("k1",)]
    Storage(path)  # a second start changes nothing
    assert _version(path) == 1 and len(_rows(path, "SELECT * FROM idempotency_reservations")) == 1


def test_the_threat_memory_of_an_older_release_upgrades_with_its_rows(tmp_path: Path):
    path = tmp_path / "threats.db"
    _legacy_threats(path)
    assert "decided_at" not in _columns(path, "threat_indicators")
    memory = ThreatMemory(path)
    try:
        assert _version(path) == threat_memory.SCHEMA_VERSION == memory.schema_version == 1
        assert "decided_at" in _columns(path, "threat_indicators")
        assert {"decided_at", "anchor_json"} <= _columns(path, "threat_fingerprints")
        assert _rows(path, "SELECT value, runs FROM threat_indicators") == [("evil.test", 3)]
        assert _rows(path, "SELECT value FROM threat_allowlist") == [("example.com",)]
    finally:
        memory.close()


def test_the_hook_database_of_an_older_release_upgrades_with_its_rows(tmp_path: Path):
    import time

    path = tmp_path / "hooks.db"
    _build(path, _LEGACY_SESSIONS, now=time.time())
    guard = HarnessGuard(path)
    assert _version(path) == store.SCHEMA_VERSION == guard.schema_version == 1
    assert {"inflight", "flagged", "soft", "refused"} <= _columns(path, "sessions")
    assert {"observed", "harness_piped", "harness_dirs"} <= {
        row[0] for row in _rows(path, "SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert _rows(path, "SELECT id, intent, taint FROM sessions") == [("s1", "tidy the repo", '["https://evil.test"]')]
    assert _rows(path, "SELECT harness, last FROM harness_events") == [("claude", 5.0)]
    guard.db.close()


def test_a_fresh_database_gets_the_current_version_in_all_three_places(tmp_path: Path):
    Storage(tmp_path / "g.db")
    ThreatMemory(tmp_path / "t.db").close()
    HarnessGuard(tmp_path / "h.db").db.close()
    assert [_version(tmp_path / n) for n in ("g.db", "t.db", "h.db")] == [
        storage.SCHEMA_VERSION, threat_memory.SCHEMA_VERSION, store.SCHEMA_VERSION]


def test_starts_at_the_same_moment_on_old_databases_do_not_collide(tmp_path: Path):
    import time

    threats, hooks = tmp_path / "threats.db", tmp_path / "hooks.db"
    _legacy_threats(threats)
    _build(hooks, _LEGACY_SESSIONS, now=time.time())
    errors: list[BaseException] = []

    def start() -> None:
        try:
            ThreatMemory(threats).close()
            HarnessGuard(hooks).db.close()
        except BaseException as exc:  # reported below
            errors.append(exc)

    workers = [threading.Thread(target=start) for _ in range(8)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert errors == []
    assert _version(threats) == 1 and _version(hooks) == 1
    assert len(_rows(hooks, "SELECT * FROM sessions")) == 1 and len(_rows(threats, "SELECT * FROM threat_indicators")) == 1


# --- a database that a newer release wrote ---------------------------------------------------------------------------------

def test_a_newer_gateway_database_still_serves_the_calls(tmp_path: Path):
    path = tmp_path / "gateway.db"
    Storage(path)
    with closing(sqlite3.connect(path)) as db:
        db.execute("ALTER TABLE runs ADD COLUMN labels TEXT")
        db.execute("CREATE TABLE audit_v2 (id INTEGER)")
        db.execute("PRAGMA user_version = 7")
        db.commit()
    store_ = Storage(path)
    store_.create_run("r9", "intent", None)
    assert [r["id"] for r in store_.list_runs(5)] == ["r9"]
    assert store_.schema_version == 7 and _version(path) == 7 and newer_schema(path, storage.SCHEMA_VERSION) == 7


def test_a_newer_threat_memory_still_answers(tmp_path: Path):
    path = tmp_path / "threats.db"
    ThreatMemory(path).close()
    with closing(sqlite3.connect(path)) as db:
        db.execute("ALTER TABLE threat_indicators ADD COLUMN reputation REAL")
        db.execute("CREATE TABLE threat_graph (a TEXT)")
        db.execute("PRAGMA user_version = 3")
        db.commit()
    memory = ThreatMemory(path)
    try:
        assert memory.schema_version == 3 and _version(path) == 3
        memory.allow("example.org")
        assert _rows(path, "SELECT value FROM threat_allowlist") == [("example.org",)]
    finally:
        memory.close()


def test_a_newer_hook_database_never_fails_the_hook(tmp_path: Path):
    path = tmp_path / "hooks.db"
    HarnessGuard(path).db.close()
    with closing(sqlite3.connect(path)) as db:
        db.execute("ALTER TABLE sessions RENAME COLUMN soft TO soft_reasons")  # a column this release reads, changed
        db.execute("PRAGMA user_version = 5")
        db.commit()
    guard = HarnessGuard(path)  # the tidy-up that reads the old column is skipped, the guard starts
    try:
        assert guard.schema_version == 5 and _version(path) == 5
    finally:
        guard.db.close()


def test_the_same_change_at_the_current_version_still_fails_closed(tmp_path: Path):
    path = tmp_path / "hooks.db"
    HarnessGuard(path).db.close()
    with closing(sqlite3.connect(path)) as db:
        db.execute("ALTER TABLE sessions RENAME COLUMN soft TO soft_reasons")
        db.commit()
    with pytest.raises(sqlite3.OperationalError):
        HarnessGuard(path)
