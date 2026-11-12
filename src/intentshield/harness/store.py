"""The sessions database of the hook: each session's intent, taint and flags, and when each harness last ran a hook."""
from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .text import _private_dir, _window

SESSION_TTL = 7 * 86_400  # seconds an idle session's prompts are kept; every hook event of it renews them
FLAGGED_TTL = 30 * 86_400  # a session with taint or a flag is forgotten only after this much idle time


class SessionStore:
    """The part of a guard that keeps state between hook processes. ``HarnessGuard`` sets ``cwd`` and ``from_harness``."""

    db: sqlite3.Connection
    cwd: str
    from_harness: bool | None

    def _open_db(self, path: str | Path) -> None:
        _private_dir(Path(path).parent)
        if not Path(path).exists():  # prompts and taint of every session: the user's only
            Path(path).touch(mode=0o600)
        self.db = sqlite3.connect(path, timeout=5, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, intent TEXT NOT NULL, "
                        "taint TEXT NOT NULL, updated REAL NOT NULL)")
        # Result scans in progress. Hook processes run in parallel, so a clean scan must never
        # restore a flag another process is setting: the counter is monotonic per scan.
        self._add_column("inflight INTEGER NOT NULL DEFAULT 0")
        # Whether any output of the session tried to instruct the agent, even one that named no
        # value to taint ("delete the repository now").
        self._add_column("flagged INTEGER NOT NULL DEFAULT 0")
        # An output only the LLM judge thought was an instruction: state-changing calls ask, but nothing
        # is tainted and no credential is denied, since the judge is wrong a few percent of the time.
        self._add_column("soft INTEGER NOT NULL DEFAULT 0")
        # Calls refused since the user's last prompt: an agent that cannot be asked retries a refused call,
        # Gemini CLI up to 75 times in the live runs, so the hook ends its turn after a few.
        self._add_column("refused INTEGER NOT NULL DEFAULT 0")
        # Recipients, URLs, accounts and paths seen in any tool output of the session.
        self.db.execute("CREATE TABLE IF NOT EXISTS observed (session TEXT NOT NULL, value TEXT NOT NULL, "
                        "PRIMARY KEY (session, value))")
        # When each harness last ran a hook: `intentshield doctor` tells hooks that never run from quiet ones.
        self.db.execute("CREATE TABLE IF NOT EXISTS harness_events (harness TEXT PRIMARY KEY, last REAL NOT NULL)")
        # Events that reached the hook from a process that is not the harness (a person piping one in by hand): kept apart, so
        # `intentshield doctor` does not take them for proof that the harness runs the hooks.
        self.db.execute("CREATE TABLE IF NOT EXISTS harness_piped (harness TEXT PRIMARY KEY, last REAL NOT NULL)")
        # ... and in which working directories: a project's settings file is only run for sessions inside it.
        self.db.execute("CREATE TABLE IF NOT EXISTS harness_dirs (harness TEXT NOT NULL, cwd TEXT NOT NULL, "
                        "last REAL NOT NULL, PRIMARY KEY (harness, cwd))")
        # Prompts are the user's words: keep them only while a session can still be live. Every hook event
        # renews a session (``touch``), and one that holds taint or a flag outlives a clean one: forgetting
        # it would let a resumed session act as if nothing had happened.
        now = time.time()
        self.db.execute("DELETE FROM sessions WHERE (updated < ? AND taint = '[]' AND flagged = 0 AND soft = 0 "
                        "AND inflight = 0) OR updated < ?", (now - SESSION_TTL, now - FLAGGED_TTL))
        self.db.execute("DELETE FROM observed WHERE session NOT IN (SELECT id FROM sessions)")
        self.db.execute("DELETE FROM harness_dirs WHERE last < ?", (now - FLAGGED_TTL,))

    def _add_column(self, definition: str) -> None:
        """Adds a sessions column an older hooks.db lacks. Only a concurrent hook adding it first is
        expected; any other error (a locked or corrupt database) propagates and the hook fails closed."""
        name = definition.split()[0]
        if name in {row[1] for row in self.db.execute("PRAGMA table_info(sessions)")}:
            return
        try:
            self.db.execute(f"ALTER TABLE sessions ADD COLUMN {definition}")
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc):
                raise

    @contextmanager
    def _tx(self) -> Iterator[None]:
        """One immediate transaction; rolled back if the body raises, so a reused guard never sits
        inside a half-done write."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        self.db.execute("COMMIT")

    def _load(self, session: str) -> tuple[str, set[str]]:
        row = self.db.execute("SELECT intent, taint FROM sessions WHERE id = ?", (session,)).fetchone()
        return (_window(row[0]), set(json.loads(row[1]))) if row else ("", set())

    def touch(self, session: str, harness: str = "") -> None:
        """A hook event of the session: it is live, whatever the event was, so its TTL starts over."""
        now = time.time()
        self.db.execute("UPDATE sessions SET updated = ? WHERE id = ?", (now, session))
        if harness and self.from_harness is False:
            self.db.execute("INSERT INTO harness_piped VALUES (?, ?) ON CONFLICT(harness) DO UPDATE SET "
                            "last = excluded.last", (harness, now))
        elif harness:
            self.db.execute("INSERT INTO harness_events VALUES (?, ?) ON CONFLICT(harness) DO UPDATE SET "
                            "last = excluded.last", (harness, now))
            if self.cwd:
                self.db.execute("INSERT INTO harness_dirs VALUES (?, ?, ?) ON CONFLICT(harness, cwd) DO UPDATE SET "
                                "last = excluded.last", (harness, self.cwd, now))

    def flag(self, session: str) -> None:
        """Marks the session as if an output had tried to instruct the agent: a result nobody could read."""
        with self._tx():
            self.db.execute("INSERT INTO sessions (id, intent, taint, updated, flagged) VALUES (?, '', '[]', ?, 1) "
                            "ON CONFLICT(id) DO UPDATE SET flagged = 1", (session, time.time()))

    def _flagged(self, session: str, soft: bool = True) -> bool:
        """Flagged by an output, or a scan of one is still running (or died) in some hook process.
        ``soft`` also counts an output only the LLM judge suspected."""
        row = self.db.execute("SELECT flagged, inflight, soft FROM sessions WHERE id = ?", (session,)).fetchone()
        return bool(row and (row[0] or row[1] > 0 or (soft and row[2])))

    def _flag_reason(self, session: str, taint: set[str]) -> str:
        row = self.db.execute("SELECT flagged, inflight, soft FROM sessions WHERE id = ?", (session,)).fetchone()
        if taint or (row and row[0]):
            return "A tool output in this session tried to instruct the agent; confirm this call."
        if row and row[2] and not row[1]:
            return ("IntentShield's LLM judge thought a tool output in this session tried to instruct the "
                    "agent; confirm this call.")
        if row and row[1]:
            return ("IntentShield has not finished inspecting a tool output in this session (the scan is still "
                    "running or was interrupted); confirm this call. A new session starts clean.")
        return "IntentShield asks for confirmation of state-changing calls."

    def _scan_begin(self, session: str) -> None:
        self.db.execute("INSERT INTO sessions (id, intent, taint, updated, inflight) VALUES (?, '', '[]', ?, 1) "
                        "ON CONFLICT(id) DO UPDATE SET inflight = inflight + 1", (session, time.time()))

    def _scan_end(self, session: str) -> None:
        self.db.execute("UPDATE sessions SET inflight = max(inflight - 1, 0) WHERE id = ?", (session,))

    def _save(self, session: str, intent: str, taint: set[str], flagged: bool = False) -> None:
        self.db.execute("INSERT INTO sessions (id, intent, taint, updated, flagged) VALUES (?, ?, ?, ?, ?) "
                        "ON CONFLICT(id) DO UPDATE SET intent = excluded.intent, taint = excluded.taint, "
                        "updated = excluded.updated, flagged = max(flagged, excluded.flagged)",
                        (session, intent, json.dumps(sorted(taint)), time.time(), int(flagged)))

    def refused(self, session: str) -> int:
        """Counts a refused call; returns how many were refused since the user's last prompt."""
        with self._tx():
            self.db.execute("INSERT INTO sessions (id, intent, taint, updated, refused) VALUES (?, '', '[]', ?, 1) "
                            "ON CONFLICT(id) DO UPDATE SET refused = refused + 1", (session, time.time()))
            refused: int = self.db.execute("SELECT refused FROM sessions WHERE id = ?", (session,)).fetchone()[0]
            return refused
