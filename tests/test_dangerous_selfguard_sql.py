"""Every statement that changes the guard's own databases (``hooks.db``, ``threats.db``) asks, as ``delete from`` does, and a
read of them does not. Every command is a string; nothing is run."""
from __future__ import annotations

import pytest

from intentshield.dangerous import assess_shell

STATEMENTS = [
    "delete from sessions", "DELETE FROM threats WHERE 1", "update sessions set taint=null", "UPDATE sessions SET flagged=0",
    "update or replace sessions set flagged=1", "UPDATE OR IGNORE threats SET expires=0", "insert into sessions values (1)",
    "INSERT OR REPLACE INTO sessions VALUES (1)", "replace into sessions values (1)", "drop table sessions", "drop trigger t",
    "alter table sessions add c int", "vacuum", "pragma writable_schema=1",
    "create trigger t after insert on sessions begin delete from sessions; end", "create table x (a int)",
    "create unique index i on sessions(session)", "create virtual table v using fts5(a)", "pragma user_version=0",
    "PRAGMA journal_mode = delete", "reindex", "analyze",
]
READS = ["select * from sessions", "select count(*) from sessions where taint is not null", ".tables", ".schema",
         "pragma table_info(sessions)", "select value from observed order by 1 limit 5"]
DATABASES = ["~/.intentshield/hooks.db", "~/.intentshield/threats.db", "$HOME/.intentshield/hooks.db",
             "/home/dev/.intentshield/threats.db"]

SQLITE = [
    'sqlite3 {db} "{sql}"', "sqlite3 {db} '{sql}'", 'sqlite3 -batch {db} "{sql}"', 'sqlite3 -cmd ".timeout 5" {db} "{sql}"',
    'cd ~/.intentshield && sqlite3 hooks.db "{sql}"', 'true && sqlite3 {db} "{sql}"', 'echo "{sql}" | sqlite3 {db}',
    'sqlite3 {db} <<< "{sql}"', 'sqlite3 {db} <<EOF\n{sql};\nEOF',
]
PYTHON = [
    "python3 -c \"import sqlite3; sqlite3.connect('{db}').execute('{sql}')\"",
    "python -c \"import sqlite3; c = sqlite3.connect('{db}'); c.execute('{sql}'); c.commit()\"",
]


def verdict(command: str) -> str:
    hit = assess_shell(command)
    return hit.decision if hit else "allow"


@pytest.mark.parametrize("sql", STATEMENTS)
@pytest.mark.parametrize("db", DATABASES)
@pytest.mark.parametrize("form", SQLITE)
def test_a_statement_that_changes_the_guards_database_asks_through_sqlite3(form, db, sql):
    assert verdict(form.format(db=db, sql=sql)) == "ask"


@pytest.mark.parametrize("sql", STATEMENTS)
@pytest.mark.parametrize("db", DATABASES)
@pytest.mark.parametrize("form", PYTHON)
def test_a_statement_that_changes_the_guards_database_asks_through_python(form, db, sql):
    assert verdict(form.format(db=db, sql=sql.replace('"', "'"))) == "ask"


@pytest.mark.parametrize("command", [
    'sqlite3 ~/.intentshield/hooks.db ".read /tmp/x.sql"', 'sqlite3 ~/.intentshield/threats.db ".restore /tmp/old.db"',
    'sqlite3 -cmd ".read x.sql" hooks.db', "sqlite3 ~/.intentshield/hooks.db < /tmp/x.sql",
    "sqlite3 < /tmp/x.sql ~/.intentshield/hooks.db", "cat /tmp/x.sql | sqlite3 ~/.intentshield/hooks.db",
    "sqlite3 ~/.intentshield/threats.db <(cat /tmp/x.sql)",
])
def test_a_script_that_sqlite3_is_fed_from_a_file_or_a_pipe_asks(command):
    assert verdict(command) == "ask"


@pytest.mark.parametrize("db", DATABASES)
def test_a_script_that_sqlite3_runs_at_its_start_asks(db):
    assert verdict(f"sqlite3 -init /tmp/x.sql {db}") == "ask"


@pytest.mark.parametrize("sql", READS)
@pytest.mark.parametrize("db", DATABASES)
@pytest.mark.parametrize("form", [*SQLITE[:5], 'sqlite3 -readonly {db} "{sql}"'])
def test_a_read_of_the_guards_database_is_allowed(form, db, sql):
    assert verdict(form.format(db=db, sql=sql)) == "allow"


@pytest.mark.parametrize("command", [
    "python3 -c \"import sqlite3; print(sqlite3.connect('/home/dev/.intentshield/hooks.db').execute('select 1').fetchall())\"",
    "python3 -c \"print(open('/home/dev/.intentshield/hooks.db', 'rb').read())\"",
    "cat /tmp/x.sql | sqlite3 ~/.intentshield/hooks.db \"select 1\"",
    'true || sqlite3 ~/.intentshield/hooks.db ".tables"',
])
def test_other_reads_of_the_guards_database_stay_allowed(command):
    assert verdict(command) == "allow"


@pytest.mark.parametrize("command", [
    'sqlite3 /tmp/app.db "update users set name=1"', 'sqlite3 app.db ".read x.sql"', "sqlite3 app.db < x.sql",
    "cat x.sql | sqlite3 app.db", 'git commit -m "update sessions in hooks.db"',
    "python3 -c \"import sqlite3; sqlite3.connect('/tmp/app.db').execute('update t set a=1')\"",
])
def test_another_database_is_not_the_guards(command):
    assert verdict(command) == "allow"
