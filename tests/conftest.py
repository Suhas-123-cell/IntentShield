import json
import logging
import os
import sqlite3
import sys
from pathlib import Path

import pytest

_JUDGE_KEYS = ("GEMINI_API_KEY", "GROQ_API_KEY", "GOOGLE_API_KEY")
_KEYS_AT_START = {name: os.environ.get(name) for name in _JUDGE_KEYS}


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch, tmp_path):
    """Keep a developer's .env, home directory and exported secrets out of the tests, and every
    test from reaching a hosted judge with the developer's key. ``delenv`` records nothing for a
    key that is absent, so each key is first set (which records its original state, present or
    not) and then deleted: whatever a test writes into os.environ is undone at teardown."""
    for name in list(os.environ):
        if name.startswith("INTENTSHIELD_"):
            monkeypatch.delenv(name)
    for name in _JUDGE_KEYS:
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.setattr("intentshield.harness.env.ENV_FILE", home / ".intentshield" / ".env")
    # A locally trained classifier would change decisions; tests run the deterministic agents.
    monkeypatch.setenv("INTENTSHIELD_INTENT_MODEL_DIR", "tests/no-intent-model")
    # The hook's verdict translation picks its replies by the harness's version and mode, which a test process cannot have
    # (and which would differ when pytest is started from inside a harness): tests written against the plain hook run with it
    # off, and tests/test_harness_translation.py turns it on where it is the subject.
    monkeypatch.setenv("INTENTSHIELD_HOOK_TRANSLATE", "off")
    # install and doctor run `<harness> --version` to record the version; a test must not start a developer's real harness
    monkeypatch.setattr("intentshield.translation.probe_and_record", lambda *a, **k: None)
    monkeypatch.setattr("intentshield.envfile.find_dotenv", lambda *a, **k: "")  # no developer .env, not even to name
    for module in ("api", "mcp_server", "mcp_verify"):
        monkeypatch.setattr(f"intentshield.{module}.load_dotenv", lambda *a, **k: False)


@pytest.fixture(autouse=True)
def _restore_the_package_logger():
    """``configure_logging`` (the server's entry points) replaces the handlers of the ``intentshield`` logger and stops it from
    propagating, for the rest of the process. A test that starts a server must not leave that behind: a later test that reads the
    package's records with ``caplog`` saw none."""
    logger = logging.getLogger("intentshield")
    handlers, level, propagate = logger.handlers[:], logger.level, logger.propagate
    yield
    logger.handlers[:], logger.level, logger.propagate = handlers, level, propagate


@pytest.fixture
def demo_proxy_config(tmp_path: Path) -> Path:
    """The committed demo proxy config with the interpreter and database made absolute, so the
    suite passes from any working directory."""
    source = Path(__file__).parents[1] / "configs" / "mcp-proxy.demo.json"
    data = json.loads(source.read_text())
    data["upstreams"][0]["command"] = sys.executable
    data["database_path"] = str(tmp_path / "demo-proxy.db")
    path = tmp_path / "mcp-proxy.demo.json"
    path.write_text(json.dumps(data))
    return path


@pytest.fixture(autouse=True)
def _close_databases_a_test_left_open(monkeypatch):
    """Close every SQLite connection the package or a test opened during the test. A guard or store that a test drops without
    closing normally goes when it is collected; under a coverage tracer on a 1,024-descriptor runner they stayed open until
    the run failed with "Too many open files"."""
    opened: list[sqlite3.Connection] = []
    connect = sqlite3.connect

    def recording(*args, **kwargs):
        conn = connect(*args, **kwargs)
        caller = sys._getframe(1).f_globals.get("__name__", "")
        if caller.startswith(("intentshield", "test_", "tests.", "hook_fidelity", "conftest")):
            opened.append(conn)
        return conn

    monkeypatch.setattr(sqlite3, "connect", recording)
    yield
    for conn in opened:
        try:
            conn.close()
        except sqlite3.Error:
            pass


def pytest_sessionfinish(session, exitstatus):
    """No test may leave a judge key behind for the rest of the session or the shell."""
    leaked = [name for name in _JUDGE_KEYS if os.environ.get(name) != _KEYS_AT_START[name]]
    if leaked:
        print(f"\nconftest: judge keys changed by the tests and not restored: {', '.join(leaked)}")
        session.exitstatus = 1


# Tests that check documents, committed results or the study's benchmark data against each other (they need a full clone, not an
# installed package): `pytest -m "not study"` leaves them out.
_STUDY_FILES = ("test_docs_", "test_hook_fidelity", "test_paper_numbers", "test_provenance", "test_security_review_counts",
                "test_coverage_study")


def pytest_collection_modifyitems(items):
    for item in items:
        if Path(str(item.fspath)).name.startswith(_STUDY_FILES):
            item.add_marker(pytest.mark.study)
