"""Rules induced from confirmed injections: a local model proposes, gates filter, the operator approves.

For an injection example the operator confirmed (``learning.py``), a local model (Ollama) proposes up to
three regular expressions for its wording, not its specifics: recipients, URLs, names and amounts change
between variants of one attack, the phrasing that steers the agent less so. A proposal is kept only if it
passes every gate:

- it compiles, is at most ``MAX_PATTERN`` characters, and has no construct prone to catastrophic
  backtracking (nested quantifiers, backreferences, lookarounds);
- it carries at least ``MIN_LITERAL`` literal letters, so it cannot be as broad as ``\\bplease\\b``;
- it matches the example it came from;
- it matches no benign text of the gate corpus.

A kept proposal waits as ``pending`` until the operator approves or rejects it through the control
plane; nothing proposed by the model goes live on its own. Approved rules read the same normalized text
as the built-in rules (``mcp_inspect.readable``) and are evidence only, like the learned detectors: a hit
sends calls to review, it never quarantines, blocks by itself or allows anything.
"""
from __future__ import annotations

import json
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterator

from .mcp_inspect import readable

MAX_PATTERN, MIN_LITERAL, MAX_PROPOSALS = 200, 12, 3
# Nested quantifier: a group that contains a quantifier and is itself repeated without bound (an
# optional group, ``(...)?``, or a bounded repeat cannot backtrack catastrophically).
_NESTED = re.compile(r"\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d*,\d*\})")
_LOOKAROUND_OR_BACKREF = re.compile(r"\(\?(?:<?[=!]|P=|<)|\\[1-9]|\\k<")
_LITERAL = re.compile(r"\\.|\[[^\]]*\]|[A-Za-z]")
PROMPT = """You write detection rules for prompt injections. The text below was confirmed by a human \
reviewer as an injection: it tries to make an AI assistant do something its user did not ask for.

Write up to 3 Python regular expressions that match the WORDING that steers the assistant, so that \
rewordings with other recipients, addresses, URLs, names, amounts or files still match. Rules:
- never put an email address, URL, domain, person name, number or file name in a pattern;
- use \\s+ between words and alternations like (?:send|forward) for synonyms;
- no lookarounds, no backreferences, no nested quantifiers; at most 200 characters each;
- the patterns are matched case-insensitively against normal benign text too, so they must not match \
ordinary requests, documentation or emails between people.
Answer only with JSON: {"patterns": ["...", "..."]}

Text:
"""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def safety_problem(pattern: str) -> str | None:
    """Why ``pattern`` may not be used, or None."""
    if not isinstance(pattern, str) or not pattern.strip():
        return "empty"
    if len(pattern) > MAX_PATTERN:
        return "too long"
    if _NESTED.search(pattern):
        return "nested quantifier"
    if _LOOKAROUND_OR_BACKREF.search(pattern):
        return "lookaround or backreference"
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return f"does not compile: {exc}"
    literal = sum(1 for token in _LITERAL.findall(pattern) if len(token) == 1)
    if literal < MIN_LITERAL:
        return "too few literal letters"
    return None


def _matcher(pattern: str) -> Callable[[str], bool]:
    compiled = re.compile(pattern, re.IGNORECASE)
    return lambda text: bool(compiled.search(" ".join(readable(text[:20_000]).split())))


def gate(pattern: str, source: str, benign: list[str]) -> dict[str, Any]:
    """Every gate's result for one proposal; ``ok`` only if all pass."""
    problem = safety_problem(pattern)
    if problem:
        return {"ok": False, "reason": problem}
    matches = _matcher(pattern)
    if not matches(source):
        return {"ok": False, "reason": "does not match its source example"}
    hits = [text[:120] for text in benign if matches(text)]
    if hits:
        return {"ok": False, "reason": f"matches {len(hits)} benign texts", "benign_examples": hits[:3]}
    return {"ok": True, "benign_checked": len(benign)}


class RuleStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        with self.connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS learned_rules (
                    id TEXT PRIMARY KEY,
                    pattern TEXT NOT NULL,
                    example_id TEXT,
                    status TEXT NOT NULL,
                    gate_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    decided_at TEXT
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

    def add(self, pattern: str, example_id: str | None, gate_result: dict[str, Any]) -> dict[str, Any]:
        row = {"id": uuid.uuid4().hex, "pattern": pattern, "example_id": example_id, "status": "pending",
               "gate_json": json.dumps(gate_result), "created_at": _now(), "decided_at": None}
        with self.connect() as db:
            db.execute("INSERT INTO learned_rules VALUES (:id,:pattern,:example_id,:status,:gate_json,"
                       ":created_at,:decided_at)", row)
        return row

    def decide(self, rule_id: str, approve: bool) -> dict[str, Any]:
        """Approve or reject a pending rule; a decided rule cannot be decided again."""
        with self.connect() as db:
            changed = db.execute("UPDATE learned_rules SET status=?, decided_at=? WHERE id=? AND status='pending'",
                                 ("approved" if approve else "rejected", _now(), rule_id)).rowcount
            row = db.execute("SELECT * FROM learned_rules WHERE id=?", (rule_id,)).fetchone()
        if row is None:
            raise KeyError(rule_id)
        if not changed:
            raise ValueError(f"rule is already {row['status']}")
        return dict(row)

    def rules(self, status: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as db:
            query = "SELECT * FROM learned_rules" + (" WHERE status=?" if status else "") + " ORDER BY created_at"
            return [dict(r) for r in db.execute(query, (status,) if status else ())]


class LearnedRules:
    """The approved rules, as one detector. Reloaded after each decision."""

    def __init__(self, store: RuleStore) -> None:
        self.store = store
        self.reload()

    def reload(self) -> None:
        self._rules = [(row["id"], _matcher(row["pattern"])) for row in self.store.rules("approved")]

    def matches(self, text: str) -> list[str]:
        return [rule_id for rule_id, match in self._rules if match(text)]

    def flags(self, text: str) -> bool:
        return bool(self.matches(text))


def propose_patterns(ask: Callable[[str], Any], text: str) -> list[str]:
    """The model's proposals for one confirmed injection (``ask`` returns parsed JSON or None)."""
    answer = ask(PROMPT + text[:4000])
    patterns = answer.get("patterns") if isinstance(answer, dict) else None
    if not isinstance(patterns, list):
        return []
    return list(dict.fromkeys(p for p in patterns if isinstance(p, str)))[:MAX_PROPOSALS]


def ollama(model: str = "qwen2.5:7b", host: str = "http://127.0.0.1:11434", timeout: float = 300) -> Callable[[str], Any]:
    """An ``ask`` for ``propose_patterns`` on a local Ollama model (JSON mode, temperature 0)."""
    import urllib.request

    def ask(prompt: str) -> Any:
        body = json.dumps({"model": model, "prompt": prompt, "format": "json", "stream": False,
                           "options": {"temperature": 0, "num_ctx": 4096}}).encode()
        request = urllib.request.Request(f"{host}/api/generate", data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(json.load(response)["response"])
        except (OSError, ValueError, KeyError):
            return None
    return ask


def induce(ask: Callable[[str], Any], store: RuleStore, text: str, benign: list[str],
           example_id: str | None = None) -> list[dict[str, Any]]:
    """Propose rules for one confirmed injection; store the ones that pass every gate as pending.
    Returns every proposal with its gate result (stored or not)."""
    results = []
    for pattern in propose_patterns(ask, text):
        result = gate(pattern, text, benign)
        row = store.add(pattern, example_id, result) if result["ok"] else None
        results.append({"pattern": pattern, "gate": result, "id": row["id"] if row else None})
    return results
