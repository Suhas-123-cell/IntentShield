"""Rules induced from confirmed injections: a local model proposes, gates filter, the operator approves.

For an injection example the operator confirmed (``learning.py``), a local model (Ollama) proposes up to
three regular expressions for its wording, not its specifics: recipients, URLs, names and amounts change
between variants of one attack, the phrasing that steers the agent less so. A proposal is kept only if it
passes every gate:

- it compiles, is at most ``MAX_PATTERN`` characters, and has no construct prone to catastrophic
  backtracking (nested quantifiers, backreferences, lookarounds);
- it carries at least ``MIN_LITERAL`` literal letters, so it cannot be as broad as ``\\bplease\\b``;
- it names no email address, URL, domain or number, which change between variants of one attack
  (a rule on the attacker's address only blocklists that address, which argument provenance does);
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
from re import _constants as _C
from re import _parser
from typing import Any, Callable, Iterator

from .mcp_inspect import readable

MAX_PATTERN, MIN_LITERAL, MAX_PROPOSALS = 200, 12, 3
# Nested quantifier: a group that contains a quantifier and is itself repeated without bound (an
# optional group, ``(...)?``, or a bounded repeat cannot backtrack catastrophically).
_NESTED = re.compile(r"\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d*,\d*\})")
_LOOKAROUND_OR_BACKREF = re.compile(r"\(\?(?:<?[=!]|P=|<)|\\[1-9]|\\k<")
_LITERAL = re.compile(r"\\.|\[[^\]]*\]|[A-Za-z]")
_SPECIFIC = re.compile(r"@|https?\b|://|\bwww\b|\\?\.(?:com|net|org|io|dev|example|test)\b", re.IGNORECASE)
# Quantifier bounds and class escapes (\d, \s) are not literal numbers.
_NOT_LITERAL = re.compile(r"\{\d*,?\d*\}|\\[A-Za-z]")
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


_REPEATS = {_C.MAX_REPEAT, _C.MIN_REPEAT, _C.POSSESSIVE_REPEAT}
_NARROW = {_C.CATEGORY_SPACE, _C.CATEGORY_DIGIT}  # cannot run into the letters of the words around them
MAX_SCAN = 20_000  # characters of a text that rules read
_WINDOW = 200  # a repeat bounded above this backtracks like an unbounded one on MAX_SCAN characters


def _wide(body: list) -> bool:
    """A repeated item that can swallow words: ``.``, ``\\w``, ``\\S``, a negated class, a range
    (``[a-z ]``) or any class with a letter in it."""
    if len(body) != 1:
        return True
    op, av = body[0]
    if op is _C.LITERAL:
        return False
    if op is _C.IN and not any(o is _C.NEGATE for o, _ in av):
        return any(o is _C.RANGE or (o is _C.CATEGORY and a not in _NARROW)
                   or (o is _C.LITERAL and chr(a).isalnum()) for o, a in av)
    return True


def _kinds(item: tuple) -> set[str] | None:
    """Coarse character kinds of one item (word, space, punctuation); None when unknown."""
    op, av = item
    chars: list[Any] = [chr(av)] if op is _C.LITERAL else []
    if op is _C.IN and not any(o is _C.NEGATE for o, _ in av):
        for o, a in av:
            if o is _C.LITERAL:
                chars.append(chr(a))
            elif o is _C.CATEGORY and a in (_C.CATEGORY_WORD, _C.CATEGORY_DIGIT):
                chars.append("w")
            elif o is _C.CATEGORY and a is _C.CATEGORY_SPACE:
                chars.append(" ")
            else:
                return None
    elif op is not _C.LITERAL:
        return None
    return {"w" if c == "w" or c.isalnum() or c == "_" else "s" if c.isspace() else "p" for c in chars}


def _delimited(body: list) -> bool:
    """Each repeat in a short bounded group is followed by an item it cannot match (``(\\w+\\s){3}``),
    so the group splits one way only."""
    if len(body) == 1 and body[0][0] is _C.SUBPATTERN:
        body = list(body[0][1][-1])
    for i, (op, av) in enumerate(body):
        if op in _REPEATS and av[1] > 1:
            if i + 1 >= len(body) or len(av[2]) != 1 or body[i + 1][0] in _REPEATS:
                return False
            mine, after = _kinds(av[2][0]), _kinds(body[i + 1])
            if mine is None or after is None or mine & after:
                return False
        elif op in _REPEATS or op in (_C.SUBPATTERN, _C.BRANCH):
            return False
    return True


def _spaces(body: list) -> bool:
    """A repeated item that can match a space, so its run is not confined to one word."""
    if len(body) != 1:
        return True
    op, av = body[0]
    if op is _C.LITERAL:
        return chr(av).isspace()
    if op is not _C.IN:
        return True
    space = any((o is _C.CATEGORY and a in (_C.CATEGORY_SPACE, _C.CATEGORY_NOT_WORD, _C.CATEGORY_NOT_DIGIT))
                or (o is _C.LITERAL and chr(a).isspace()) or (o is _C.RANGE and a[0] <= 32 <= a[1]) for o, a in av)
    return space != any(o is _C.NEGATE for o, _ in av)


def _inlined(items: list) -> list:
    """``items`` with each capturing group replaced by its body: ``(\\d+)(\\d+)`` runs two repeats together
    like ``\\d+\\d+`` (the parser inlines non-capturing groups already)."""
    flat: list = []
    for item in items:
        if item[0] is _C.SUBPATTERN:
            flat.extend(_inlined(list(item[1][-1])))
        else:
            flat.append(item)
    return flat


def _overlapping(items: list) -> bool:
    """Repeats in one sequence that can match the same character with nothing between them that must match
    another (``\\d+\\d+\\d+``, ``\\d+\\s*\\d+``): the text can be split between them in as many ways as the
    product of their bounds, and the search tries each. A separator that cannot be their character
    (``\\d+\\s+\\d+``) ends the run. Spaces are left out: the text is collapsed to single spaces first. A
    repeat of a group, a range or a wildcard is not tracked here: the checks of wide repeats and nested
    quantifiers read those."""
    pending: list[tuple[set[str], int]] = []
    for item in _inlined(items):
        op, av = item
        if op in _REPEATS and av[1] > 1:
            body = list(av[2])
            while len(body) == 1 and body[0][0] is _C.SUBPATTERN:  # (\\d)+ repeats \\d
                body = list(body[0][1][-1])
            kinds = _kinds(body[0]) if len(body) == 1 else None
            if kinds is None:
                pending = []
                continue
            if kinds == {"s"}:  # whitespace is collapsed before rules run: a run of it is one space
                pending = [(k, b) for k, b in pending if k & kinds] if av[0] > 0 else pending
                continue
            cost = min(av[1], MAX_SCAN)
            same = [bound for known, bound in pending if known & kinds]
            for bound in same:
                cost *= bound
            if same and cost > _WINDOW ** 2:
                return True
            pending.append((kinds, min(av[1], MAX_SCAN)))
            if av[0] > 0:  # it must match, so what it cannot match is cut off from what follows
                pending = [(k, b) for k, b in pending if k & kinds]
        elif op is _C.LITERAL or op is _C.IN:
            kinds = _kinds(item)
            pending = [(k, b) for k, b in pending if kinds is None or k & kinds]
        elif op is _C.BRANCH and any(_nullable(list(branch)) for branch in av[1]):
            continue  # "(?:x|)" may match nothing, so the repeats on either side of it can still meet
        elif op is _C.BRANCH or op in _REPEATS and av[0] > 0:
            pending = []  # a branch or a repeated group that must match something is not followed through
    return False


def _nullable(items: list) -> bool:
    """``items`` can match the empty string: every one is optional, an anchor, or a group or branch that can."""
    for op, av in items:
        if op in _REPEATS:
            if av[0] > 0 and not _nullable(list(av[2])):
                return False
        elif op is _C.SUBPATTERN:
            if not _nullable(list(av[-1])):
                return False
        elif op is _C.BRANCH:
            if not any(_nullable(list(branch)) for branch in av[1]):
                return False
        elif op is not _C.AT:
            return False
    return True


def _optional(items: list) -> bool:
    """An item that may match nothing (``x?``) anywhere in ``items``, groups included."""
    for op, av in items:
        if op in _REPEATS:
            if av[0] == 0 and av[1] == 1 or _optional(list(av[2])):
                return True
        elif op is _C.SUBPATTERN:
            if _optional(list(av[-1])):
                return True
        elif op is _C.BRANCH and any(_optional(list(branch)) for branch in av[1]):
            return True
    return False


def _backtracking(items: list, inside: bool, wide: list[int]) -> str | None:
    if _overlapping(items):
        return "adjacent repeats of the same characters"
    for op, av in items:
        if op in _REPEATS:
            low, high, body = av
            if high > 1:
                if _optional(list(body)):  # (?:x?x?x?)+ and (?:\d\d?)+ split a run in exponentially many ways
                    return "optional items in a repeated group"
                if inside:
                    return "nested quantifier"
                if any(o is _C.BRANCH or (o is _C.SUBPATTERN and any(x is _C.BRANCH for x, _ in a[-1]))
                       for o, a in body):
                    return "repeated alternation"
                if _wide(list(body)):
                    wide[0] += high > _WINDOW
                    wide[1] *= min(high, MAX_SCAN) if _spaces(list(body)) else 1
                if high <= 10 and _delimited(list(body)):
                    continue
            if problem := _backtracking(list(body), inside or high > 1, wide):
                return problem
        elif op is _C.SUBPATTERN:
            if problem := _backtracking(list(av[-1]), inside, wide):
                return problem
        elif op is _C.BRANCH:
            for branch in av[1]:
                if problem := _backtracking(list(branch), inside, wide):
                    return problem
        elif op in (_C.ASSERT, _C.ASSERT_NOT, _C.GROUPREF, _C.GROUPREF_EXISTS, _C.ATOMIC_GROUP):
            return "lookaround or backreference"
    return None


def _leading_wildcard(items: list) -> bool | None:
    """Whether the first item ``search`` must match is a wildcard; optional items (``e?``) are
    skipped, None when every item is optional."""
    for op, av in items:
        if op is _C.AT:
            continue
        if op is _C.SUBPATTERN:
            found = _leading_wildcard(list(av[-1]))
        elif op is _C.BRANCH:
            results = [_leading_wildcard(list(branch)) for branch in av[1]]
            found = True if any(results) else None if None in results else False
        elif op in _REPEATS:
            found = True if av[1] > 1 and _wide(list(av[2])) else _leading_wildcard(list(av[2]))
            found = None if av[0] == 0 and not found else found
        else:
            found = False
        if found is not None:
            return found
    return None


def backtracking_problem(pattern: str) -> str | None:
    """Catastrophic or quadratic backtracking, read from the parsed pattern rather than its text: a
    repeat inside a repeat (unless a short bounded group splits one way only), a repeated
    alternation, more than one unbounded wildcard (``forward.*?to.*?subject`` takes seconds on two
    thousand characters of its own words; a window wider than ``_WINDOW`` counts as unbounded),
    windows that cross words and multiply past ``_WINDOW ** 2`` (three ``.{0,200}`` take seconds), or
    a leading wildcard (optional items skipped), which ``search`` retries from every position.
    One unbounded wildcard after a literal stays allowed: it is quadratic in the starts of that
    literal times ``MAX_SCAN``, about 0.3 s for ``\\bignore\\b.*`` on 20k characters of ``ignore`` and
    3 s at worst for a one-letter literal (``e.*`` on 20k ``e``)."""
    tree = list(_parser.parse(pattern, re.IGNORECASE))
    wide = [0, 1]
    if problem := _backtracking(tree, False, wide):
        return problem
    if _leading_wildcard(tree):
        return "starts with a wildcard"
    if wide[0] > 1:
        return f"{wide[0]} unbounded wildcards"
    return "wildcard windows multiply" if wide[1] > _WINDOW ** 2 else None


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
    if problem := backtracking_problem(pattern):
        return problem
    if _SPECIFIC.search(pattern) or re.search(r"[0-9]", _NOT_LITERAL.sub("", pattern)):
        return "names an address, URL, domain or number"
    literal = sum(1 for token in _LITERAL.findall(pattern) if len(token) == 1)
    if literal < MIN_LITERAL:
        return "too few literal letters"
    return None


def _matcher(pattern: str) -> Callable[[str], bool]:
    compiled = re.compile(pattern, re.IGNORECASE)
    return lambda text: bool(compiled.search(" ".join(readable(text[:MAX_SCAN]).split())[:MAX_SCAN]))


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
