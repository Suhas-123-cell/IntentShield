"""Adaptive threat memory: what rule-confirmed attacks used, remembered across runs and processes.

The proxy's taint set lives in one process and a hook's taint in one session, so an attacker whose
injection is caught once can retry from a new session with the same exfiltration address or a lightly
reworded template. This memory keeps what the deterministic rules confirmed in one SQLite file that
every proxy and hook process shares, and hands it back as evidence. New defenses that need no code
arrive as signed data (``rule_packs``), which a running process picks up without a restart.

Who may teach it, and what:

- ``record_attack``: only text on which the built-in deterministic rules (``mcp_inspect.scan_output``
  and ``scan_description``) fired. The named rules are re-run on the text, and a finding they do not
  reproduce teaches nothing: not this memory's own ``known_attack_variant``, not a pack rule, not a
  learned detector, not the weaker ``collapsed_*`` evidence. Text flagged only by the memory therefore
  never creates fingerprints or indicators; the memory cannot train itself on its own matches. Only the
  injected region is read (each sentence with a rule match and its neighbours, not the whole output, so
  the other mails of an inbox are not learned). From it come:

  * indicators: emails, URLs, accounts and paths (``authority_values``) minus what the user typed, the
    operator allowlist and URLs on shared hosts (``hostlists.PROTECTED``: one host serves everyone, and an
    injected page links to itself; a tenant's own name on a platform that rents them out, as
    ``evil.workers.dev``, is not shared). A mailbox at a shared provider is one owner's, so it is kept.
  * domains: an email or URL host becomes a domain indicator once at least two distinct exact
    indicators on it were seen in at least two runs and from at least three distinct source servers (an
    attacker rotating local parts across the pages it controls; one server that names a colleague in many
    pages is one source), never for a protected, allowlisted or user-typed domain (an address or a bare
    domain in the user's text). Hosts are compared as written: no public suffix list.
  * fingerprints: hashed word 3-grams of each matched sentence and the one after it (trigger plus
    payload), and of the same window with the rule matches blanked (the payload alone, which survives
    a rewording of exactly the phrases the rules look for, learned only with an anchor: the rest of the
    matched sentence, or for a bare trigger the sentence that names a destination), read as the rules read (``readable``) with
    emails, URLs, paths and ids masked and stop words dropped. A fingerprint with fewer than
    ``MIN_WORDS`` content words, or that a text of the
    benign gate corpus (``data/benign_gate.jsonl`` plus the operator's ``add_benign``) would contain, is
    stored as ``rejected`` with its gate result, for audit, and never matches.
  * reputation: the distinct runs in which a source (``server`` or ``server:tool``) produced attacks.
    A source is ``hostile`` with ``HOSTILE_RUNS`` (five) such runs in the last ``HOSTILE_DAYS`` days. That is
    weak evidence on its outputs only (they are read as possibly injected), never on a call's
    arguments, and the operator clears it by approving a call to that server (``clear_source``) or
    allowlisting it.

  Everything learned is ``observed``: it expires ``ttl_days`` after it was last seen and is evicted
  oldest first beyond the global caps. Per call at most ``PER_CALL_INDICATORS`` indicators and
  ``PER_CALL_FINGERPRINTS`` fingerprints are learned, and a sighting counts once per run, so one run
  cannot inflate counts by repeating itself.
- the operator: ``confirm``, ``revoke`` (sticky: a revoked value is not learned again), ``allow``
  (allowlist; revokes what it covers), ``import_feed`` (IOCs with provenance, ``confirmed``) and
  ``add_benign`` (extends the gate and revokes fingerprints that now match).

What it answers is evidence only and never authorizes anything: ``check_values`` (an exact or domain
indicator; ``level`` is ``block`` only for operator-confirmed, imported or trusted-pack indicators and
``review`` for learned ones), ``check_text`` (``known_attack_variant`` when a fingerprint's shingles are
contained in the text at ``CONTAINMENT`` or more, ``pack:<id>`` for a pack rule or fingerprint) and
``hostile``. Values the user typed and allowlisted values never match, whatever taught them.

Threat model. The attacker controls tool text and so controls what gets learned: they can make the
memory remember a victim's colleague named in an injection. That is why learned values only ever give
``review`` and only the operator (or a pack the operator trusts) can make one ``block``. Flooding is
bounded by the caps, counts by per-run sightings, overbroad fingerprints by the gate, stale entries by
the TTL. An attacker who never reuses infrastructure or wording gains nothing from the memory and loses
nothing to it; the rules still apply as before. Whoever can write the database file can change what it
says, so it belongs with the hook database, readable by the user only.

Concurrency: hooks are separate short-lived processes on one file, so the database runs in WAL mode
with a busy timeout and every write is one short ``BEGIN IMMEDIATE`` transaction on its own connection.
Checks read an in-memory cache rebuilt only when another connection committed (``PRAGMA data_version``);
a database error keeps the last cache and a failed learn is reported, never raised.

    python -m intentshield.threat_memory --db PATH {list,stats,confirm ID,revoke ID,allow VALUE,
                                                   import FEED,export,benign TEXT,pack ...}
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import sys
import threading
import time
import zlib
from collections import Counter
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import UTC, datetime
from functools import cached_property, lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator
from urllib.parse import urlsplit

from .hostlists import PROTECTED_FIRST_PARTY, shared_host
from .mcp_inspect import (
    _DESCRIPTION_RULES,
    _OUTPUT_RULES,
    _VALUE_PATTERNS,
    _normalize,
    authority_values,
    leaf_text,
    readable,
    sourced_from,
)
from .storage import add_column

MAX_TEXT = 20_000  # as learning.MAX_TEXT (not imported: learning needs numpy)
SHINGLE, MIN_WORDS, MAX_WORDS, CONTAINMENT = 3, 8, 80, 0.6
PER_CALL_INDICATORS, PER_CALL_FINGERPRINTS, MAX_BLOCKS = 20, 3, 10
MAX_INDICATORS, MAX_FINGERPRINTS, MAX_REJECTED = 5000, 500, 500
ESCALATE_INDICATORS, ESCALATE_RUNS, ESCALATE_SERVERS, HOSTILE_RUNS, HOSTILE_DAYS, TTL_DAYS = 2, 2, 3, 5, 7, 30
ANCHOR_WORDS, ANCHOR_CONTAINMENT = 4, 0.5
VARIANT = "known_attack_variant"
BENIGN_PATH = Path(__file__).with_name("data") / "benign_gate.jsonl"
# Shared infrastructure (``hostlists.PROTECTED``): never learned as a domain, and URLs on a first-party site are not
# learned at all. A platform that rents out names (``workers.dev``, ``ngrok.io``, ``github.io``) is shared only as a
# whole: its bare suffix is never a domain indicator, but a tenant's own name under it (``evil.workers.dev``) is one
# owner's, and its URLs are learned like any other site's.
_BARE_HOST = re.compile(r"(?<![\w@.-])(?:[a-z0-9-]+\.)+[a-z]{2,}(?![\w-])")
# Registries that sell names under them ("evil.co.uk"): never a domain indicator on their own.
PUBLIC_SUFFIXES = frozenset("""
co.uk org.uk ac.uk gov.uk me.uk com.au net.au org.au edu.au co.nz org.nz co.jp ne.jp or.jp co.kr
co.in net.in org.in com.br com.cn net.cn org.cn com.mx com.ar com.tr co.za com.sg com.hk com.tw
co.il co.id com.my com.ph com.vn com.pl com.ua co.th
""".split())
_RULES = dict(_DESCRIPTION_RULES + _OUTPUT_RULES)
_STOP = frozenset("""
a about above after again all also am an and any are as at be been being but by can could did do does
doing during each etc for from had has have having he her here hers him his how i if in into is it its
itself just let me more most my of off on once only or other our ours out over own per please s same she
should so some such t than that the their them then there these they this those through to too under
until up us very via was we were what when where which while who whom why will with would you your yours
""".split())
_PLACEHOLDERS = frozenset({"xemail", "xurl", "xpath", "xid"})
_MASKS = ((_VALUE_PATTERNS[1], " xurl "), (_VALUE_PATTERNS[0], " xemail "), (_VALUE_PATTERNS[4], " xpath "),
          (_VALUE_PATTERNS[2], " xid "), (_VALUE_PATTERNS[5], " xid "))
# Sentence ends and line breaks (``leaf_text`` puts every JSON key and string on its own line).
_BOUNDARY = re.compile(r"(?<=[.!?])\s+|\n+")
_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}")
_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_indicators (
    id TEXT PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL, domain TEXT, status TEXT NOT NULL,
    origin TEXT NOT NULL, provenance_json TEXT NOT NULL, runs INTEGER NOT NULL DEFAULT 0,
    first_seen REAL NOT NULL, last_seen REAL NOT NULL, UNIQUE (kind, value));
CREATE INDEX IF NOT EXISTS threat_indicators_domain ON threat_indicators (domain);
CREATE TABLE IF NOT EXISTS threat_fingerprints (
    id TEXT PRIMARY KEY, shingles_json TEXT NOT NULL, excerpt TEXT NOT NULL, words INTEGER NOT NULL,
    status TEXT NOT NULL, origin TEXT NOT NULL, gate_json TEXT NOT NULL, source TEXT,
    runs INTEGER NOT NULL DEFAULT 0, first_seen REAL NOT NULL, last_seen REAL NOT NULL);
CREATE TABLE IF NOT EXISTS threat_sightings (
    item TEXT NOT NULL, run_key TEXT NOT NULL, source TEXT, seen REAL NOT NULL, PRIMARY KEY (item, run_key));
CREATE TABLE IF NOT EXISTS threat_sources (
    source TEXT NOT NULL, run_key TEXT NOT NULL, seen REAL NOT NULL, PRIMARY KEY (source, run_key));
CREATE TABLE IF NOT EXISTS threat_allowlist (value TEXT PRIMARY KEY, added REAL NOT NULL);
CREATE TABLE IF NOT EXISTS threat_benign (id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT NOT NULL, added REAL NOT NULL);
"""
# Columns added after the first schema. Processes starting together may both try to add one.
_ADDED = (("threat_indicators", "decided_at", "REAL"), ("threat_fingerprints", "decided_at", "REAL"),
          ("threat_fingerprints", "anchor_json", "TEXT"))


def _id(*parts: str) -> str:
    return hashlib.sha256("\x00".join(parts).encode()).hexdigest()[:20]


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def as_text(value: Any) -> str:
    """Any tool payload as bounded text, the way the rules read it (``leaf_text``); never raises."""
    try:
        value = value if isinstance(value, str) else leaf_text(value)
    except (TypeError, ValueError, RecursionError):
        value = ""
    return window(value)


def window(text: str) -> str:
    """The head and the tail of a long text: padding before a payload must not hide it."""
    if len(text) <= MAX_TEXT:
        return text
    half = MAX_TEXT // 2
    return text[:half] + "\n" + text[-half:]


def canonical(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    value = _normalize(value[:2048]).strip().strip(".,;:\"'<>(){}").lower()
    # a bracketed IPv6 address keeps its brackets when a port follows ("[2001:db8::5]:8080")
    return value if re.fullmatch(r"\[[0-9a-f:.]+\]:\d{1,5}", value) else value.strip("[]")


_IPV4 = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_IPV6 = re.compile(r"[0-9a-f:]{2,39}(?:\.\d{1,3}){0,3}")


def domain_of(value: str) -> str | None:
    """The host an email, URL, bare host or IPv4 address points at, without ``www.``; None for accounts and paths."""
    if "://" in value:
        try:
            host = urlsplit(value).hostname or ""
        except ValueError:
            return None
    elif "@" in value and "/" not in value:
        host = value.rpartition("@")[2]
    elif "/" not in value and "@" not in value:
        host = value  # a bare host, as ``authority_values`` returns one
    else:
        return None
    host = host.strip(".").lower().removeprefix("www.").strip("[]")
    return host if _HOST.fullmatch(host) or is_ip(host) else None


def is_ip(host: str) -> bool:
    """An IPv4 address, or an IPv6 one in its compressed or full form (what a URL's brackets hold)."""
    if _IPV4.fullmatch(host):
        return True
    if ":" in host and _IPV6.fullmatch(host):
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return False
        return True
    return False


def is_domain(value: str) -> bool:
    return (bool(_HOST.fullmatch(value)) or is_ip(value)) and "@" not in value


def exact_forms(value: str) -> list[str]:
    """The exact indicators a call's value may be listed as: itself, its URL without the query and the fragment (an
    endpoint is the same endpoint with another query), and either without a leading ``www.``."""
    forms = [value]
    if "://" in value:
        stem = value.partition("#")[0].partition("?")[0].rstrip("/")
        forms += [stem] if stem != value else []
    return forms + [bare for form in forms if (bare := _without_www(form)) != form]


def _without_www(value: str) -> str:
    return re.sub(r"^([a-z][a-z0-9+.\-]*://)www\.", r"\1", value, count=1)


def shared(host: str | None) -> bool:
    """``host`` is shared infrastructure: a first-party site in ``PROTECTED`` (or a name under one), or the bare suffix
    of a platform that rents out names. A tenant's name under that suffix is not."""
    return shared_host(host, PROTECTED_FIRST_PARTY)


def host_keys(host: str) -> list[str]:
    """The domain indicators that cover ``host``: itself and each parent but the last label alone; an address
    only itself (its "parents" are not domains)."""
    if is_ip(host):
        return [host]
    parts = host.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


def indicator_keys(value: str) -> list[str]:
    """The keys an exact indicator is stored under: as written, and as ``authority_values`` reads the same
    value in a call (https for http, no port, no trailing slash, no "+tag"), which is the form that is looked up."""
    keys = [value, *sorted(authority_values(value) - {value})[:4]]
    return keys + [bare for key in keys if (bare := _without_www(key)) not in keys]


def under(host: str | None, domains: Iterable[str]) -> str | None:
    """The entry of ``domains`` that ``host`` is or is a subdomain of."""
    domains = domains if isinstance(domains, (set, frozenset, dict)) else set(domains)
    parts = (host or "").split(".")
    return next((d for i in range(len(parts) - 1) if (d := ".".join(parts[i:])) in domains), None)


def tokens(text: str) -> list[str]:
    """Content words of already normalized text, values masked, lightly stemmed."""
    for pattern, placeholder in _MASKS:
        text = pattern.sub(placeholder, text)
    words = []
    for word in re.findall(r"[a-z]+", text.lower()):
        if len(word) < 2 or word in _STOP:
            continue
        if len(word) > 5 and word.endswith("ing"):
            word = word[:-3]
        elif len(word) > 3 and word.endswith("s") and not word.endswith("ss"):
            word = word[:-1]
        words.append(word)
    return words


def shingles(words: list[str]) -> frozenset[int]:
    grams = [" ".join(words[i:i + SHINGLE]) for i in range(max(1, len(words) - SHINGLE + 1))] if words else []
    # Stable across processes (unlike hash()), and fast: two independent 32-bit checksums.
    return frozenset(zlib.crc32(b) << 32 | zlib.adler32(b) for g in grams if (b := g.encode()))


def text_shingles(value: Any) -> frozenset[int]:
    return shingles(tokens(readable(as_text(value))))


def contained(part: frozenset[int], whole: frozenset[int]) -> float:
    return len(part & whole) / len(part) if part else 0.0


def content_words(words: list[str]) -> int:
    return sum(word not in _PLACEHOLDERS for word in words)


@lru_cache(maxsize=1)
def benign_corpus() -> tuple[str, ...]:
    """The built-in benign gate texts: tool descriptions, agent hints in outputs, requests between
    people, advisories quoting attacks, API docs and everyday text."""
    try:
        lines = BENIGN_PATH.read_text(encoding="utf-8").splitlines()
        return tuple(json.loads(line)["text"] for line in lines if line.strip())
    except (OSError, ValueError, KeyError, TypeError):
        return ()


@lru_cache(maxsize=1)
def benign_shingles() -> tuple[frozenset[int], ...]:
    return tuple(text_shingles(text) for text in benign_corpus())


def gate(words: list[str], benign: Iterable[frozenset[int]], containment: float = CONTAINMENT) -> dict[str, Any]:
    """Whether a fingerprint may go live: specific enough, and contained in no benign text."""
    n, prints = content_words(words), shingles(words)
    if n < MIN_WORDS:
        return {"ok": False, "reason": f"too generic: {n} content words", "content_words": n}
    checked = 0
    for checked, text in enumerate(benign, 1):
        if contained(prints, text) >= containment:
            return {"ok": False, "reason": "matches a benign gate text", "content_words": n,
                    "benign_index": checked - 1}
    return {"ok": True, "content_words": n, "benign_checked": checked}


def sentences(text: str) -> list[tuple[int, int]]:
    spans, start = [], 0
    for match in _BOUNDARY.finditer(text):
        spans.append((start, match.start()))
        start = match.end()
    spans.append((start, len(text)))
    return [(s, e) for s, e in spans if text[s:e].strip()]


def masked(text: str) -> str:
    text = " ".join(text.split())
    for pattern, placeholder in _MASKS:
        text = pattern.sub(placeholder.strip(), text)
    return text


@dataclass(frozen=True)
class ThreatMatch:
    id: str
    value: str          # the indicator
    matched: str        # the checked value it matched
    kind: str           # exact | domain
    status: str         # observed | confirmed | pack
    origin: str         # learned | escalated | operator | feed | pack:<name>
    level: str          # review | block


@dataclass
class _State:
    prints: dict[str, tuple[frozenset[int], str, float]] = field(default_factory=dict)
    index: dict[int, list[str]] = field(default_factory=dict)
    anchors: dict[str, frozenset[int]] = field(default_factory=dict)  # injected-sentence shingles of a window
    prints_loaded: bool = False
    allow: frozenset[str] = frozenset()
    benign_texts: tuple[str, ...] = ()  # the operator's; shingled only when something is learned

    @cached_property
    def benign(self) -> tuple[frozenset[int], ...]:
        return benign_shingles() + tuple(map(text_shingles, self.benign_texts))


def strongest(matches: Iterable[ThreatMatch | None]) -> ThreatMatch | None:
    return max((m for m in matches if m), key=lambda m: (m.level == "block", m.kind == "exact"), default=None)


def allowed(value: str, allow: frozenset[str] | set[str]) -> bool:
    """An allowlisted value, or one on (or under) an allowlisted domain."""
    return value in allow or under(domain_of(value) or (value if is_domain(value) else None), allow) is not None


class ThreatMemory:
    def __init__(self, path: str | Path, *, ttl_days: float = TTL_DAYS, hostile_runs: int = HOSTILE_RUNS,
                 hostile_days: float = HOSTILE_DAYS, containment: float = CONTAINMENT,
                 clock: Callable[[], float] = time.time, packs: Any = None) -> None:
        self.path, self.ttl, self.hostile_runs = Path(path), ttl_days * 86400, hostile_runs
        self.hostile_window = min(hostile_days * 86400, self.ttl)
        self.containment, self.clock = containment, clock
        self.packs = packs  # a rule_packs.PackSet: more evidence, merged into the checks
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():  # what attacks used, and the operator's decisions: the user's only
            self.path.touch(mode=0o600)
        db = self._connect()
        try:
            try:
                db.execute("PRAGMA journal_mode=WAL")
            except sqlite3.OperationalError:  # another process is switching it; busy_timeout still holds
                pass
            db.executescript(_SCHEMA)
            for table, column, kind in _ADDED:
                add_column(db, table, column, kind)
        finally:
            db.close()
        self._lock = threading.Lock()
        self._reader = self._connect()
        self._version: int | None = None
        self._state = _State()

    def _connect(self) -> sqlite3.Connection:
        # Short: a hook must not stall on optional evidence; a write that cannot get the lock is reported.
        db = sqlite3.connect(self.path, timeout=2, isolation_level=None, check_same_thread=False)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=2000")
        return db

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
            except BaseException:
                db.execute("ROLLBACK")
                raise
            db.execute("COMMIT")
        finally:
            db.close()

    def _read(self, query: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._reader.execute(query, params).fetchall()

    def close(self) -> None:
        with self._lock:
            self._reader.close()

    # --- the cache the checks read -------------------------------------------------------------

    def _cache(self) -> _State:
        with self._lock:
            try:
                version = self._reader.execute("PRAGMA data_version").fetchone()[0]
                if version != self._version:
                    self._state, self._version = self._load(), version
            except sqlite3.Error:  # locked or broken: answer from what was last read
                pass
            return self._state

    def _load(self) -> _State:
        """The small part of the cache; indicators are looked up by value and fingerprints load on the
        first text check, so a hook process that answers one call does not read the whole memory."""
        state = _State()
        state.allow = frozenset(r[0] for r in self._reader.execute("SELECT value FROM threat_allowlist"))
        state.benign_texts = tuple(r[0] for r in self._reader.execute("SELECT text FROM threat_benign"))
        return state

    def _prints(self) -> _State:
        state = self._cache()
        with self._lock:
            if state.prints_loaded:
                return state
            try:
                rows = self._reader.execute(
                    "SELECT id, shingles_json, status, last_seen, anchor_json FROM threat_fingerprints WHERE "
                    "status='confirmed' OR (status='observed' AND last_seen>=?)", (self.clock() - self.ttl,)).fetchall()
            except sqlite3.Error:
                return state
            for row in rows:
                prints = frozenset(json.loads(row["shingles_json"]))
                state.prints[row["id"]] = (prints, row["status"], row["last_seen"])
                if row["anchor_json"]:
                    state.anchors[row["id"]] = frozenset(json.loads(row["anchor_json"]))
                for item in prints:
                    state.index.setdefault(item, []).append(row["id"])
            state.prints_loaded = True
            return state

    def _live(self, status: str, last_seen: float) -> bool:
        return status == "confirmed" or (status == "observed" and last_seen >= self.clock() - self.ttl)

    # --- evidence ------------------------------------------------------------------------------

    @staticmethod
    def values_of(items: Any) -> set[str]:
        """Canonical authority values of loose input: strings, a collection of them, or a structure."""
        if isinstance(items, (set, frozenset, list, tuple)):
            items = [item for item in list(items)[:2000] if isinstance(item, str)]
        else:
            items = [as_text(items)] if items else []
        found: set[str] = set()
        for item in items:
            found |= authority_values(window(item))
            if (value := canonical(item)) and " " not in value:
                found.add(value)
        return found

    def check_values(self, values: Any, trusted: Any = frozenset()) -> ThreatMatch | None:
        """The strongest indicator any of ``values`` hits, ignoring what the user typed and the allowlist."""
        state = self._cache()
        # A domain the user names in prose ("anyone at acme-corp.com") is theirs as much as an address.
        named = set(_BARE_HOST.findall(trusted.lower())) if isinstance(trusted, str) else set()
        trusted = self.values_of(trusted)
        trusted_domains = {d for v in trusted if (d := domain_of(v))} | {h.removeprefix("www.") for h in named}
        checked = {v for v in self.values_of(values) - trusted if not allowed(v, state.allow)}
        wanted: dict[tuple[str, str], list[str]] = {}
        for value in checked:
            for form in exact_forms(value):
                wanted.setdefault(("exact", form), []).append(value)
            host = domain_of(value)
            if host and not under(host, trusted_domains):
                for key in host_keys(host):
                    wanted.setdefault(("domain", key), []).append(value)
                # an exact host indicator: an address imported before they were domains, or a host with a port
                # ("c2.example:8080", stored also as "c2.example"), which a call's canonical value has dropped
                for form in (host, f"[{host}]") if ":" in host else (host,):
                    wanted.setdefault(("exact", form), []).append(value)
        rows: list[sqlite3.Row] = []
        keys = sorted({value for _, value in wanted})
        try:
            for start in range(0, len(keys), 500):
                chunk = keys[start:start + 500]
                rows += self._read(f"SELECT * FROM threat_indicators WHERE value IN ({','.join('?' * len(chunk))})",
                                   tuple(chunk))
        except sqlite3.Error:  # locked or broken: the packs still answer
            rows = []
        matches = []
        for row in rows:
            for value in wanted.get((row["kind"], row["value"]), ()):
                if self._live(row["status"], row["last_seen"]):
                    matches.append(ThreatMatch(row["id"], row["value"], value, row["kind"], row["status"],
                                               row["origin"], "block" if row["status"] == "confirmed" else "review"))
        if self.packs is not None and checked:
            matches += self.packs.check_values(checked, trusted_domains)
        return strongest(matches)

    def fingerprint_hits(self, text: Any, prints: frozenset[int] | None = None) -> list[tuple[str, float, str]]:
        """(fingerprint id, containment, status) of every live fingerprint ``text`` contains, best first."""
        state = self._prints()
        if not state.prints:
            return []
        prints = text_shingles(text) if prints is None else prints
        counts = Counter(fid for item in prints for fid in state.index.get(item, ()))
        hits = []
        for fid, n in counts.items():
            own, status, last_seen = state.prints[fid]
            anchor = state.anchors.get(fid)
            if anchor and len(anchor & prints) < ANCHOR_CONTAINMENT * len(anchor):
                continue
            if n / len(own) >= self.containment and self._live(status, last_seen):
                hits.append((fid, round(n / len(own), 3), status))
        return sorted(hits, key=lambda hit: -hit[1])

    def text_matches(self, text: Any, target: str = "output") -> list[dict[str, Any]]:
        """Every fingerprint and pack rule ``text`` matches, with its level (``target`` is ``output``,
        ``description`` or ``argument``; fingerprints read outputs and descriptions only)."""
        norm = readable(as_text(text))
        prints = shingles(tokens(norm))
        found = []
        if target != "argument":
            found += [{"name": VARIANT, "id": fid, "containment": score,
                       "level": "block" if status == "confirmed" else "review"}
                      for fid, score, status in self.fingerprint_hits(None, prints)]
        if self.packs is not None:
            found += self.packs.check_text(norm, prints, target, self.containment)
        return found

    def check_text(self, text: Any, target: str = "output") -> list[str]:
        return list(dict.fromkeys(match["name"] for match in self.text_matches(text, target)))

    def reputation(self, source: Any) -> int:
        if not isinstance(source, str):
            return 0
        try:
            return self._read("SELECT COUNT(DISTINCT run_key) FROM threat_sources WHERE source=? AND seen>=?",
                              (source[:200], self.clock() - self.hostile_window))[0][0]
        except sqlite3.Error:
            return 0

    def hostile(self, source: Any) -> bool:
        return self.reputation(source) >= self.hostile_runs and not (
            isinstance(source, str) and source.lower() in self._cache().allow)

    # --- learning from rule-confirmed attacks --------------------------------------------------

    def record_attack(self, text: Any, findings: Any, *, source: Any, run_key: Any, trusted: Any = "") -> dict[str, Any]:
        """Learn from one output or description the built-in rules flagged; returns what was learned."""
        if isinstance(findings, str):
            findings = [findings]
        names = sorted({f.removeprefix("split_") for f in findings if isinstance(f, str)}
                       if isinstance(findings, (list, tuple, set, frozenset)) else set())
        rules = [_RULES[name] for name in names if name in _RULES]
        if not rules:
            return {"learned": False, "reason": "no built-in rule among the findings"}
        source, run_key = str(source)[:200], str(run_key)[:200]
        norm, trusted = readable(as_text(text)), as_text(trusted) if trusted else ""
        folded = " ".join(_normalize(trusted).lower().split())
        spans = [m.span() for rule in rules for m in rule.finditer(norm)
                 if " ".join(m.group(0).lower().split()) not in folded]
        if not spans:
            return {"learned": False, "reason": "the named rules do not fire on this text"}
        parts = sentences(norm)
        hit = sorted({i for i, (s, e) in enumerate(parts) for a, b in spans if a < e and b > s})
        state = self._prints()

        # Indicators: the values of the injected region, closest to a match first.
        user = authority_values(_normalize(trusted)) if trusted else set()
        user_domains = {d for v in user if (d := domain_of(v) or (v if is_domain(v) else None))
                        and not shared(d)}
        distance: dict[str, int] = {}
        for j, (s, e) in enumerate(parts):
            # The sentence before a match to the one after it: further out lie the next mail's sender,
            # the next record's owner, values the attacker did not choose.
            if any(i - 1 <= j <= i + 1 for i in hit):
                near = min(abs(j - i) for i in hit)
                for value in authority_values(norm[s:e]):
                    distance[value] = min(distance.get(value, 9), near)
        urls = [v for v in distance if "://" in v]
        values = [v for v in sorted(sourced_from(set(distance), set(distance), user), key=lambda v: (distance[v], v))
                  if not allowed(v, state.allow) and not under(domain_of(v), user_domains)
                  and not ("://" in v and shared(domain_of(v)))
                  and not (v.startswith("/") and any(v in url for url in urls))][:PER_CALL_INDICATORS]

        # Fingerprints: each matched sentence plus the one after it; overlapping windows merge.
        blocks: list[list[int]] = []
        for i in hit:
            if blocks and i <= blocks[-1][-1]:
                blocks[-1] = sorted({*blocks[-1], i, i + 1} & set(range(len(parts))))
            else:
                blocks.append([j for j in (i, i + 1) if j < len(parts)])
        # A second print of each window has the rule matches blanked out: the payload, which survives
        # an attacker rewording exactly the phrases the rules look for.
        blanked = list(norm)
        for a, b in spans:
            blanked[a:b] = " " * (b - a)
        blanked = "".join(blanked)
        candidates, seen, matched = [], set(), set(hit)
        for block in blocks[:MAX_BLOCKS]:
            for source_text in (norm, blanked):
                excerpt = " ".join(source_text[parts[j][0]:parts[j][1]].strip() for j in block)
                words = tokens(excerpt)[:MAX_WORDS]
                prints = shingles(words)
                if not prints or prints in seen:
                    continue
                own = tokens(" ".join(source_text[parts[j][0]:parts[j][1]] for j in block if j in matched))
                # The window must be matched with part of the injected sentence itself: a long disclaimer after
                # a short trigger would otherwise match every mail that carries it.
                anchor = shingles(own) & prints
                if source_text is blanked and content_words(own) < ANCHOR_WORDS:
                    # The payload after a bare trigger ("IGNORE PREVIOUS INSTRUCTIONS. <payload>") has nothing of
                    # the trigger's sentence to anchor on, so the sentence that names a destination (as exfiltration
                    # does and boilerplate does not) is the anchor.
                    dest = next((w for j in block if _PLACEHOLDERS & set(w := tokens(source_text[parts[j][0]:parts[j][1]]))),
                                [])
                    anchor = shingles(dest) & prints if content_words(dest) >= ANCHOR_WORDS else frozenset()
                if source_text is blanked and not anchor:
                    continue  # never a print of the payload alone
                seen.add(prints)
                known = [fid for fid, (other, _, _) in state.prints.items()
                         if contained(other, prints) >= self.containment]
                candidates.append((excerpt, words, prints, gate(words, state.benign, self.containment), known,
                                   anchor))

        now = self.clock()
        summary: dict[str, Any] = {"learned": True, "rules": names, "indicators": [], "domains": [],
                                   "fingerprints": [], "skipped": []}
        try:
            with self._write() as db:
                self._purge(db, now)
                for value in values:
                    item = self._upsert(db, "exact", value, now, "learned", {"source": source, "rules": names})
                    if item is None:
                        summary["skipped"].append({"value": value, "reason": "revoked by the operator"})
                        continue
                    self._sight(db, item, run_key, source, now)
                    summary["indicators"].append(value)
                self._escalate(db, summary, run_key, source, now, user_domains, state.allow)
                self._learn_prints(db, summary, candidates, run_key, source, now)
                for key in {source, source.partition(":")[0]} - {""}:
                    db.execute("INSERT INTO threat_sources VALUES (?,?,?) ON CONFLICT(source, run_key) DO UPDATE "
                               "SET seen=excluded.seen", (key, run_key, now))
                self._caps(db)
        except sqlite3.Error as exc:
            return {"learned": False, "reason": f"database error: {exc}"}
        return summary

    def _escalate(self, db: sqlite3.Connection, summary: dict[str, Any], run_key: str, source: str, now: float,
                  user_domains: set[str], allow: frozenset[str]) -> None:
        for host in sorted({d for v in summary["indicators"] if (d := domain_of(v))}):
            if shared(host) or under(host, user_domains) or allowed(host, allow) \
                    or host in PUBLIC_SUFFIXES or "." not in host:
                continue
            # Distinct servers, not runs alone: one server that carries a colleague's address in many of its
            # pages makes a hundred runs from one source, and it is not an attacker rotating mailboxes.
            n, runs, servers = db.execute(
                "SELECT COUNT(DISTINCT i.id), COUNT(DISTINCT s.run_key), COUNT(DISTINCT CASE WHEN instr(s.source, ':') > 0 "
                "THEN substr(s.source, 1, instr(s.source, ':') - 1) ELSE s.source END) FROM threat_indicators i JOIN "
                "threat_sightings s ON s.item=i.id WHERE i.kind='exact' AND i.domain=? AND i.status!='revoked'",
                (host,)).fetchone()
            if n >= ESCALATE_INDICATORS and runs >= ESCALATE_RUNS and servers >= ESCALATE_SERVERS:
                item = self._upsert(db, "domain", host, now, "escalated",
                                    {"indicators": n, "runs": runs, "servers": servers})
                if item:
                    self._sight(db, item, run_key, source, now)
                    summary["domains"].append(host)

    def _learn_prints(self, db: sqlite3.Connection, summary: dict[str, Any], candidates: list, run_key: str,
                      source: str, now: float) -> None:
        revoked = [frozenset(json.loads(r[0])) for r in
                   db.execute("SELECT shingles_json FROM threat_fingerprints WHERE status='revoked'")]
        learned = 0
        for excerpt, words, prints, result, known, anchor in candidates:
            if result["ok"] and any(max(contained(r, prints), contained(prints, r)) >= self.containment
                                    for r in revoked):
                result = {"ok": False, "reason": "the operator revoked a matching fingerprint"}
            if result["ok"] and known:
                for fid in known:
                    db.execute("UPDATE threat_fingerprints SET last_seen=? WHERE id=? AND status IN "
                               "('observed','confirmed')", (now, fid))
                    self._sight(db, fid, run_key, source, now, "threat_fingerprints")
                summary["fingerprints"].append({"id": known[0], "status": "refreshed"})
                continue
            if result["ok"] and learned >= PER_CALL_FINGERPRINTS:
                continue
            status = "observed" if result["ok"] else "rejected"
            fid = _id("fingerprint", json.dumps(sorted(prints)))
            inserted = db.execute(
                "INSERT OR IGNORE INTO threat_fingerprints (id, shingles_json, excerpt, words, status, origin, "
                "gate_json, source, first_seen, last_seen, anchor_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (fid, json.dumps(sorted(prints)), masked(excerpt)[:2000], len(words), status, "learned",
                 json.dumps(result), source, now, now, json.dumps(sorted(anchor)) if anchor else None)).rowcount
            if result["ok"]:
                learned += 1
                if not inserted:
                    db.execute("UPDATE threat_fingerprints SET last_seen=? WHERE id=? AND status='observed'", (now, fid))
                self._sight(db, fid, run_key, source, now, "threat_fingerprints")
            summary["fingerprints"].append({"id": fid, "status": status, "gate": result})

    def _upsert(self, db: sqlite3.Connection, kind: str, value: str, now: float, origin: str,
                provenance: dict[str, Any], status: str = "observed") -> str | None:
        """The id of the indicator (created, refreshed or confirmed), or None when the operator revoked
        it. A learned sighting never downgrades a confirmed indicator."""
        row = db.execute("SELECT id, status FROM threat_indicators WHERE kind=? AND value=?", (kind, value)).fetchone()
        if row is None:
            item = _id(kind, value)
            db.execute("INSERT INTO threat_indicators (id, kind, value, domain, status, origin, provenance_json, "
                       "first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?)",
                       (item, kind, value, domain_of(value) if kind == "exact" else value, status, origin,
                        json.dumps(provenance), now, now))
            return item
        if row["status"] == "revoked":  # only the operator's own confirm() undoes a revoke
            return None
        if status == "confirmed":
            db.execute("UPDATE threat_indicators SET status='confirmed', origin=?, provenance_json=?, last_seen=?, "
                       "decided_at=? WHERE id=?", (origin, json.dumps(provenance), now, now, row["id"]))
        else:
            db.execute("UPDATE threat_indicators SET last_seen=? WHERE id=?", (now, row["id"]))
        return row["id"]

    @staticmethod
    def _sight(db: sqlite3.Connection, item: str, run_key: str, source: str, now: float,
               table: str = "threat_indicators") -> None:
        if db.execute("INSERT OR IGNORE INTO threat_sightings VALUES (?,?,?,?)", (item, run_key, source, now)).rowcount:
            db.execute(f"UPDATE {table} SET runs=runs+1 WHERE id=?", (item,))

    def _purge(self, db: sqlite3.Connection, now: float) -> None:
        cutoff = now - self.ttl
        for table in ("threat_indicators", "threat_fingerprints"):
            db.execute(f"DELETE FROM threat_sightings WHERE item IN (SELECT id FROM {table} "
                       "WHERE status IN ('observed','rejected') AND last_seen<?)", (cutoff,))
            db.execute(f"DELETE FROM {table} WHERE status IN ('observed','rejected') AND last_seen<?", (cutoff,))
        db.execute("DELETE FROM threat_sources WHERE seen<?", (cutoff,))

    @staticmethod
    def _caps(db: sqlite3.Connection) -> None:
        for table, status, cap in (("threat_indicators", "observed", MAX_INDICATORS),
                                   ("threat_fingerprints", "observed", MAX_FINGERPRINTS),
                                   ("threat_fingerprints", "rejected", MAX_REJECTED)):
            extra = db.execute(f"SELECT COUNT(*) FROM {table} WHERE status=?", (status,)).fetchone()[0] - cap
            if extra > 0:
                old = [r[0] for r in db.execute(f"SELECT id FROM {table} WHERE status=? ORDER BY last_seen, rowid "
                                                "LIMIT ?", (status, extra))]
                marks = ",".join("?" * len(old))
                db.execute(f"DELETE FROM threat_sightings WHERE item IN ({marks})", old)
                db.execute(f"DELETE FROM {table} WHERE id IN ({marks})", old)

    # --- the operator --------------------------------------------------------------------------

    def _decide(self, item_id: str, status: str) -> dict[str, Any]:
        with self._write() as db:
            for table in ("threat_indicators", "threat_fingerprints"):
                row = db.execute(f"SELECT * FROM {table} WHERE id=?", (str(item_id),)).fetchone()
                if row is None:
                    continue
                if row["status"] == "rejected":
                    raise ValueError("a fingerprint the gate rejected cannot be decided on")
                now = self.clock()
                db.execute(f"UPDATE {table} SET status=?, last_seen=?, decided_at=? WHERE id=?",
                           (status, now, now, item_id))
                if table == "threat_indicators":  # the other keys of a feed indicator follow it
                    group = json.loads(row["provenance_json"]).get("group")
                    for other in self._group(db, group):
                        db.execute("UPDATE threat_indicators SET status=?, last_seen=?, decided_at=? WHERE id=?",
                                   (status, now, now, other))
                return {**self._public(dict(row)), "status": status}
        raise KeyError(item_id)

    @staticmethod
    def _group(db: sqlite3.Connection, group: Any) -> list[str]:
        """The ids of the rows ``import_feed`` made for one indicator."""
        if not isinstance(group, str):
            return []
        return [r["id"] for r in db.execute("SELECT id, provenance_json FROM threat_indicators WHERE kind='exact' "
                                            "AND provenance_json LIKE ?", (f'%"group": {json.dumps(group)}%',))
                if json.loads(r["provenance_json"]).get("group") == group]

    def confirm(self, item_id: str) -> dict[str, Any]:
        """Confirmed entries give ``block`` and never expire."""
        return self._decide(item_id, "confirmed")

    def revoke(self, item_id: str) -> dict[str, Any]:
        """Revoked entries never match and are not learned again."""
        return self._decide(item_id, "revoked")

    def allow(self, value: str) -> dict[str, Any]:
        """Allowlist an exact value or a whole domain, and revoke every indicator it covers."""
        value = canonical(value)
        if not value or " " in value:
            raise ValueError("nothing to allow")
        with self._write() as db:
            db.execute("INSERT OR IGNORE INTO threat_allowlist VALUES (?,?)", (value, self.clock()))
            self._clear_source(db, value)  # a server, too
            rows = db.execute("SELECT id, value, domain, provenance_json FROM threat_indicators "
                              "WHERE status!='revoked'").fetchall()
            covered = [r["id"] for r in rows if r["value"] == value or
                       json.loads(r["provenance_json"]).get("group") == value or
                       (is_domain(value) and under(r["domain"] or "", {value}))]
            db.executemany("UPDATE threat_indicators SET status='revoked', decided_at=? WHERE id=?",
                           [(self.clock(), i) for i in covered])
        return {"allowed": value, "revoked": covered}

    def clear_source(self, server: str) -> None:
        """The operator approved a call to ``server``: forget the attacks it and its tools produced."""
        with self._write() as db:
            self._clear_source(db, canonical(server))

    @staticmethod
    def _clear_source(db: sqlite3.Connection, server: str) -> None:
        db.execute("DELETE FROM threat_sources WHERE lower(source)=? OR substr(lower(source), 1, ?)=?",
                   (server, len(server) + 1, f"{server}:"))

    def import_feed(self, feed: str | Path | dict[str, Any], *, origin: str = "feed") -> dict[str, Any]:
        """Import IOCs (and fingerprint texts) with their provenance as ``confirmed``. Rows marked
        ``observed``, ``revoked`` or ``rejected`` at their origin are skipped (an export must not launder
        learned values into blocking ones), and so are allowlisted values and protected domains.
        Fingerprints pass the same gate as learned ones."""
        if not isinstance(feed, dict):
            feed = json.loads(Path(feed).read_text(encoding="utf-8"))
        rows = feed.get("indicators", []) if isinstance(feed, dict) else None
        texts = feed.get("fingerprints", []) if isinstance(feed, dict) else None
        if not isinstance(rows, list) or not isinstance(texts, list):
            raise ValueError("a feed is a JSON object with an 'indicators' list")
        name, now = str(feed.get("name") or "feed")[:200], self.clock()
        imported, skipped, prints = [], [], []
        state = self._cache()
        with self._write() as db:
            for item in rows[:10_000]:
                item = {"value": item} if isinstance(item, str) else item
                value = canonical(item.get("value")) if isinstance(item, dict) else ""
                kind = (item.get("kind") if isinstance(item, dict) else None) or ("domain" if is_domain(value) else "exact")
                reason = ("not a value" if not value or " " in value or kind not in ("exact", "domain") else
                          "not confirmed at its origin" if item.get("status") in ("observed", "revoked", "rejected") else
                          "allowlisted" if allowed(value, state.allow) else
                          "protected shared domain" if kind == "domain" and shared(value) else None)
                if reason:
                    skipped.append({"value": str(item.get("value") if isinstance(item, dict) else item)[:200],
                                    "reason": reason})
                    continue
                value = value.removeprefix("www.") if kind == "domain" else value
                provenance = {k: v if isinstance(v, (int, float)) else str(v)[:500] for k, v in item.items()
                              if k not in ("value", "kind", "status") and isinstance(v, (str, int, float))}
                # An exact indicator is also stored as a call's value for it reads: a feed's "http://x.example/a/"
                # would otherwise never meet the "https://x.example/a" a call to it is looked up as.
                keys = indicator_keys(value) if kind == "exact" else [value]
                if self._upsert(db, kind, value, now, origin, provenance | {"feed": name, "group": value}, "confirmed"):
                    imported.append(value)
                    for key in keys[1:]:
                        self._upsert(db, kind, key, now, origin, provenance | {"feed": name, "group": value,
                                                                              "alias_of": value}, "confirmed")
                else:
                    skipped.append({"value": value, "reason": "revoked by the operator"})
            for item in texts[:1000]:
                text = item.get("text") if isinstance(item, dict) else item
                if not isinstance(text, str) or (isinstance(item, dict) and
                                                 item.get("status") in ("observed", "revoked", "rejected")):
                    continue
                words = tokens(readable(text[:MAX_TEXT]))[:MAX_WORDS]
                result = gate(words, state.benign, self.containment)
                fid = _id("fingerprint", json.dumps(sorted(shingles(words))))
                if result["ok"]:
                    db.execute("INSERT INTO threat_fingerprints (id, shingles_json, excerpt, words, status, origin, "
                               "gate_json, source, first_seen, last_seen, decided_at) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
                               "ON CONFLICT(id) DO UPDATE SET status='confirmed', origin=excluded.origin "
                               "WHERE threat_fingerprints.status!='revoked'",
                               (fid, json.dumps(sorted(shingles(words))), masked(text)[:2000], len(words), "confirmed",
                                origin, json.dumps(result | {"feed": name}), name, now, now, now))
                prints.append({"id": fid, "status": "confirmed" if result["ok"] else "rejected", "gate": result})
        return {"feed": name, "imported": imported, "skipped": skipped, "fingerprints": prints}

    def add_benign(self, text: str) -> dict[str, Any]:
        """Extend the gate corpus; fingerprints that the new text contains are revoked."""
        text = as_text(text).strip()
        if not text:
            raise ValueError("an empty benign text")
        benign = text_shingles(text)
        with self._write() as db:
            item = db.execute("INSERT INTO threat_benign (text, added) VALUES (?,?)", (text, self.clock())).lastrowid
            revoked = []
            for row in db.execute("SELECT id, shingles_json, gate_json FROM threat_fingerprints "
                                  "WHERE status IN ('observed','confirmed')").fetchall():
                if contained(frozenset(json.loads(row["shingles_json"])), benign) >= self.containment:
                    result = {**json.loads(row["gate_json"]), "revoked_by_benign": item}
                    db.execute("UPDATE threat_fingerprints SET status='revoked', gate_json=?, decided_at=? WHERE id=?",
                               (json.dumps(result), self.clock(), row["id"]))
                    revoked.append(row["id"])
        return {"id": item, "revoked": revoked}

    @staticmethod
    def _public(row: Any) -> dict[str, Any]:
        row = dict(row)
        for key in ("provenance_json", "gate_json"):
            if key in row:
                row[key.removesuffix("_json")] = json.loads(row.pop(key))
        row.pop("shingles_json", None)
        for key in ("first_seen", "last_seen", "decided_at"):
            if row.get(key) is not None:
                row[key] = datetime.fromtimestamp(row[key], UTC).isoformat(timespec="seconds")
        return row

    def items(self) -> dict[str, Any]:
        indicators = self._read("SELECT * FROM threat_indicators ORDER BY last_seen DESC")
        fingerprints = self._read("SELECT * FROM threat_fingerprints ORDER BY last_seen DESC")
        return {"indicators": [self._public(r) for r in indicators],
                "fingerprints": [self._public(r) for r in fingerprints],
                "allowlist": [r[0] for r in self._read("SELECT value FROM threat_allowlist ORDER BY value")]}

    def export(self) -> dict[str, Any]:
        """Everything not revoked or rejected, in the feed format ``import_feed`` reads (which imports
        only the rows confirmed here)."""
        indicators = []
        for row in self._read("SELECT * FROM threat_indicators WHERE status!='revoked' ORDER BY first_seen"):
            row = self._public(row)
            if row["provenance"].get("alias_of"):
                continue  # a spelling of the one before it
            indicators.append({**{k: v for k, v in row["provenance"].items() if isinstance(v, (str, int, float))},
                               "value": row["value"], "kind": row["kind"], "status": row["status"],
                               "origin": row["origin"], "runs": row["runs"], "first_seen": row["first_seen"],
                               "last_seen": row["last_seen"]})
        prints = [{"id": r["id"], "text": r["excerpt"], "status": r["status"], "runs": r["runs"]}
                  for r in self._read("SELECT * FROM threat_fingerprints WHERE status IN ('observed','confirmed') "
                                      "ORDER BY first_seen")]
        return {"format": "intentshield-threat-feed/1", "name": "intentshield-export", "exported_at": _now_iso(),
                "indicators": indicators, "fingerprints": prints}

    def stats(self) -> dict[str, Any]:
        def counts(table: str) -> dict[str, int]:
            return {r[0]: r[1] for r in self._read(f"SELECT status, COUNT(*) FROM {table} GROUP BY status")}
        sources = self._read("SELECT source, COUNT(DISTINCT run_key) AS runs FROM threat_sources WHERE seen>=? "
                             "GROUP BY source ORDER BY runs DESC LIMIT 20", (self.clock() - self.hostile_window,))
        result = {"indicators": counts("threat_indicators"),
                  "domains": self._read("SELECT COUNT(*) FROM threat_indicators WHERE kind='domain' "
                                        "AND status!='revoked'")[0][0],
                  "fingerprints": counts("threat_fingerprints"),
                  "allowlist": self._read("SELECT COUNT(*) FROM threat_allowlist")[0][0],
                  "benign": {"builtin": len(benign_corpus()),
                             "operator": self._read("SELECT COUNT(*) FROM threat_benign")[0][0]},
                  "sources": [{"source": r[0], "runs": r[1], "hostile": r[1] >= self.hostile_runs} for r in sources],
                  "ttl_days": self.ttl / 86400, "hostile_days": self.hostile_window / 86400}
        if self.packs is not None:
            result["packs"] = self.packs.status()
        return result


def default_db() -> str:
    return os.getenv("INTENTSHIELD_THREAT_DB", str(Path.home() / ".intentshield" / "threats.db"))


def main(argv: list[str] | None = None) -> None:
    """``intentshield-threats``: inspect and steer the threat memory and the threat packs; prints JSON."""
    from . import rule_packs

    parser = argparse.ArgumentParser(prog="intentshield-threats", description=__doc__.split("\n")[0])
    parser.add_argument("--db", default=default_db(),
                        help="threat memory database (default $INTENTSHIELD_THREAT_DB or ~/.intentshield/threats.db)")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("list", "every remembered attack value and rule, with its level and source"),
                            ("stats", "counts by level, source and age"),
                            ("export", "the memory as a feed another operator can import")):
        commands.add_parser(name, help=help_text)
    for name, arg, help_text, arg_help in (
            ("confirm", "id", "promote a remembered attack from review to block", "item id from `list`"),
            ("revoke", "id", "forget a remembered attack", "item id from `list`"),
            ("allow", "value", "mark a value benign so it is never remembered as an attack", "the exact value"),
            ("import", "feed", "import a feed written by `export`", "path of the feed file"),
            ("benign", "text", "record an output text as benign (a false positive)", "the output text")):
        commands.add_parser(name, help=help_text).add_argument(arg, help=arg_help)
    rule_packs.add_commands(commands.add_parser("pack", help="verify, install, update, export and sign threat packs"))
    args = parser.parse_args(argv)
    try:
        if args.command == "pack":
            result = rule_packs.run_command(args)
        else:
            memory = ThreatMemory(args.db)
            result = {"list": memory.items, "stats": memory.stats, "export": memory.export,
                      "confirm": lambda: memory.confirm(args.id), "revoke": lambda: memory.revoke(args.id),
                      "allow": lambda: memory.allow(args.value), "import": lambda: memory.import_feed(args.feed),
                      "benign": lambda: memory.add_benign(args.text)}[args.command]()
    except (KeyError, ValueError, OSError, sqlite3.Error, rule_packs.PackError) as exc:
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        sys.exit(1)
    print(json.dumps(result, indent=2, default=lambda o: asdict(o) if is_dataclass(o) else str(o)))


if __name__ == "__main__":  # pragma: no cover
    main()
