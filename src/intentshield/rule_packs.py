"""Threat packs: new defenses delivered as verified data and picked up by running processes.

A threat pack is a versioned JSON document (``FORMAT``) with four kinds of entry:

- ``rules``: regular expressions with an ``id``, a ``target`` (``output``, ``description`` or
  ``argument``) and a ``level`` (``review`` or ``block``). They read the text the built-in rules read
  (``mcp_inspect.readable``, whitespace collapsed so a line break cannot split a phrase). Optional
  ``examples`` must each match, as a check that the rule says what its author meant.
- ``indicators``: exact values (emails, URLs, accounts, paths) or domains, with a ``level``.
- ``fingerprints``: attack texts, matched like the threat memory's learned fingerprints.
- ``benign``: texts this pack's own entries must not match, on top of the built-in gate corpus.

Every entry is gated before it is loaded, and a rejected entry is reported with its reason, never
loaded: a regex must pass ``signatures.safety_problem`` (bounded length, no nested quantifiers,
lookarounds or backreferences, enough literal letters, no addresses or numbers) and match no benign
gate text; a fingerprint must be specific (``threat_memory.MIN_WORDS``) and contained in no benign
text; a domain indicator may not name shared infrastructure (``threat_memory.PROTECTED``).

Packs only add evidence. The format has no way to remove or relax a built-in rule, allowlist a value
or authorize a call; fields that try (``allowlist``, ``disable``, ...) are reported and ignored, the
operator allowlist of the threat memory beats every pack indicator, and a pack's benign texts gate
only that pack (they never revoke what the memory learned). ``block`` is honoured only for a trusted
pack; otherwise every entry gives ``review``.

Integrity. A pack is accepted only when its canonical body (sorted-key JSON without ``signature``)
has a digest the operator pinned (``sha256:<hex>``), or carries a ``signature`` made with an HMAC-SHA256
key the operator holds, or an Ed25519 signature for a public key the operator configured (only when
the ``cryptography`` package is importable; otherwise such a pack is refused with that reason). A
verified pack is trusted. Unverified packs are refused unless the operator opts in
(``allow_unverified``), and then load as review-only and never replace a verified pack; a signature
that does not verify, or names a key the operator does not hold, is refused always unless the digest is
pinned. Versions only move forward: a pack older than the one loaded (a validly signed replay), or the
same version with other content, is refused.

Hot reload. ``PackSet.refresh`` stats the pack directory at most every ``interval`` seconds and reloads
changed files. A file that fails to parse, verify or move forward is reported in ``status`` and the
last good version stays loaded; a copy of every accepted verified pack is kept in ``.good/`` so a restart
after tampering still starts from the last good pack. Deleting a file does not unload it until restart; the
CLI's ``pack remove`` deletes the good copy too.

``pack update --url`` is opt-in, HTTPS only (redirects too), size-capped, and installs only what
verifies. Nothing in a pack is ever executed: it is parsed as JSON and its regexes are only matched.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import re
import tempfile
import threading
import time
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from .mcp_inspect import readable
from .signatures import safety_problem
from .threat_memory import (
    MAX_TEXT,
    MAX_WORDS,
    PROTECTED,
    ThreatMatch,
    ThreatMemory,
    benign_corpus,
    benign_shingles,
    canonical,
    domain_of,
    gate,
    is_domain,
    shingles,
    text_shingles,
    tokens,
    under,
)

FORMAT = "intentshield-threat-pack/1"
MAX_PACK_BYTES = 2_000_000
MAX_RULES, MAX_INDICATORS, MAX_FINGERPRINTS, MAX_BENIGN = 500, 10_000, 1000, 1000
TARGETS, LEVELS = ("output", "description", "argument"), ("review", "block")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}")
_KNOWN = {"format", "name", "version", "created", "description", "provenance", "rules", "indicators",
          "fingerprints", "benign", "signature"}


class PackError(ValueError):
    pass


def body(pack: dict[str, Any]) -> bytes:
    """What digests and signatures cover: the pack without its signature, as canonical JSON."""
    return json.dumps({k: v for k, v in pack.items() if k != "signature"}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode()


def digest(pack: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(body(pack)).hexdigest()


def _ed25519() -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        return ed25519
    except ImportError:
        return None


@dataclass(frozen=True)
class Trust:
    hmac_keys: dict[str, bytes] = field(default_factory=dict)
    ed25519_keys: dict[str, bytes] = field(default_factory=dict)
    pins: frozenset[str] = frozenset()
    allow_unverified: bool = False

    @classmethod
    def from_env(cls, **extra: Any) -> "Trust":
        """``INTENTSHIELD_PACK_HMAC_KEY`` (a secret, key id ``default``) or ``..._HMAC_KEY_FILE``,
        ``INTENTSHIELD_PACK_ED25519_KEYS`` (``id:hex,...`` raw public keys) and ``INTENTSHIELD_PACK_PINS``
        (``sha256:<hex>,...``), merged with ``extra``."""
        keys = dict(extra.pop("hmac_keys", {}))
        if secret := os.getenv("INTENTSHIELD_PACK_HMAC_KEY"):
            keys.setdefault("default", secret.encode())
        if path := os.getenv("INTENTSHIELD_PACK_HMAC_KEY_FILE"):
            keys.setdefault("default", Path(path).expanduser().read_bytes().strip())
        public = dict(extra.pop("ed25519_keys", {}))
        for item in filter(None, os.getenv("INTENTSHIELD_PACK_ED25519_KEYS", "").split(",")):
            key_id, _, value = item.strip().rpartition(":")
            public.setdefault(key_id or "default", bytes.fromhex(value))
        pins = set(extra.pop("pins", ())) | {p.strip() for p in os.getenv("INTENTSHIELD_PACK_PINS", "").split(",")
                                             if p.strip()}
        return cls(keys, public, frozenset(pins), **extra)


def _signed_by(signature: Any, pack: dict[str, Any], trust: Trust) -> str:
    """The key that made ``signature``; raises PackError for any signature that does not verify."""
    if not isinstance(signature, dict) or not isinstance(signature.get("value"), str):
        raise PackError("malformed signature")
    alg, key_id, value = signature.get("alg"), str(signature.get("key_id", "default")), signature["value"]
    bad = PackError("signature does not verify: the pack was changed or signed with another key")
    if alg == "hmac-sha256":
        if (key := trust.hmac_keys.get(key_id)) is None:
            raise PackError(f"signed with unknown hmac key {key_id!r}")
        expected = hmac.new(key, body(pack), hashlib.sha256).hexdigest().encode()
        if not hmac.compare_digest(expected, value.lower().encode("utf-8", "replace")):
            raise bad
        return f"hmac:{key_id}"
    if alg == "ed25519":
        if (key := trust.ed25519_keys.get(key_id)) is None:
            raise PackError(f"signed with unknown ed25519 key {key_id!r}")
        if (ed25519 := _ed25519()) is None:
            raise PackError("ed25519 signatures need the 'cryptography' package")
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(value, validate=True), body(pack))
        except Exception as exc:  # InvalidSignature, bad key or encoding
            raise bad from exc
        return f"ed25519:{key_id}"
    raise PackError(f"unknown signature algorithm {alg!r}")


def verify(pack: dict[str, Any], trust: Trust) -> str | None:
    """How ``pack`` was verified (``pin``, ``hmac:<key id>``, ``ed25519:<key id>``), None for an
    unsigned pack the operator allowed; raises PackError otherwise. A signature that does not verify
    (an unknown key included) is refused even under ``allow_unverified``, unless the digest is pinned."""
    pinned = digest(pack) in trust.pins
    if pack.get("signature") is not None:
        try:
            return _signed_by(pack["signature"], pack, trust)
        except PackError:
            if not pinned:
                raise
    if pinned:
        return "pin"
    if trust.allow_unverified:
        return None
    raise PackError(f"unverified pack ({digest(pack)}): pin its digest or sign it with a key the operator holds")


@dataclass
class LoadedPack:
    name: str
    version: int
    digest: str
    verified_by: str | None
    rules: list[tuple[str, str, str, re.Pattern[str]]]     # id, target, level, pattern
    exact: dict[str, tuple[str, str]]                       # value -> (id, level)
    domains: dict[str, tuple[str, str]]
    fingerprints: list[tuple[str, frozenset[int], str]]     # id, shingles, level
    rejected: list[dict[str, Any]]
    meta: dict[str, Any]

    @property
    def trusted(self) -> bool:
        return self.verified_by is not None

    def summary(self) -> dict[str, Any]:
        return {"name": self.name, "version": self.version, "digest": self.digest, "verified_by": self.verified_by,
                "trusted": self.trusted, "rules": len(self.rules), "indicators": len(self.exact) + len(self.domains),
                "fingerprints": len(self.fingerprints), "rejected": self.rejected, **self.meta}


def _collapsed(text: str) -> str:
    return " ".join(readable(text[:MAX_TEXT]).split())


def compile_pack(pack: Any, verified_by: str | None) -> LoadedPack:
    """Gate every entry of a (verified) pack; the rejected ones are listed with their reason."""
    if not isinstance(pack, dict) or pack.get("format") != FORMAT:
        raise PackError(f"not a threat pack: 'format' must be {FORMAT!r}")
    name, version = pack.get("name"), pack.get("version")
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise PackError("a pack needs a 'name' of letters, digits, '.', '_' or '-'")
    if not isinstance(version, int) or isinstance(version, bool) or version < 0:
        raise PackError("a pack needs a non-negative integer 'version'")
    entries = {key: pack.get(key, []) for key in ("rules", "indicators", "fingerprints", "benign")}
    if not all(isinstance(value, list) for value in entries.values()):
        raise PackError("rules, indicators, fingerprints and benign must be lists")
    trusted = verified_by is not None
    rejected = [{"field": key, "reason": "unknown field ignored: a pack can only add rules, indicators, "
                                          "fingerprints and benign texts, never relax protection"}
                for key in sorted(set(pack) - _KNOWN)]
    benign = [t[:5000] for t in entries["benign"][:MAX_BENIGN] if isinstance(t, str) and t.strip()]
    gate_texts = [_collapsed(t) for t in (*benign_corpus(), *benign)]
    gate_prints = benign_shingles() + tuple(text_shingles(t) for t in benign)

    def level_of(entry: dict[str, Any], default: str) -> str:
        level = entry.get("level", default)
        return level if trusted and level in LEVELS else "review"

    rules, seen = [], set()
    for entry in entries["rules"][:MAX_RULES]:
        entry = entry if isinstance(entry, dict) else {}
        rule_id, pattern, target = entry.get("id"), entry.get("pattern"), entry.get("target", "output")
        reason = ("needs an 'id' of letters, digits, '.', '_' or '-'" if not isinstance(rule_id, str)
                  or not _NAME.fullmatch(rule_id) else "duplicate id" if rule_id in seen
                  else f"unknown target {target!r}" if target not in TARGETS
                  else f"unknown level {entry.get('level')!r}" if entry.get("level", "review") not in LEVELS
                  else safety_problem(pattern))
        if isinstance(rule_id, str):
            seen.add(rule_id)
        if not reason:
            compiled = re.compile(pattern, re.IGNORECASE)
            examples = [e for e in entry.get("examples", []) if isinstance(e, str)] \
                if isinstance(entry.get("examples"), list) else []
            hits = [text[:120] for text in gate_texts if compiled.search(text)]
            if any(not compiled.search(_collapsed(e)) for e in examples):
                reason = "does not match its own example"
            elif hits:
                reason = f"matches {len(hits)} benign gate texts, e.g. {hits[0]!r}"
        if reason:
            rejected.append({"rule": str(rule_id)[:64], "reason": reason})
            continue
        rules.append((rule_id, target, level_of(entry, "review"), compiled))

    exact: dict[str, tuple[str, str]] = {}
    domains: dict[str, tuple[str, str]] = {}
    for entry in entries["indicators"][:MAX_INDICATORS]:
        entry = {"value": entry} if isinstance(entry, str) else entry if isinstance(entry, dict) else {}
        value = canonical(entry.get("value"))
        kind = entry.get("kind") or ("domain" if is_domain(value) else "exact")
        reason = ("not a value" if not value or " " in value or kind not in ("exact", "domain")
                  else "domain indicators need a host name" if kind == "domain" and not is_domain(value)
                  else "protected shared domain" if kind == "domain" and under(value, PROTECTED) else None)
        if reason:
            rejected.append({"indicator": str(entry.get("value"))[:200], "reason": reason})
            continue
        value = value.removeprefix("www.") if kind == "domain" else value
        (domains if kind == "domain" else exact)[value] = (str(entry.get("id") or value)[:64], level_of(entry, "block"))

    prints = []
    for i, entry in enumerate(entries["fingerprints"][:MAX_FINGERPRINTS]):
        entry = {"text": entry} if isinstance(entry, str) else entry if isinstance(entry, dict) else {}
        fid, text = str(entry.get("id") or f"fingerprint-{i}")[:64], entry.get("text")
        words = tokens(readable(text[:MAX_TEXT]))[:MAX_WORDS] if isinstance(text, str) else []
        result = gate(words, gate_prints)
        if not result["ok"]:
            rejected.append({"fingerprint": fid, "reason": result["reason"]})
            continue
        prints.append((fid, shingles(words), level_of(entry, "review")))
    meta = {k: pack[k] for k in ("description", "created", "provenance") if k in pack}
    return LoadedPack(name, version, digest(pack), verified_by, rules, exact, domains, prints, rejected, meta)


def read_pack(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    if path.stat().st_size > MAX_PACK_BYTES:
        raise PackError(f"pack is larger than {MAX_PACK_BYTES} bytes")
    pack = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(pack, dict):
        raise PackError("a pack is a JSON object")
    return pack


def load(pack: dict[str, Any], trust: Trust) -> LoadedPack:
    return compile_pack(pack, verify(pack, trust))


def _write_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


class PackSet:
    """The packs of one directory, as one detector; reloads changed files at most every ``interval`` s."""

    def __init__(self, directory: str | Path, trust: Trust | None = None, *, interval: float = 5.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.directory, self.trust = Path(directory).expanduser(), trust if trust is not None else Trust.from_env()
        self.interval, self.clock = interval, clock
        self.packs: dict[str, LoadedPack] = {}
        self.errors: dict[str, str] = {}
        self._files: dict[Path, tuple[int, int]] = {}
        self._lock = threading.Lock()
        self._checked = -math.inf
        # Last good copies first, so a file replaced while no process ran cannot roll a pack back.
        for path in sorted((self.directory / ".good").glob("*.json")):
            self._consider(path, quiet=True)
        self._merge()
        self.refresh(force=True)

    def refresh(self, force: bool = False) -> bool:
        """Reload changed pack files; True when what is loaded changed."""
        now = self.clock()
        if not force and now - self._checked < self.interval:
            return False
        with self._lock:
            self._checked, changed = now, False
            try:
                paths = sorted(self.directory.glob("*.json"))
            except OSError:
                paths = []
            for path in paths:
                try:
                    stat = path.stat()
                except OSError:
                    continue
                if self._files.get(path) != (stat.st_mtime_ns, stat.st_size):
                    self._files[path] = (stat.st_mtime_ns, stat.st_size)
                    changed |= self._consider(path)
            if changed:
                self._merge()
            return changed

    def _consider(self, path: Path, quiet: bool = False) -> bool:
        try:
            raw = read_pack(path)
            pack = load(raw, self.trust)
        except Exception as exc:  # also RecursionError from deep JSON: one bad file never stops the others
            if not quiet:
                self.errors[path.name] = f"{type(exc).__name__}: {exc}; the last good version stays loaded"
            return False
        current = self.packs.get(pack.name)
        if current and current.digest == pack.digest:
            self.errors.pop(path.name, None)
            return False
        if current and current.trusted and not pack.trusted:
            if not quiet:
                self.errors[path.name] = f"an unverified pack cannot replace verified {pack.name}; refused"
            return False
        if current and pack.version <= current.version:
            if not quiet:
                self.errors[path.name] = (f"version {pack.version} does not move past loaded version "
                                          f"{current.version} of {pack.name}; refused")
            return False
        self.packs[pack.name] = pack
        self.errors.pop(path.name, None)
        if not quiet and pack.trusted:
            try:
                _write_atomic(self.directory / ".good" / f"{pack.name}.json", raw)
            except OSError:
                pass  # a read-only directory only costs the restart fallback
        return True

    def _merge(self) -> None:
        rules: list[tuple[str, str, str, str, re.Pattern[str]]] = []
        exact: dict[str, tuple[str, str, str]] = {}
        domains: dict[str, tuple[str, str, str]] = {}
        prints: dict[str, tuple[str, frozenset[int], str]] = {}
        index: dict[int, list[str]] = {}
        rank = {"review": 0, "block": 1}
        for pack in sorted(self.packs.values(), key=lambda p: p.name):
            rules += [(pack.name, *rule) for rule in pack.rules]
            for target, source in ((exact, pack.exact), (domains, pack.domains)):
                for value, (item, level) in source.items():
                    if value not in target or rank[level] > rank[target[value][2]]:
                        target[value] = (pack.name, item, level)
            for fid, own, level in pack.fingerprints:
                key = f"{pack.name}/{fid}"
                prints[key] = (pack.name, own, level)
                for item in own:
                    index.setdefault(item, []).append(key)
        self._rules, self._exact, self._domains, self._prints, self._index = rules, exact, domains, prints, index

    def check_values(self, values: set[str], trusted_domains: set[str] = frozenset()) -> list[ThreatMatch]:
        """Pack indicators among ``values`` (canonical, already without user-typed and allowlisted ones)."""
        self.refresh()
        matches = []
        for value in values:
            found = [(self._exact.get(value), "exact", value)]
            host = domain_of(value)
            if host and not under(host, trusted_domains):
                parts = host.split(".")
                found += [(self._domains.get(d), "domain", d) for d in (".".join(parts[i:]) for i in range(len(parts) - 1))]
            for entry, kind, indicator in found:
                if entry:
                    pack, item, level = entry
                    matches.append(ThreatMatch(item, indicator, value, kind, "pack", f"pack:{pack}", level))
        return matches

    def check_text(self, norm: str, prints: frozenset[int], target: str = "output",
                   containment: float = 0.6) -> list[dict[str, Any]]:
        """Pack rules and fingerprints that already ``readable`` text matches."""
        self.refresh()
        collapsed = " ".join(norm.split())[:MAX_TEXT]  # as learned rules: matching time stays bounded
        found = [{"name": f"pack:{rule_id}", "pack": pack, "level": level}
                 for pack, rule_id, rule_target, level, pattern in self._rules
                 if rule_target == target and pattern.search(collapsed)]
        if target != "argument" and self._prints:
            for key, n in Counter(key for item in prints for key in self._index.get(item, ())).items():
                pack, own, level = self._prints[key]
                if n / len(own) >= containment:
                    found.append({"name": f"pack:{key.partition('/')[2]}", "pack": pack, "level": level,
                                  "containment": round(n / len(own), 3)})
        return found

    def status(self) -> dict[str, Any]:
        return {"directory": str(self.directory), "packs": [p.summary() for p in self.packs.values()],
                "errors": dict(self.errors)}


def installed(directory: Path, name: str, trust: Trust) -> LoadedPack | None:
    """The newest verified copy of pack ``name`` in ``directory`` (its file or its last good copy)."""
    best = None
    for path in (directory / f"{name}.json", directory / ".good" / f"{name}.json"):
        try:
            pack = load(read_pack(path), trust)
        except Exception:
            continue
        if best is None or pack.version > best.version:
            best = pack
    return best


def install(source: str | Path | dict[str, Any], directory: str | Path, trust: Trust) -> dict[str, Any]:
    """Verify and gate a pack, then place it in ``directory`` where running processes pick it up."""
    raw = source if isinstance(source, dict) else read_pack(source)
    pack = load(raw, trust)
    directory = Path(directory).expanduser()
    current = installed(directory, pack.name, trust)
    if current is not None and pack.version <= current.version and pack.digest != current.digest:
        raise PackError(f"version {pack.version} does not move past installed version {current.version}")
    good = directory / ".good" / f"{pack.name}.json"
    # A good copy is a pack some process verified, maybe with keys or pins this command lacks.
    if not pack.trusted and (good.exists() or installed(directory, pack.name, replace(trust, allow_unverified=False))):
        raise PackError(f"an unverified pack cannot replace the verified pack {pack.name}; 'pack remove' it first")
    _write_atomic(directory / f"{pack.name}.json", raw)
    if pack.trusted:  # the restart fallback holds verified packs only
        _write_atomic(good, raw)
    return {"installed": str(directory / f"{pack.name}.json"), **pack.summary()}


def _https_only() -> Any:
    import urllib.request  # only ``pack update`` downloads; a hook process should not pay for it

    class HttpsOnly(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
            if urlsplit(newurl).scheme != "https":
                raise PackError(f"refused a redirect away from HTTPS: {newurl}")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    return urllib.request, HttpsOnly


def fetch(url: str, max_bytes: int = MAX_PACK_BYTES, timeout: float = 20) -> dict[str, Any]:
    """Download a pack (HTTPS only, at most ``max_bytes``) as parsed JSON; nothing is executed."""
    if urlsplit(url).scheme != "https":
        raise PackError("pack updates are fetched over HTTPS only")
    urllib_request, https_only = _https_only()
    opener = urllib_request.build_opener(https_only)
    request = urllib_request.Request(url, headers={"Accept": "application/json", "User-Agent": "intentshield-threats"})
    with opener.open(request, timeout=timeout) as response:
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise PackError(f"pack is larger than {max_bytes} bytes")
    pack = json.loads(data.decode("utf-8"))
    if not isinstance(pack, dict):
        raise PackError("a pack is a JSON object")
    return pack


def sign(pack: dict[str, Any], key: bytes, key_id: str = "default", alg: str = "hmac-sha256") -> dict[str, Any]:
    """``pack`` with a signature: HMAC-SHA256 with a shared secret, or Ed25519 with a raw 32-byte private key."""
    if alg == "hmac-sha256":
        value = hmac.new(key, body(pack), hashlib.sha256).hexdigest()
    elif alg == "ed25519":
        if (ed25519 := _ed25519()) is None:
            raise PackError("ed25519 signatures need the 'cryptography' package")
        value = base64.b64encode(ed25519.Ed25519PrivateKey.from_private_bytes(key).sign(body(pack))).decode()
    else:
        raise PackError(f"unknown signature algorithm {alg!r}")
    return {**{k: v for k, v in pack.items() if k != "signature"},
            "signature": {"alg": alg, "key_id": key_id, "value": value}}


def export_pack(memory: ThreatMemory, name: str = "local-export", version: int | None = None) -> dict[str, Any]:
    """The memory's operator-confirmed and imported entries as an unsigned pack, to sign and share.
    Learned (``observed``) entries stay local: they were taught by attacker-controlled text."""
    items = memory.items()
    indicators = [{"value": r["value"], "kind": r["kind"], "level": "block", "origin": r["origin"],
                   "first_seen": r["first_seen"]} for r in items["indicators"] if r["status"] == "confirmed"]
    prints = [{"id": r["id"], "text": r["excerpt"], "level": "review"} for r in items["fingerprints"]
              if r["status"] == "confirmed"]
    return {"format": FORMAT, "name": name, "version": int(time.time()) if version is None else version,
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "description": "Operator-confirmed threat memory entries", "rules": [],
            "indicators": indicators, "fingerprints": prints, "benign": []}


def add_commands(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dir", help="pack directory (default: $INTENTSHIELD_THREAT_PACKS or threat-packs/ next to --db)")
    parser.add_argument("--hmac-key-file", help="file holding the operator's HMAC secret")
    parser.add_argument("--key-id", default="default")
    parser.add_argument("--public-key", action="append", default=[], help="ed25519 public key as [id:]hex")
    parser.add_argument("--pin", action="append", default=[], help="accepted pack digest, sha256:<hex>")
    parser.add_argument("--allow-unverified", action="store_true", help="load unverified packs as review-only")
    commands = parser.add_subparsers(dest="pack_command", required=True)
    for name in ("verify", "install"):
        commands.add_parser(name).add_argument("file")
    update = commands.add_parser("update")
    update.add_argument("--url", required=True)
    update.add_argument("--max-bytes", type=int, default=MAX_PACK_BYTES)
    export = commands.add_parser("export")
    export.add_argument("--name", default="local-export")
    export.add_argument("--version", type=int)
    signer = commands.add_parser("sign")
    signer.add_argument("file")
    signer.add_argument("--key-file", required=True, help="HMAC secret, or a hex raw ed25519 private key")
    signer.add_argument("--alg", choices=("hmac-sha256", "ed25519"), default="hmac-sha256")
    signer.add_argument("--out")
    commands.add_parser("list")
    commands.add_parser("remove").add_argument("name")


def run_command(args: argparse.Namespace) -> dict[str, Any]:
    keys = {args.key_id: Path(args.hmac_key_file).expanduser().read_bytes().strip()} if args.hmac_key_file else {}
    public = {}
    for item in args.public_key:
        key_id, _, value = item.rpartition(":")
        public[key_id or "default"] = bytes.fromhex(value)
    trust = Trust.from_env(hmac_keys=keys, ed25519_keys=public, pins=args.pin, allow_unverified=args.allow_unverified)
    directory = Path(args.dir or os.getenv("INTENTSHIELD_THREAT_PACKS") or Path(args.db).parent / "threat-packs")
    command = args.pack_command
    if command == "verify":
        return {"ok": True, **load(read_pack(args.file), trust).summary()}
    if command == "install":
        return install(args.file, directory, trust)
    if command == "update":
        return install(fetch(args.url, args.max_bytes), directory, trust)
    if command == "export":
        return export_pack(ThreatMemory(args.db), args.name, args.version)
    if command == "sign":
        key = Path(args.key_file).expanduser().read_bytes().strip()
        signed = sign(read_pack(args.file), bytes.fromhex(key.decode()) if args.alg == "ed25519" else key,
                      args.key_id, args.alg)
        if args.out:
            _write_atomic(Path(args.out), signed)
        return {"digest": digest(signed), "signature": signed["signature"], "out": args.out} if args.out else signed
    if command == "list":
        return PackSet(directory, trust).status()
    if not _NAME.fullmatch(args.name):
        raise PackError("not a pack name")
    removed = [str(p) for p in (directory / f"{args.name}.json", directory / ".good" / f"{args.name}.json") if p.exists()]
    for path in removed:
        Path(path).unlink()
    return {"removed": removed}
