"""Credentials in MCP traffic and configs: provider token formats, private keys and signed tokens.

Each pattern is a provider's published prefix and length, so a match is a credential, not a guess about
a random-looking id; ids without a known prefix are left to the provenance checks. A credential found is
only ever shown masked (its kind and first four characters).
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections.abc import Callable
from typing import Any

from .mcp_inspect import leaf_text

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}")),
    ("slack_token", re.compile(r"\bxox[abposre]-[A-Za-z0-9\-]{10,}|\bxapp-\d-[A-Za-z0-9]{8,}-\d{8,}-[A-Za-z0-9]{20,}")),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{20,}")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}|\bwhsec_[A-Za-z0-9]{24,}")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    # A legacy key is one unbroken run of mixed-case alphanumerics; a prefixed one may hold - and _ but
    # carries a capital and a digit. "sk-Learn-Compatible-..." (words) is rejected in _VALID.
    ("openai_key", re.compile(r"\bsk-(?!ant-)(?:(?:proj|svcacct|admin)-(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Z])"
                              r"[A-Za-z0-9_\-]{32,}|(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Z])(?=[A-Za-z0-9]*[a-z])"
                              r"[A-Za-z0-9]{32,})")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])")),
    ("google_oauth_token", re.compile(r"\bya29\.[A-Za-z0-9_\-]{20,}")),
    ("groq_key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}")),
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi_token", re.compile(r"\bpypi-AgE[A-Za-z0-9_\-]{50,}")),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{40,}")),
    ("twilio_key", re.compile(r"\bSK[0-9a-f]{32}\b")),
    ("digitalocean_token", re.compile(r"\bdo[por]_v1_[a-f0-9]{64}\b")),
    ("docker_token", re.compile(r"\bdckr_pat_[A-Za-z0-9_\-]{20,}")),
    ("shopify_token", re.compile(r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("age_key", re.compile(r"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    # The scheme is bounded where a word boundary lets a match start inside a run: unbounded, every start in a
    # long dotted or hyphenated run rescans the run. A longer scheme can only start at the first
    # letter after a word boundary in its run, which the second form tries once per run. The user may be empty
    # (redis://:password@host).
    ("url_credentials", re.compile(
        r"(?:\b[A-Za-z][A-Za-z0-9+.\-]{0,31}|(?<![A-Za-z0-9+.\-])(?:(?:[0-9][A-Za-z0-9]*)?[+.\-])*[A-Za-z][A-Za-z0-9+.\-]{32,})"
        r"://([^\s/:@]*):([^\s/@]+)@[^\s/?#]+")),
)


def _words(token: str) -> bool:
    """Three or more plain words joined by hyphens: a slug, not a key."""
    return sum(bool(re.fullmatch(r"[A-Za-z]{3,}", part)) for part in token.split("-")) >= 3


def _real_url_credentials(match: re.Match[str]) -> bool:
    user, password = match[1], match[2]
    if user.lower() == password.lower() or re.search(r"[${}<>%*\[\]]|\.\.\.", password):
        return False  # postgres:postgres, ${DB_PASSWORD}, <password>, ****
    return password.lower() not in {"pass", "password", "passwd", "pwd", "secret", "changeme", "xxx", "xxxx", "token"}


# Documented examples and slugs that carry a provider's prefix and length but are no credential.
_VALID: dict[str, Callable[[re.Match[str]], bool]] = {
    "aws_access_key": lambda m: not m[0].endswith("EXAMPLE"),
    "openai_key": lambda m: not _words(m[0][3:]),
    "url_credentials": _real_url_credentials,
}
_MASKED_RUN = re.compile(r"[xX*]{8,}")
_NO_PLACEHOLDER_CHECK = frozenset({"private_key", "url_credentials"})


def _surface(text: str) -> str:
    """``text`` as a model reads it: NFKC (full-width underscore, look-alike digits) with invisible
    format characters (zero-width spaces and joiners, bidi marks) and variation selectors dropped."""
    return "".join(ch for ch in unicodedata.normalize("NFKC", text)
                   if unicodedata.category(ch) != "Cf" and not "︀" <= ch <= "️")


# A run that may be a token in base64 (standard or URL-safe) or hex: long enough to hold the shortest prefixed one.
_ENCODED = re.compile(r"(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{24,}={0,2}")


def _decodings(text: str) -> list[tuple[str, str]]:
    """(token, decoded) for each base64 or hex run in ``text`` that decodes to printable ASCII."""
    found = []
    for token in _ENCODED.findall(text)[:500]:
        raws = []
        body = token.rstrip("=")
        if re.fullmatch(r"[0-9a-fA-F]+", body) and len(body) % 2 == 0:
            raws.append(bytes.fromhex(body))
        try:
            padded = body + "=" * (-len(body) % 4)
            raws.append(base64.urlsafe_b64decode(padded) if re.search(r"[-_]", body)
                        else base64.b64decode(padded, validate=True))
        except (binascii.Error, ValueError):
            pass
        for raw in raws:
            try:
                decoded = raw.decode("ascii")
            except UnicodeDecodeError:
                continue
            if decoded.isprintable() or decoded.replace("\n", "").isprintable():
                found.append((token, decoded))
    return found


# Formats without a fixed prefix of their own, which text run together would glue to a neighbouring word.
_UNPREFIXED = frozenset({"url_credentials", "private_key"})


def _match(surface: str, joined: bool = False) -> dict[str, str]:
    found: dict[str, str] = {}
    for kind, pattern in _PATTERNS:
        if joined and kind in _UNPREFIXED:
            continue
        for m in pattern.finditer(surface):
            if kind not in _NO_PLACEHOLDER_CHECK and _MASKED_RUN.search(m[0]):
                continue  # "ghp_xxxxxxxx...": a placeholder, whatever the prefix
            if (check := _VALID.get(kind)) is None or check(m):
                found[m[0]] = kind
    return found


def find(value: Any) -> dict[str, str]:
    """Every credential in the strings of ``value`` (a string or a structure), as {credential: kind}.
    The text is read as written, with Unicode tricks undone, reversed, with its fields and lines run
    together (a token split in two), and with each base64 or hex run decoded; a credential is returned
    as it reads once undone."""
    text = leaf_text(value)
    found: dict[str, str] = {}
    leaves = _strings(value)
    pairs = ["".join(leaves[i:i + 2]) for i in range(min(len(leaves) - 1, 200))]  # a token split over two fields
    plain = (text, _surface(text))
    for surface in dict.fromkeys((*plain, "".join(text.split()), *pairs)):
        found.update(_match(surface, joined=surface not in plain))
        for _, decoded in _decodings(surface):
            found.update(_match(decoded))
    found.update(_match(_surface(text)[::-1]))
    return found


def _strings(value: Any) -> list[str]:
    """The string values of a structure in order, without its keys."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for item in value.values() for s in _strings(item)]
    if isinstance(value, (list, tuple)):
        return [s for item in value for s in _strings(item)]
    return []


def masked(credential: str, kind: str) -> str:
    return f"{kind} {credential[:4]}…"


def _masked_text(text: str) -> str:
    for credential, kind in sorted(find(text).items(), key=lambda item: -len(item[0])):
        text = text.replace(credential, f"[{masked(credential, kind)}]")
        text = text.replace(credential[::-1], f"[{masked(credential, kind)}, reversed]")
    for token, decoded in _decodings(text):  # an encoded credential is cut out as it is written
        if (inside := _match(decoded)):
            credential, kind = next(iter(inside.items()))
            text = text.replace(token, f"[{masked(credential, kind)}, encoded]")
    return text


def mask(text: str) -> str:
    """``text`` with every credential in it replaced by its masked form."""
    out = _masked_text(text)
    plain = _surface(out)
    # A credential that shows only once normalized cannot be cut out of the original: return the
    # normalized text with it masked rather than leave it whole.
    again = _masked_text(plain)
    return out if again == plain else again
