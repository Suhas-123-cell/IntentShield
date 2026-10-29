"""Credentials in MCP traffic and configs: provider token formats, private keys and signed tokens.

Each pattern is a provider's published prefix and length, so a match is a credential, not a guess about
a random-looking id; ids without a known prefix are left to the provenance checks. A credential found is
only ever shown masked (its kind and first four characters).
"""
from __future__ import annotations

import re
from typing import Any

from .mcp_inspect import leaf_text

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{20,}")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    # "sk-" alone is common ("sk-learn-compatible"): a key is long and has a capital and a digit.
    ("openai_key", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Z])"
                              r"[A-Za-z0-9_\-]{32,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])")),
    ("groq_key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}")),
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
)


def find(value: Any) -> dict[str, str]:
    """Every credential in the strings of ``value`` (a string or a structure), as {credential: kind}."""
    text = leaf_text(value)
    return {m[0]: kind for kind, pattern in _PATTERNS for m in pattern.finditer(text)}


def masked(credential: str, kind: str) -> str:
    return f"{kind} {credential[:4]}…"


def mask(text: str) -> str:
    """``text`` with every credential in it replaced by its masked form."""
    for credential, kind in sorted(find(text).items(), key=lambda item: -len(item[0])):
        text = text.replace(credential, f"[{masked(credential, kind)}]")
    return text
