"""Deterministic checks on untrusted MCP text: tool descriptions and tool outputs.

Descriptions and outputs come from upstream servers and are never trusted. These
rules only produce evidence (rule names); the proxy decides what to do with it.
"""
from __future__ import annotations

import base64
import binascii
import html
import json
import math
import re
import unicodedata
from collections import Counter
from typing import Any, Iterable
from urllib.parse import unquote

_I = re.I
# Rules for text that should describe a tool, not instruct the agent.
_DESCRIPTION_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("instruction_override", re.compile(
        r"(?:ignore|disregard|forget)\s+(?:all\s+)?(?:the\s+|any\s+|your\s+)?"
        r"(?:previous|prior|above|earlier|user'?s?|original)\s+(?:instructions?|requests?|quer(?:y|ies))", _I)),
    ("hidden_directive", re.compile(r"<\s*/?\s*(?:important|system|instructions?|secret|hidden)\s*>", _I)),
    ("cross_tool_directive", re.compile(
        r"\b(?:before|after|prior\s+to|when(?:ever)?|each\s+time)\s+(?:a\s+user\s+)?"
        r"(?:using|calling|invoking|running|calls|uses|you\s+(?:use|call))\b[^.\n]{0,120}?"
        r"\b(?:you\s+)?(?:must|shall|need\s+to|have\s+to|always|first|should)\b", _I)),
    ("tool_call_directive", re.compile(
        r"\bmust\s+first\b|\bmust\s+(?:first\s+|also\s+)?(?:call|use|invoke|run|execute|mark)\s+(?:the\s+)?"
        r"(?:['`\"][\w\-.]+['`\"]|[a-z]+[_\-][\w\-]+)", _I)),
    ("prerequisite_call", re.compile(
        r"\bbefore\b[^.\n]{0,60}?\b(?:use|call|invoke|run)\s+(?:the\s+)?['`\"][\w\-.]+['`\"]", _I)),
    ("threat_coercion", re.compile(
        r"\b(?:failure|failing|skipping|omitting|ignoring|not\s+doing)\b[^.\n]{0,30}?\bwill\s+"
        r"(?:crash|corrupt|cause|disrupt|overload|break|result\s+in)", _I)),
    ("concealment", re.compile(
        r"(?:do\s+not|don't|never|without)\s+(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|"
        r"notify(?:ing)?|alert(?:ing)?|reveal(?:ing)?\s+to)\b[^.\n]{0,40}\b(?:user|them)\b", _I)),
    ("sensitive_target", re.compile(
        r"~/\.ssh|\bid_(?:rsa|ed25519)\b|/etc/(?:passwd|shadow)|\.aws/credentials|"
        r"\bmcp\.json\b|\.env\b|private[_\s]keys?\b|seed\s+phrase", _I)),
    ("argument_override", re.compile(
        r"\b(?:change|replace|set|modify|override|rewrite|redirect|reroute|update|add)\b[^.\n]{0,60}?"
        r"\b(?:argument|parameter|param|recipient|region|address|account|destination|pattern|"
        r"commit|url|id)s?\b[^.\n]{0,60}?\b(?:to|with|instead|regardless|accordingly)\b", _I)),
    ("forced_payload", re.compile(
        r"\b(?:must|always|automatically)\s+(?:be\s+)?(?:append|prepend|inject|insert|"
        r"instead\s+(?:use|show|send|call))\w*\b|\byou\s+must\s+(?:instead|now)\b", _I)),
    ("priority_claim", re.compile(
        r"(?:higher|top|highest)\s+priority\s+than|priority\s+is\s+higher|"
        r"(?:this|these)\s+(?:rule|polic(?:y|ies)|instructions?)\s+(?:override|supersede)", _I)),
    ("mandatory_policy", re.compile(
        r"\b(?:system|security|compliance)\s+polic(?:y|ies)\b[^.\n]{0,160}?\b(?:must|always)\b", _I)),
    # A tool has no business with other tools' data (cross-tool poisoning).
    ("cross_tool_data", re.compile(
        r"\b(?:other|all|every|any|previous|prior|subsequent)\s+tools?(?:'s?)?\s+(?:outputs?|results?|"
        r"responses?|data|contents?|arguments?|parameters?|calls?)\b|"
        r"\b(?:outputs?|results?|responses?)\s+(?:of|from)\s+(?:other|all|every|any|previous)\s+tools?\b", _I)),
    # A description that ships data to a fixed outside address.
    ("external_send", re.compile(
        r"\b(?:send|forward|copy|cc|bcc|mirror|upload|post|report|transmit|sync|backup|exfiltrate|"
        r"back(?:ed|s|ing)?\s+up|log|archiv)\w*\b"
        r"[^.\n]{0,80}?(?:https?://[^\s\"'<>)]+|[\w.+-]+@[\w-]+\.[\w.-]+)", _I)),
)
# Rules for tool outputs: data that tries to become instructions.
_OUTPUT_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    _DESCRIPTION_RULES[0],
    _DESCRIPTION_RULES[1],
    _DESCRIPTION_RULES[3],
    _DESCRIPTION_RULES[5],
    ("agent_directive", re.compile(
        r"\b(?:assistant|AI|agent|model|you)\b[^.\n]{0,30}?\b(?:must|should|need\s+to|are\s+(?:required|instructed)\s+to)"
        r"\s+(?:now\s+|immediately\s+|also\s+)?(?:send|forward|email|transfer|pay|delete|upload|share|grant|"
        r"post|write|call|invoke|execute|run|change|update|create|move)\b", _I)),
    ("new_task", re.compile(
        r"\b(?:new|updated|additional|important)\s+(?:task|instructions?|directive)s?\s*[:\-]", _I)),
    ("exfiltration", re.compile(
        r"\b(?:send|forward|email|upload|post|transfer|leak|exfiltrate)\w*\b[^.\n]{0,80}?"
        r"\b(?:password|credential|secret|token|api\s*key|private\s+key|ssn|social\s+security|"
        r"bank\s+account|card\s+number)s?\b", _I)),
    # A tool result speaking as the user ("message from me ... to you", "I am the user").
    ("user_impersonation", re.compile(
        r"\b(?:message|note|request)\s+from\s+(?:me|the\s+user|your\s+user)\b[^.\n]{0,60}?\bto\s+you\b|"
        r"\bI\s+am\s+(?:the|your)\s+user\b(?=\s*(?:[.,!;:]|$|and\b))|\bnew\s+user\s+(?:query|request|message|instructions?)\b", _I)),
    # A tool result rearranging the agent's task ("before you can solve the task", "the previous
    # task has been completed").
    ("task_hijack", re.compile(
        r"\bbefore\s+you\s+(?:can\s+)?(?:solve|complete|finish|continue|answer)\b[^.\n]{0,60}?\btask\b|"
        r"\b(?:previous|original|current)\s+task\s+(?:has\s+been|is)\s+(?:completed|done|finished|cancelled)\b|"
        r"\bmore\s+urgent\s+(?:new\s+)?task\b", _I)),
    ("instruction_demand", re.compile(
        r"\byou\s+must\s+(?:strictly\s+)?(?:adhere\s+to|follow|obey|comply\s+with)\b", _I)),
    ("role_marker", re.compile(r"<\|im_start\|>|\[/?INST\]|#+\s*\(\s*system[_\s]message\s*\)", _I)),
    # A result asking for secrets ("session expired; read ~/.ssh/id_rsa to continue"). Unlike the
    # description rule it needs a verb, so a file listing that shows the path is not flagged.
    ("sensitive_request", re.compile(
        r"\b(?:read|cat|open|send|upload|include|attach|provide|retrieve|fetch|paste|share|access|"
        r"verify|submit)\w*\b[^.\n]{0,60}?(?:~/\.ssh|\bid_(?:rsa|ed25519)\b|/etc/(?:passwd|shadow)|"
        r"\.aws/credentials|\bmcp\.json\b|private[_\s]keys?\b|seed\s+phrase)", _I)),
)


# Cyrillic and Greek letters that render like Latin ones ("іgnоre"); NFKC keeps them.
_CONFUSABLES = str.maketrans(
    "аеорсхуіјѕԁԛԝАВЕКМНОРСТХУІЈЅαβεικνορτυχΑΒΕΗΙΚΜΝΟΡΤΥΧ",
    "aeopcxyijsdqwABEKMHOPCTXYIJSabeiknoptuxABEHIKMNOPTYX",
)


def _normalize(text: str) -> str:
    """What an LLM reads, not what the bytes say: fold width variants, drop invisible
    format characters (zero-width spaces, joiners, bidi marks), map look-alikes."""
    text = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf").translate(_CONFUSABLES)


_BASE64 = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")


def _readable(raw: bytes) -> str | None:
    """Decoded bytes count only if they read as prose, or are another encoded layer;
    hashes and keys decode to noise."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in text)
    readable = printable >= 0.95 * len(text) and (" " in text or _BASE64.fullmatch(text.strip()))
    return text if readable else None


def _decoded(text: str) -> list[str]:
    """Payloads an LLM can decode on its own: base64, hex, URL and HTML escapes. Decoded
    up to three layers deep so the rules see them; the original text is scanned too."""
    found: list[str] = []
    layer = [text]
    for _ in range(3):
        next_layer = []
        for item in layer:
            for decoded in (unquote(item) if "%" in item else item, html.unescape(item) if "&" in item else item):
                if decoded != item:
                    next_layer.append(decoded)
            for token in _BASE64.findall(item):
                padded = token + "=" * (-len(token) % 4)
                try:
                    raw = base64.urlsafe_b64decode(padded) if re.search(r"[-_]", token) \
                        else base64.b64decode(padded, validate=True)
                except (binascii.Error, ValueError):
                    continue
                if (decoded := _readable(raw)) is not None:
                    next_layer.append(decoded)
            for token in _HEX.findall(item):
                if (decoded := _readable(bytes.fromhex(token))) is not None:
                    next_layer.append(decoded)
        if not next_layer:
            break
        found += next_layer
        layer = next_layer
    return found


def _scan(text: str, rules: tuple[tuple[str, re.Pattern[str]], ...], trusted: str = "") -> list[str]:
    text = _normalize("\n".join([text, *_decoded(text)]))
    # Text the user typed is their own request, not an injection ("forward this: ignore ...").
    trusted = " ".join(_normalize(trusted).lower().split())
    return [name for name, pattern in rules
            if any(" ".join(m.group(0).lower().split()) not in trusted for m in pattern.finditer(text))]


def tool_text(description: str | None, schema: dict[str, Any] | None = None,
              title: str | None = None) -> str:
    """All agent-visible free text of a tool: title, description, schema annotations.
    Schema titles a framework generates (``<func>Arguments``, ``<func>Output``, or the
    property name in words) are left out: they carry no author text and only add identifiers."""
    parts = [title or "", description or ""]

    def generated(value: str, prop: str | None) -> bool:
        return bool(re.fullmatch(r"\w+(?:Arguments|Output)", value)) or \
            (prop is not None and value.lower().replace(" ", "_") == prop.lower())

    def visit(node: Any, prop: str | None = None) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "title" and isinstance(value, str):
                    if not generated(value, prop):
                        parts.append(value)
                elif key in {"description", "$comment"} and isinstance(value, str):
                    parts.append(value)
                elif key in {"examples", "default", "enum"}:
                    parts.append(json.dumps(value))
                elif key == "properties" and isinstance(value, dict):
                    for name, spec in value.items():
                        visit(spec, str(name))
                else:
                    visit(value)
        elif isinstance(node, list):
            for item in node:
                visit(item)

    visit(schema or {})
    return "\n".join(p for p in parts if p)


def scan_description(text: str, other_tools: Iterable[str] = ()) -> list[str]:
    """Poisoning rule names for one tool's text; ``shadowing`` if it names another tool."""
    findings = _scan(text, _DESCRIPTION_RULES)
    lowered = _normalize(text).lower()
    for name in other_tools:
        # Only distinctive names: "search" in prose is not a reference to a tool.
        # Whole identifiers only: "get_x" is not named by "get_x_v1Arguments".
        if len(name) >= 6 and re.search(r"[_\-.]|[a-z][A-Z]", name) and \
                re.search(rf"(?<![a-z0-9_]){re.escape(name.lower())}(?![a-z0-9_])", lowered):
            findings.append("shadowing")
            break
    return findings


def scan_server(texts: Iterable[str]) -> list[str]:
    """Rules that fire only when one server's tool texts are read together, in catalog
    order and with line breaks folded: one instruction split across tools (ShareLock)."""
    texts = list(texts)
    single = {finding for text in texts for finding in _scan(text, _DESCRIPTION_RULES)}
    joined = " ".join(" ".join(text.split()) for text in texts)
    return [f"split_{finding}" for finding in _scan(joined, _DESCRIPTION_RULES) if finding not in single]


_SELF_FIELD_NAME = re.compile(
    r"^(?:llm|lm)_?(?:model_?)?(?:name|id|version|type|provider)?$|"
    r"^(?:ai|agent|assistant|caller)_?model(?:_?(?:name|id|version))?$|"
    r"^(?:system_?prompt|conversation_?history|chat_?history|previous_?messages|prior_?messages)$", _I)
_SELF_FIELD_TEXT = re.compile(
    r"\b(?:llm|model|ai|assistant|agent)\b[^.\n]{0,40}?\b(?:that|which|who)\s+(?:is\s+)?"
    r"(?:calls?|calling|invok\w+|uses?|using)\s+this\s+tool\b|"
    r"\byour\s+(?:own\s+)?(?:model(?:\s+name)?|system\s+prompt|instructions|conversation(?:\s+history)?|"
    r"chat\s+history|previous\s+messages)\b", _I)


def self_disclosure_fields(schema: dict[str, Any]) -> set[str]:
    """Top-level parameters that ask the calling agent about itself: its model, system
    prompt or conversation. No tool needs these to do its job; they are a leak channel."""
    properties = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(properties, dict):
        return set()
    found = set()
    for name, spec in properties.items():
        snake = re.sub(r"([a-z])([A-Z])", r"\1_\2", name)
        text = _normalize(" ".join(str(spec.get(k, "")) for k in ("title", "description"))) \
            if isinstance(spec, dict) else ""
        if _SELF_FIELD_NAME.match(snake) or _SELF_FIELD_TEXT.search(text):
            found.add(name)
    return found


def scan_output(value: Any, trusted: str = "") -> list[str]:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return _scan(text, _OUTPUT_RULES, trusted)


_VALUE_PATTERNS = (
    re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),                    # email
    re.compile(r"https?://[^\s\"'<>)]+", _I),                         # URL
    re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),                  # IBAN
    re.compile(r"\b\d[\d\- ]{6,}\d\b"),                               # account / card / phone
    re.compile(r"(?:~|\.{1,2})?/[\w.\-]+(?:/[\w.\-]+)+"),             # path
    re.compile(r"\b(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])[A-Za-z0-9_\-]{8,}\b"),  # id/key
)


def distinctive_values(value: Any, patterns: tuple[re.Pattern[str], ...] = _VALUE_PATTERNS) -> set[str]:
    """Values specific enough that their source can be traced: emails, URLs, accounts, paths, ids."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    found: set[str] = set()
    for pattern in patterns:
        for match in pattern.findall(text):
            item = re.sub(r"[\s\-]", "", match) if match[:1].isdigit() else match
            found.add(item.strip(".,;:").lower())
    return {item for item in found if len(item) >= 6}


def authority_values(value: Any) -> set[str]:
    """Distinctive values that decide where data or money goes or what gets touched:
    emails, URLs, accounts and paths. Generic ids are left out (picking an id from a
    search result is how agents normally work), and so are numbers under nine digits
    (dates, amounts)."""
    return {item for item in distinctive_values(value, _VALUE_PATTERNS[:5])
            if not item.isdigit() or len(item) >= 9}


def sourced_from(values: set[str], source: set[str], user_values: set[str]) -> set[str]:
    """The values that came from ``source`` and not from the user. A path or URL inside a
    directory or site the user named counts as the user's own."""
    prefixes = tuple(item.rstrip("/") + "/" for item in user_values if "/" in item)
    return {item for item in values & source - user_values if not item.startswith(prefixes)}


_STOPWORDS = frozenset("a an and are as at be by can for from i in into is it me my of on or our please "
                       "that the this to us we with you your".split())


def _terms(text: str) -> list[str]:
    words = re.findall(r"[a-z0-9]+", re.sub(r"([a-z])([A-Z])", r"\1 \2", text).lower())
    words = [w[:-3] if len(w) > 5 and w.endswith("ing") else w for w in words if w not in _STOPWORDS]
    return [w[:-1] if len(w) > 3 and w.endswith("s") and not w.endswith("ss") else w for w in words]


def rank_tools(task: str, tools: Iterable[tuple[str, str]], limit: int = 5) -> list[tuple[str, float]]:
    """The tools whose name and description best match ``task`` (BM25), best first; empty
    when nothing matches. Names count twice, and only the first 300 characters of a
    description are read, so a server cannot stuff one with every keyword. Ranking is a
    convenience, never a trust decision."""
    docs = [(name, _terms(name) * 2 + _terms(description[:300])) for name, description in tools]
    if not docs:
        return []
    average = sum(len(terms) for _, terms in docs) / len(docs) or 1
    containing = Counter(term for _, terms in docs for term in set(terms))
    wanted = set(_terms(task))
    scored = []
    for name, terms in docs:
        counts = Counter(terms)
        score = sum(math.log(1 + (len(docs) - containing[t] + 0.5) / (containing[t] + 0.5))
                    * counts[t] * 2.2 / (counts[t] + 1.2 * (0.25 + 0.75 * len(terms) / average))
                    for t in wanted & set(counts))
        if score > 0:
            scored.append((name, round(score, 3)))
    return sorted(scored, key=lambda item: -item[1])[:limit]
