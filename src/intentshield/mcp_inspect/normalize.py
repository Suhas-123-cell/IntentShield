"""A text as a reader sees it: tags, escapes, look-alike letters, encodings and spacing undone, so a rule reads the words."""
from __future__ import annotations

import base64
import binascii
import codecs
import functools
import html
import json
import re
import unicodedata
from typing import Any
from urllib.parse import unquote

from .rules import _CONFUSABLES, _I, _TAG_MARK, _Rule

# Default-ignorable code points outside category Cf, which a renderer shows as nothing: variation
# selectors, the combining grapheme joiner, Hangul fillers, Mongolian selectors, tags.
_IGNORABLE = re.compile("[\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180f\u3164\ufe00-\ufe0f\uffa0"
                        "\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff]")
_TAGS = re.compile("[\U000e0020-\U000e007e]+")


def _untag(match: re.Match[str]) -> str:
    """A run of Unicode tag characters is ASCII an LLM reads and a person does not see: written out, and
    marked when it is four characters or more."""
    return f" {''.join(chr(ord(ch) - 0xE0000) for ch in match[0])} " + (_TAG_MARK if len(match[0]) >= 4 else "")


# The dots of a host in a script that has its own ("evil。example", "evil｡example"; NFKC leaves U+3002) and the middle
# dot: read as "." where they stand between the parts of a Latin-script name, not in CJK text, where "。" ends a sentence.
_DOTS = re.compile(r"(?<=[A-Za-z0-9\-\u00c0-\u024f\u0370-\u03ff\u0400-\u04ff])\u3002(?=[A-Za-z0-9/:?#\s]|\Z)|"
                   r"(?<=[A-Za-z0-9])\u00b7(?=[A-Za-z0-9])")


def _normalize(text: str) -> str:
    """What an LLM reads, not what the bytes say: fold width variants, write out tag characters, drop invisible
    characters (zero-width spaces, joiners, bidi marks, variation selectors), map look-alikes.
    Only the rules read the result; the agent and the tool see the original."""
    if text.isascii():  # most tool text: nothing to fold, drop or map
        return text
    text = _IGNORABLE.sub("", _TAGS.sub(_untag, unicodedata.normalize("NFKC", text)))
    return _DOTS.sub(".", "".join(ch for ch in text if unicodedata.category(ch) != "Cf").translate(_CONFUSABLES))


_BASE64 = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
_SPACED_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}[ :,\-]){7,}[0-9a-fA-F]{2}\b")  # "69 67 6e 6f 72 65", "69:67:6e"
_ESCAPES = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")  # \u0040, \x40 written out in a string


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
    # Each layer can multiply the copies (URL and HTML escapes of each other); cap the total.
    budget = len(text) + 65_536
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
                if (text_of := _readable(raw)) is not None:
                    next_layer.append(text_of)
            for token in _HEX.findall(item):
                if (text_of := _readable(bytes.fromhex(token))) is not None:
                    next_layer.append(text_of)
            for token in _SPACED_HEX.findall(item) if " " in item or ":" in item else ():
                if (text_of := _readable(bytes.fromhex(re.sub(r"[ :,\-]", "", token)))) is not None:
                    next_layer.append(text_of)
            if "\\" in item and (decoded := _ESCAPES.sub(lambda m: chr(int(m[1] or m[2], 16)), item)) != item:
                next_layer.append(decoded)
        if not next_layer:
            break
        found += next_layer
        budget -= sum(map(len, next_layer))
        if budget <= 0:
            break
        layer = next_layer
    return found


# Leetspeak ("1gn0r3 4ll pr3v10u5 1n5truct10n5"): a line with a word of letters and digits shaped like it
# (a digit inside the word, or standing for the first or last letter of a longer one) is read once more
# with those words' digits as letters. Only words standing alone are read so: "t0x1@mail.test", "/v1/api"
# and "build-a1b3" are values, and a rewritten value would teach the threat memory an address nobody sent.
# Lines without such a word ("served in 12ms", "v2", "2026-10-29") are not copied.
_LEET = str.maketrans("013457", "oieast")
# Each branch starts at the digit, so the search skips straight to digits instead of trying every letter.
_LEET_SHAPE = re.compile(r"[013457](?:(?<=[^\W\d_].)[013457]*[^\W\d_]|(?<!\w.)[^\W\d_]{3}|(?<=[^\W\d_]{3}.)(?!\w))")
_LEET_WORD = re.compile(r"(?<![\w@.:/\\-])(?:[^\W\d_]|[013457])+(?![\w@:/\\-]|\.\w)")


def _unleet(text: str) -> list[str]:
    if not _LEET_SHAPE.search(text):
        return []
    lines = []
    for line in text.splitlines():
        if _LEET_SHAPE.search(line) and any(_LEET_SHAPE.search(m[0]) for m in _LEET_WORD.finditer(line)):
            lines.append(_LEET_WORD.sub(lambda m: m[0].translate(_LEET), line))
    return lines


# A right-to-left override (U+202E) shows what follows it reversed, up to a pop (U+202C) or the line end:
# stored as "snoitcurtsni suoiverp erongI", it is shown as "Ignore previous instructions". That span is
# read in the shown order too.
_RLO = re.compile("\u202e([^\u202c\n]*)")
_LATIN_MARKED = re.compile("[\u00c0-\u024f\u0300-\u036f\u1e00-\u1eff]")


def _unaccent(text: str) -> str:
    """The text without the accents and combining marks on Latin letters ("ìgnórè", "i\u0361gnore"), which
    NFKC leaves; marks on other scripts (Devanagari) stay, since their words need them."""
    out: list[str] = []
    for ch in unicodedata.normalize("NFKD", text):
        if not (unicodedata.category(ch) == "Mn" and out and out[-1].isalpha() and ord(out[-1]) < 0x250):
            out.append(ch)
    return "".join(out)


_INLINE_TAG = re.compile(r"</?(?:b|i|u|s|em|strong|span|font|code|sub|sup|wbr|a|mark|small|big|del|ins)\b[^>]{0,200}>", _I)
_ANY_TAG = re.compile(r"</?[a-z][^>]{0,200}>", _I)
_COMMENT = re.compile(r"<!--[\s\S]{0,2000}?-->")
_EMPHASIS = re.compile(r"\*+|~~")


def _unmarked(text: str) -> str:
    """The text without HTML comments and tags (inline ones close up, "ig<b>no</b>re"; others read as a
    space) and without markdown emphasis ("ig**no**re")."""
    return _EMPHASIS.sub("", _ANY_TAG.sub(" ", _INLINE_TAG.sub("", _COMMENT.sub(" ", text))))


# Single letters spelled out with one separator: "i g n o r e", "i.g.n.o.r.e", "i-g-n-o-r-e".
_SPELLED_OUT = re.compile(r"(?<!\w)[^\W\d_]([ .\-_*|/\u00b7])(?:[^\W\d_]\1)+[^\W\d_](?!\w)")


def _joined(text: str) -> str:
    return _SPELLED_OUT.sub(lambda m: m[0].replace(m[1], ""), text)


def _views(text: str) -> list[str]:
    """Other ways to read the normalized text, each only if it differs: without accents on Latin letters,
    without markup, with spelled-out letters joined."""
    found = []
    if _LATIN_MARKED.search(text):
        found.append(_unaccent(text))
    if "<" in text or "*" in text or "~~" in text:
        found.append(_unmarked(text))
    found.append(_joined(text))
    return [view for view in found if view != text]


# Reference-style markdown: "![s][1]" with "[1]: https://..." elsewhere, which renders like "![s](https://...)".
_REF_DEFINITION = re.compile(r"^[ \t]{0,3}\[([^\]\n]{1,100})\]:[ \t]*<?(\S+?)>?(?:[ \t]+[\"'(].*)?$", re.M)
_REF_IMAGE = re.compile(r"!\[([^\]\n]{0,100})\](?:\[([^\]\n]{0,100})\])?(?![(\[:])")


def _hidden_views(text: str) -> list[str]:
    """Readings only the output rules get, since their text is no source of values: the text reversed and
    in rot13 (an instruction written so to slip past the rules; a model reads both when asked to), and
    reference-style markdown images written inline, so the image rules see where they send data."""
    found = [text[::-1], codecs.encode(text, "rot13")]
    if "![" in text and (refs := {m[1].strip().lower(): m[2] for m in _REF_DEFINITION.finditer(text)}):
        def inline(m: re.Match[str]) -> str:
            url = refs.get((m[2] or m[1]).strip().lower())
            return f"![{m[1]}]({url})" if url else m[0]
        if (resolved := _REF_IMAGE.sub(inline, text)) != text:
            found.append(resolved)
    return found


@functools.lru_cache(maxsize=8)  # the hook reads one output for the rules and for its values in a row
def _read(text: str) -> str:
    """The raw text plus its decoded layers and its right-to-left overrides as shown, normalized."""
    return _normalize("\n".join([text, *_decoded(text), *(m[1][::-1] for m in _RLO.finditer(text))]))


def readable(text: str) -> str:
    """The text the rules read: ``_read``, then its leetspeak lines read as letters, and the other readings of it."""
    text = _read(text)
    return "\n".join([text, *_unleet(text), *_views(text)])


def leaf_text(value: Any) -> str:
    """The keys, strings and numbers of a structured value, one per line, in order: what a model
    reads. JSON encoding is not that text: it turns a line break into a literal backslash-n (so
    ``new\\ntask:`` loses its word boundary) and every non-ASCII character into an escape."""
    if isinstance(value, str):
        return value
    parts: list[str] = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            parts.append(item)
        elif isinstance(item, dict):
            stack.extend(reversed([part for pair in item.items() for part in pair]))
        elif isinstance(item, (list, tuple)):
            stack.extend(reversed(item))
        elif isinstance(item, (int, float)) and not isinstance(item, bool):
            parts.append(str(item))
    return "\n".join(parts)


def argument_surface(value: Any) -> str:
    """One line of JSON with every key and string normalized as the rules read it (decoded,
    NFKC, invisible characters dropped, look-alikes mapped, whitespace collapsed), objects as
    sorted key-value pairs. The gateway's argument rules match this instead of ``canonical_json``,
    which stays the hashing form."""
    def clean(item: Any) -> Any:
        if isinstance(item, str):
            return " ".join(readable(item).split())
        if isinstance(item, dict):
            # Pairs, not a dict: keys equal only after normalization ("value" and "valu\u200be")
            # must not overwrite each other and drop a value before the rules see it.
            pairs = [[clean(str(key)), clean(child)] for key, child in item.items()]
            return sorted(pairs, key=lambda pair: json.dumps(pair, sort_keys=True, ensure_ascii=False))
        if isinstance(item, (list, tuple)):
            return [clean(child) for child in item]
        return item
    return json.dumps(clean(value), sort_keys=True, ensure_ascii=False, default=str)


def normalized_intent(text: str) -> str:
    """The user's request as the argument rules compare against it."""
    return " ".join(_normalize(text).lower().split())


def _scan(text: str, rules: tuple[tuple[str, _Rule], ...], trusted: str = "",
          collapse: bool = False, hidden: bool = False) -> list[str]:
    text = readable(text)
    if hidden:
        text = "\n".join([text, *_hidden_views(text)])
    if collapse:
        text = " ".join(text.split())
    # Text the user typed is their own request, not an injection ("forward this: ignore ...").
    # The whole sentence around a match must be the user's, not just the trigger words: a prompt that
    # says "send the password reset link to bob" does not cover "send the password to evil@x".
    trusted = " ".join(_normalize(trusted).lower().split())

    def users_own(match: re.Match[str]) -> bool:
        if not trusted:
            return False
        start = max(text.rfind(sep, 0, match.start()) for sep in ".\n!?;") + 1
        ends = [i for i in (text.find(sep, match.end()) for sep in ".\n!?;") if i >= 0]
        sentence = " ".join(text[start:min(ends) if ends else len(text)].lower().split())
        return sentence in trusted

    return [name for name, pattern in rules if any(not users_own(m) for m in pattern.finditer(text))]


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
                    parts.append(leaf_text(value))
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
