"""The values a text carries (addresses, hosts, accounts, numbers) in a canonical form, and the tools a prompt matches."""
from __future__ import annotations

import base64
import binascii
import codecs
import functools
import ipaddress
import math
import posixpath
import re
import socket
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlsplit

from intentshield.hostlists import COMMON_FIRST_PARTY, NEEDS_SUBDOMAIN, TLDS, bare_tld, shared_host

from .normalize import _BASE64, _HEX, _read, leaf_text
from .rules import _I

# Top-level domains of the dotted-word spellings of an address ("audit [at] canary dot example"): few, since "dot" and
# "at" are words. A bare host in text ("evil.example") is read against the whole root zone (``hostlists.TLDS``) instead.
_TLD = (r"com|net|org|io|dev|ai|app|co|uk|de|fr|jp|cn|ru|in|au|ca|us|eu|info|biz|me|xyz|cloud|tech|site|online|store|"
        r"gov|edu|mil|int|example|test|invalid|local|internal|localhost|top|click|live|space|link|network|email|pw|tk")
# A bare host: letters and digits of any script (an internationalized name), then a top-level domain, or an IPv4
# address as dotted decimal, octal or hex parts. Whether the last label is a real top-level domain is ``_real_host``'s.
_LABEL = r"[^\W_](?:[^\W_]|-){0,62}"
_OCTET = r"(?:0x[0-9a-f]{1,8}|0\d{1,10}|\d{1,3})"
_HOSTS = rf"(?:(?:{_LABEL}\.)+[^\W\d_](?:[^\W_]|-){{1,62}}|(?:{_OCTET}\.){{3}}{_OCTET})"
_HOME = r"(?:~|\$\{?home\}?|%userprofile%)"
# The lookbehinds start a match only where a run begins; without them findall retries
# from every character of a long run and the scan goes quadratic. Indices 0 to 5 are the threat memory's masks.
_VALUE_PATTERNS = (
    re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),         # email
    re.compile(r"(?<![\w+.\-])[a-z][a-z0-9+.\-]*://[^\s\"'<>)]+", _I),  # URL: https, ftp, s3, file, ...
    re.compile(r"\b[A-Z]{2}\d{2}[A-Z\d]{10,30}\b"),                  # IBAN
    re.compile(r"\b\d[\d\- ]{6,}\d\b"),                               # account / card / phone
    # path, absolute or relative; "~", "$HOME" and "%USERPROFILE%" start one; doubled slashes are one
    re.compile(rf"(?<![\w.\-~/$%])(?!//)(?:{_HOME}|[\w.\-]+)?/+[\w.\-]+(?:/+[\w.\-]+)+", _I),
    re.compile(r"(?<![A-Za-z0-9_\-])(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])[A-Za-z0-9_\-]{8,}\b"),  # id/key
    # IBAN as printed, in groups of four ("DE89 3704 0044 ..."), either case, groups split by space, dot or dash.
    re.compile(r"\b[A-Za-z]{2}\d{2}(?:[ .\-][A-Za-z\d]{4}){2,7}(?:[ .\-]\d{1,4})?\b"),
    # A bare host, IPv4 address or host:port with no scheme ("evil.example", "203.0.113.7:8443"): a read tool's
    # target is a destination too. Not when a path follows: that is a URL without its scheme (below). A full stop
    # that ends the sentence ("domain: evil.example.") still ends the host.
    re.compile(rf"(?<![\w@.\-/]){_HOSTS}(?::\d{{2,5}})?(?![\w@\-]|\.[\w\-]|/[\w%~.\-])", _I),
)
_EXTRA_PATTERNS = (
    ("url", re.compile(rf"(?<![\w:/.\-])//{_HOSTS}(?::\d{{2,5}})?(?:/[^\s\"'<>)]*)?", _I)),  # //host/path
    ("url", re.compile(rf"(?<![\w@.\-/]){_HOSTS}(?::\d{{2,5}})?/[^\s\"'<>)]+", _I)),          # host/path
    ("path", re.compile(r"(?<![\w\\])[A-Za-z]:\\+(?:[\w.\-]+\\+)*[\w.\-]+")),                # C:\Users\me\x
    # one-segment dotfiles of the home directory (~/.npmrc, $HOME/.env), which the path pattern needs two segments for
    ("path", re.compile(rf"(?<![\w.\-~/$%]){_HOME}/+\.[\w\-][\w.\-]*(?![\w.\-]|/+[\w.\-])", _I)),
    # An IPv6 address, bracketed with or without a port, or bare ("2001:db8::1"); ``_canon`` drops what is no address.
    ("host6", re.compile(r"(?<![\w:.\-/%@])\[[0-9a-f:.]{2,45}\](?::\d{2,5})?", _I)),
    ("host6", re.compile(r"(?<![\w:.\-/%@\[])(?=[0-9a-f.]*:[0-9a-f.]*:)[0-9a-f:.]{5,45}(?![\w:.\-/%\]])", _I)),
    ("iban", re.compile(r"\b[a-z]{2}\d{2}[a-z\d]{10,30}\b")),                               # lowercase: checksum below
    ("number", re.compile(r"\b\d{4}(?:\.\d{4}){2,}\b")),                                      # 1234.5678.9012
)
# A two-label name on a top-level domain that is also a file extension or a word of code ("evilhost.sh", "x.cc"), or a
# name on one of the root zone's word domains ("relay.example.abc", ``hostlists.bare_tld``), is not a host by its shape,
# but is one after a word that points at a destination, quoted or not:
# "send the notes to `evilhost.sh`", "curl evilhost.sh/steal", "ssh x.cc" ("open", "at" and "into" are not such words:
# "open main.py", "at index.js:12"). Measured on 11,902 local READMEs and docs, 90 (0.8 %) have one, nearly all
# "to CHANGELOG.md".
_GO = (r"(?<![\w.\-])(?:to|via|towards?|visit|fetch|ping|curl|wget|ssh|scp|server|domain|site|endpoint|"
       r"address|contact|upload|forward)[ \t]*:?[ \t]+(?:the[ \t]+)?[`\"'(*]{0,2}")
_POINTED = rf"(?:{_LABEL}\.)+[^\W\d_](?:[^\W_]|-){{1,62}}"
_POINTED_PATTERNS = (
    ("host", re.compile(rf"{_GO}({_POINTED})(?::\d{{2,5}})?(?![\w@\-]|\.[\w\-]|/)", _I)),
    ("url", re.compile(rf"{_GO}({_POINTED}(?::\d{{2,5}})?/[^\s\"'<>)]+)", _I)),
)
_KINDS = ("email", "url", "iban", "number", "path", "id", "iban", "host")
_SPECS = (*zip(_KINDS, _VALUE_PATTERNS), *_EXTRA_PATTERNS, *_POINTED_PATTERNS)
# YYYY-MM-DD, DD/MM/YYYY (or MM/DD/YYYY) and YYYYMMDD, not inside a longer number or path.
_DATE = re.compile(r"(?<![\d/\-])(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4}|"
                   r"(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))(?![\d/\-])")
_PLAIN_WORDS = re.compile(r"[a-z]+(?:/[a-z]+)+")  # "read/write/execute": words, not a relative path
_SECRET_WORDS = frozenset({"secret", "secrets", "credentials", "keys", "passwords", "tokens", "ssh"})
_WEB_SCHEMES = frozenset({"http", "https", "ws", "wss"})
# Hosts a document mentions in passing (``hostlists.COMMON_FIRST_PARTY``, and the bare suffix of a platform that rents out
# names): seeing one says nothing about a call to another address on it. A name under such a platform's suffix
# ("evil.github.io") is one tenant's own site, and is not common.
_COMMON_HOSTS = COMMON_FIRST_PARTY


def _common_host(host: str) -> bool:
    return shared_host(host)


# Second-level labels of country registries ("co.uk", "com.au"): a name under one is not one site.
_REGISTRY_LABELS = frozenset("co com org net gov ac edu ne or go".split())


def host_suffixes(host: str, first: int = 0) -> list[str]:
    """The suffixes of ``host`` from label ``first`` on, the last label alone left out ("a.b.example" gives
    itself, "b.example"). Only the last 127 labels count, the most a DNS name has: a "host" of 50,000
    labels (a hostile URL) would otherwise cost a quadratic number of characters to list."""
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(max(first, len(labels) - 127), len(labels) - 1)]


def _under_host(host: str, parent: str) -> bool:
    """``host`` is a subdomain of ``parent``, a site's own name ("data.mirror.example" under "mirror.example"),
    not of a registry suffix or a popular site, where subdomains belong to different owners."""
    labels = parent.split(".")
    return (host.endswith("." + parent) and len(labels) >= 2 and not _common_host(parent)
            and not (len(labels) == 2 and labels[0] in _REGISTRY_LABELS))


@functools.cache
def _home_dir() -> str:
    return str(Path.home()).lower().rstrip("/")


_IDEOGRAPHIC_STOPS = str.maketrans("\u3002\uff0e\uff61", "...")


def _label(label: str) -> str:
    folded = unicodedata.normalize("NFKC", label).lower()
    if folded.isascii():
        return folded
    try:
        return "xn--" + folded.encode("punycode").decode("ascii")
    except UnicodeError:
        return folded


@functools.lru_cache(maxsize=4096)
def _idna(host: str) -> str:
    """A host as its punycode (``xn--``) form, label by label (NFKC, lowercase, then punycode: the ``idna`` codec's
    nameprep costs twice as much). No name has more than 253 characters, and a longer run of labels is not
    encoded."""
    host = host.translate(_IDEOGRAPHIC_STOPS).lower().strip(".")
    if host.isascii() or len(host) > 253:
        return host
    return ".".join(map(_label, host.split(".")))


_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}")


def _v6(text: str) -> str | None:
    """An IPv6 address as one key (compressed, lowercase; an IPv4-mapped one as the IPv4 address), None if it is none."""
    try:
        address = ipaddress.IPv6Address(text.partition("%")[0])
    except ValueError:
        return None
    return str(address.ipv4_mapped) if address.ipv4_mapped else address.compressed


def _host_key(host: str) -> str:
    """A host as one key: lowercase, IDNA, no trailing dot, port or userinfo; an address written as one
    number or in hex or octal parts ("3405803783", "0xcb007107") as a dotted quad."""
    host = host.rpartition("@")[2]
    if host.startswith("[") and "]" in host:
        host = host[1:host.index("]")]
    elif host.count(":") < 2:  # not a bare IPv6 address
        host = host.partition(":")[0]
    if ":" in host:
        return _v6(host) or host
    if _NUMERIC_HOST.fullmatch(host := host.lower().rstrip(".")):
        try:
            return socket.inet_ntoa(socket.inet_aton(host))
        except OSError:
            pass
    return _idna(host)


def _canon_path(path: str) -> str:
    """A path as one key: no ``file:``, forward slashes, lowercase, ``~`` for ``$HOME`` and for any home
    directory (``/Users/x``, ``/home/x``, ``C:\\Users\\x``), dots and doubled slashes resolved, no trailing slash.
    A relative path keeps the ``..`` it starts with."""
    path = path.lower().replace("\\", "/")
    path = re.sub(r"^/?[a-z]:(?=/)", "", re.sub(r"^file:/*", "/", path))
    path = re.sub(rf"^{_HOME}(?=/|$)", "~", path)
    if path.startswith(("/", "~")):
        path = posixpath.normpath("/" + path.lstrip("/") if not path.startswith("~") else "/" + path)
        path = path[1:] if path.startswith("/~") else path
    else:  # relative: a leading ".." stays, it is not the root's parent ("../x/y" is not "/x/y")
        path = posixpath.normpath(path) if path else ""
        path = "" if path == "." else path
    if (own := _home_dir()) and (path == own or path.startswith(own + "/")):
        path = "~" + path[len(own):]
    return re.sub(r"^/(?:users|home)/[^/]+(?=/|$)|^/root(?=/|$)", "~", path)


def _canon_url(url: str) -> str | None:
    """A URL as one key: ``scheme://host/path?query`` with the host as ``_host_key`` reads it, the scheme ``https``
    for http, https, ws and wss, the path percent-decoded, all lowercase, without fragment, port, userinfo or
    trailing slash. A ``file:`` URL is a path; one without a scheme is taken as https."""
    if url.lower().startswith("file:"):
        return _canon_path(unquote(url))
    url = "https:" + url if url.startswith("//") else url if "://" in url else "https://" + url
    try:
        parts = urlsplit(url)
        host = _host_key(parts.netloc)
    except ValueError:
        return None
    if not host:
        return None
    scheme = "https" if parts.scheme.lower() in _WEB_SCHEMES else parts.scheme.lower()
    path = posixpath.normpath("/" + unquote(parts.path).lower().lstrip("/")).rstrip("/") if parts.path.strip("/") else ""
    query = f"?{parts.query.lower()}" if parts.query else ""
    return f"{scheme}://{f'[{host}]' if ':' in host else host}{path}{query}"


def _canon_email(email: str) -> str:
    local, _, domain = email.rpartition("@")
    local = local.lower().removeprefix("mailto:")
    return f"{local.split('+', 1)[0] or local}@{_host_key(domain)}"


def _iban_valid(compact: str) -> bool:
    moved = (compact[4:] + compact[:4]).upper()
    return int("".join(str(int(ch, 36)) for ch in moved)) % 97 == 1


def _ascii_digits(text: str) -> str:
    """Every Unicode decimal digit (Arabic-Indic, Devanagari, ...) as its ASCII digit: the model that reads an
    account number in one script writes it in another."""
    return "".join(str(unicodedata.decimal(ch)) if ch.isdecimal() and not ch.isascii() else ch for ch in text)


def _canon(kind: str, match: str) -> str | None:
    match = unicodedata.normalize("NFKC", match)
    # A path may start with dots ("./x/y", "../x/y"): only its end can be a sentence's full stop.
    match = match.lstrip(",;:").rstrip(".,;:") if kind == "path" else match.strip(".,;:")
    if kind == "email":
        return _canon_email(match)
    if kind == "url":
        return _canon_url(match)
    if kind == "path":
        return _canon_path(match)
    if kind == "host":
        return _host_key(match)
    if kind == "host6":
        address = _v6(match.strip("[]").partition("]")[0])
        return None if address is None or len(match) < 6 else address if "." in address else f"[{address}]"
    match = _ascii_digits(match)
    if kind == "iban":
        compact = re.sub(r"[\s.\-]", "", match).lower()
        # Printed in capitals or in groups it is an IBAN by its shape; a lowercase run is any word with
        # digits unless its checksum holds.
        return compact if match.isupper() or re.search(r"[\s.\-]", match) or _iban_valid(compact) else None
    return re.sub(r"[\s\-.]" if match[:1].isdigit() else r"\s", "", match).lower()


def _ordinary(item: str) -> bool:
    """Dates, numbers under nine digits (amounts, short counts) and plain words: any text has them,
    so one in an argument says nothing about where it came from."""
    return (item.isdigit() and len(item) < 9) or bool(_DATE.fullmatch(item) or (
        _PLAIN_WORDS.fullmatch(item) and not _SECRET_WORDS & set(item.split("/"))))


# What an agent reads from an address written to dodge a filter: "audit [at] canary [dot] example",
# "audit @ canary . example", "hxxps://canary[.]example", "audit@canary,example".
_DEFANG_HINT = re.compile(r"hxxp|fxp|[\[({<]\s*(?:\.|dot|at|@|:(?://)?)\s*[\])}>]|\sdot\s|\w\s@\s\w|\w\s\.\s\w|@[\w.-]+,\w|"
                          r"@[\w.-]*\.[ \t]*\n", _I)
_SPELLED = re.compile(r"([\w.+-]{1,64})\s+at\s+([\w-]+(?:\s+dot\s+[\w-]+)+)(?![\w-])", _I)
_SPACED = re.compile(r"([\w.+-]{1,64}) *@ *([\w-]+(?: *\. *[\w-]+)+)")
_TLD_END = re.compile(rf"(?:{_TLD})\Z", _I)
_DOT_WORD, _DOT_SPACED = re.compile(r"\s+dot\s+", _I), re.compile(r" *\. *")


def _replace_between_blanks(core: re.Pattern[str], replacement: str, text: str, leading: int = 0) -> str:
    """``re.sub(r"\\s*CORE\\s*", replacement, text)`` (``\\s+`` before it when ``leading`` is 1), by finding CORE
    alone and eating the whitespace around each match. Written as one regex, the leading ``\\s*`` starts again at
    every character of a run of whitespace that no CORE follows: 40,000 spaces next to one "[at]" took 8 s, and the
    text is the agent's call arguments. Each character is read a constant number of times here."""
    out: list[str] = []
    at = 0
    for match in core.finditer(text):
        start = match.start()
        while start > at and text[start - 1].isspace():
            start -= 1
        if match.start() - start < leading:
            continue
        out += (text[at:start], replacement)
        at = match.end()
        while at < len(text) and text[at].isspace():
            at += 1
    out.append(text[at:])
    return "".join(out)


_BRACKETED = (  # (the brackets around it, what it reads as): "[:]", "(dot)", "{at}"
    (re.compile(r"[\[({<]\s*:\s*(?://)?\s*[\])}>]"), "://"),
    (re.compile(r"[\[({<]\s*(?:\.|dot)\s*[\])}>]", _I), "."),
    (re.compile(r"[\[({<]\s*(?:@|at)\s*[\])}>]", _I), "@"),
)
# "evil . example": a host written with blanks around its dots, read as one only when it ends in a real top-level domain.
_SPACED_HOST = re.compile(r"(?<![\w.@\-])((?:[^\W_][\w-]{0,62}\.){0,8}[^\W_][\w-]{0,62})[ \t]+\.[ \t]+"
                          r"([^\W\d_][\w-]{1,62})(?![\w-])")
_DOT_BEFORE_TLD = re.compile(rf"dot(?=\s+(?:{_TLD})\b)", _I)


def _defang(text: str) -> str:
    """``text`` with the defanged addresses in it written out, or "" if there are none."""
    if not _DEFANG_HINT.search(text):
        return ""
    out = re.sub(r"\bhxxp(s?)\b", r"http\1", text, flags=_I)
    out = re.sub(r"\bfxp(s?)\b", r"ftp\1", out, flags=_I)
    for core, replacement in _BRACKETED:
        out = _replace_between_blanks(core, replacement, out)
    out = _SPELLED.sub(lambda m: f"{m[1]}@{_DOT_WORD.sub('.', m[2])}" if _TLD_END.search(m[2]) else m[0], out)
    out = _replace_between_blanks(_DOT_BEFORE_TLD, ".", out, leading=1)
    out = _SPACED.sub(lambda m: f"{m[1]}@{_DOT_SPACED.sub('.', m[2])}" if _TLD_END.search(m[2]) else m[0], out)
    out = _SPACED_HOST.sub(lambda m: f"{m[1]}.{m[2]}" if _real_host(f"{m[1]}.{m[2]}".lower()) else m[0], out)
    out = re.sub(rf"(@[\w-]+(?:\.[\w-]+)*),((?:{_TLD})\b)", r"\1.\2", out, flags=_I)
    out = re.sub(r"(@[\w.-]*\.)[ \t]*\n[ \t]*([a-z][\w-]*)", r"\1\2", out, flags=_I)
    return out if out != text else ""


def _decoded_values(text: str) -> list[str]:
    """Encodings an agent is told to undo for an address: base64 and hex that decode to a printable string
    holding an address or a path (the prose test of ``readable`` would drop a bare address), and text marked
    rot13 or "backwards"."""
    found = []
    for token in (*_BASE64.findall(text), *_HEX.findall(text)):
        try:
            raw = bytes.fromhex(token) if re.fullmatch(r"[0-9a-fA-F]+", token) else base64.b64decode(
                token.replace("-", "+").replace("_", "/") + "=" * (-len(token) % 4))
            decoded = raw.decode("ascii")
        except (ValueError, binascii.Error):
            continue
        if decoded.isprintable() and re.search(r"@\w|://|\w/\w|\w\.\w", decoded):
            found.append(decoded)
    if re.search(r"\brot-?13\b", text, _I):
        found.append(codecs.decode(text, "rot13"))
    # Not reversed(x), x.reverse(), reverse=True, 'reverse', row-reverse or "backwards compatible", which is how the
    # word appears in source code.
    if re.search(r"(?<![.\w'\"\-])(?:backwards?|reversed?)\b(?![(=_'\"\-]|[ -]compat)", text, _I):
        found.append(text[::-1])
    return found


@functools.lru_cache(maxsize=8)
def _value_text(text: str) -> str:
    """The text values are read from: the raw text, then what an agent reads of it (decoded, normalized,
    defanged, with the encodings of an address undone)."""
    seen = _read(text)
    views = [seen] if text.isascii() else [text, seen]
    return "\n".join(views + [view for view in (_defang(seen), *_decoded_values(seen)) if view])


# The patterns that read a host without a scheme in front of it.
_BARE = frozenset({_VALUE_PATTERNS[7], _EXTRA_PATTERNS[0][1], _EXTRA_PATTERNS[1][1]})
_POINTED_ONLY = frozenset(pattern for _, pattern in _POINTED_PATTERNS)


def _real_host(host: str) -> bool:
    """A name ending in a top-level domain of the root zone, or an address: not "report.txt" or "a.b.c". The
    domains that are also file extensions or words of code ("build.sh", "main.py", "item.name") need a label before the
    registered name."""
    if host.startswith("[") or not host or host.replace(".", "").isdigit():
        return True
    tld = _idna(host).rpartition(".")[2]
    return bare_tld(tld) and (tld not in NEEDS_SUBDOMAIN or host.count(".") >= 2) and not _suffix_only(host)


def _suffix_only(host: str) -> bool:
    """A registry's own second level under a country code ("co.uk", "org.nz"), which names no site."""
    first, _, tld = host.partition(".")
    return len(tld) == 2 and first in ("co", "com", "org", "net", "ac", "gov", "edu", "or", "ne", "go")


def distinctive_values(value: Any, authority: bool = False) -> set[str]:
    """Values specific enough that their source can be traced: emails, URLs, accounts, paths, ids, each as one
    canonical key, so that its spellings are one value: an address defanged, encoded or in capitals, a URL in
    either scheme, with a port, userinfo or a trailing dot, a path with ``~`` or ``$HOME`` for the home
    directory. Read from what an agent reads (decoded, normalized), not only the raw text. Dates are taken
    out before numbers are read, so "2026-10-01 10:00" is not the number 2026100110."""
    text = _value_text(leaf_text(value))
    undated = _DATE.sub(" ", text)
    found: set[str] = set()
    for kind, pattern in _SPECS:
        if authority and kind == "id":
            continue
        for match in pattern.findall(undated if pattern is _VALUE_PATTERNS[3] else text):
            # A host is as short as "z.io"; every other value is at least six characters.
            if (len(match.strip(".,;:\\")) >= 6 or kind == "host") and (key := _canon(kind, match)) \
                    and len(key) >= 3 and not _ordinary(key) \
                    and not (pattern in _BARE and not _real_host(_parse(key)[1])) \
                    and not (pattern in _POINTED_ONLY and _idna(_parse(key)[1]).rpartition(".")[2] not in TLDS):
                found.add(key)
    return found


def authority_values(value: Any) -> set[str]:
    """Distinctive values that decide where data or money goes or what gets touched:
    emails, URLs, accounts and paths. Generic ids are left out (picking an id from a
    search result is how agents normally work)."""
    return distinctive_values(value, authority=True)


def _parse(key: str) -> tuple[str, str, list[str]]:
    """(kind, host, path segments) of a canonical key; kind is url, path, email, host or other."""
    if "://" in key:
        host, _, path = key.partition("://")[2].partition("?")[0].partition("/")
        return "url", host, [part for part in path.split("/") if part]
    if "/" in key or key.startswith("~"):
        return "path", "", [part for part in key.split("/") if part]
    if "@" in key:
        return "email", key.rpartition("@")[2], []
    return ("host", key, []) if re.fullmatch(_HOSTS, key) or re.fullmatch(r"\[[0-9a-f:]+\]", key) else ("other", "", [])


def _nested(a: list[str], b: list[str]) -> bool:
    """One URL path is the other's directory, the shorter at least one segment deep."""
    short = min(len(a), len(b))
    return short >= 1 and a[:short] == b[:short]


def _user_prefixes(user: Iterable[str]) -> tuple[str, ...]:
    """Directories and sites the user named closely enough that what lies under them is theirs: two path
    segments or more, so a bare site or "~" is not a whole site or home directory."""
    return tuple(item.rstrip("/") + "/" for item in user if len(_parse(item)[2]) >= 2 and _parse(item)[0] != "email")


def _under_user(item: str, prefixes: tuple[str, ...]) -> bool:
    """Inside a directory or site the user named, and not a dotfile in it (naming a project directory
    does not hand over its ``.env`` or ``.ssh``)."""
    return any(item.startswith(prefix) and not any(
        part.startswith(".") for part in item[len(prefix):].split("/")) for prefix in prefixes)


def _url_root(value: str) -> tuple[str, str] | None:
    kind, host, segments = _parse(value)
    return (host, "/".join(segments)) if kind == "url" and value.startswith("https://") and host else None


def on_tainted_hosts(values: Iterable[str], tainted: Iterable[str], user: Iterable[str] = ()) -> set[str]:
    """Addresses among ``values`` on the host of a tainted address, whatever their path: a file that is written
    with an address from an output that tried to instruct the agent, even another path on that host, is the
    attacker's. A popular site or a host the user named does not count."""
    def host_of(value: str) -> str:
        kind, host, _ = _parse(value)
        return host if kind in ("url", "host") and host and not _common_host(host) else ""
    user_hosts = {host_of(v) for v in user} - {""}
    bad = {host_of(v) for v in tainted} - {""} - user_hosts
    return {v for v in values if host_of(v) in bad} if bad else set()


def traced_urls(values: set[str], tainted: Iterable[str], user: Iterable[str] = ()) -> dict[str, str]:
    """URLs among ``values`` built on a tainted URL rather than equal to it: the exfiltration
    step "call this address with the data appended". ``path`` when the URL is on the tainted
    host under the tainted path (``https://x.test/u`` covers ``/u/notes`` and ``/u?d=notes``);
    ``host`` when the tainted URL had no path (or the tainted value was a bare host), so any URL on that
    host is suspect but weaker evidence. Never by host alone otherwise: an injected issue on a code host
    must not taint the whole site. A tainted URL the user named, or one inside a site or directory they
    named, traces nothing: an injected page that repeats the user's own address does not make it the
    attacker's."""
    user = set(user)
    prefixes = _user_prefixes(user)
    user_hosts = {root[0] for item in user if (root := _url_root(item))} | {
        item for item in user if _parse(item)[0] == "host"}
    roots = set()
    for url in tainted:
        if url in user or _under_user(url, prefixes):
            continue
        if _parse(url)[0] == "host":
            if not _common_host(url) and url not in user_hosts:
                roots.add((url, ""))
        elif (root := _url_root(url)) and (root[1] or root[0] not in user_hosts):
            roots.add(root)
    found: dict[str, str] = {}
    for value in values:
        if not (root := _url_root(value)):
            continue
        for host, path in roots:
            # a bare tainted host covers its subdomains as well (weaker: "host")
            if root[0] != host and (path or not _under_host(root[0], host)):
                continue
            if path and (root[1] == path or root[1].startswith(path + "/")):
                found[value] = "path"
                break
            if not path:
                found.setdefault(value, "host")
    return found


def sourced_from(values: set[str], source: Iterable[str], user_values: set[str]) -> set[str]:
    """The values that came from ``source`` and not from the user. Values are canonical keys, as
    ``distinctive_values`` returns them. A value is sourced when ``source`` has it, or a URL it is inside or
    that is inside it (one segment deep at least), or has its host bare or as an email's domain (hosts of
    popular sites excepted). A path is sourced only when ``source`` has that path: a directory listing names
    the directory every file the agent then writes lies in (measured: one benign call in fifty asked). A path
    or URL inside a directory or site the user named (two segments or more, no dotfile) counts as the user's
    own, like what the user typed."""
    user = set(user_values)
    prefixes = _user_prefixes(user)
    pending = {item for item in values if item not in user and not _under_user(item, prefixes)}
    found = {item for item in pending if item in source}
    pending -= found
    if not pending:
        return found
    parsed = {item: _parse(item) for item in pending}
    hosts = {host for kind, host, _ in parsed.values() if kind in ("url", "email", "host") and not _common_host(host)}
    named: set[str] = set()  # hosts the source names bare or as an email's domain
    url_paths: dict[str, list[list[str]]] = {}
    parents = {parent for host in hosts for parent in host_suffixes(host, 1)}
    for key in source:
        parent = key.rpartition("@")[2]  # a bare host, or an email's domain, the call's host lies under
        if parent in parents and _parse(key)[0] in ("host", "email"):
            named |= {host for host in hosts if _under_host(host, parent)}
            if parent == key:
                continue
        if hosts and any(host in key for host in hosts):
            kind, host, segments = _parse(key)
            if host in hosts:
                if kind == "url":
                    url_paths.setdefault(host, []).append(segments)
                elif kind in ("host", "email"):
                    named.add(host)
    for item, (kind, host, segments) in parsed.items():
        if host not in hosts:
            continue
        elif kind == "url":
            hit = host in named or any(not other or _nested(segments, other) for other in url_paths.get(host, ()))
        else:  # an email: its domain named; a bare host: named, or the host of a URL
            hit = host in named or (kind == "host" and host in url_paths)
        if hit:
            found.add(item)
    return found


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
