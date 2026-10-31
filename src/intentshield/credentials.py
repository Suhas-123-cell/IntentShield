"""Credentials in MCP traffic and configs: provider token formats, private keys and signed tokens.

Each pattern is a provider's published prefix and length, so a match is a credential, not a guess about
a random-looking id; ids without a known prefix are left to the provenance checks. A credential found is
only ever shown masked (its kind and first four characters).
"""
from __future__ import annotations

import base64
import binascii
import bisect
import itertools
import re
import unicodedata
from collections.abc import Callable, Iterator
from typing import Any

from .mcp_inspect import leaf_text

# A prefix that is distinctive on its own (ghp_, glpat-, xoxb-) is matched wherever it stands, so text glued
# to it ("xghp_...", "TOKEN_ghp_...") does not hide it. The others, which could end a longer word ("task-ant-"),
# must not follow a letter or digit; "_" and "-" before them are fine, which \b does not allow for "_".
_L = r"(?<![A-Za-z0-9])"
_R = r"(?![A-Za-z0-9])"
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(_L + r"(?:AKIA|ASIA)[0-9A-Z]{16}" + _R)),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}" + _R + r"|github_pat_[A-Za-z0-9_]{22,255}\b")),
    ("gitlab_token", re.compile(r"glpat-[A-Za-z0-9_\-]{20,}")),
    ("slack_token", re.compile(r"xox[abposre]-[A-Za-z0-9\-]{10,}|xapp-\d-[A-Za-z0-9]{8,}-\d{8,}-[A-Za-z0-9]{20,}")),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{20,}")),
    ("stripe_key", re.compile(_L + r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}|" + _L + r"whsec_[A-Za-z0-9]{24,}")),
    ("anthropic_key", re.compile(_L + r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    # A legacy key is one unbroken run of mixed-case alphanumerics; a prefixed one may hold - and _ but
    # carries a capital and a digit. "sk-Learn-Compatible-..." (words) is rejected in _VALID.
    ("openai_key", re.compile(_L + r"sk-(?!ant-)(?:(?:proj|svcacct|admin)-(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Z])"
                              r"[A-Za-z0-9_\-]{32,}|(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Z])(?=[A-Za-z0-9]*[a-z])"
                              r"[A-Za-z0-9]{32,})")),
    ("google_api_key", re.compile(_L + r"AIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])")),
    ("google_oauth_token", re.compile(_L + r"ya29\.[A-Za-z0-9_\-]{20,}")),
    ("groq_key", re.compile(r"gsk_[A-Za-z0-9]{40,}")),
    ("huggingface_token", re.compile(_L + r"hf_[A-Za-z0-9]{30,}")),
    ("npm_token", re.compile(_L + r"npm_[A-Za-z0-9]{36}" + _R)),
    ("pypi_token", re.compile(r"pypi-AgE[A-Za-z0-9_\-]{50,}")),
    ("sendgrid_key", re.compile(_L + r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{40,}")),
    ("twilio_key", re.compile(_L + r"SK[0-9a-f]{32}" + _R)),
    ("digitalocean_token", re.compile(_L + r"do[por]_v1_[a-f0-9]{64}" + _R)),
    ("docker_token", re.compile(r"dckr_pat_[A-Za-z0-9_\-]{20,}")),
    ("shopify_token", re.compile(_L + r"shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}" + _R)),
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("age_key", re.compile(r"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}")),
    ("jwt", re.compile(_L + r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    # The scheme is bounded where a word boundary lets a match start inside a run: unbounded, every start in a
    # long dotted or hyphenated run rescans the run. A longer scheme can only start at the first
    # letter after a word boundary in its run, which the second form tries once per run. The user may be empty
    # (redis://:password@host).
    ("url_credentials", re.compile(
        r"(?:\b[A-Za-z][A-Za-z0-9+.\-]{0,31}|(?<![A-Za-z0-9+.\-])(?:(?:[0-9][A-Za-z0-9]*)?[+.\-])*[A-Za-z][A-Za-z0-9+.\-]{32,})"
        r"://([^\s/:@]*):([^\s/@]+)@[^\s/?#]+")),
)


# A token glued to the word before it ("x" + "AKIA...", "Bearer" + "sk-...", a literal "\\n" in front) has no boundary on
# its left: text as written is also read with the patterns without it, and a match glued to a letter must look like a
# token (see _glued_token). Not the run-together readings: with the spaces gone every word is glued to the next.
_JOINED_PATTERNS = tuple((kind, re.compile(p.pattern.replace(_L, ""), p.flags)) for kind, p in _PATTERNS if _L in p.pattern)


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


def _surface_map(text: str) -> tuple[str, list[int]]:
    """:func:`_surface` with, for each character of the result, where it starts in ``text``."""
    out, offs = [], []
    for i, ch in enumerate(text):
        for c in unicodedata.normalize("NFKC", ch):
            if unicodedata.category(c) != "Cf" and not "︀" <= c <= "️":
                out.append(c)
                offs.append(i)
    return "".join(out), offs


# A run that may be a token in base64 (standard or URL-safe), base32 or hex: long enough to hold the shortest prefixed one.
_ENCODED = re.compile(r"(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{24,}={0,6}")


def _decodings(text: str) -> list[tuple[str, str]]:
    """(token, decoded) for each base64, base32 or hex run in ``text`` that decodes to printable ASCII."""
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
        if re.fullmatch(r"[A-Za-z2-7]+", body):
            try:
                raws.append(base64.b32decode(body.upper() + "=" * (-len(body) % 8)))
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


# Escapes a model reads as the character: %67, g, \x67, &#103; and &#x67;. A list of eight or more byte
# values in hex (0x67, 0x68, ...) or decimal (103 104 ...) is the text it spells.
_ESCAPES = re.compile(r"%(?P<pct>[0-9A-Fa-f]{2})|\\u(?P<u4>[0-9A-Fa-f]{4})|\\x(?P<x2>[0-9A-Fa-f]{2})|"
                      r"&#(?P<dec>\d{1,3})(?!\d);?|&#(?P<dec4>\d{4,7});|&#[xX](?P<hex>[0-9A-Fa-f]{1,6});?|"
                      r"\\u\{(?P<ub>[0-9A-Fa-f]{1,6})\}|\\U(?P<u8>[0-9A-Fa-f]{8})|\\(?P<oct>[0-3][0-7]{2})")
_HEX_LIST = re.compile(r"(?<![0-9A-Za-z])(?:0[xX][0-9A-Fa-f]{2}[\s,;]+){7,}0[xX][0-9A-Fa-f]{2}(?![0-9A-Za-z])")
_CODE_LIST = re.compile(r"(?<![0-9A-Za-z.])(?:\d{2,3}[\s,;]+){7,}\d{2,3}(?![0-9A-Za-z.])")
_BASES = {"dec": 10, "dec4": 10, "oct": 8}


def _unescaped(text: str) -> str:
    def escape(m: re.Match[str]) -> str:
        try:
            return chr(int(m[m.lastgroup], _BASES.get(m.lastgroup, 16)))
        except (ValueError, OverflowError):
            return m[0]

    def listed(m: re.Match[str]) -> str:
        codes = [int(n, 16 if n[:2] in ("0x", "0X") else 10) for n in re.findall(r"0[xX][0-9A-Fa-f]{2}|\d+", m[0])]
        return "".join(map(chr, codes)) if all(32 <= c < 127 for c in codes) else m[0]

    return _CODE_LIST.sub(listed, _HEX_LIST.sub(listed, _ESCAPES.sub(escape, text)))


# The words of a provider's prefix whose "-", "_" or "." belong to the token, kept when separators are stripped,
# with the separator each one takes when a run holds several ("g-h-p-_-A1": the "_" is the token's).
_PREFIX_WORD = re.compile(r"(?<![A-Za-z0-9])(?:gh[pousr]|github|pat|glpat|xox[abposre]|xapp|sk|rk|ant|proj|svcacct|admin|"
                          r"live|test|whsec|gsk|hf|npm|pypi|SG|dckr|do[por]|v1|shp(?:at|ca|pa|ss)|ya29|AGE|SECRET|KEY)\Z")
_DASH_WORDS = frozenset({"glpat", "ant","proj", "svcacct", "admin", "pypi", "xapp", "AGE", "SECRET", "KEY"})
_DOT_WORDS = frozenset({"SG", "ya29"})
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]+")
# What a token starts with, written without separators ("g-h-p-_" reads "ghp"): a separator run before it is a
# word apart from the token, kept as a space in one reading of the text ("token: ghp_...", "key=AKIA...").
_TOKEN_START = re.compile(r"AKIA|ASIA|AIza|ya29|eyJ|gh[pousr]|github|glpat|xox[abposre]|xapp|gsk|hf|npm|pypi|dckr|whsec|"
                          r"shp(?:at|ca|pa|ss)|do[por]v1|SG|SK|AGE|sk|rk")


_START_LETTERS = frozenset("AeghnpdswxySr")  # first letters of _TOKEN_START, to skip most runs without a lookahead
_APART = "\x00"


def _starts_token(text: str, pos: int) -> bool:
    if pos >= len(text) or text[pos] not in _START_LETTERS:
        return False
    return _TOKEN_START.match(_NON_ALNUM.sub("", text[pos:pos + 48])) is not None


def _stripped_marked(text: str, offs: list[int] | None = None) -> tuple[str, list[int]]:
    """``text`` with each run of separators that is not only spaces deleted (dashes, dots, commas, quotes,
    plus signs and brackets, with or without spaces: how a token is cut into pieces), except the one
    separator that follows a provider's prefix word. Where the run stood before something that starts like a
    token, a NUL marks the spot (see :func:`_stripped`). With ``offs`` (where each character of ``text`` came
    from) also the offsets of what is left."""
    out: list[str] = []
    kept: list[int] = []
    pos = 0
    tail = ""  # the last 12 characters of the result
    for m in _NON_ALNUM.finditer(text):
        segment = text[pos:m.start()]
        out.append(segment)
        tail = (tail + segment)[-12:]
        if offs is not None:
            kept.extend(offs[pos:m.start()])
        pos = m.end()
        if m[0].isspace():  # words apart, not a token in pieces (a token split by spaces is read run together)
            out.append(m[0])
            tail = (tail + m[0])[-12:]
            if offs is not None:
                kept.extend(offs[m.start():pos])
            continue
        seps = [c for c in m[0] if c in "-_."]
        prefix = _PREFIX_WORD.search(tail) if seps else None
        if prefix:
            word = prefix[0]
            wanted = "-" if word in _DASH_WORDS else "." if word in _DOT_WORDS else "_"
            sep = wanted if wanted in seps else seps[0]
            out.append(sep)
            tail = (tail + sep)[-12:]
            if offs is not None:
                kept.append(offs[m.start() + m[0].index(sep)])
        elif _starts_token(text, pos):
            out.append(_APART)
            tail = (tail + " ")[-12:]
            if offs is not None:
                kept.append(offs[m.start()])
    out.append(text[pos:])
    if offs is not None:
        kept.extend(offs[pos:])
    return "".join(out), kept


def _stripped(text: str, offs: list[int] | None = None, apart: bool = False) -> tuple[str, list[int]]:
    """:func:`_stripped_marked` as one reading of the text. With ``apart``, a run before something that
    starts like a token reads as a space instead of nothing, so the token keeps a word boundary on its left
    ("token: ghp_...", "key=AKIA...", "example.com/ghp_..."); without, the neighbouring word is glued on."""
    marked, kept = _stripped_marked(text, offs)
    if offs is None:
        return marked.replace(_APART, " " if apart else ""), kept
    pairs = [(c, o) for c, o in zip(marked, kept, strict=True) if apart or c != _APART]
    return "".join(" " if c == _APART else c for c, _ in pairs), [o for _, o in pairs]


# "sk-Learn-Compatible-Estimator-Wrapper-...": a slug that would read as a key once its hyphens are gone.
_SLUG = re.compile(r"sk-(?:[A-Za-z]{3,}-){3,}[A-Za-z0-9]*")

# A run of x or * put into a token, or at either end of it, so that it reads as a placeholder.
# Whole runs only (a start inside a run is refused by the look-behind), so that a long row of asterisks is read once.
_RUN_START = re.compile(r"(?<![xX*])[xX*]{8,}")


def _delete_inserted_runs(surface: str) -> str:
    def drop(m: re.Match[str]) -> str:
        before = surface[m.start() - 1] if m.start() else ""
        after = surface[m.end()] if m.end() < len(surface) else ""
        return "" if (before.isascii() and before.isalnum()) or (after.isascii() and after.isalnum()) else m[0]

    return _RUN_START.sub(drop, surface)

# Formats without a fixed prefix of their own, which text run together would glue to a neighbouring word.
_UNPREFIXED = frozenset({"url_credentials", "private_key"})
# Formats whose body is any run of letters and digits: run together, prose and code glue into one ("hf_login(token,
# add_to_git_credential=False)" reads "hf_logintokenaddtogit..."), so a digit is required, and for the long
# random bodies a capital and a small letter too, as in a real token.
_NEEDS_DIGIT_JOINED = frozenset({"slack_token", "gitlab_token"})
_NEEDS_MIXED_JOINED = frozenset({"github_token", "groq_key", "huggingface_token", "npm_token", "stripe_key", "anthropic_key",
                                 "google_oauth_token", "pypi_token", "docker_token", "sendgrid_key", "openai_key"})


def _random_like(credential: str) -> bool:
    """Letters and digits that change class (lower case, capital, digit) as often as a random token's do,
    about six times in ten; glued words and identifiers ("ecdsasha2nistp256opensshcomThese") change in a
    few places only."""
    alnum = re.sub(r"[^A-Za-z0-9]", "", credential)
    classes = [2 if c.isdigit() else 1 if c.isupper() else 0 for c in alnum]
    changes = sum(a != b for a, b in zip(classes, classes[1:], strict=False))
    return changes >= 0.3 * (len(classes) - 1)


_NEEDS_DIGIT_FIXED_JOINED = frozenset({"aws_access_key", "google_api_key", "twilio_key", "digitalocean_token",
                                       "shopify_token", "age_key", "jwt"})


def _token_like(kind: str, credential: str) -> bool:
    if kind == "slack_token" and not re.search("[A-Za-z]", credential[5:]):
        return False  # the secret ends in letters and digits; "xoxb-123456789012" alone is the team's numeric id
    if kind in _NEEDS_DIGIT_JOINED:
        return re.search(r"\d", credential) is not None
    if kind in _NEEDS_MIXED_JOINED:
        return all(re.search(r, credential) for r in (r"\d", "[a-z]", "[A-Z]")) and _random_like(credential)
    return True


def _placeholder(pattern: re.Pattern[str], token: str, kind: str = "") -> bool:
    """"ghp_xxxxxxxx...": a placeholder, whatever the prefix. A token with a run put into it is still a
    credential when what is left of it, the run deleted, has the shape of the provider's token and looks random
    (:func:`_token_like`): a documentation token masked after a few characters ("sk_live_abcdef...0123xxxxxxxx",
    "xoxb-123456789012-xxxxxxxx", whose rest is only the team's numeric id) stays a placeholder."""
    if not _MASKED_RUN.search(token):
        return False
    rest = _MASKED_RUN.sub("", token)
    return pattern.fullmatch(rest) is None or not _token_like(kind, rest)


def _glued_token(kind: str, credential: str) -> bool:
    """A match that starts inside a word: it must look as run-together text does (see :func:`_token_like`), and a
    fixed-length format needs a digit as well (an upper-case word is not an AWS key)."""
    if kind in _NEEDS_DIGIT_FIXED_JOINED and not re.search(r"\d", credential):
        return False
    return _token_like(kind, credential)


def _hits(surface: str, joined: bool = False) -> Iterator[tuple[re.Match[str], str]]:
    for glued, patterns in ((False, _PATTERNS), (True, _JOINED_PATTERNS)):
        if glued and joined:
            continue
        for kind, pattern in patterns:
            if joined and kind in _UNPREFIXED or glued and kind in _UNPREFIXED:
                continue
            for m in pattern.finditer(surface):
                if glued and (not m.start() or not surface[m.start() - 1].isalnum()):
                    continue  # no word before it: the first pass has it
                if joined and not _token_like(kind, m[0]) or glued and not _glued_token(kind, m[0]):
                    continue  # "xoxb- tokens are bot tokens": the words after the prefix, glued, are not a token
                if kind not in _NO_PLACEHOLDER_CHECK and _placeholder(pattern, m[0], kind):
                    continue
                if (check := _VALID.get(kind)) is None or check(m):
                    yield m, kind


def _match(surface: str, joined: bool = False) -> dict[str, str]:
    return {m[0]: kind for m, kind in _hits(surface, joined)}


_Seen = dict[tuple[str, bool, bool], int]  # the surfaces scanned, as (text, joined, strip), and how deep


def _scan(surface: str, joined: bool, depth: int, found: dict[str, str], seen: _Seen, strip: bool = True) -> None:
    """Match ``surface``, then what it hides: its separators stripped (unless it has no spaces left to tell
    its words apart), an inserted run of x deleted, its escapes read, its encoded runs decoded; each of
    those the same again down to ``depth``."""
    if seen.get((surface, joined, strip), -1) >= depth:
        return
    seen[surface, joined, strip] = depth
    found.update(_match(surface, joined))
    if depth == 0:
        return
    marked = _stripped_marked(_SLUG.sub(" ", surface))[0] if strip else ""
    for derived, run_together, derived_strip in (
        *(((marked.replace(_APART, ""), True, True), (marked.replace(_APART, " "), True, True)) if strip else ()),
        (_delete_inserted_runs(surface), True, strip), (_unescaped(surface), joined, strip),
        *((decoded, False, True) for _, decoded in _decodings(surface)),
    ):
        if derived != surface:
            _scan(derived, joined or run_together, depth - 1, found, seen, derived_strip)


def _find_all(value: Any) -> dict[str, str]:
    text = leaf_text(value)
    found: dict[str, str] = {}
    seen: _Seen = {}
    leaves = _strings(value)
    plain = _surface(text)
    pairs = ["".join(leaves[i:i + 2]) for i in range(min(len(leaves) - 1, 200))]  # a token split over two fields
    for surface, joined, strip in ((text, False, True), (plain, False, True),
                                   ("".join(_surface("".join(leaves[:5000])).split()), True, False),
                                   (_surface("".join(leaves[:5000])), True, True),
                                   *((_surface(pair), True, True) for pair in pairs), (plain[::-1], False, True)):
        _scan(surface, joined, 2, found, seen, strip)
    if not found and not isinstance(value, str):
        # every leaf run together, keys and numbers too ({t[:20]: t[20:]}, [t[:-3], 123]); only when nothing else
        # was found, since a key glued to a token found in the values would read as a second token
        _scan("".join(plain.split()), True, 2, found, seen, False)
    return found


def find(value: Any) -> dict[str, str]:
    """Every credential in the strings of ``value`` (a string or a structure), as {credential: kind}.
    The text is read as written, with Unicode tricks undone, reversed, with its fields, lines and
    separators run together (a token split in pieces), with escapes read and with each base64, base32
    or hex run decoded, twice over; a credential is returned as it reads once undone. One that is the
    same letters and digits as one found before it, or holds it with a neighbouring word glued on, is
    that credential, not a second one."""
    found = _find_all(value)
    if len(found) > 50:
        return found
    kept: dict[str, str] = {}
    signatures: list[tuple[str, str]] = []
    for credential, kind in found.items():
        signature = re.sub(r"[^A-Za-z0-9]", "", credential)
        if kind in _UNPREFIXED or not any(k == kind and (known in signature or signature in known) for k, known in signatures):
            kept[credential] = kind
            signatures.append((kind, signature))
    return kept


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


_PEM_END = re.compile(r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")


def _mask_private_keys(text: str) -> str:
    """Each PEM private key replaced from its BEGIN line to its END line (to the end of the text when the
    END line is missing, as in a truncated message), not only the BEGIN line the pattern matches."""
    begins = list(dict(_PATTERNS)["private_key"].finditer(text))
    if not begins:
        return text
    ends = [m.span() for m in _PEM_END.finditer(text)]
    starts = [start for start, _ in ends]
    out, pos = [], 0
    for m in begins:
        if m.start() < pos:
            continue  # inside the block before it
        i = bisect.bisect_left(starts, m.end())
        out += [text[pos:m.start()], f"[{masked(m[0], 'private_key')}]"]
        pos = ends[i][1] if i < len(ends) else len(text)
    return "".join(out) + text[pos:]


def _masked_text(text: str) -> str:
    for credential, kind in sorted(_find_all(text).items(), key=lambda item: -len(item[0])):
        text = text.replace(credential, f"[{masked(credential, kind)}]")
        text = text.replace(credential[::-1], f"[{masked(credential, kind)}, reversed]")
    for token, decoded in _decodings(text):  # an encoded credential is cut out as it is written
        if (inside := _match(decoded)):
            credential, kind = next(iter(inside.items()))
            text = text.replace(token, f"[{masked(credential, kind)}, encoded]")
    return text


def _span_hits(text: str) -> list[tuple[int, int, str, str, bool]]:
    """(start, end, kind, credential, joined) in ``text`` for each credential that shows as written (joined
    false) or only with the text's spaces, line breaks and separators run together (joined true), from the
    credential's first character to its last, whatever lies between."""
    plain, offs = _surface_map(text)
    squeezed = [(c, o) for c, o in zip(plain, offs, strict=True) if not c.isspace()]
    stripped, stripped_offs = _stripped(plain, offs)
    apart, apart_offs = _stripped(plain, offs, True)
    spans = []
    for surface, where, joined in ((plain, offs, False), ("".join(c for c, _ in squeezed), [o for _, o in squeezed], True),
                                   (stripped, stripped_offs, True), (apart, apart_offs, True)):
        for m, kind in _hits(surface, joined):
            spans.append((where[m.start()], where[m.end() - 1] + 1, kind, m[0], joined))
    return spans


def _cut(text: str, spans: list[tuple[int, int, str, str]]) -> str:
    out, pos = [], 0
    for start, end, kind, credential in sorted(spans):
        if start < pos:
            pos = max(pos, end)
            continue
        out += [text[pos:start], f"[{masked(credential, kind)}]"]
        pos = end
    return "".join(out) + text[pos:]


def _mask_spans(text: str) -> str:
    """A credential that only reads as one with the text's spaces, line breaks and separators run
    together is cut out from its first character to its last in ``text``, whatever lies between."""
    return _cut(text, [(start, end, kind, credential) for start, end, kind, credential, _ in _span_hits(text)])


# Formats with no upper bound on the body: a hit may be the first piece of a longer token cut at a space.
_OPEN_ENDED = frozenset({"gitlab_token", "slack_token", "anthropic_key", "openai_key", "google_oauth_token", "groq_key",
                         "huggingface_token", "pypi_token", "sendgrid_key", "docker_token"})


def _piece_of_token(word: str) -> bool:
    alnum = re.sub(r"[^A-Za-z0-9]", "", word)
    return len(alnum) >= 8 and re.search(r"\d", alnum) is not None and re.search(r"[A-Za-z]", alnum) is not None


def _mask_tails(text: str) -> str:
    """A credential whose first piece is already one on its own ("sk-ant-..." cut at a space) goes on in the
    words after it that look like more of it (eight or more letters and digits with a digit and a letter),
    and they are cut out with it; plain prose after a credential is left alone."""
    hits = _span_hits(text)
    plain = [h for h in hits if not h[4]]
    spans = []
    for start, end, kind, credential, joined in hits:
        if not joined or not (inside := [p[1] for p in plain if start <= p[0] and p[1] < end]):
            continue
        stop = first = max(inside)
        for word in re.finditer(r"\S+", text[first:end]):
            if not _piece_of_token(word[0]):
                break
            stop = first + word.end()
        if stop > first:
            spans.append((start, stop, kind, credential))
    for start, end, kind, credential, joined in plain:
        if joined or kind not in _OPEN_ENDED:
            continue  # a fixed-length token is whole; the words after it are not more of it
        stop = end
        for word in itertools.islice(re.finditer(r"\s+(\S+)", text[end:end + 2000]), 8):
            if word.start() != stop - end or not _piece_of_token(word[1]):
                break
            stop = end + word.end()
        if stop > end:
            spans.append((start, stop, kind, credential))
    return _cut(text, spans)


def mask(text: str) -> str:
    """``text`` with every credential in it replaced by its masked form."""
    out = _mask_private_keys(text)
    if not _find_all(out):  # nothing in it, in any form
        return out
    out = _masked_text(_mask_tails(out))
    plain = _surface(out)
    if plain != out and (again := _masked_text(plain)) != plain:
        # A credential that shows only once normalized cannot be cut out of the original: return the
        # normalized text with it masked rather than leave it whole.
        out = again
    if find(out):  # one that reads only run together: cut out from its first character to its last
        out = _mask_spans(out)
        if leftover := find(out):  # a form with no place in the text to cut: say so rather than leak it
            credential, kind = next(iter(leftover.items()))
            return f"[{masked(credential, kind)}; the text held it in a form that could not be cut out, so it is withheld]"
    return out
