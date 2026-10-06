"""White-box evasion of the description scanner (no model needed).

Takes every MCPTox poisoned description the scanner currently flags and rewrites it
the way an attacker who has read mcp_inspect.py would: same instruction for an LLM
reader, different surface for the regexes. Reports how many stay flagged.

    .venv/bin/python benchmarks/adaptive.py --data artifacts/data/MCPTox-Benchmark
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).parent))
import mcptox  # noqa: E402

from intentshield.evaluation import wilson  # noqa: E402
from intentshield.mcp_inspect import distinctive_values, scan_description  # noqa: E402

_LOOKALIKE = str.maketrans({"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "i": "і"})  # Cyrillic
_PARAPHRASE = (
    (r"<\s*(/?)\s*important\s*>", r"[\1NOTE]"),
    (r"ignore (?:all )?(?:the )?previous instructions", "set aside what you were told earlier"),
    (r"\bmust\b", "are required to"),
    (r"\bbefore (?:using|calling|invoking)\b", "prior to any use of"),
    (r"\b(?:call|invoke|use|run|execute)\b", "make a request to"),
    (r"\bfirst\b", "at the outset"),
    (r"\bpriority\b", "precedence"),
    (r"\b(?:do not|don't|never) (?:tell|inform|mention)", "keep it from"),
    (r"\bfail(?:ure|ing)? to\b", "skipping this step would mean you do not"),
)


def _words(text: str, fn: Callable[[str], str]) -> str:
    # Leave paths, URLs and other distinctive values intact: the payload must still work.
    keep = " ".join(distinctive_values(text))
    return re.sub(r"[A-Za-z]{4,}", lambda m: m.group(0) if m.group(0).lower() in keep else fn(m.group(0)), text)


def homoglyph(text: str) -> str:
    return _words(text, lambda w: w.translate(_LOOKALIKE))


def zero_width(text: str) -> str:
    return _words(text, lambda w: w[:2] + "​" + w[2:])


def paraphrase(text: str) -> str:
    for pattern, repl in _PARAPHRASE:
        text = re.sub(pattern, repl, text, flags=re.I)
    return text


def line_split(text: str) -> str:
    # Most rules stop at a newline ([^.\n]); break the sentence between trigger and verb.
    return re.sub(r"\b(must|before|after|when|ignore|always|priority)\b", "\n\\1", text, flags=re.I)


TRANSFORMS: dict[str, Callable[[str], str]] = {
    "original": lambda t: t,
    "homoglyph": homoglyph,
    "zero_width": zero_width,
    "paraphrase": paraphrase,
    "line_split": line_split,
    "paraphrase+zero_width": lambda t: zero_width(paraphrase(t)),
}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path("artifacts/data/MCPTox-Benchmark"))
    parser.add_argument("--out", type=Path, default=Path("artifacts/adaptive"))
    args = parser.parse_args(argv)

    raw = json.loads((args.data / "response_all.json").read_text())
    caught = []
    for sv in raw["servers"].values():
        for inst in sv["malicious_instance"]:
            if inst.get("wrong_data"):
                continue
            system, name = inst["datas"][0]["system"], mcptox.poisoned_name(inst["poisoned_tool"])
            text = mcptox.parse_descriptions(system).get(name, "")
            others = [n for n in mcptox.parse_tools(system) if n != name]
            if scan_description(text, others):
                caught.append((text, others))
    report = {}
    for transform, fn in TRANSFORMS.items():
        flagged = sum(bool(scan_description(fn(text), others)) for text, others in caught)
        report[transform] = {"still_flagged": round(flagged / len(caught), 4), "n": len(caught),
                             "ci95": wilson(flagged, len(caught))}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
