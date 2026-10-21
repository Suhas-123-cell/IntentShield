"""Prompt-injection detection: one corpus, every detector, recall per attack family and benign false flags.

    .venv/bin/python benchmarks/injection_eval.py [--classifier artifacts/injection-deberta-v3-small] [--judge groq]

Corpus (label ``instruction`` = tries to steer the agent, ``data`` = benign):
- ``artifacts/injection/dataset.jsonl`` (benchmarks/injection_data.py): MCPTox poisoned and clean
  descriptions, generated outputs in four injection styles and benign ones, and translations. Split by
  MCPTox server; only its ``test`` split is scored by default, since the classifier trained on the rest.
- InjecAgent (``artifacts/data/InjecAgent``): every injected tool response of the four settings, and the
  17 user-case response templates with the attacker slot left empty as benign.
- AgentDojo (``artifacts/data/agentdojo-strings.jsonl``, benchmarks/agentdojo_export.py): five attacks'
  injection texts and the suites' default environment strings as benign.
- Hard benign texts (``artifacts/injection/hard_negatives.jsonl``, benchmarks/hard_negatives.py): agent-
  addressed guidance, quoted attacks and human-to-human requests. Split by topic; ``test`` is scored, and
  ``train`` may seed learned detectors.
External rows are never trained on (split ``external``). The family of a row is its source, with the
translations of each source merged into one ``_translated`` family.

A detector maps (text, kind) to flagged or not, where kind is ``description`` or ``output``; it returns
None where it does not apply (the judge has no output check). Wilson CIs treat rows as independent; they
are not (rows share templates), so read them as a floor.
"""
from __future__ import annotations

import argparse
import collections
import functools
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Callable

from dotenv import load_dotenv

from intentshield.evaluation import wilson
from intentshield.mcp_inspect import scan_description, scan_output

Detector = Callable[[str, str], "bool | None"]
INJECAGENT_SETTINGS = ("dh_base", "dh_enhanced", "ds_base", "ds_enhanced")
LANGUAGES = ("spanish", "french", "german", "chinese", "hindi", "portuguese")  # injection_data.py's


def kind_of(source: str) -> str:
    return "description" if "description" in source else "output"


def family_of(source: str) -> str:
    """The source, with the six translation sources of each style merged (a few rows each)."""
    base, _, language = source.rpartition("_")
    return f"{base}_translated" if language in LANGUAGES else source


def load_corpus(dataset: Path, injecagent: Path, agentdojo: Path, hard: Path | None = None) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in dataset.read_text().splitlines()] if dataset.exists() else []
    if hard and hard.exists():
        rows += [json.loads(line) for line in hard.read_text().splitlines() if line.strip()]
    if injecagent.exists():
        seen = set()
        for setting in INJECAGENT_SETTINGS:
            for case in json.loads((injecagent / f"test_cases_{setting}.json").read_text()):
                if case["Tool Response"] not in seen:
                    seen.add(case["Tool Response"])
                    rows.append({"text": case["Tool Response"], "label": "instruction",
                                 "source": f"injecagent_{setting}", "group": case["User Tool"]})
        for line in (injecagent / "user_cases.jsonl").read_text().splitlines():
            case = json.loads(line)
            rows.append({"text": case["Tool Response Template"].replace("<Attacker Instruction>", ""),
                         "label": "data", "source": "injecagent_benign", "group": case["User Tool"]})
    if agentdojo.exists():
        rows += [json.loads(line) for line in agentdojo.read_text().splitlines()]
    for row in rows:
        row.setdefault("split", "external")
        row["kind"], row["family"] = kind_of(row["source"]), family_of(row["source"])
    return rows


def rules(text: str, kind: str) -> bool:
    return bool(scan_description(text) if kind == "description" else scan_output(text))


def detectors(args: argparse.Namespace) -> dict[str, Detector]:
    found: dict[str, Detector] = {"rules": rules}
    if args.classifier:
        from intentshield.injection_classifier import InjectionClassifier
        classifier = InjectionClassifier(args.classifier)
        if not classifier.ready:
            sys.exit(f"classifier not usable: {classifier.reason}")
        found["classifier"] = lambda text, kind: classifier.flags(text)
    if args.prompt_guard:
        from intentshield.prompt_guard import PromptGuard
        guard = PromptGuard(args.prompt_guard, threshold=args.prompt_guard_threshold,
                            cache=Path("artifacts/injection-eval/prompt-guard-scores.jsonl"))
        found["prompt_guard"] = lambda text, kind: guard.flags(text)
    if args.exemplars:
        from intentshield.exemplars import Embedder, ExemplarIndex
        embedder = Embedder(args.embedder)
        if not embedder.ready:
            sys.exit(f"embedder not usable: {embedder.reason}")
        index = ExemplarIndex.load(args.exemplars, embedder)
        found["exemplars"] = lambda text, kind: index.flags(text, kind)
    if args.judge:
        from intentshield.judge import Judge
        judge = Judge.from_spec(args.judge)
        found["judge"] = lambda text, kind: (judge.tool("tool", text) is not None) if kind == "description" else None
    found = {name: functools.lru_cache(maxsize=None)(detect) for name, detect in found.items()}
    for combo in filter(None, (args.combine or "").split(",")):
        parts = combo.split("+")
        if not set(parts) <= set(found):
            sys.exit(f"--combine {combo}: unknown detector among {sorted(found)}")
        found[combo] = any_of({part: found[part] for part in parts})
    if len(found) > 1:
        found["any"] = any_of({k: v for k, v in found.items() if "+" not in k})
    return found


def any_of(found: dict[str, Detector]) -> Detector:
    """Flagged by any detector that applies; None if none applies."""
    def detect(text: str, kind: str) -> bool | None:
        votes = [v for v in (d(text, kind) for d in found.values()) if v is not None]
        return any(votes) if votes else None
    return detect


def evaluate(rows: list[dict[str, Any]], found: dict[str, Detector]) -> dict[str, Any]:
    """Per detector: flagged k/n per family and per label, over the rows it applies to."""
    report: dict[str, Any] = {}
    for name, detect in found.items():
        by_family: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
        by_label: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
        for row in rows:
            flagged = detect(row["text"], row["kind"])
            if flagged is None:
                continue
            for counter in (by_family[f"{row['label']}:{row['family']}"], by_label[row["label"]]):
                counter["n"] += 1
                counter["flagged"] += flagged
        rate = lambda c: {"flagged": c["flagged"], "n": c["n"], "rate": round(c["flagged"] / c["n"], 4),
                          "ci95": wilson(c["flagged"], c["n"])}
        report[name] = {"recall": rate(by_label["instruction"]) if by_label["instruction"]["n"] else None,
                        "benign_flagged": rate(by_label["data"]) if by_label["data"]["n"] else None,
                        "families": {k: rate(c) for k, c in sorted(by_family.items())}}
    return report


def print_report(report: dict[str, Any]) -> None:
    names = list(report)
    families = sorted({f for r in report.values() for f in r["families"]})
    cell = lambda r: f"{r['flagged']}/{r['n']} {100 * r['flagged'] / r['n']:.1f}%" if r else "-"
    print("family".ljust(52) + "".join(n.ljust(20) for n in names))
    for key, label in (("recall", "ALL instruction (recall)"), ("benign_flagged", "ALL data (benign flagged)")):
        print(label.ljust(52) + "".join(cell(report[n][key]).ljust(20) for n in names))
    for family in families:
        print(family.ljust(52) + "".join(cell(report[n]["families"].get(family)).ljust(20) for n in names))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=Path("artifacts/injection/dataset.jsonl"))
    parser.add_argument("--injecagent", type=Path, default=Path("artifacts/data/InjecAgent/data"))
    parser.add_argument("--agentdojo", type=Path, default=Path("artifacts/data/agentdojo-strings.jsonl"))
    parser.add_argument("--splits", default="test,external", help="dataset splits to score (external = never trained on)")
    parser.add_argument("--classifier", default=None, help="injection classifier artifact dir")
    parser.add_argument("--judge", default=None, help="groq or gemini[:model]; descriptions only, uses free-tier quota")
    parser.add_argument("--prompt-guard", nargs="?", const="meta-llama/llama-prompt-guard-2-86m", default=None,
                        help="Llama Prompt Guard 2 on Groq (free tier; scores cached on disk)")
    parser.add_argument("--prompt-guard-threshold", type=float, default=0.5)
    parser.add_argument("--exemplars", type=Path, default=None, help="exemplar index dir (intentshield.exemplars)")
    parser.add_argument("--embedder", type=Path, default=Path("artifacts/embedder-e5-small"))
    parser.add_argument("--hard", type=Path, default=Path("artifacts/injection/hard_negatives.jsonl"))
    parser.add_argument("--combine", default=None,
                        help="extra any-of columns, e.g. rules+exemplars,rules+prompt_guard")
    parser.add_argument("--rows-out", type=Path, default=None,
                        help="per-row verdicts as JSONL (text hash, source, label, split, every detector)")
    parser.add_argument("--out", type=Path, default=Path("artifacts/injection-eval/report.json"))
    args = parser.parse_args(argv)
    load_dotenv(".env")
    rows = [r for r in load_corpus(args.dataset, args.injecagent, args.agentdojo, args.hard)
            if r["split"] in args.splits.split(",")]
    found = detectors(args)
    report = evaluate(rows, found)
    if args.rows_out:  # detectors are cached, so this costs nothing more
        args.rows_out.parent.mkdir(parents=True, exist_ok=True)
        args.rows_out.write_text("".join(json.dumps({
            "sha256": hashlib.sha256(r["text"].encode()).hexdigest()[:16], "source": r["source"],
            "family": r["family"], "label": r["label"], "split": r["split"], "kind": r["kind"],
            "verdicts": {name: detect(r["text"], r["kind"]) for name, detect in found.items()}}) + "\n" for r in rows))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"rows": len(rows), "splits": args.splits, "detectors": report}, indent=2))
    print(f"{len(rows)} rows, splits {args.splits}")
    print_report(report)


if __name__ == "__main__":
    main()
