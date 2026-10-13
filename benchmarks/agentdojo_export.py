"""Export AgentDojo injection texts and benign environment strings as JSONL (no model calls).

Runs in its own environment, since agentdojo is not a project dependency:

    uv venv artifacts/data/agentdojo-venv --python 3.12
    uv pip install --python artifacts/data/agentdojo-venv/bin/python agentdojo
    artifacts/data/agentdojo-venv/bin/python benchmarks/agentdojo_export.py --out artifacts/data/agentdojo-strings.jsonl

Injections: every suite's injection tasks rendered by each attack, against the suite's first user
task. Benign: every distinct string of 20+ characters in each suite's default environment, with
the injection vectors left at their benign defaults.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterator

from agentdojo.attacks.attack_registry import load_attack
from agentdojo.task_suite.load_suites import get_suites

ATTACKS = ("important_instructions", "tool_knowledge", "system_message", "ignore_previous", "direct")


class _Pipeline:
    # A model AgentDojo maps to the neutral "AI assistant"; the attacks only read the name.
    name = "meta-llama/Llama-3-70b-chat-hf"


def strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from strings(v)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="v1")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    rows, seen = [], set()
    for name, suite in sorted(get_suites(args.version).items()):
        user_task = next(iter(suite.user_tasks.values()))
        for attack_name in ATTACKS:
            attack = load_attack(attack_name, suite, _Pipeline())
            for task_id, task in sorted(suite.injection_tasks.items()):
                text = next(iter(attack.attack(user_task, task).values()))
                rows.append({"text": text, "label": "instruction", "source": f"agentdojo_{attack_name}",
                             "group": f"{name}/{task_id}"})
        env = suite.load_and_inject_default_environment(suite.get_injection_vector_defaults())
        for text in strings(env.model_dump()):
            if len(text) >= 20 and text not in seen:
                seen.add(text)
                rows.append({"text": text, "label": "data", "source": "agentdojo_environment", "group": name})
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("".join(json.dumps(r) + "\n" for r in rows))
    print(f"{len(rows)} rows -> {args.out}")


if __name__ == "__main__":
    main()
