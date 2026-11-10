"""Derive the version ranges of the verdict-translation table from the lanes' per-release outcomes, using only the FIT releases.

    python benchmarks/hook_fidelity/derive_table.py [--all] > ranges.json

Input: results/hook-fidelity/mitigation/lane-features.json (class of each measured release, per harness and feature,
extracted from the lanes' runs.jsonl by the r3-mitigation lane). The releases of each harness are sorted; the FIT set is every
other one (positions 0, 2, 4, ...), the HELD-OUT set the rest (positions 1, 3, 5, ...); a feature is derived from the fit
releases that measured it. Between two fit releases of different class the versions are NOT assigned to either side: that gap is
class "uncertain", and the translation treats it as the worse of the two. Outside the measured releases the class is
"unmeasured". ``--all`` derives from every release (what ships after the held-out check).

A span is ``[kind, lo, hi, class]``: kind "run" covers lo..hi inclusive, "gap" covers the versions strictly between lo and hi.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FEATURES = HERE.parents[1] / "results" / "hook-fidelity" / "mitigation" / "lane-features.json"
SUPPLEMENT = FEATURES.with_name("lane-features-r4.json")   # releases measured after the held-out check (round 4)
# Releases the lanes could not use as a measurement of anything (listed so the split is reproducible).
UNUSABLE = {"claude": ("2.1.0",)}


def vkey(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split(".")[:3])


def usable_releases(features: dict, harness: str) -> list[str]:
    """Every release the lane measured at least one feature on, sorted: the list that is split into fit and held-out."""
    seen: set[str] = set()
    for classes in features[harness].values():
        seen |= set(classes)
    return sorted(seen - set(UNUSABLE.get(harness, ())), key=vkey)


def split(features: dict, harness: str) -> tuple[list[str], list[str]]:
    releases = usable_releases(features, harness)
    return releases[0::2], releases[1::2]


def derive(classes: dict[str, str], fit: set[str] | None = None) -> list[list]:
    observed = sorted((v for v in classes if fit is None or v in fit), key=vkey)
    spans: list[list] = []
    i = 0
    while i < len(observed):
        j = i
        while j + 1 < len(observed) and classes[observed[j + 1]] == classes[observed[i]]:
            j += 1
        spans.append(["run", observed[i], observed[j], classes[observed[i]]])
        if j + 1 < len(observed):
            spans.append(["gap", observed[j], observed[j + 1], "uncertain"])
        i = j + 1
    return spans


def with_supplement(features: dict) -> dict:
    """``features`` plus the round 4 releases of lane-features-r4.json (the Claude ask bisect). Only the shipped table uses it;
    the fit and held-out split, and the frozen fit-only table, are made from the round 3 features alone."""
    merged = {h: {f: dict(c) for f, c in by.items()} for h, by in features.items()}
    if SUPPLEMENT.exists():
        for harness, by_feature in json.loads(SUPPLEMENT.read_text()).items():
            if harness.startswith("_"):
                continue
            for feature, classes in by_feature.items():
                merged.setdefault(harness, {}).setdefault(feature, {}).update(classes)
    return merged


def derive_all(features: dict, use_all: bool = False) -> dict:
    out: dict = {}
    source = with_supplement(features) if use_all else features
    for harness in features:
        fit, held = split(features, harness)
        use = None if use_all else set(fit)
        out[harness] = {"fit": fit, "held_out": held,
                        "ranges": {feature: derive(classes, use) for feature, classes in source[harness].items()}}
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--all", action="store_true", help="derive from every release, not only the fit set")
    args = parser.parse_args()
    print(json.dumps(derive_all(json.loads(FEATURES.read_text()), args.all), indent=1))


if __name__ == "__main__":
    main()
