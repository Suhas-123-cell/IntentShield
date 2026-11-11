#!/usr/bin/env python3
"""Fetch stars, last-push date, archived flag and default branch of every corpus repo from the public GitHub API.

    python3 fetch_github_meta.py [corpus.json] > github_meta.json

Unauthenticated (60 requests an hour; the corpus has 26 repos), no token is read or sent. Run once and commit the output: build.py
reads github_meta.json and never touches the network. `gh` is not used.
"""

from __future__ import annotations

import datetime
import json
import sys
import urllib.request
from pathlib import Path


def fetch(repo_url: str) -> dict:
    slug = repo_url.removeprefix("https://github.com/").strip("/")
    req = urllib.request.Request(
        f"https://api.github.com/repos/{slug}",
        headers={"User-Agent": "hook-fidelity-corpus", "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.load(resp)
    return {
        "stars": data["stargazers_count"],
        "forks": data["forks_count"],
        "pushed_at": data["pushed_at"],
        "archived": data["archived"],
        "created_at": data["created_at"],
        "license": (data.get("license") or {}).get("spdx_id"),
    }


def main(argv: list[str]) -> int:
    path = Path(argv[0]) if argv else Path(__file__).resolve().parents[3] / "results" / "hook-fidelity" / "corpus.json"
    guards = json.loads(path.read_text())["guards"]
    out = {"_fetched": datetime.date.today().isoformat(), "_source": "api.github.com/repos/<owner>/<repo>, unauthenticated"}
    for guard in guards:
        try:
            out[guard["id"]] = fetch(guard["repo"])
        except Exception as exc:
            out[guard["id"]] = {"error": f"{type(exc).__name__}: {exc}"}
    json.dump(out, sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
