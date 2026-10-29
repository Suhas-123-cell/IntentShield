"""Llama Prompt Guard 2 on Groq: a learned score for "this text tries to instruct the model".

Evidence only, like the judge and the local classifier: a high score can send a call to review or
withhold a tool, never authorize anything. Errors, quota exhaustion and unscorable text give no
opinion (None) and are counted in ``errors``.

The model reads 512 tokens. Groq rejects longer input, so a text is scored in overlapping
character windows and its score is the highest window's. Characters per token vary by language,
so a window Groq rejects as too long is split in half and retried, down to ``MIN_WINDOW``.
Scores are cached per window, in memory and optionally on disk. Standard library only.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

from .judge import post_chat

URL = "https://api.groq.com/openai/v1/chat/completions"
MODELS = ("meta-llama/llama-prompt-guard-2-86m", "meta-llama/llama-prompt-guard-2-22m")
WINDOW, MIN_WINDOW = 1500, 150
# Past this many windows the rest of a text is not scored (a 1500-char window covers ~24k chars).
MAX_WINDOWS = 16


def windows(text: str, size: int) -> list[str]:
    """Overlapping slices of ``size`` characters; the overlap is a fifth, so a phrase cut by one
    boundary is whole in the next window."""
    step = size - size // 5
    return [text[i:i + size] for i in range(0, max(len(text) - size // 5, 1), step)][:MAX_WINDOWS]


class PromptGuard:
    # Window scores shared by every instance in the process; written from ``to_thread`` workers.
    _scores: dict[str, float] = {}
    _cache_lock = threading.Lock()

    def __init__(self, model: str = MODELS[0], api_key: str | None = None, threshold: float = 0.5,
                 cache: str | Path | None = None, timeout: float = 30, retries: int = 4) -> None:
        if model not in MODELS:
            raise ValueError(f"prompt guard model must be one of {MODELS}")
        self.model, self.threshold = model, threshold
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        if not self.api_key:
            raise ValueError("prompt guard needs GROQ_API_KEY")
        self.timeout, self.retries, self.errors, self.last_error = timeout, retries, 0, ""
        self.cache_path = Path(cache) if cache else None
        if self.cache_path and self.cache_path.exists():
            for line in self.cache_path.read_text().splitlines():
                item = json.loads(line)
                self._scores[item["key"]] = item["score"]

    def _window(self, text: str) -> float | None:
        """One window's score; splits it in halves while Groq says it is too long."""
        key = hashlib.sha256(f"{self.model}\0{text}".encode()).hexdigest()
        with self._cache_lock:
            if key in self._scores:
                return self._scores[key]
        content, error = post_chat(URL, self.api_key, {"model": self.model,
                                                       "messages": [{"role": "user", "content": text}]},
                                   self.timeout, self.retries)
        if content is None and "reduce the length" in error and len(text) // 2 >= MIN_WINDOW:
            halves = [self._window(part) for part in windows(text, len(text) // 2)]
            return None if None in halves else max(halves)  # type: ignore[type-var]
        try:
            score = float(content) if content is not None else None
        except ValueError:
            score, error = None, f"unparsable score: {content[:80]!r}"
        if score is None or not 0.0 <= score <= 1.0:
            self.errors, self.last_error = self.errors + 1, error or "score out of range"
            return None
        with self._cache_lock:
            self._scores[key] = score
            while len(self._scores) > 20_000:  # bounded, oldest window out
                del self._scores[next(iter(self._scores))]
        if self.cache_path:
            with self.cache_path.open("a") as handle:
                handle.write(json.dumps({"key": key, "score": score}) + "\n")
        return score

    def score(self, text: str) -> float | None:
        """The highest window score, or None if any window could not be scored."""
        if not text.strip():
            return 0.0
        scores = [self._window(part) for part in windows(text, WINDOW)]
        return None if None in scores else max(scores)  # type: ignore[type-var]

    def flags(self, text: str) -> bool | None:
        score = self.score(text)
        return None if score is None else score >= self.threshold
