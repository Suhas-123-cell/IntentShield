"""The one way IntentShield sends a JSON request to a model provider: a POST to an ``http`` or ``https`` address only."""
from __future__ import annotations

import json
import urllib.request
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit


def open_json_post(url: str, payload: Any, headers: Mapping[str, str], timeout: float) -> Any:
    """The open response to a JSON POST of ``payload`` (use it as a context manager). A URL that is not ``http`` or ``https``
    (``file:``, ``ftp:``, a bare path) raises ``ValueError``: ``urllib`` would open it, and the address can come from a
    setting. Errors of the request itself are those of ``urllib.request.urlopen``."""
    scheme = urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"not an http or https address: {url[:60]!r}")
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(url, data, {"Content-Type": "application/json", **headers}, method="POST")  # noqa: S310
    return urllib.request.urlopen(request, timeout=timeout)  # noqa: S310  (the scheme was checked above)
