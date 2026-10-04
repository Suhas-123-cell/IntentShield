from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """One JSON object per line; extra fields passed via `extra=` are included."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            **{k: v for k, v in record.__dict__.items() if k not in _RESERVED},
        }
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger("intentshield")
    root.handlers[:] = [handler]
    root.setLevel(os.getenv("INTENTSHIELD_LOG_LEVEL", "INFO").upper())
    root.propagate = False
