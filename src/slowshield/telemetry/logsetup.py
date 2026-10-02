"""Structured JSON logging to stdout, correlated with the active trace."""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any

import msgspec
from opentelemetry import trace

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {"message", "asctime", "taskName"}
_REDACT = ("token", "authorization", "password", "secret", "api_key")
_encoder = msgspec.json.Encoder()


def _clean(key: str, value: Any) -> Any:
    if any(r in key.lower() for r in _REDACT):
        return "[redacted]"
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [v if isinstance(v, (str, int, float, bool)) or v is None else str(v) for v in value]
    return str(value)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        ctx = trace.get_current_span().get_span_context()
        if ctx.is_valid:
            out["trace_id"] = format(ctx.trace_id, "032x")
            out["span_id"] = format(ctx.span_id, "016x")
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                out[key] = _clean(key, value)
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return _encoder.encode(out).decode()


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = {k: _clean(k, v) for k, v in record.__dict__.items() if k not in _RESERVED and not k.startswith("_")}
        return f"{base} {extras}" if extras else base


class _Handler(logging.StreamHandler):
    """Marker type so repeated `configure()` calls replace (not stack) our handler."""


def configure(level: str | None = None, fmt: str | None = None) -> None:
    level = (level or os.environ.get("SLOWSHIELD_LOG_LEVEL") or "info").upper()
    fmt = (fmt or os.environ.get("SLOWSHIELD_LOG_FORMAT") or ("json" if not sys.stderr.isatty() else "text")).lower()
    handler = _Handler(sys.stdout)
    handler.setFormatter(
        JsonFormatter() if fmt == "json" else TextFormatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    )
    root = logging.getLogger()
    for h in list(root.handlers):
        if isinstance(h, _Handler):
            root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(level)
    # Quiet chatty libraries unless debugging.
    for noisy in ("granian.access", "urllib3", "opentelemetry"):
        logging.getLogger(noisy).setLevel(max(logging.WARNING, root.level))
