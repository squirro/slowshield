"""JSON from another instance of the shield wall, read strictly.

A signed message can still carry numbers that break the code reading it rather than any rule: NaN and the
infinities, which compare false with everything and which SQLite stores as NULL, and integers too large for a float
or a SQLite INTEGER, which raise OverflowError deep inside a transaction. Every number another instance sends is read
here as a finite float or an integer that fits in 64 bits; anything else makes the whole message malformed.
"""

from __future__ import annotations

import json
import math
from typing import Any

INT64 = 1 << 63
# Sequence numbers, cursors and policy versions: far below INT64, so a version that grows by one never overflows.
MAX_SEQ = 1 << 53


def _int(text: str) -> int:
    value = int(text)
    if not -INT64 <= value < INT64:
        raise ValueError("integer out of range")
    return value


def _float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("number out of range")
    return value


def _constant(name: str) -> Any:
    raise ValueError(f"{name} is not a number")


def loads(data: bytes | str) -> Any:
    """JSON from another instance. NaN, the infinities, integers beyond 64 bits and nesting too deep to parse raise
    ValueError."""
    try:
        return json.loads(data, parse_int=_int, parse_float=_float, parse_constant=_constant)
    except RecursionError as exc:
        raise ValueError("nested too deeply") from exc


def seq(value: Any) -> int:
    """A sequence number, cursor or policy version from another instance."""
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_SEQ:
        raise ValueError(f"not a sequence number: {str(value)[:40]}")
    return value
