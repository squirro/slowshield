"""Injectable wall clock so policy decisions are testable without monkeypatching time."""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> float:
        """Current UNIX time in seconds."""
        ...


class SystemClock:
    __slots__ = ()

    def now(self) -> float:
        return time.time()


class FrozenClock:
    """Test clock: stays put until advanced."""

    __slots__ = ("_t",)

    def __init__(self, t: float) -> None:
        self._t = float(t)

    def now(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += seconds

    def set(self, t: float) -> None:
        self._t = float(t)
