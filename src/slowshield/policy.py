"""The release-age policy: pure functions, no I/O.

A *candidate* is one installable unit (a PyPI file or an npm version) with a publish time and a
version. Evaluation decides which candidates may be served right now:

1. blocked candidates are never served (not even when failing open);
2. candidates at least `delay` old are served;
3. if *no* unblocked candidate is old enough and fail-open is enabled, every unblocked candidate is
   served instead (installs keep working for brand-new packages; the event is recorded);
4. a candidate without a known publish time is treated as too new.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

DAY = 86400.0


@dataclass(frozen=True, slots=True)
class Candidate[T]:
    item: T
    version: str | None
    published: float | None  # UNIX seconds


@dataclass(slots=True)
class Evaluation[T]:
    allowed: list[Candidate[T]] = field(default_factory=list)
    held: list[Candidate[T]] = field(default_factory=list)  # too new (and not blocked)
    blocked: list[Candidate[T]] = field(default_factory=list)
    fail_open: bool = False
    # Earliest moment at which a currently-held candidate becomes servable (cache expiry hint).
    next_change: float = math.inf

    @property
    def everything_blocked(self) -> bool:
        return bool(self.blocked) and not self.allowed and not self.held


def age_seconds(published: float | None, now: float) -> float | None:
    return None if published is None else now - published


def is_old_enough(published: float | None, delay_days: float, now: float) -> bool:
    if delay_days <= 0:
        return published is None or published <= now
    if published is None:
        return False
    return now - published >= delay_days * DAY


def retry_after(published: float | None, delay_days: float, now: float) -> int | None:
    """Seconds until the candidate becomes servable, or None if unknown (no publish time)."""
    if published is None:
        return None
    return max(0, math.ceil(published + delay_days * DAY - now))


def evaluate[T](
    candidates: Iterable[Candidate[T]],
    *,
    now: float,
    delay_for: Callable[[str | None], float],
    is_blocked: Callable[[str | None], bool],
    fail_open: bool,
) -> Evaluation[T]:
    ev: Evaluation[T] = Evaluation()
    for c in candidates:
        if is_blocked(c.version):
            ev.blocked.append(c)
            continue
        delay = delay_for(c.version)
        if is_old_enough(c.published, delay, now):
            ev.allowed.append(c)
        else:
            ev.held.append(c)
            if c.published is not None:
                ev.next_change = min(ev.next_change, c.published + delay * DAY)
    if not ev.allowed and ev.held and fail_open:
        ev.allowed, ev.held = ev.held, []
        ev.fail_open = True
        # Once failing open, the result changes as soon as anything graduates.
    return ev
