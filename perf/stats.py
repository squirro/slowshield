"""Small, dependency-free statistics for the perf gate."""

from __future__ import annotations

import itertools
import math
import statistics
from collections.abc import Sequence


def median(xs: Sequence[float]) -> float:
    return statistics.median(xs) if xs else math.nan


def mann_whitney_p(a: Sequence[float], b: Sequence[float]) -> float:
    """Exact two-sided Mann-Whitney U p-value (enumeration; fine for the handful of rounds we run).

    Falls back to the normal approximation above ~20 samples per side.
    """
    n1, n2 = len(a), len(b)
    if n1 == 0 or n2 == 0:
        return 1.0
    combined = sorted((v, i) for i, v in enumerate(list(a) + list(b)))
    ranks = [0.0] * (n1 + n2)
    i = 0
    while i < len(combined):
        j = i
        while j + 1 < len(combined) and combined[j + 1][0] == combined[i][0]:
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[combined[k][1]] = avg
        i = j + 1
    r1 = sum(ranks[:n1])
    u1 = r1 - n1 * (n1 + 1) / 2
    mean_u = n1 * n2 / 2
    observed = abs(u1 - mean_u)
    if n1 + n2 > 40:
        sd = math.sqrt(n1 * n2 * (n1 + n2 + 1) / 12)
        z = (observed - 0.5) / sd if sd else 0.0
        return math.erfc(max(0.0, z) / math.sqrt(2))
    total = 0
    extreme = 0
    for combo in itertools.combinations(range(n1 + n2), n1):
        u = sum(ranks[c] for c in combo) - n1 * (n1 + 1) / 2
        total += 1
        if abs(u - mean_u) >= observed - 1e-9:
            extreme += 1
    return extreme / total


def relative_change(baseline: float, candidate: float) -> float:
    if baseline == 0 or math.isnan(baseline) or math.isnan(candidate):
        return 0.0
    return (candidate - baseline) / baseline
