"""Server-rendered charts: axis ticks are round, distinct numbers, and gridlines sit exactly at their labels."""

from __future__ import annotations

import re

import pytest

from slowshield.ui import svg


@pytest.mark.parametrize(
    ("peak", "ticks"),
    [
        (0, [1]),
        (1, [1]),
        (2, [1, 2]),  # was 0, 1, 2, 2: quarters of the peak, rounded
        (5, [2, 4, 6]),  # was 1, 2, 4, 5
        (10, [5, 10]),
        (100, [25, 50, 75, 100]),
        (1234, [500, 1000, 1500]),
    ],
)
def test_axis_ticks(peak: int, ticks: list[int]) -> None:
    assert svg.axis_ticks(peak) == ticks


def test_axis_labels_are_distinct_and_cover_the_peak() -> None:
    for peak in range(20_001):
        ticks = svg.axis_ticks(peak)
        labels = [svg._short(t) for t in ticks]
        assert len(ticks) <= 4 and ticks[-1] >= peak, peak
        assert len(set(labels)) == len(labels), (peak, labels)
        assert all(t == int(t) for t in ticks), (peak, ticks)  # counts: never a fractional tick


def test_chart_gridlines_sit_at_their_labels() -> None:
    chart = str(svg.stacked_bars([0, 3600], {"go": {0: 2, 3600: 1}}, step=3600, order=["go"]))
    labels = re.findall(r'<text class="axis" x="38" y="[0-9.]+" text-anchor="end">([^<]+)</text>', chart)
    assert labels == ["1", "2"]
    # The 2-download bar reaches the top gridline (y = 8), the 1-download bar the middle one.
    bars = re.findall(r'<rect class="s-go" x="[0-9.]+" y="([0-9.]+)"', chart)
    grid = re.findall(r'<line class="grid" x1="44" y1="([0-9.]+)"', chart)
    assert bars == [grid[1], grid[0]]
