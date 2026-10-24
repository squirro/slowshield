"""RubyGems versions: a port of `Gem::Version`'s parsing and order.

A version is numbers and letters separated by dots (`1.2.3`, `1.0.0.rc1`, `2.0.0.pre.beta`); a `-` is read as
`.pre.`. It splits into segments, runs of digits (numbers) and runs of letters (text), so `1.0.0rc1` is
`1, 0, 0, "rc", 1`. Any letter makes it a prerelease.

Order (`Gem::Version#<=>`): trailing zeros of the numeric part and of the text part are dropped, then the segments
are compared one by one, a missing segment counting as 0. Numbers compare as numbers, text as text, and a number is
above any text: `1.0.a` < `1.0` < `1.0.1`. `1.0` and `1.0.0` are equal in order, but rubygems.org keeps them as two
versions, so SlowShield matches exact versions as spelled.
"""

from __future__ import annotations

import re
from functools import lru_cache, total_ordering

_PATTERN = re.compile(r"[0-9]+(?:\.[0-9a-zA-Z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")
_SEGMENT = re.compile(r"[0-9]+|[a-zA-Z]+")

type Segment = int | str


@total_ordering
class GemVersion:
    __slots__ = ("segments", "text")

    def __init__(self, text: str, segments: tuple[Segment, ...]) -> None:
        self.text = text
        self.segments = segments  # canonical segments: what the order compares

    @property
    def is_prerelease(self) -> bool:
        return any(isinstance(s, str) for s in self.segments)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, GemVersion) and compare_segments(self.segments, other.segments) == 0

    def __lt__(self, other: GemVersion) -> bool:
        return compare_segments(self.segments, other.segments) < 0

    def __hash__(self) -> int:
        return hash(self.segments)

    def __repr__(self) -> str:
        return f"GemVersion({self.text!r})"


def _canonical(segments: list[Segment]) -> tuple[Segment, ...]:
    """`Gem::Version#canonical_segments`: drop the trailing zeros of the numeric part and of the rest."""
    split = next((i for i, s in enumerate(segments) if isinstance(s, str)), len(segments))
    out: list[Segment] = []
    for part in (segments[:split], segments[split:]):
        end = len(part)
        while end and part[end - 1] == 0:
            end -= 1
        out.extend(part[:end])
    return tuple(out)


@lru_cache(maxsize=65536)
def parse(value: str) -> GemVersion | None:
    text = value.strip()
    if not _PATTERN.fullmatch(text):
        return None
    segments: list[Segment] = [int(s) if s.isdigit() else s for s in _SEGMENT.findall(text.replace("-", ".pre."))]
    return GemVersion(text, _canonical(segments))


def compare_segments(a: tuple[Segment, ...], b: tuple[Segment, ...]) -> int:
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else 0
        y = b[i] if i < len(b) else 0
        if x == y:
            continue
        if isinstance(x, str) and isinstance(y, int):
            return -1
        if isinstance(x, int) and isinstance(y, str):
            return 1
        return -1 if x < y else 1  # ty: ignore[unsupported-operator]
    return 0


def compare(a: str, b: str) -> int | None:
    pa, pb = parse(a), parse(b)
    if pa is None or pb is None:
        return None
    return compare_segments(pa.segments, pb.segments)
