"""NuGet versions: a port of NuGet.Versioning's parsing (`NuGetVersion.TryParse`), normalized form
(`ToNormalizedString`) and order (`VersionComparer.Default`).

A version is one to four numbers, then an optional prerelease (`-` and dot-separated labels) and optional build
metadata (`+...`). Missing numbers are 0 and leading zeros don't count, so `1`, `1.0`, `1.0.0` and `1.0.0.0` are one
version. The normalized form writes three numbers, a fourth only when it isn't 0, and the labels, without the
metadata: `1.01.0.0-Beta+abc` is `1.1.0-Beta`. nuget.org's paths use it in lower case (`canonical`).

Order: the four numbers, then a release above any of its prereleases, then the labels one by one (numbers compare as
numbers and sort below text, text compares without regard to case, and fewer labels sort first). Metadata is
ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

_PART = re.compile(r"[0-9A-Za-z-]+")
_NUMBER = re.compile(r"[0-9]+")
_INT_LABEL = re.compile(r"-?[0-9]+")  # what .NET's int.TryParse accepts among label characters
INT_MAX = 2**31 - 1


@dataclass(frozen=True, slots=True)
class NuGetVersion:
    major: int
    minor: int
    patch: int
    revision: int
    release: tuple[str, ...] = ()  # the prerelease labels, as written
    metadata: str = ""
    key: tuple[Any, ...] = field(default=(), compare=False, repr=False)

    @property
    def is_prerelease(self) -> bool:
        return bool(self.release)

    @property
    def normalized(self) -> str:
        """NuGet's normalized string: `1.0.0`, `1.0.0.1`, `1.0.0-Beta.1` (labels as written, no metadata)."""
        out = f"{self.major}.{self.minor}.{self.patch}"
        if self.revision:
            out += f".{self.revision}"
        if self.release:
            out += "-" + ".".join(self.release)
        return out

    @property
    def canonical(self) -> str:
        """The normalized string in lower case: how nuget.org spells the version in paths, and SlowShield's key."""
        return self.normalized.lower()


def _label_key(label: str) -> tuple[int, int, str]:
    if _INT_LABEL.fullmatch(label):
        n = int(label)
        if -INT_MAX - 1 <= n <= INT_MAX:
            return (0, n, "")
    return (1, 0, label.lower())  # OrdinalIgnoreCase: ASCII labels, so lower() is the same order


def _valid_label(label: str) -> bool:
    """`IsValidPart` without leading zeros: letters, digits and `-`; `0` is fine, `01` is not."""
    if not _PART.fullmatch(label):
        return False
    return not (len(label) > 1 and label[0] == "0" and label.isdigit())


@lru_cache(maxsize=65536)
def parse(value: str) -> NuGetVersion | None:
    """The version, or None when NuGet wouldn't accept it. Surrounding whitespace is ignored; whitespace inside is
    refused (NuGet accepts some, but no registry or path carries it)."""
    text = value.strip()
    if not text or any(c.isspace() for c in text):
        return None
    dash, plus = text.find("-"), text.find("+")
    metadata: str | None = None
    labels: str | None = None
    if plus >= 0 and (dash < 0 or plus < dash):
        core, metadata = text[:plus], text[plus + 1 :]
    elif dash >= 0:
        core, rest = text[:dash], text[dash + 1 :]
        labels, sep, meta = rest.partition("+")
        metadata = meta if sep else None
    else:
        core = text
    numbers = core.split(".")
    if not 1 <= len(numbers) <= 4 or not all(_NUMBER.fullmatch(n) for n in numbers):
        return None
    parts = [int(n) for n in numbers]
    if any(p > INT_MAX for p in parts):
        return None
    parts += [0] * (4 - len(parts))
    release: tuple[str, ...] = ()
    if labels is not None:
        release = tuple(labels.split("."))
        if not all(_valid_label(label) for label in release):
            return None
    if metadata is not None and not all(_PART.fullmatch(p) for p in metadata.split(".")):
        return None
    major, minor, patch, revision = parts
    release_key: tuple[Any, ...] = (1,) if not release else (0, *(_label_key(label) for label in release))
    return NuGetVersion(
        major, minor, patch, revision, release, metadata or "", (major, minor, patch, revision, release_key)
    )


def canonical(value: str) -> str | None:
    v = parse(value)
    return None if v is None else v.canonical


def compare(a: str, b: str) -> int | None:
    """-1, 0 or 1 in NuGet's order, or None when either isn't a version."""
    va, vb = parse(a), parse(b)
    if va is None or vb is None:
        return None
    return (va.key > vb.key) - (va.key < vb.key)
