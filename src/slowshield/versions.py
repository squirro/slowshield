"""Version parsing/ordering for PyPI (PEP 440) and npm (SemVer 2.0), plus advisory range matching.

Ranges use the comma-separated comparator form shared by GitHub advisories and our blocklist table,
e.g. ``">= 1.0.0, < 1.4.2"`` or ``"= 0.30.4"``. Each comma part must hold (logical AND).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from packaging.version import InvalidVersion, Version

_SEMVER = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)
_COMPARATOR = re.compile(r"^\s*(>=|<=|>|<|==|=|!=)?\s*(\S+)\s*$")


@dataclass(frozen=True, slots=True, order=False)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[int | str, ...] = ()

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease)

    def _key(self) -> tuple[Any, ...]:
        # Release sorts above any prerelease of the same core; numeric identifiers sort below alnum.
        pre: tuple[Any, ...] = (
            (1,)
            if not self.prerelease
            else (0, *((0, p, "") if isinstance(p, int) else (1, 0, p) for p in self.prerelease))
        )
        return (self.major, self.minor, self.patch, pre)

    def __lt__(self, other: SemVer) -> bool:
        return self._key() < other._key()

    def __le__(self, other: SemVer) -> bool:
        return self._key() <= other._key()

    def __gt__(self, other: SemVer) -> bool:
        return self._key() > other._key()

    def __ge__(self, other: SemVer) -> bool:
        return self._key() >= other._key()


@lru_cache(maxsize=65536)
def parse_semver(value: str) -> SemVer | None:
    m = _SEMVER.match(value.strip())
    if not m:
        return None
    pre: tuple[int | str, ...] = ()
    if m.group(4):
        pre = tuple(int(p) if p.isdigit() else p for p in m.group(4).split("."))
    return SemVer(int(m.group(1)), int(m.group(2)), int(m.group(3)), pre)


@lru_cache(maxsize=65536)
def parse_pep440(value: str) -> Version | None:
    try:
        return Version(value)
    except InvalidVersion:
        return None


def canonical(ecosystem: str, version: str) -> str:
    """Canonical string used for exact version matching (blocklist, exceptions)."""
    if ecosystem == "pypi":
        v = parse_pep440(version)
        return str(v) if v is not None else version.strip()
    return version.strip().removeprefix("v") if parse_semver(version) else version.strip()


def sort_key(ecosystem: str, version: str) -> tuple[int, Any]:
    """Total-order key: parseable versions first by value, unparseable ones lexically (sorted low)."""
    if ecosystem == "pypi":
        v = parse_pep440(version)
        return (1, v) if v is not None else (0, version)
    s = parse_semver(version)
    return (1, s._key()) if s is not None else (0, version)


def is_prerelease(ecosystem: str, version: str) -> bool:
    if ecosystem == "pypi":
        v = parse_pep440(version)
        return bool(v and (v.is_prerelease or v.is_devrelease))
    s = parse_semver(version)
    return bool(s and s.is_prerelease)


def _cmp(ecosystem: str, a: str, b: str) -> int | None:
    if ecosystem == "pypi":
        va, vb = parse_pep440(a), parse_pep440(b)
    else:
        va, vb = parse_semver(a), parse_semver(b)  # type: ignore[assignment]
    if va is None or vb is None:
        return None
    return (va > vb) - (va < vb)  # type: ignore[operator]


def in_range(ecosystem: str, version: str, spec: str) -> bool:
    """True if `version` satisfies every comparator in `spec`. Unparseable input never matches."""
    parts = [p for p in spec.split(",") if p.strip()]
    if not parts:
        return False
    for part in parts:
        m = _COMPARATOR.match(part)
        if not m:
            return False
        op, bound = m.group(1) or "=", m.group(2)
        if bound in {"0", "0.0.0"} and op == ">=":
            continue
        c = _cmp(ecosystem, version, bound)
        if c is None:
            # Fall back to exact string comparison for equality operators.
            if op in {"=", "=="}:
                if canonical(ecosystem, version) != canonical(ecosystem, bound):
                    return False
                continue
            return False
        ok = {
            "=": c == 0,
            "==": c == 0,
            "!=": c != 0,
            ">": c > 0,
            ">=": c >= 0,
            "<": c < 0,
            "<=": c <= 0,
        }[op]
        if not ok:
            return False
    return True


def range_is_everything(spec: str | None) -> bool:
    """`None`, `""`, `">= 0"` and friends mean "all versions" (a package-level block)."""
    if spec is None:
        return True
    parts = [p.strip().replace(" ", "") for p in spec.split(",") if p.strip()]
    return not parts or all(p in {">=0", ">=0.0.0", ">0", "*"} for p in parts)


def exact_version(spec: str | None) -> str | None:
    """`"= 1.2.3"` -> `"1.2.3"`, else None."""
    if spec is None:
        return None
    parts = [p for p in spec.split(",") if p.strip()]
    if len(parts) != 1:
        return None
    m = _COMPARATOR.match(parts[0])
    if m and (m.group(1) in {"=", "=="}):
        return m.group(2)
    return None
