"""Version parsing/ordering for PyPI (PEP 440), npm and Go (SemVer 2.0), plus advisory range matching.

Ranges use the comma-separated comparator form shared by GitHub advisories and our blocklist table,
e.g. ``">= 1.0.0, < 1.4.2"`` or ``"= 0.30.4"``. Each comma part must hold (logical AND).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from packaging.version import InvalidVersion, Version

_SEMVER = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)
_COMPARATOR = re.compile(r"^\s*(>=|<=|>|<|==|=|!=)?\s*(\S+)\s*$")
_EVERYTHING = {">=0", ">=0.0.0", ">0", "*"}


def _semver_key(major: int, minor: int, patch: int, pre: tuple[int | str, ...]) -> tuple[Any, ...]:
    # A release sorts above any prerelease of the same core; numeric identifiers sort below alnum ones.
    pre_key: tuple[Any, ...] = (1,) if not pre else (0, *((0, p, "") if isinstance(p, int) else (1, 0, p) for p in pre))
    return (major, minor, patch, pre_key)


@dataclass(frozen=True, slots=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[int | str, ...] = ()
    key: tuple[Any, ...] = field(default=(), compare=False, repr=False)

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease)

    def __lt__(self, other: SemVer) -> bool:
        return self.key < other.key

    def __le__(self, other: SemVer) -> bool:
        return self.key <= other.key

    def __gt__(self, other: SemVer) -> bool:
        return self.key > other.key

    def __ge__(self, other: SemVer) -> bool:
        return self.key >= other.key


@lru_cache(maxsize=65536)
def parse_semver(value: str) -> SemVer | None:
    m = _SEMVER.match(value.strip())
    if not m:
        return None
    pre: tuple[int | str, ...] = ()
    if m.group(4):
        pre = tuple(int(p) if p.isdigit() else p for p in m.group(4).split("."))
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    return SemVer(major, minor, patch, pre, _semver_key(major, minor, patch, pre))


@lru_cache(maxsize=65536)
def parse_pep440(value: str) -> Version | None:
    try:
        return Version(value)
    except InvalidVersion:
        return None


@lru_cache(maxsize=65536)
def canonical(ecosystem: str, version: str) -> str:
    """Canonical string used for exact version matching (blocklist, exceptions)."""
    if ecosystem == "pypi":
        v = parse_pep440(version)
        return str(v) if v is not None else version.strip()
    if not parse_semver(version):
        return version.strip()
    out = version.strip().removeprefix("v")
    # Go: OSV and GitHub write versions without the `v`, and `+incompatible` (the only build metadata Go allows)
    # names the same module version as the plain one.
    return out.split("+", 1)[0] if ecosystem == "go" else out


def sort_key(ecosystem: str, version: str) -> tuple[int, Any]:
    """Total-order key: parseable versions first by value, unparseable ones lexically (sorted low)."""
    if ecosystem == "pypi":
        v = parse_pep440(version)
        return (1, v) if v is not None else (0, version)
    s = parse_semver(version)
    return (1, s.key) if s is not None else (0, version)


def is_prerelease(ecosystem: str, version: str) -> bool:
    if ecosystem == "pypi":
        v = parse_pep440(version)
        return bool(v and (v.is_prerelease or v.is_devrelease))
    s = parse_semver(version)
    return bool(s and s.is_prerelease)


def _cmp(ecosystem: str, a: str, b: str) -> int | None:
    if ecosystem == "pypi":
        pa, pb = parse_pep440(a), parse_pep440(b)
        if pa is None or pb is None:
            return None
        return (pa > pb) - (pa < pb)
    sa, sb = parse_semver(a), parse_semver(b)
    if sa is None or sb is None:
        return None
    return (sa.key > sb.key) - (sa.key < sb.key)


@lru_cache(maxsize=4096)
def _compile(spec: str) -> tuple[tuple[str, str], ...] | None:
    """Parse a comparator spec once: ((op, bound), ...); None if malformed or empty."""
    parts = [p for p in spec.split(",") if p.strip()]
    if not parts:
        return None
    out: list[tuple[str, str]] = []
    for part in parts:
        m = _COMPARATOR.match(part)
        if not m:
            return None
        op, bound = m.group(1) or "=", m.group(2)
        if op == "==":
            op = "="
        if op == ">=" and bound in {"0", "0.0.0"}:
            continue  # matches everything
        out.append((op, bound))
    return tuple(out)


_OPS = {
    "=": lambda c: c == 0,
    "!=": lambda c: c != 0,
    ">": lambda c: c > 0,
    ">=": lambda c: c >= 0,
    "<": lambda c: c < 0,
    "<=": lambda c: c <= 0,
}


def in_range(ecosystem: str, version: str, spec: str) -> bool:
    """True if `version` satisfies every comparator in `spec`. Unparseable input never matches."""
    compiled = _compile(spec)
    if compiled is None:
        return False
    for op, bound in compiled:
        c = _cmp(ecosystem, version, bound)
        if c is None:
            # Fall back to exact string comparison for equality.
            if op == "=" and canonical(ecosystem, version) == canonical(ecosystem, bound):
                continue
            return False
        if not _OPS[op](c):
            return False
    return True


def range_is_everything(spec: str | None) -> bool:
    """`None`, `""`, `">= 0"` and friends mean "all versions" (a package-level block)."""
    if spec is None:
        return True
    parts = [p.strip().replace(" ", "") for p in spec.split(",") if p.strip()]
    return not parts or all(p in _EVERYTHING for p in parts)


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
