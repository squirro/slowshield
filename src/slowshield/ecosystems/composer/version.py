"""Composer versions: `VersionParser::normalize` (composer/semver) and PHP's `version_compare` order.

Packagist sends each version's normalized form (`version_normalized`); advisories, exceptions and blocks name versions
as people write them (`v1.2`, `1.2.0-RC1`), so both go through `normalize` before they are compared: `v1.2` and `1.2.0`
are both `1.2.0.0`. Branches are `dev-<name>`, or `<n>.x-dev` normalized to `<n>.9999999.9999999.9999999-dev`.
"""

from __future__ import annotations

import re
from functools import lru_cache

_MODIFIER = r"[._-]?(?:(stable|beta|b|RC|alpha|a|patch|pl|p)((?:[.-]?\d+)*+)?)?([.-]?dev)?"
_CLASSIC = re.compile(r"^v?(\d{1,5}+)(\.\d++)?(\.\d++)?(\.\d++)?" + _MODIFIER + "$", re.IGNORECASE)
_DATED = re.compile(r"^v?(\d{4}(?:[.:-]?\d{2}){1,6}(?:[.:-]?\d{1,3}){0,2})" + _MODIFIER + "$", re.IGNORECASE)
_BRANCH = re.compile(r"^v?(\d++)(\.(?:\d++|[xX*]))?(\.(?:\d++|[xX*]))?(\.(?:\d++|[xX*]))?$")
_DEV_SUFFIX = re.compile(r"^(.*?)[.-]?dev$", re.IGNORECASE)
_STABILITY = {"a": "alpha", "b": "beta", "p": "patch", "pl": "patch", "rc": "RC"}
# PHP's special forms (ext/standard/versioning.c), matched as prefixes in this order; a number counts as "#".
_SPECIAL = (
    ("dev", 0), ("alpha", 1), ("a", 1), ("beta", 2), ("b", 2), ("RC", 3), ("rc", 3), ("#", 4), ("pl", 5), ("p", 5),
)  # fmt: skip
_NUMBER = 4
_END = (_NUMBER, -1)  # after the last part: above any special form below "#", below any number and "patch"
_PRERELEASE = re.compile(r"-(?:dev|alpha|beta|RC)", re.IGNORECASE)


def _expand_stability(value: str) -> str:
    value = value.lower()
    return _STABILITY.get(value, value)


def _normalize_branch(name: str) -> str:
    if name in ("master", "trunk", "default"):
        return "dev-" + name
    m = _BRANCH.match(name)
    if m:
        parts = "".join((m.group(i) or ".x").replace("*", "x").replace("X", "x") for i in range(1, 5))
        return parts.replace("x", "9999999") + "-dev"
    return "dev-" + name


@lru_cache(maxsize=65536)
def normalize(version: str) -> str | None:
    """Composer's normalized form (`1.2.0.0`, `1.0.0.0-beta2`, `dev-main`), or None for what Composer refuses."""
    v = version.strip()
    if " as " in v:  # an inline alias, `dev-main as 1.0.x-dev`
        v = v.split(" as ", 1)[0].strip()
    v = re.sub(r"@(?:stable|RC|beta|alpha|dev)$", "", v, flags=re.IGNORECASE)
    if v in ("master", "trunk", "default"):
        v = "dev-" + v
    if v[:4].lower() == "dev-":
        return "dev-" + v[4:]
    m = re.match(r"^([^,\s+]++)\+[^\s]++$", v)
    if m:
        v = m.group(1)  # build metadata
    m = _CLASSIC.match(v)
    if m:
        out = m.group(1) + "".join(m.group(i) or ".0" for i in (2, 3, 4))
        index = 5
    else:
        m = _DATED.match(v)
        if m is None:
            dev = _DEV_SUFFIX.match(v)
            if dev:
                branch = _normalize_branch(dev.group(1))
                if not branch.startswith("dev-"):
                    return branch
            return None
        out = re.sub(r"\D", ".", m.group(1))
        index = 2
    if m.group(index):
        if m.group(index) == "stable":
            return out
        out += "-" + _expand_stability(m.group(index)) + (m.group(index + 1) or "").lstrip(".-")
    if m.group(index + 2):
        out += "-dev"
    return out


def canonical(version: str) -> str | None:
    return normalize(version)


def _canonicalize(version: str) -> list[str]:
    """PHP's `php_canonicalize_version`, split into its parts: `-`, `_` and `+` become dots, and a dot goes between
    a digit and a letter."""
    out: list[str] = []
    prev = ""
    for ch in version:
        if ch in "-_+" or not ch.isalnum():
            if out and out[-1] != ".":
                out.append(".")
        elif prev and prev not in ".-_+" and prev.isalnum() and (prev.isdigit() != ch.isdigit()):
            if out and out[-1] != ".":
                out.append(".")
            out.append(ch)
        else:
            out.append(ch)
        prev = ch
    return [p for p in "".join(out).split(".") if p]


def _special(part: str) -> int:
    for name, order in _SPECIAL:
        if part.startswith(name):
            return order
    return -1


@lru_cache(maxsize=65536)
def key(version: str) -> tuple[tuple[int, int], ...]:
    """Sort key in `version_compare` order of the normalized version (or of the raw string Composer can't
    normalize). A number counts as the special form "#", so `1.0.0.0-beta2` < `1.0.0.0` < `1.0.0.0-patch1`."""
    parts = _canonicalize(normalize(version) or version.strip())
    return (*((_NUMBER, int(p)) if p.isdigit() else (_special(p), 0) for p in parts), _END)


def compare(a: str, b: str) -> int:
    ka, kb = key(a), key(b)
    return (ka > kb) - (ka < kb)


def is_dev(version: str) -> bool:
    n = normalize(version)
    return n is not None and (n.startswith("dev-") or n.endswith("-dev"))


def is_prerelease(version: str) -> bool:
    """Anything but a stable release: a branch, or an alpha, beta or RC. A patch release is stable."""
    n = normalize(version)
    return n is not None and (n.startswith("dev-") or _PRERELEASE.search(n) is not None)
