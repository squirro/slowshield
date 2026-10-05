"""Package-name validation and normalisation for PyPI (PEP 503/508), npm and Go modules."""

from __future__ import annotations

import re
from functools import lru_cache

_PEP503_SEP = re.compile(r"[-_.]+")
# PEP 508 project names (also enforced by PyPI on upload).
_PYPI_NAME = re.compile(r"^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$", re.IGNORECASE)
# npm: optional @scope/, then the name. Legacy packages may contain upper-case letters.
_NPM_PART = r"[A-Za-z0-9~-][A-Za-z0-9._~-]*"
_NPM_NAME = re.compile(rf"^(?:@{_NPM_PART}/)?{_NPM_PART}$")
NPM_MAX_LEN = 214
PYPI_MAX_LEN = 200


@lru_cache(maxsize=65536)
def normalize_pypi(name: str) -> str:
    """PEP 503 normalised form: lower case, runs of `-_.` collapsed into `-`."""
    return _PEP503_SEP.sub("-", name).lower()


def is_valid_pypi(name: str) -> bool:
    return 0 < len(name) <= PYPI_MAX_LEN and _PYPI_NAME.match(name) is not None


def normalize_npm(name: str) -> str:
    """npm names are matched exactly (the registry is case-sensitive for legacy names)."""
    return name.strip()


def is_valid_npm(name: str) -> bool:
    if not (0 < len(name) <= NPM_MAX_LEN) or _NPM_NAME.match(name) is None:
        return False
    base = name.rsplit("/", 1)[-1]
    return not base.startswith((".", "_")) and base not in {"node_modules", "favicon.ico"}


def npm_basename(name: str) -> str:
    """`@scope/pkg` -> `pkg` (tarball files are named `<basename>-<version>.tgz`)."""
    return name.rsplit("/", 1)[-1]


# Go module paths (decoded, case-sensitive) as golang.org/x/mod/module.CheckPath accepts them: a lower-case
# first element with a dot (a domain), then elements of letters, digits and `-._~` that neither start nor end
# with a dot. Windows-reserved element names are refused too.
_GO_FIRST = re.compile(r"^[a-z0-9.-]+$")
_GO_ELEM = re.compile(r"^[A-Za-z0-9_~-](?:[A-Za-z0-9._~-]*[A-Za-z0-9_~-])?$")
_GO_MAJOR = re.compile(r"^v(?:0|1|0\d+)$")  # /v0, /v1 and /v01 are not major-version suffixes
_WINDOWS = frozenset({"con", "prn", "aux", "nul", *(f"{d}{i}" for d in ("com", "lpt") for i in range(1, 10))})
GO_MAX_LEN = 1024


def normalize_go(path: str) -> str:
    """Go module paths are matched exactly (case-sensitive; the proxy protocol's `!` escaping is decoded first)."""
    return path.strip()


@lru_cache(maxsize=65536)
def is_valid_go(path: str) -> bool:
    if not (0 < len(path) <= GO_MAX_LEN) or path.startswith("-"):
        return False
    elems = path.split("/")
    first = elems[0]
    if "." not in first or not _GO_FIRST.match(first):
        return False
    for elem in elems:
        if not _GO_ELEM.match(elem) or elem.split(".", 1)[0].lower() in _WINDOWS:
            return False
    return len(elems) == 1 or not _GO_MAJOR.match(elems[-1])
