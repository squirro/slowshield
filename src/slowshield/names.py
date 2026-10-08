"""Package-name validation and normalisation for PyPI (PEP 503/508), npm, Go modules, Maven, Cargo, NuGet and OCI
images."""

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


# Maven coordinates `groupId:artifactId`, as Maven Central accepts them: dot-separated groupId segments and an
# artifactId of letters, digits and `_-.` (matched exactly; Maven is case-sensitive here).
_MAVEN_PART = r"[A-Za-z0-9_-](?:[A-Za-z0-9_.-]*[A-Za-z0-9_-])?"
_MAVEN_NAME = re.compile(rf"^{_MAVEN_PART}:{_MAVEN_PART}$")
MAVEN_MAX_LEN = 512


def normalize_maven(name: str) -> str:
    return name.strip()


def is_valid_maven(name: str) -> bool:
    return 0 < len(name) <= MAVEN_MAX_LEN and _MAVEN_NAME.match(name) is not None and ".." not in name


# Crate names as crates.io accepts them: ASCII letters, digits, `-` and `_`, at most 64 characters. crates.io treats
# names that differ only in case or in `-` versus `_` as the same crate, and so does its own canonical form.
_CARGO_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def normalize_cargo(name: str) -> str:
    """crates.io's canonical crate name (`canon_crate_name`): lower case, `-` written as `_`."""
    return name.strip().lower().replace("-", "_")


def is_valid_cargo(name: str) -> bool:
    return _CARGO_NAME.match(name) is not None


# NuGet package ids as nuget.org accepts them (NuGet's PackageIdValidator, ASCII only): runs of letters, digits and
# `_`, joined by single `.` or `-`, at most 100 characters. Ids are case-insensitive; nuget.org's paths use lower case.
_NUGET_ID = re.compile(r"^[A-Za-z0-9_]+(?:[.-][A-Za-z0-9_]+)*$")
NUGET_MAX_LEN = 100


def normalize_nuget(name: str) -> str:
    """The lower-case id, as nuget.org's flat container and registration paths spell it."""
    return name.strip().lower()


def is_valid_nuget(name: str) -> bool:
    return 0 < len(name) <= NUGET_MAX_LEN and _NUGET_ID.match(name) is not None


# OCI image repositories: `<registry>/<path>` as Docker spells references. A first component with a `.` or `:`, or
# `localhost`, is the registry; anything else is on Docker Hub, where one-component names live under `library/`.
# Path components follow the distribution spec: lower-case letters and digits, separated by `.`, `_`, `__` or dashes.
_OCI_COMPONENT = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*")
_OCI_HOST = re.compile(r"(?:[a-z0-9-]+(?:\.[a-z0-9-]+)+|localhost)(?::[0-9]{1,5})?")
OCI_DOCKER_HUB = "docker.io"
OCI_HUB_ALIASES = frozenset({"docker.io", "index.docker.io", "registry-1.docker.io"})
OCI_MAX_LEN = 255


def oci_split(name: str) -> tuple[str, str]:
    """`nginx` -> (`docker.io`, `library/nginx`); `ghcr.io/a/b` -> (`ghcr.io`, `a/b`)."""
    name = name.strip().lower()
    first, _, rest = name.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, path = first, rest
    else:
        registry, path = OCI_DOCKER_HUB, name
    if registry in OCI_HUB_ALIASES:
        registry = OCI_DOCKER_HUB
        if "/" not in path:
            path = f"library/{path}"
    return registry, path


def normalize_oci(name: str) -> str:
    """The canonical repository: `docker.io/library/nginx`, `ghcr.io/squirro/slowshield`."""
    registry, path = oci_split(name)
    return f"{registry}/{path}"


def is_valid_oci(name: str) -> bool:
    if not (0 < len(name) <= OCI_MAX_LEN):
        return False
    registry, path = oci_split(name)
    return _OCI_HOST.fullmatch(registry) is not None and all(_OCI_COMPONENT.fullmatch(c) for c in path.split("/"))


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
