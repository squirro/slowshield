"""Go module proxy protocol paths (go.dev/ref/mod#goproxy-protocol): the `!` case-encoding, canonical versions,
and which request a path is. Anything outside the protocol parses to None and is answered with 404.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from slowshield import names

# A canonical module version: semver with a `v`, and `+incompatible` as the only build metadata Go allows.
_CANONICAL = re.compile(
    r"^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+incompatible)?$"
)
# What `.info` may be asked to resolve instead: a branch, tag or commit hash.
_QUERY = re.compile(r"^[A-Za-z0-9_+~-][A-Za-z0-9._+~-]{0,127}$")
# Checksum database tiles: tile/<H>/<L or data>/<N in x000/ groups>[.p/<W>] (golang.org/x/mod/sumdb/tlog).
TILE = re.compile(r"^tile/[1-9][0-9]?/(?:data|[0-9]{1,2})/(?:x[0-9]{3}/)*[0-9]{3}(?:\.p/[1-9][0-9]{0,2})?$")


def unescape(value: str) -> str | None:
    """`github.com/!azure/x` -> `github.com/Azure/x`; None unless validly escaped (no upper case, no stray `!`)."""
    out: list[str] = []
    bang = False
    for ch in value:
        if bang:
            if not "a" <= ch <= "z":
                return None
            out.append(ch.upper())
            bang = False
        elif ch == "!":
            bang = True
        elif "A" <= ch <= "Z":
            return None
        else:
            out.append(ch)
    return None if bang else "".join(out)


def escape(value: str) -> str:
    """`github.com/Azure/x` -> `github.com/!azure/x` (module.EscapePath / EscapeVersion)."""
    return "".join("!" + ch.lower() if "A" <= ch <= "Z" else ch for ch in value)


def is_canonical(version: str) -> bool:
    return _CANONICAL.match(version) is not None


def is_release(version: str) -> bool:
    """No prerelease part (pseudo-versions are prereleases)."""
    return "-" not in version.split("+", 1)[0]


@dataclass(frozen=True, slots=True)
class ProxyRequest:
    module: str  # decoded module path, as stored and matched
    escaped: str  # as on the wire (and sent upstream)
    kind: str  # list | latest | info | mod | zip
    version: str | None = None  # decoded; canonical except for `.info` queries
    escaped_version: str | None = None


def parse(path: str) -> ProxyRequest | None:
    """`/github.com/!azure/x/@v/v1.2.3.zip` -> ProxyRequest(module="github.com/Azure/x", kind="zip", ...)."""
    path = path.lstrip("/")
    file: str | None
    if path.endswith("/@latest"):
        escaped, kind, file = path[: -len("/@latest")], "latest", None
    else:
        escaped, sep, file = path.partition("/@v/")  # module paths never contain `@`
        if not sep or "/" in file:
            return None
        if file == "list":
            kind, file = "list", None
        else:
            stem, dot, kind = file.rpartition(".")
            if not dot or kind not in ("info", "mod", "zip"):
                return None
            file = stem
    module = unescape(escaped)
    if module is None or not names.is_valid_go(module):
        return None
    if file is None:
        return ProxyRequest(module, escaped, kind)
    version = unescape(file)
    if version is None or not (is_canonical(version) or (kind == "info" and _QUERY.match(version))):
        return None
    return ProxyRequest(module, escaped, kind, version, file)


def parse_lookup(spec: str) -> tuple[str, str] | None:
    """Checksum database `lookup/<escaped module>@<escaped version>` -> (module, version)."""
    escaped, sep, escaped_version = spec.partition("@")
    module, version = unescape(escaped), unescape(escaped_version)
    if not sep or module is None or version is None or not names.is_valid_go(module) or not is_canonical(version):
        return None
    return module, version
