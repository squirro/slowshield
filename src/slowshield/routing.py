"""The root URL contract: which first path segments SlowShield answers on (docs/design/routing.md).

One host serves every ecosystem under its own path, named after the protocol (`/pypi/`, `/npm/`, `/go/`,
`/maven/<repo-id>/`, `/cargo/`, later `/rpm/<repo-id>/` ...). Everything else lives under a few reserved names, so a
future protocol never collides with the UI. A test fails when a route outside these names is added.
"""

from __future__ import annotations

# Served today.
ECOSYSTEMS = frozenset({"pypi", "npm", "go", "maven", "cargo"})

# Reserved for the ecosystems on the roadmap, so nothing else takes their names. `oci` is the container
# mirror-mode prefix (Docker registry-mirrors, containerd); explicit image references need `v2` below.
RESERVED_ECOSYSTEMS = frozenset(
    {
        "nuget",
        "rubygems",
        "composer",
        "helm",
        "terraform",
        "huggingface",
        "apt",
        "rpm",
        "apk",
        "oci",
        "homebrew",
        "github",
        "github-api",
        "openvsx",
        "jetbrains",
    }
)

# Not ecosystems: the UI (everything, including its assets), health probes, and the two root paths that
# protocols mandate (the OCI distribution API and RFC 8615 well-known URIs). `favicon.ico` only redirects.
SYSTEM = frozenset({"", "ui", "healthz", "readyz", "favicon.ico", "v2", ".well-known"})

# Deprecated, removed in 0.1: the root PyPI alias from the Rust version and the old UI asset path.
LEGACY = frozenset({"simple", "packages", "static"})

ALLOWED = ECOSYSTEMS | RESERVED_ECOSYSTEMS | SYSTEM | LEGACY


def first_segment(path: str) -> str:
    """`/pypi/simple/x/` -> `pypi`; `/` -> ``."""
    return path.lstrip("/").split("/", 1)[0]
