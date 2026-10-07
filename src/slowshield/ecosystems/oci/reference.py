"""OCI distribution API paths (at /v2/): which registry, repository and object a request names.

Clients name the upstream registry in one of two ways:
- the path: `/v2/<registry>/<repository>/...` (Podman, CRI-O, skopeo, BuildKit mirrors, crane). Docker's own rule
  decides: a first component with a `.` or `:`, or `localhost`, is a registry host; anything else is Docker Hub.
- containerd's `?ns=<registry>` query parameter, which it adds to every request it sends to a mirror; the path is
  then the repository alone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from slowshield import names

DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
_REGISTRY = re.compile(r"(?:[a-z0-9-]+(?:\.[a-z0-9-]+)+|localhost)(?::[0-9]{1,5})?")
_KINDS = ("manifests", "blobs", "referrers")


@dataclass(frozen=True, slots=True)
class Request:
    registry: str  # canonical: docker.io, ghcr.io
    path: str  # the repository at that registry: library/nginx
    kind: str  # manifests | blobs | referrers | tags
    reference: str  # a tag or digest; "" for tags/list

    @property
    def repository(self) -> str:
        """The canonical repository, as stored and matched: docker.io/library/nginx."""
        return f"{self.registry}/{self.path}"

    @property
    def is_digest(self) -> bool:
        return DIGEST.fullmatch(self.reference) is not None


def parse(path: str, ns: str | None = None) -> Request | None:
    """`/<name>/manifests/<tag|digest>`, `/<name>/blobs/<digest>`, `/<name>/referrers/<digest>`, `/<name>/tags/list`,
    or None for anything else."""
    path = path.strip("/")
    name = kind = ref = ""
    if path.endswith("/tags/list"):
        name, kind = path[: -len("/tags/list")], "tags"
    else:
        for k in _KINDS:
            head, sep, tail = path.rpartition(f"/{k}/")
            if sep and head and tail and "/" not in tail:
                name, kind, ref = head, k, tail
                break
    if not name:
        return None
    if kind == "manifests" and not (DIGEST.fullmatch(ref) or TAG.fullmatch(ref)):
        return None
    if kind in ("blobs", "referrers") and not DIGEST.fullmatch(ref):
        return None
    if ns:
        ns = ns.strip().lower()
        if not _REGISTRY.fullmatch(ns):
            return None
        name = f"{ns}/{name}"
    if name != name.lower() or not names.is_valid_oci(name):
        return None  # the distribution spec allows lower-case repository names only: no silent renaming
    registry, repo = names.oci_split(name)
    return Request(registry, repo, kind, ref)
