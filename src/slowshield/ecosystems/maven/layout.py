"""Maven repository layout: which request a path inside a repository is. Anything else parses to None (404), so
`/maven/` never browses or proxies arbitrary paths (no directory listings, no `.index/`)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from slowshield.ecosystems.maven.version import is_snapshot

_SEGMENT = re.compile(r"^[A-Za-z0-9_+~-][A-Za-z0-9._+~-]*$")
CHECKSUMS = ("sha1", "md5", "sha256", "sha512")
METADATA = "maven-metadata.xml"
PASSTHROUGH = frozenset({"archetype-catalog.xml"})


@dataclass(frozen=True, slots=True)
class MavenRequest:
    rel: str  # the path inside the repository, as requested
    kind: str  # metadata | file | checksum | passthrough
    group: str | None = None
    artifact: str | None = None
    version: str | None = None
    filename: str | None = None  # the file itself (for a checksum: the file it belongs to)
    algo: str | None = None  # checksum algorithm, for checksum and metadata-checksum requests

    @property
    def name(self) -> str:
        return f"{self.group}:{self.artifact}"

    @property
    def base(self) -> str:
        """The path without the checksum suffix."""
        return self.rel[: -len(self.algo) - 1] if self.algo else self.rel

    @property
    def snapshot(self) -> bool:
        """A file of a snapshot version. Only the version decides: an artifactId may end in `-SNAPSHOT` too, and
        its releases are judged like any other."""
        return bool(self.version and is_snapshot(self.version))

    @property
    def snapshot_metadata(self) -> bool:
        """Metadata in a directory named like a snapshot version (for metadata, `artifact` is that directory): a
        snapshot's builds, or the versions of an artifact named that way. The content tells which."""
        return self.kind == "metadata" and bool(self.artifact and is_snapshot(self.artifact))


def parse(rel: str) -> MavenRequest | None:
    if not rel or len(rel) > 1024:
        return None
    segments = rel.split("/")
    if any(not _SEGMENT.match(s) for s in segments) or segments[0] == ".index":
        return None
    last = segments[-1]
    if last.startswith(METADATA):
        suffix = last[len(METADATA) :]
        algo = suffix[1:] if suffix.startswith(".") else None
        if (suffix and algo not in CHECKSUMS) or len(segments) < 3:
            return None
        # Artifact-level (versions), group-level (plugin prefixes) or snapshot-level: the content tells which.
        return MavenRequest(rel, "metadata", ".".join(segments[:-2]), segments[-2], algo=algo)
    if len(segments) == 1 and last in PASSTHROUGH:
        return MavenRequest(rel, "passthrough")
    if len(segments) < 4:
        return None
    group, artifact, version, filename = ".".join(segments[:-3]), segments[-3], segments[-2], last
    algo = next((a for a in CHECKSUMS if filename.endswith(f".{a}")), None)
    base = filename[: -len(algo) - 1] if algo else filename
    if not (is_snapshot(version) or base.startswith(f"{artifact}-{version}")):
        return None  # every file of a version is named <artifactId>-<version>[-<classifier>].<ext>
    return MavenRequest(rel, "checksum" if algo else "file", group, artifact, version, base, algo)
