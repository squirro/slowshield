"""Cargo sparse index files: paths, parsing, and rendering with held versions marked as yanked.

An index file lists one version per line, each a JSON object, oldest first
(https://doc.rust-lang.org/cargo/reference/registry-index.html). SlowShield passes the lines on byte for byte,
except that a version it holds back gets `"yanked":true`. Cargo then resolves to an older version, and a lockfile
that pins the held version still asks for the download, which SlowShield refuses with a message cargo prints.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime

import msgspec

from slowshield import names

MAX_INDEX_BYTES = 64 << 20
_YANKED = b'"yanked":false'  # crates.io writes compact JSON: every line it serves carries this token
_YANKED_TRUE = b'"yanked":true'
_CKSUM = re.compile(r"^[0-9a-f]{64}$")


class _Line(msgspec.Struct):
    name: str
    vers: str
    cksum: str = ""
    yanked: bool = False
    pubtime: str | None = None


_decoder = msgspec.json.Decoder(_Line)


@dataclass(frozen=True, slots=True)
class Version:
    name: str  # exactly as published (static.crates.io is case- and `-`/`_`-sensitive)
    vers: str
    cksum: str  # sha256 of the .crate
    yanked: bool
    pubtime: float | None  # as the index states it; None when missing or unreadable
    line: bytes


@dataclass(frozen=True, slots=True)
class IndexFile:
    name: str  # lower case, as in the path
    versions: dict[str, Version]  # by `vers`, in file order
    content_id: str
    weight: int  # approximate memory cost, for the metadata cache


def path_of(name: str) -> str:
    """The index file of a crate, relative to the index root: `1/a`, `2/ab`, `3/a/abc`, `ab/cd/abcd...`. Cargo
    asks for the lower-case name."""
    n = name.lower()
    if len(n) <= 2:
        return f"{len(n)}/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def name_of(path: str) -> str | None:
    """The crate an index file path names (`se/rd/serde` -> `serde`), or None for anything else."""
    name = path.rsplit("/", 1)[-1]
    if not names.is_valid_cargo(name) or name != name.lower() or path != path_of(name):
        return None
    return name


def parse_pubtime(raw: str | None) -> float | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw).timestamp() if raw.endswith(("Z", "+00:00")) else None
    except ValueError:
        return None


def parse(name: str, body: bytes) -> IndexFile:
    """The versions of crate `name` (lower case) in an index file. Lines that don't parse, name another crate,
    repeat a version or lack a sha256 `cksum` are left out, as cargo would not use them either."""
    versions: dict[str, Version] = {}
    size = 0
    for raw in body.split(b"\n"):
        line = raw.strip()
        if not line:
            continue
        try:
            d = _decoder.decode(line)
        except msgspec.DecodeError:
            continue
        if d.name.lower() != name or d.vers in versions or not _CKSUM.match(d.cksum):
            continue
        versions[d.vers] = Version(d.name, d.vers, d.cksum, d.yanked, parse_pubtime(d.pubtime), line)
        size += len(line)
    content_id = hashlib.blake2b(body, digest_size=12).hexdigest()
    return IndexFile(name, versions, content_id, 512 + size + 256 * len(versions))


def yank(line: bytes) -> bytes | None:
    """`line` with `"yanked":true`, or None when it can't be marked safely (then the line is left out instead)."""
    if _YANKED not in line:
        return None
    out = line.replace(_YANKED, _YANKED_TRUE, 1)
    try:
        return out if _decoder.decode(out).yanked else None
    except msgspec.DecodeError:
        return None


def render(idx: IndexFile, hold: Collection[str]) -> bytes:
    """The index file as served: upstream lines, with the versions in `hold` marked as yanked."""
    out: list[bytes] = []
    for v in idx.versions.values():
        line: bytes | None = v.line
        if v.vers in hold and not v.yanked:
            line = yank(v.line)
        if line is not None:
            out.append(line)
    return b"\n".join(out) + b"\n" if out else b""
