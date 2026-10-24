"""RubyGems compact index info files: parsing, and rendering without the lines SlowShield holds back.

`/info/<name>` is `---` and then one line per published version and platform
(https://guides.rubygems.org/rubygems-org-compact-index-api/):

    1.19.4-x86_64-linux-gnu racc:~> 1.4|checksum:<sha256>,ruby:< 4.1.dev&>= 3.2,rubygems:>= 3.3.22,created_at:<ISO>

The part before the space is the version and, after the first `-`, the platform: together they name the file
(`nokogiri-1.19.4-x86_64-linux-gnu.gem`). SlowShield passes the lines on byte for byte and leaves out the ones it
holds back; RubyGems has no marker for a version that can't be installed.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime

MAX_INFO_BYTES = 32 << 20
_CHECKSUM = re.compile(rb"[0-9a-f]{64}")
_SEPARATOR = b"---"


@dataclass(frozen=True, slots=True)
class Line:
    key: str  # `<version>[-<platform>]`, as in the file name
    version: str
    platform: str  # "ruby" when the line has none
    sha256: str
    created_at: float | None  # as the file states it; None when missing or unreadable
    raw: bytes


@dataclass(frozen=True, slots=True)
class InfoFile:
    name: str
    header: bytes  # everything up to and including the `---` line
    lines: dict[str, Line]  # by key, in file order
    content_id: str
    weight: int  # approximate memory cost, for the metadata cache


def parse_time(raw: bytes | None) -> float | None:
    if not raw:
        return None
    text = raw.decode("ascii", "replace")
    if not text.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def parse_line(raw: bytes) -> Line | None:
    """One info line, or None when it has no version or no sha256 `checksum` (nothing a download could be checked
    against)."""
    head, sep, rest = raw.partition(b" ")
    if not sep or not head:
        return None
    _deps, _, reqs = rest.partition(b"|")
    fields: dict[bytes, bytes] = {}
    for item in reqs.split(b","):
        k, _, v = item.partition(b":")
        fields.setdefault(k, v)
    checksum = fields.get(b"checksum", b"")
    if not _CHECKSUM.fullmatch(checksum):
        return None
    try:
        key = head.decode("ascii")
    except UnicodeDecodeError:
        return None
    version, _, platform = key.partition("-")
    if not version:
        return None
    return Line(key, version, platform or "ruby", checksum.decode(), parse_time(fields.get(b"created_at")), raw)


def parse(name: str, body: bytes) -> InfoFile:
    """The lines of gem `name`'s info file. Lines that don't parse or repeat a key are left out, as are any before
    the `---` separator (kept as the header)."""
    raw_lines = body.split(b"\n")
    try:
        start = raw_lines.index(_SEPARATOR) + 1
    except ValueError:
        start = 0
    header = b"".join(r + b"\n" for r in raw_lines[:start])
    lines: dict[str, Line] = {}
    size = len(header)
    for raw in raw_lines[start:]:
        line = parse_line(raw.rstrip(b"\r"))
        if line is None or line.key in lines:
            continue
        lines[line.key] = line
        size += len(line.raw)
    content_id = hashlib.blake2b(body, digest_size=12).hexdigest()
    return InfoFile(name, header, lines, content_id, 512 + size + 200 * len(lines))


def render(info: InfoFile, drop: Collection[str]) -> bytes:
    """The info file as served: the upstream header and lines, without the keys in `drop`."""
    out = [info.header or b"---\n"]
    out.extend(line.raw + b"\n" for key, line in info.lines.items() if key not in drop)
    return b"".join(out)


def etag(body: bytes) -> str:
    """The compact index ETag: the MD5 of the body, quoted. Bundler 2.4 and older check it against the body."""
    return '"' + hashlib.md5(body, usedforsecurity=False).hexdigest() + '"'


def repr_digest(body: bytes) -> str:
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def split_file(stem: str) -> list[tuple[str, str]]:
    """The (name, key) pairs a file name stem can mean: `rack-3.1.8` -> [("rack", "3.1.8")]. Names may contain `-`,
    and versions start with a digit, so every `-` followed by a digit is a candidate, the shortest name first."""
    return [(stem[:i], stem[i + 1 :]) for i, ch in enumerate(stem) if ch == "-" and stem[i + 1 : i + 2].isdigit()]
