"""RubyGems compact index info files: parsing, and rendering without the lines SlowShield holds back.

`/info/<name>` is `---` and then one line per published version and platform
(https://guides.rubygems.org/rubygems-org-compact-index-api/):

    1.19.4-x86_64-linux-gnu racc:~> 1.4|checksum:<sha256>,ruby:< 4.1.dev&>= 3.2,rubygems:>= 3.3.22,created_at:<ISO>

The part before the space (the key) is the version and, after a `-`, the platform: together they name the file
(`nokogiri-1.19.4-x86_64-linux-gnu.gem`). SlowShield passes the lines on byte for byte and leaves out the ones it
holds back; RubyGems has no marker for a version that can't be installed.

A version may contain `-` too (`1.0.0-beta.1`, which RubyGems reads as `1.0.0.pre.beta.1`), so a key doesn't always
split at its first `-`; see `split_key`.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime

from slowshield.ecosystems.rubygems import version as G

MAX_INFO_BYTES = 32 << 20
_CHECKSUM = re.compile(rb"[0-9a-f]{64}")
_SEPARATOR = b"---"
# The operating systems `Gem::Platform.new(<string>)` knows (lib/rubygems/platform.rb); any other reads as "unknown".
# It looks at the part after the first `-` (the cpu before it), or at the whole string when there is no `-`.
_GEM_OS = re.compile(
    r"aix|cygwin|darwin|freebsd|linux|mingw|mswin\d|netbsdelf|openbsd|solaris|wasi"
    r"|^(?:macruby|java|dotnet)|^jruby$|^dalvik-?\d*$|^\w+_platform"
)
# `Gem::ContentAddress`: a content-addressed line's key ends in a prefix of the gem's sha256 instead of its platform,
# and the platform is in the line's `platform:` field.
_CONTENT_ADDRESS = re.compile(r"[0-9a-f]{8,64}")
# RubyGems before 3.5 (2023-12) made every prerelease gem require `> 1.3.1` of RubyGems.
_PRERELEASE_MARK = "> 1.3.1"


@dataclass(frozen=True, slots=True)
class Line:
    key: str  # `<version>[-<platform>]`, as in the file name
    version: str  # the version the key names (see `split_key`)
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
    try:
        rubygems = fields.get(b"rubygems", b"").decode("ascii").split("&")
        platform = fields.get(b"platform", b"").decode("ascii")
    except UnicodeDecodeError:
        rubygems, platform = [], ""
    version, platform = split_key(key, prerelease=_PRERELEASE_MARK in rubygems, platform=platform)
    if not version:
        return None
    return Line(key, version, platform, checksum.decode(), parse_time(fields.get(b"created_at")), raw)


def is_platform(value: str) -> bool:
    """Whether `Gem::Platform.new(value)` knows the platform (`x86_64-linux-gnu`, `java`, `universal-darwin-19`), as
    opposed to reading it as "unknown" (`beta.1`, but also `windows` or `android`, which old gems do use)."""
    cpu, _, os = value.rstrip("-").partition("-")
    return value == "ruby" or bool(_GEM_OS.search(os or cpu))


def _prerelease(version: str) -> bool:
    parsed = G.parse(version)
    return parsed is not None and parsed.is_prerelease


def split_key(key: str, *, prerelease: bool = False, platform: str = "") -> tuple[str, str]:
    """The (version, platform) a line's key names; `prerelease`: the line requires `> 1.3.1` of RubyGems, `platform`:
    its `platform:` field.

    The compact index writes `<version>-<platform>` and Bundler reads it back by splitting at the first `-`, which
    is what rubygems.org's API says for nearly every key, odd platforms included (`1.1.1-1.1.1`, `0.4-windows`,
    `0.0.2-do_not_install`). A version that itself contains `-` (`1.0.0-beta.1`) is a prerelease and, from gems
    built before RubyGems 3.5, carries the `> 1.3.1` mark: a line with the mark whose key, up to the first `-`, is no
    prerelease and goes on with no platform RubyGems knows, is one version. A content-addressed key
    (`0.4.2-04da877c`) is the version and a digest, with the platform in its own field."""
    version, sep, suffix = key.partition("-")
    if not sep:
        return key, "ruby"
    if _CONTENT_ADDRESS.fullmatch(suffix) and platform.lstrip("= ") not in ("", "ruby"):
        return version, platform.lstrip("= ")
    if prerelease and not is_platform(suffix) and not _prerelease(version) and G.parse(key) is not None:
        return key, "ruby"
    return version, suffix or "ruby"


def readings(key: str) -> list[str]:
    """The versions `key` can name when its line isn't at hand (a file no longer listed): the part before the first
    `-`, and the whole key unless the rest is a platform RubyGems knows."""
    version, sep, suffix = key.partition("-")
    return [version, key] if sep and not is_platform(suffix) else [version]


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
