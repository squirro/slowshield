"""Packagist's p2 metadata files: parsing, filtering, dist URL rewriting and Composer's minified format.

A p2 file (`p2/<vendor>/<package>.json`, the branches in `<package>~dev.json`) lists a package's versions newest
first. Packagist minifies it (`"minified": "composer/2.0"`): each entry holds only the keys that differ from the
entry before it, and `"__unset"` removes a key. SlowShield expands the list, leaves out the versions it holds back,
points every dist at itself, and minifies the rest again, so the entries still diff against the right ones
(composer/metadata-minifier's `expand` and `minify`). Everything else in an entry and in the file is passed on.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Collection
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import msgspec

MAX_P2_BYTES = 64 << 20
MINIFIED = "composer/2.0"
UNSET = "__unset"
# A dist's reference (a commit, for every VCS Packagist reads) and type, as they appear in SlowShield's dist URLs.
REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
DIST_TYPE = re.compile(r"[a-z0-9]{1,10}")
# GitHub API archive URLs redirect to codeload.github.com, which has no API rate limit (60 an hour without a token).
_GITHUB_API = re.compile(
    r"https://api\.github\.com/repos/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/(zipball|tarball)/([A-Za-z0-9._-]+)"
)
_decoder = msgspec.json.Decoder()
_encoder = msgspec.json.Encoder()


@dataclass(frozen=True, slots=True)
class Version:
    version: str  # as published: `3.12.1`, `v6.4.0`, `dev-main`
    published: float | None  # `published-time` as the file states it; None when missing or unreadable
    reference: str | None  # dist.reference, when it can name a file in a URL
    dist_type: str | None
    dist_url: str | None
    shasum: str | None  # dist.shasum (sha1, hex), when not empty
    data: dict[str, Any]  # the expanded entry

    @property
    def servable(self) -> bool:
        """Whether SlowShield can serve this version's dist: a URL, a usable reference and type, and a GitHub archive
        URL that names that reference."""
        return bool(self.dist_url and self.reference and self.dist_type) and self.fetch_url is not None

    @property
    def fetch_url(self) -> str | None:
        return fetch_url(self.dist_url, self.reference) if self.dist_url and self.reference else None

    @property
    def filename(self) -> str:
        return f"{self.reference}.{self.dist_type}"


@dataclass(frozen=True, slots=True)
class P2File:
    name: str
    dev: bool  # the branches (`~dev`)
    versions: dict[str, Version]  # by `version`, in file order (newest first)
    extra: dict[str, Any]  # the file's other keys (`security-advisories`, `filter`), passed on
    content_id: str
    weight: int  # approximate memory cost, for the metadata cache


def file_of(name: str, dev: bool) -> str:
    """The p2 path of a package, relative to the repository root."""
    return f"p2/{name}{'~dev' if dev else ''}.json"


def expand(entries: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if current is None:
            current = dict(entry)
        else:
            current = dict(current)
            for key, value in entry.items():
                if value == UNSET:
                    current.pop(key, None)
                else:
                    current[key] = value
        out.append(current)
    return out


def minify(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    last: dict[str, Any] | None = None
    for entry in entries:
        if last is None:
            last = dict(entry)
            out.append(entry)
            continue
        diff = {k: v for k, v in entry.items() if k not in last or last[k] != v}
        last.update(diff)
        for key in [k for k in last if k not in entry]:
            diff[key] = UNSET
            del last[key]
        out.append(diff)
    return out


def _time(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt.timestamp() if dt.tzinfo is not None else None


def _version(entry: dict[str, Any]) -> Version | None:
    ver = entry.get("version")
    if not isinstance(ver, str) or not ver or len(ver) > 255:
        return None
    dist = entry.get("dist")
    url = ref = typ = shasum = None
    if isinstance(dist, dict):
        url = dist.get("url") if isinstance(dist.get("url"), str) else None
        ref = dist.get("reference") if isinstance(dist.get("reference"), str) else None
        typ = dist.get("type") if isinstance(dist.get("type"), str) else None
        sha = dist.get("shasum")
        shasum = sha.lower() if isinstance(sha, str) and re.fullmatch(r"[0-9a-fA-F]{40}", sha) else None
    return Version(
        version=ver,
        published=_time(entry.get("published-time")),
        reference=ref if ref and REFERENCE.fullmatch(ref) else None,
        dist_type=typ if typ and DIST_TYPE.fullmatch(typ) else None,
        dist_url=url if url and url.startswith(("https://", "http://")) else None,
        shasum=shasum,
        data=entry,
    )


def parse(name: str, dev: bool, body: bytes) -> P2File | None:
    """The p2 file of `name`, or None if `body` isn't one (an error page, a broken mirror)."""
    try:
        doc = _decoder.decode(body)
    except msgspec.DecodeError:
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("packages"), dict):
        return None
    entries = doc["packages"].get(name, [])
    if not isinstance(entries, list):
        return None
    if doc.get("minified") == MINIFIED:
        entries = expand(entries)
    versions: dict[str, Version] = {}
    for entry in entries:
        v = _version(entry) if isinstance(entry, dict) else None
        if v is not None:
            versions.setdefault(v.version, v)
    extra = {k: v for k, v in doc.items() if k not in ("packages", "minified")}
    content_id = hashlib.blake2b(body, digest_size=12).hexdigest()
    return P2File(name, dev, versions, extra, content_id, 1024 + 3 * len(body))


def render(
    p2: P2File,
    drop: Collection[str],
    dist_url: Callable[[Version], str],
    *,
    warning: str | None = None,
) -> bytes:
    """The file without the versions in `drop`, every dist at `dist_url(version)` and without mirrors (Composer
    would fall back to a mirror, or to the original URL, when SlowShield refuses a download), minified."""
    entries: list[dict[str, Any]] = []
    for v in p2.versions.values():
        if v.version in drop:
            continue
        entry = dict(v.data)
        dist = entry.get("dist")
        if isinstance(dist, dict):
            entry["dist"] = {**{k: x for k, x in dist.items() if k != "mirrors"}, "url": dist_url(v)}
        source = entry.get("source")
        if isinstance(source, dict) and "mirrors" in source:
            entry["source"] = {k: x for k, x in source.items() if k != "mirrors"}
        entries.append(entry)
    doc: dict[str, Any] = {"minified": MINIFIED, "packages": {p2.name: minify(entries)}, **p2.extra}
    if warning:
        doc["warning"] = warning
    return _encoder.encode(doc)


def parse_summary(body: bytes) -> bool:
    """Whether `body` is a filter list summary (`{"filter": {"malware": {"<name>": "<constraint>"}}}`): anything
    else isn't stored, as Composer would stop on it."""
    try:
        doc = _decoder.decode(body)
    except msgspec.DecodeError:
        return False
    return isinstance(doc, dict) and isinstance(doc.get("filter"), dict)


def parse_advisories(body: bytes) -> bool:
    """Whether `body` is an answer of Packagist's advisory API (`{"advisories": {"<name>": [...]}}`)."""
    try:
        doc = _decoder.decode(body)
    except msgspec.DecodeError:
        return False
    return isinstance(doc, dict) and isinstance(doc.get("advisories"), (dict, list))


def fetch_url(dist_url: str, reference: str) -> str | None:
    """Where SlowShield fetches a dist: GitHub API archive URLs go to codeload.github.com, where they redirect. None
    when a GitHub archive URL names another commit than `reference`: the dist is cached and fingerprinted under the
    reference, so it must be that commit's archive."""
    m = _GITHUB_API.fullmatch(dist_url)
    if m is None:
        return dist_url
    owner, repo, kind, ref = m.groups()
    if ref != reference:
        return None
    return f"https://codeload.github.com/{owner}/{repo}/{'legacy.zip' if kind == 'zipball' else 'legacy.tar.gz'}/{ref}"
