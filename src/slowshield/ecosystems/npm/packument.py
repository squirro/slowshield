"""npm packument filtering without decoding the whole document.

Packuments can be tens of MB (thousands of versions with full manifests and READMEs). We decode only
the top-level map, `time`, `dist-tags` and the `versions` map *as raw JSON blobs* (`msgspec.Raw`);
kept versions are spliced back byte-for-byte (after a tarball URL rewrite), so every field,
signature and attestation the registry published survives untouched.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import msgspec
from msgspec import UNSET, Raw, UnsetType

from slowshield import versions as V

_raw_map = msgspec.json.Decoder(dict[str, Raw])
_any = msgspec.json.Decoder()
_enc = msgspec.json.Encoder()


class _Dist(msgspec.Struct):
    tarball: str | None = None
    integrity: str | None = None
    shasum: str | None = None
    unpackedSize: int | float | None = None  # noqa: N815 - npm field name


class _VersionLite(msgspec.Struct):
    dist: _Dist = msgspec.field(default_factory=_Dist)


_lite = msgspec.json.Decoder(_VersionLite)
_lite_map = msgspec.json.Decoder(dict[str, _VersionLite])

_R = Raw | UnsetType


class _Corgi(msgspec.Struct, omit_defaults=True):
    """Abbreviated ("corgi") version manifest, per the npm registry docs. Values stay raw JSON."""

    name: _R = UNSET
    version: _R = UNSET
    deprecated: _R = UNSET
    dependencies: _R = UNSET
    optionalDependencies: _R = UNSET  # noqa: N815
    devDependencies: _R = UNSET  # noqa: N815
    bundleDependencies: _R = UNSET  # noqa: N815
    peerDependencies: _R = UNSET  # noqa: N815
    peerDependenciesMeta: _R = UNSET  # noqa: N815
    acceptDependencies: _R = UNSET  # noqa: N815
    bin: _R = UNSET
    directories: _R = UNSET
    dist: _R = UNSET
    engines: _R = UNSET
    cpu: _R = UNSET
    os: _R = UNSET
    libc: _R = UNSET
    funding: _R = UNSET
    has_shrinkwrap: _R = msgspec.field(default=UNSET, name="_hasShrinkwrap")
    hasInstallScript: _R = UNSET  # noqa: N815
    scripts: _R = UNSET  # decoded only to derive hasInstallScript; never emitted


ABBREVIATED_FIELDS = tuple(_Corgi.__struct_encode_fields__[:-1])
_corgi_map = msgspec.json.Decoder(dict[str, _Corgi])
_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")
_INSTALL_MARKERS = tuple(f'"{s}"'.encode() for s in _INSTALL_SCRIPTS)
_TRUE = Raw(b"true")


def parse_time(raw: Any) -> float | None:
    if not isinstance(raw, str):
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.timestamp()


@dataclass(slots=True)
class VersionInfo:
    version: str
    raw: Raw | bytes
    published: float | None
    tarball: str | None
    integrity: str | None
    shasum: str | None
    size: int | None
    key_json: bytes = b""


@dataclass(slots=True)
class Packument:
    name: str
    top: dict[str, Raw]
    versions: dict[str, VersionInfo]
    time: dict[str, Any]
    dist_tags: dict[str, str]
    etag: str | None
    raw_size: int
    unpublished: bool = False
    content_id: str = ""  # hash of the upstream bytes: rendered bodies are keyed by it
    by_tarball_path: dict[str, str] = field(default_factory=dict)  # "/pkg/-/pkg-1.0.0.tgz" -> version


def _lites(blob: Raw, raws: dict[str, Raw]) -> dict[str, _Dist]:
    """dist info of every version in one pass; falls back to per-version decoding on odd data."""
    try:
        return {k: v.dist for k, v in _lite_map.decode(blob).items()}
    except msgspec.ValidationError:
        out: dict[str, _Dist] = {}
        for k, raw in raws.items():
            try:
                out[k] = _lite.decode(raw).dist
            except msgspec.ValidationError:
                out[k] = _Dist()
        return out


def parse(raw: bytes, *, name: str, etag: str | None, upstream_bases: list[str]) -> Packument:
    top = _raw_map.decode(raw)
    time_map = _any.decode(top["time"]) if "time" in top else {}
    if not isinstance(time_map, dict):
        time_map = {}
    tags_raw = _any.decode(top["dist-tags"]) if "dist-tags" in top else {}
    dist_tags = {k: v for k, v in tags_raw.items() if isinstance(v, str)} if isinstance(tags_raw, dict) else {}
    versions: dict[str, VersionInfo] = {}
    by_path: dict[str, str] = {}
    prefixes: list[str] = []
    for base in upstream_bases:
        prefixes.append(base + "/")
        if base.startswith("https://"):
            prefixes.append("http://" + base[len("https://") :] + "/")
    if "versions" in top:
        blob = top["versions"]
        raws = _raw_map.decode(blob)
        dists = _lites(blob, raws)
        for ver, vraw in raws.items():
            dist = dists.get(ver) or _Dist()
            tarball = dist.tarball if isinstance(dist.tarball, str) else None
            size = dist.unpackedSize
            versions[ver] = VersionInfo(
                version=ver,
                raw=vraw,
                published=parse_time(time_map.get(ver)),
                tarball=tarball,
                integrity=dist.integrity,
                shasum=dist.shasum,
                size=int(size) if isinstance(size, (int, float)) else None,
                key_json=_enc.encode(ver),
            )
            if tarball:
                for prefix in prefixes:
                    if tarball.startswith(prefix):
                        by_path[tarball[len(prefix) - 1 :]] = ver
                        break
    return Packument(
        name=name,
        top=top,
        versions=versions,
        time=time_map,
        dist_tags=dist_tags,
        etag=etag,
        raw_size=len(raw),
        unpublished=bool(time_map.get("unpublished")) and not versions,
        content_id=hashlib.blake2b(raw, digest_size=12).hexdigest(),
        by_tarball_path=by_path,
    )


class IndexEntry(msgspec.Struct, array_like=True, frozen=True):
    version: str
    published: float | None
    tarball: str | None
    integrity: str | None
    shasum: str | None
    size: int | None


class _IndexWire(msgspec.Struct, array_like=True):
    name: str
    etag: str | None
    content_id: str
    unpublished: bool
    dist_tags: dict[str, str]
    entries: list[IndexEntry]
    by_tarball_path: dict[str, str]


_index_enc = msgspec.msgpack.Encoder()
_index_dec = msgspec.msgpack.Decoder(_IndexWire)


@dataclass(slots=True)
class Index:
    """What policy and tarball requests need from a packument: about 2 % of its size (no manifests, readme,
    maintainers or time map), so a burst of tarball requests never holds full documents in memory."""

    name: str
    etag: str | None
    content_id: str
    unpublished: bool
    dist_tags: dict[str, str]
    versions: dict[str, IndexEntry]  # upstream order
    by_tarball_path: dict[str, str]

    @property
    def weight(self) -> int:
        """Approximate memory: ~300 bytes per version for the entry, its strings and the two dicts."""
        return 300 * len(self.versions) + 2048

    def encode(self) -> bytes:
        wire = _IndexWire(
            self.name,
            self.etag,
            self.content_id,
            self.unpublished,
            self.dist_tags,
            list(self.versions.values()),
            self.by_tarball_path,
        )
        return _index_enc.encode(wire)

    @classmethod
    def decode(cls, data: bytes) -> Index:
        w = _index_dec.decode(data)
        versions = {e.version: e for e in w.entries}
        return cls(w.name, w.etag, w.content_id, w.unpublished, w.dist_tags, versions, w.by_tarball_path)


def index_of(p: Packument) -> Index:
    return Index(
        name=p.name,
        etag=p.etag,
        content_id=p.content_id,
        unpublished=p.unpublished,
        dist_tags=dict(p.dist_tags),
        versions={
            v.version: IndexEntry(v.version, v.published, v.tarball, v.integrity, v.shasum, v.size)
            for v in p.versions.values()
        },
        by_tarball_path=dict(p.by_tarball_path),
    )


def recompute_tags(original: dict[str, str], kept: list[str]) -> dict[str, str]:
    """`latest` -> highest kept stable version <= the original latest (falls back to the highest kept);
    other tags are kept only if their target is still served."""
    if not kept:
        return {}
    kept_set = set(kept)
    out = {tag: target for tag, target in original.items() if tag != "latest" and target in kept_set}
    latest = original.get("latest")
    if latest is not None and latest in kept_set:
        return {"latest": latest, **out}
    cap_v = V.parse_semver(latest) if latest else None
    cap = cap_v.key if cap_v is not None else None
    # One pass; each slot holds (sort key, version).
    stable_below = stable_any = any_below = any_any = None
    for v in kept:
        s = V.parse_semver(v)
        key: Any = (1, s.key) if s is not None else (0, v)
        below = cap is None or (s is not None and s.key <= cap)
        item = (key, v)
        if any_any is None or key > any_any[0]:
            any_any = item
        if below and (any_below is None or key > any_below[0]):
            any_below = item
        if s is None or not s.is_prerelease:
            if stable_any is None or key > stable_any[0]:
                stable_any = item
            if below and (stable_below is None or key > stable_below[0]):
                stable_below = item
    pick = (stable_below or stable_any) if stable_any is not None else (any_below or any_any)
    assert pick is not None  # kept is non-empty  # noqa: S101
    return {"latest": pick[1], **out}


def _rewrite(raw: bytes, upstream_bases: list[str], public_base: str) -> bytes:
    pub = public_base.encode() + b"/"
    for base in upstream_bases:
        b = base.encode() + b"/"
        if b in raw:
            raw = raw.replace(b, pub)
        if b.startswith(b"https://"):
            hb = b"http://" + b[len(b"https://") :]
            if hb in raw:
                raw = raw.replace(hb, pub)
    return raw


def _versions_blob(p: Packument, kept: list[str], upstream_bases: list[str], public_base: str) -> bytes:
    parts: list[Any] = [b"{"]
    for i, v in enumerate(kept):
        info = p.versions[v]
        if i:
            parts.append(b",")
        parts.append(info.key_json or _enc.encode(v))
        parts.append(b":")
        parts.append(info.raw)
    parts.append(b"}")
    return _rewrite(b"".join(parts), upstream_bases, public_base)


def render_full(
    p: Packument, kept: list[str], tags: dict[str, str], *, upstream_bases: list[str], public_base: str
) -> bytes:
    versions_blob = Raw(_versions_blob(p, kept, upstream_bases, public_base))
    kept_set = set(kept)
    time_out = {k: v for k, v in p.time.items() if k in ("created", "modified", "unpublished") or k in kept_set}
    out: dict[str, Any] = {}
    for key, blob in p.top.items():
        if key == "versions":
            out[key] = versions_blob
        elif key == "time":
            out[key] = time_out
        elif key == "dist-tags":
            out[key] = tags
        else:
            out[key] = blob
    if "versions" not in out and kept:
        out["versions"] = versions_blob
    return _enc.encode(out)


def render_abbreviated(
    p: Packument, kept: list[str], tags: dict[str, str], *, upstream_bases: list[str], public_base: str
) -> bytes:
    blob = _versions_blob(p, kept, upstream_bases, public_base)
    try:
        vers = _corgi_map.decode(blob)
    except msgspec.ValidationError:
        vers = {}
        for v in kept:
            try:
                vers[v] = msgspec.json.decode(
                    _rewrite(bytes(p.versions[v].raw), upstream_bases, public_base), type=_Corgi
                )
            except msgspec.ValidationError:
                continue
    for c in vers.values():
        scripts = c.scripts
        if c.hasInstallScript is UNSET and isinstance(scripts, Raw):
            raw = bytes(scripts)
            if any(m in raw for m in _INSTALL_MARKERS):
                decoded = _any.decode(raw)
                if isinstance(decoded, dict) and any(s in decoded for s in _INSTALL_SCRIPTS):
                    c.hasInstallScript = _TRUE
        c.scripts = UNSET
    out: dict[str, Any] = {"name": p.name, "dist-tags": tags, "versions": vers}
    modified = p.time.get("modified")
    if isinstance(modified, str):
        out["modified"] = modified
    return _enc.encode(out)


def render_version(p: Packument, version: str, *, upstream_bases: list[str], public_base: str) -> bytes:
    return _rewrite(bytes(p.versions[version].raw), upstream_bases, public_base)
