"""npm packument filtering without decoding the whole document.

Packuments can be tens of MB (thousands of versions with full manifests and READMEs). We decode only
the top-level map, `time`, `dist-tags` and the `versions` map *as raw JSON blobs* (`msgspec.Raw`);
kept versions are spliced back byte-for-byte (after a tarball URL rewrite), so every field,
signature and attestation the registry published survives untouched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import msgspec

from slowshield import versions as V

_raw_map = msgspec.json.Decoder(dict[str, msgspec.Raw])
_any = msgspec.json.Decoder()
_enc = msgspec.json.Encoder()


class _Dist(msgspec.Struct):
    tarball: str | None = None
    integrity: str | None = None
    shasum: str | None = None
    unpackedSize: int | None = None  # noqa: N815 - npm field name


class _VersionLite(msgspec.Struct):
    dist: _Dist = msgspec.field(default_factory=_Dist)


_lite = msgspec.json.Decoder(_VersionLite)

# Fields kept in the abbreviated ("corgi") format, per the npm registry docs.
ABBREVIATED_FIELDS = (
    "name",
    "version",
    "deprecated",
    "dependencies",
    "optionalDependencies",
    "devDependencies",
    "bundleDependencies",
    "peerDependencies",
    "peerDependenciesMeta",
    "acceptDependencies",
    "bin",
    "directories",
    "dist",
    "engines",
    "cpu",
    "os",
    "libc",
    "funding",
    "_hasShrinkwrap",
    "hasInstallScript",
)
_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")


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
    raw: bytes
    published: float | None
    tarball: str | None
    integrity: str | None
    shasum: str | None
    size: int | None


@dataclass(slots=True)
class Packument:
    name: str
    top: dict[str, msgspec.Raw]
    versions: dict[str, VersionInfo]
    time: dict[str, Any]
    dist_tags: dict[str, str]
    etag: str | None
    raw_size: int
    unpublished: bool = False
    by_tarball_path: dict[str, str] = field(default_factory=dict)  # "/pkg/-/pkg-1.0.0.tgz" -> version


def parse(raw: bytes, *, name: str, etag: str | None, upstream_bases: list[str]) -> Packument:
    top = _raw_map.decode(raw)
    time_map = _any.decode(top["time"]) if "time" in top else {}
    if not isinstance(time_map, dict):
        time_map = {}
    tags_raw = _any.decode(top["dist-tags"]) if "dist-tags" in top else {}
    dist_tags = {k: v for k, v in tags_raw.items() if isinstance(v, str)} if isinstance(tags_raw, dict) else {}
    versions: dict[str, VersionInfo] = {}
    by_path: dict[str, str] = {}
    if "versions" in top:
        for ver, blob in _raw_map.decode(top["versions"]).items():
            data = bytes(blob)
            lite = _lite.decode(data)
            tarball = lite.dist.tarball
            versions[ver] = VersionInfo(
                version=ver,
                raw=data,
                published=parse_time(time_map.get(ver)),
                tarball=tarball,
                integrity=lite.dist.integrity,
                shasum=lite.dist.shasum,
                size=lite.dist.unpackedSize,
            )
            if tarball:
                for base in upstream_bases:
                    for scheme_base in (base, base.replace("https://", "http://", 1)):
                        if tarball.startswith(scheme_base + "/"):
                            by_path[tarball[len(scheme_base) :]] = ver
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
        by_tarball_path=by_path,
    )


def recompute_tags(original: dict[str, str], kept: list[str]) -> dict[str, str]:
    """`latest` -> highest kept stable version (falls back to highest kept); other tags kept only if
    their target is still served."""
    if not kept:
        return {}
    kept_set = set(kept)
    out: dict[str, str] = {}
    for tag, target in original.items():
        if tag != "latest" and target in kept_set:
            out[tag] = target
    latest = original.get("latest")
    if latest in kept_set:
        out["latest"] = latest  # type: ignore[assignment]
    else:
        stable = [v for v in kept if not V.is_prerelease("npm", v)]
        pool = stable or kept
        cap = V.parse_semver(latest) if latest else None
        below = [v for v in pool if cap is None or (V.parse_semver(v) is not None and V.parse_semver(v) <= cap)]  # type: ignore[operator]
        out["latest"] = max(below or pool, key=lambda v: V.sort_key("npm", v))
    return {"latest": out.pop("latest"), **out}


def _rewrite(raw: bytes, upstream_bases: list[str], public_base: str) -> bytes:
    pub = public_base.encode()
    for base in upstream_bases:
        b = base.encode()
        if b in raw:
            raw = raw.replace(b + b"/", pub + b"/")
        hb = b.replace(b"https://", b"http://", 1)
        if hb != b and hb in raw:
            raw = raw.replace(hb + b"/", pub + b"/")
    return raw


def render_full(
    p: Packument, kept: list[str], tags: dict[str, str], *, upstream_bases: list[str], public_base: str
) -> bytes:
    versions_blob = (
        b"{"
        + b",".join(_enc.encode(v) + b":" + _rewrite(p.versions[v].raw, upstream_bases, public_base) for v in kept)
        + b"}"
    )
    kept_set = set(kept)
    time_out = {k: v for k, v in p.time.items() if k in ("created", "modified", "unpublished") or k in kept_set}
    out: dict[str, Any] = {}
    for key, blob in p.top.items():
        if key == "versions":
            out[key] = msgspec.Raw(versions_blob)
        elif key == "time":
            out[key] = time_out
        elif key == "dist-tags":
            out[key] = tags
        else:
            out[key] = blob
    if "versions" not in out and kept:
        out["versions"] = msgspec.Raw(versions_blob)
    return _enc.encode(out)


def render_abbreviated(
    p: Packument, kept: list[str], tags: dict[str, str], *, upstream_bases: list[str], public_base: str
) -> bytes:
    vers: dict[str, Any] = {}
    for v in kept:
        doc = _any.decode(_rewrite(p.versions[v].raw, upstream_bases, public_base))
        if not isinstance(doc, dict):
            continue
        slim = {k: doc[k] for k in ABBREVIATED_FIELDS if k in doc}
        scripts = doc.get("scripts")
        if "hasInstallScript" not in slim and isinstance(scripts, dict) and any(s in scripts for s in _INSTALL_SCRIPTS):
            slim["hasInstallScript"] = True
        vers[v] = slim
    modified = p.time.get("modified")
    out: dict[str, Any] = {"name": p.name, "dist-tags": tags, "versions": vers}
    if isinstance(modified, str):
        out["modified"] = modified
    return _enc.encode(out)


def render_version(p: Packument, version: str, *, upstream_bases: list[str], public_base: str) -> bytes:
    return _rewrite(p.versions[version].raw, upstream_bases, public_base)
