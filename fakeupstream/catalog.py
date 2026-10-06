"""Deterministic package catalog for the fake registry (PyPI, npm, Go modules, Maven, crates.io, OSV, GitHub
advisories).

All times are relative to a fixed reference `now` so tests, e2e runs and perf runs are reproducible.
Small artifacts are *real* installable distributions (wheel/sdist/npm tarball, deterministic bytes);
perf-only artifacts (`big-wheel`) are raw deterministic bytes generated on the fly.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import random
import tarfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

DAY = 86400.0
CHUNK = 64 * 1024
_ZIP_TIME = (2020, 1, 1, 0, 0, 0)


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def iso_s(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def pep503(name: str) -> str:
    import re

    return re.sub(r"[-_.]+", "-", name).lower()


# ---- blobs --------------------------------------------------------------------------------------


@dataclass(slots=True)
class Blob:
    """An artifact body: either concrete bytes or a generated stream of `size` bytes."""

    key: str
    data: bytes | None = None
    size: int = 0
    seed: int = 0
    tampered: bool = False
    _digests: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.data is not None:
            self.size = len(self.data)

    def chunks(self, tampered: bool = False) -> Iterator[bytes]:
        if self.data is not None:
            data = _tamper(self.data) if tampered else self.data
            for i in range(0, len(data), CHUNK):
                yield data[i : i + CHUNK]
            return
        block = random.Random(f"{self.seed}:{self.key}").randbytes(1 << 20)
        remaining = self.size
        first = True
        while remaining > 0:
            part = block[: min(len(block), remaining)]
            if tampered and first:
                part = _tamper(part)
            first = False
            for i in range(0, len(part), CHUNK):
                yield part[i : i + CHUNK]
            remaining -= len(part)

    def digests(self) -> dict[str, str]:
        if not self._digests:
            h256, h512, h1, hb = (
                hashlib.sha256(),
                hashlib.sha512(),
                hashlib.sha1(usedforsecurity=False),
                hashlib.blake2b(digest_size=32),
            )
            for c in self.chunks():
                for h in (h256, h512, h1, hb):
                    h.update(c)
            self._digests = {
                "sha256": h256.hexdigest(),
                "sha512_b64": base64.b64encode(h512.digest()).decode(),
                "sha1": h1.hexdigest(),
                "blake2b": hb.hexdigest(),
            }
        return self._digests


def _tamper(data: bytes) -> bytes:
    """Same length, different bytes (so only the digests betray it)."""
    if not data:
        return b"x"
    b = bytearray(data)
    for i in range(0, min(len(b), 4096), 97):
        b[i] ^= 0x5A
    b[-1] ^= 0xFF
    return bytes(b)


# ---- distribution builders -------------------------------------------------------------------------


def _zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            info = zipfile.ZipInfo(name, date_time=_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, content)
    return buf.getvalue()


def _targz(files: dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mtime = 0
            info.mode = 0o644
            info.uname = info.gname = ""
            tf.addfile(info, io.BytesIO(content))
    return gzip.compress(raw.getvalue(), mtime=0)


def _metadata(name: str, version: str) -> bytes:
    return (
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
        f"Summary: Fake package {name} for SlowShield tests\nRequires-Python: >=3.8\n"
    ).encode()


def make_wheel(name: str, version: str) -> tuple[bytes, bytes]:
    """(wheel bytes, METADATA bytes) for a pure-Python wheel that pip/uv can install."""
    dist = pep503(name).replace("-", "_")
    di = f"{dist}-{version}.dist-info"
    module = f"{dist}/__init__.py"
    meta = _metadata(name, version)
    files = {
        module: f'__version__ = "{version}"\n'.encode(),
        f"{di}/METADATA": meta,
        f"{di}/WHEEL": b"Wheel-Version: 1.0\nGenerator: fakeupstream\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    record_lines = []
    for path, content in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        record_lines.append(f"{path},sha256={digest},{len(content)}")
    record_lines.append(f"{di}/RECORD,,")
    files[f"{di}/RECORD"] = ("\n".join(record_lines) + "\n").encode()
    return _zip(files), meta


def make_sdist(name: str, version: str, filename: str) -> bytes:
    stem = filename.removesuffix(".tar.gz").removesuffix(".zip")
    dist = pep503(name).replace("-", "_")
    files = {
        f"{stem}/PKG-INFO": _metadata(name, version),
        f"{stem}/pyproject.toml": (
            f'[build-system]\nrequires = []\nbuild-backend = "fake"\n'
            f'[project]\nname = "{name}"\nversion = "{version}"\n'
        ).encode(),
        f"{stem}/{dist}/__init__.py": f'__version__ = "{version}"\n'.encode(),
    }
    return _zip(files) if filename.endswith(".zip") else _targz(files)


def go_h1(files: dict[str, bytes]) -> str:
    """The checksum database's h1 of a set of files (dirhash Hash1), computed from the files themselves."""
    summary = "".join(f"{hashlib.sha256(files[n]).hexdigest()}  {n}\n" for n in sorted(files))
    return "h1:" + base64.b64encode(hashlib.sha256(summary.encode()).digest()).decode()


def make_go_module(path: str, version: str) -> tuple[bytes, bytes, str, str]:
    """(zip, go.mod, zip h1, go.mod h1) for a module the go command can download and build."""
    mod = f"module {path}\n\ngo 1.19\n".encode()
    pkg = path.rsplit("/", 1)[-1].replace(".", "_").replace("-", "_").lower()
    prefix = f"{path}@{version}/"
    files = {
        prefix + "go.mod": mod,
        prefix + f"{pkg}.go": f'package {pkg}\n\n// Version is {version}.\nconst Version = "{version}"\n'.encode(),
    }
    return _zip(files), mod, go_h1(files), go_h1({"go.mod": mod})


def make_pom(group: str, artifact: str, version: str, packaging: str = "jar") -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        f"  <modelVersion>4.0.0</modelVersion>\n  <groupId>{group}</groupId>\n  <artifactId>{artifact}</artifactId>\n"
        f"  <version>{version}</version>\n  <packaging>{packaging}</packaging>\n</project>\n"
    ).encode()


def make_jar(group: str, artifact: str, version: str) -> bytes:
    return _zip({"META-INF/MANIFEST.MF": f"Manifest-Version: 1.0\nImplementation-Version: {version}\n".encode()})


def make_crate(name: str, version: str, deps: tuple[tuple[str, str], ...] = ()) -> bytes:
    """A .crate cargo can unpack and build: a gzipped tarball of `<name>-<version>/` with Cargo.toml and src/lib.rs."""
    stem = f"{name}-{version}"
    manifest = f'[package]\nname = "{name}"\nversion = "{version}"\nedition = "2021"\n'
    if deps:
        manifest += "\n[dependencies]\n" + "".join(f'{dep} = "{req}"\n' for dep, req in deps)
    lib = f'pub const VERSION: &str = "{version}";\n'
    return _targz({f"{stem}/Cargo.toml": manifest.encode(), f"{stem}/src/lib.rs": lib.encode()})


def make_npm_tarball(name: str, version: str) -> bytes:
    pkg = f'{{"name": "{name}", "version": "{version}", "main": "index.js", "license": "MIT"}}\n'.encode()
    return _targz({"package/package.json": pkg, "package/index.js": f"module.exports = {version!r};\n".encode()})


# ---- catalog model ----------------------------------------------------------------------------------


@dataclass(slots=True)
class PyFile:
    filename: str
    blob: Blob
    upload_time: float
    metadata: Blob | None = None
    yanked: bool | str = False
    requires_python: str | None = ">=3.8"

    @property
    def path(self) -> str:
        b = self.blob.digests()["blake2b"]
        return f"/packages/{b[:2]}/{b[2:4]}/{b[4:]}/{self.filename}"


@dataclass(slots=True)
class PyProject:
    name: str
    versions: dict[str, list[PyFile]] = field(default_factory=dict)


@dataclass(slots=True)
class NpmVersion:
    version: str
    published: float
    blob: Blob
    integrity: bool = True
    deprecated: str | None = None
    install_script: bool = False


@dataclass(slots=True)
class NpmPackage:
    name: str
    versions: dict[str, NpmVersion] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    created: float = 0.0

    @property
    def basename(self) -> str:
        return self.name.rsplit("/", 1)[-1]


@dataclass(slots=True)
class GoVersion:
    version: str
    stored: float | None  # when the mirror stored it (its Last-Modified); None: not on the mirror yet
    commit: float  # the `.info` Time: the commit time, which the author sets (and can backdate)
    zip: Blob
    mod: Blob
    zip_h1: str
    mod_h1: str
    record: int  # checksum database record number


@dataclass(slots=True)
class GoModule:
    path: str
    versions: dict[str, GoVersion] = field(default_factory=dict)
    head: str | None = None  # what @latest resolves the default branch to, for modules without tags


@dataclass(slots=True)
class MavenFile:
    blob: Blob
    stored: float | None  # Last-Modified; None: rewritten on every request (a repository that migrates files)


@dataclass(slots=True)
class MavenArtifact:
    repo: str  # central | google | portal | snapshots
    group: str
    artifact: str
    versions: dict[str, dict[str, MavenFile]] = field(default_factory=dict)  # version -> filename -> file

    @property
    def path(self) -> str:
        return f"{self.group.replace('.', '/')}/{self.artifact}"


@dataclass(slots=True)
class CrateVersion:
    name: str  # exactly as published (the fake static host is case- and `-`/`_`-sensitive, like the real one)
    vers: str
    pubtime: float | None  # None: an index line without `pubtime`
    blob: Blob
    yanked: bool = False
    deps: tuple[tuple[str, str], ...] = ()  # (name, requirement)


@dataclass(slots=True)
class Advisory:
    source: str  # osv | github
    ecosystem: str  # PyPI | npm | Go | Maven | crates.io (OSV) / pip | npm | go | maven | rust (GitHub)
    id: str
    package: str
    modified: float
    versions: list[str] = field(default_factory=list)
    ranges: list[tuple[str | None, str | None]] = field(default_factory=list)  # (introduced, fixed)
    gh_range: str | None = None
    withdrawn: bool = False
    summary: str = ""
    aliases: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)  # RustSec's database_specific.categories


class Catalog:
    def __init__(self, *, now: float, seed: int = 1, perf: bool = False) -> None:
        self.now = now
        self.seed = seed
        self.perf = perf
        self.pypi: dict[str, PyProject] = {}
        self.npm: dict[str, NpmPackage] = {}
        self.go: dict[str, GoModule] = {}
        self.maven: dict[tuple[str, str], MavenArtifact] = {}  # (repo, "group/path/artifact") -> artifact
        self.crates: dict[str, dict[str, CrateVersion]] = {}  # lower-case name -> version -> line
        self.advisories: list[Advisory] = []
        self.files_by_path: dict[str, PyFile] = {}
        self.meta_by_path: dict[str, PyFile] = {}
        self.tarballs: dict[str, tuple[NpmPackage, NpmVersion]] = {}
        self._build()

    # -- helpers --
    def add_pypi(self, name: str, version: str, age_days: float, *, yanked: bool | str = False, big: int = 0) -> None:
        proj = self.pypi.setdefault(pep503(name), PyProject(name=pep503(name)))
        t = self.now - age_days * DAY
        files: list[PyFile] = []
        dist = pep503(name).replace("-", "_")
        if big:
            fname = f"{dist}-{version}-py3-none-any.whl"
            files.append(PyFile(fname, Blob(key=fname, size=big, seed=self.seed), t, yanked=yanked))
        else:
            wheel, meta = make_wheel(name, version)
            fname = f"{dist}-{version}-py3-none-any.whl"
            files.append(
                PyFile(
                    fname,
                    Blob(key=fname, data=wheel),
                    t,
                    metadata=Blob(key=fname + ".metadata", data=meta),
                    yanked=yanked,
                )
            )
            sname = f"{name}-{version}.tar.gz"
            files.append(PyFile(sname, Blob(key=sname, data=make_sdist(name, version, sname)), t + 60, yanked=yanked))
        proj.versions[version] = files
        for f in files:
            self.files_by_path[f.path] = f
            if f.metadata is not None:
                self.meta_by_path[f.path + ".metadata"] = f

    def add_pypi_files(self, name: str, version: str, age_days: float, filenames: list[str]) -> None:
        proj = self.pypi.setdefault(pep503(name), PyProject(name=pep503(name)))
        t = self.now - age_days * DAY
        files = []
        for fname in filenames:
            if fname.endswith(".whl"):
                data, meta = make_wheel(name, version)
                files.append(
                    PyFile(fname, Blob(key=fname, data=data), t, metadata=Blob(key=fname + ".metadata", data=meta))
                )
            else:
                files.append(PyFile(fname, Blob(key=fname, data=make_sdist(name, version, fname)), t))
        proj.versions[version] = files
        for f in files:
            self.files_by_path[f.path] = f
            if f.metadata is not None:
                self.meta_by_path[f.path + ".metadata"] = f

    def add_npm(
        self,
        name: str,
        version: str,
        age_days: float,
        *,
        integrity: bool = True,
        tag: str | None = None,
        install_script: bool = False,
        deprecated: str | None = None,
    ) -> None:
        pkg = self.npm.setdefault(name, NpmPackage(name=name))
        t = self.now - age_days * DAY
        blob = Blob(key=f"{name}@{version}", data=make_npm_tarball(name, version))
        pkg.versions[version] = NpmVersion(
            version, t, blob, integrity=integrity, install_script=install_script, deprecated=deprecated
        )
        pkg.created = min(pkg.created or t, t)
        if tag:
            pkg.tags[tag] = version
        self.tarballs[f"/{name}/-/{pkg.basename}-{version}.tgz"] = (pkg, pkg.versions[version])

    def add_go(
        self,
        path: str,
        version: str,
        age_days: float | None,
        *,
        commit_age_days: float | None = None,
        head: bool = False,
    ) -> None:
        """`age_days` is how long ago the mirror stored the version (None: not on the mirror yet)."""
        mod = self.go.setdefault(path, GoModule(path=path))
        zip_bytes, mod_bytes, zip_h1, mod_h1 = make_go_module(path, version)
        stored = None if age_days is None else self.now - age_days * DAY
        commit = self.now - (commit_age_days if commit_age_days is not None else (age_days or 0) + 0.01) * DAY
        mod.versions[version] = GoVersion(
            version,
            stored,
            commit,
            Blob(key=f"{path}@{version}.zip", data=zip_bytes),
            Blob(key=f"{path}@{version}.mod", data=mod_bytes),
            zip_h1,
            mod_h1,
            record=1_000_000 + sum(len(m.versions) for m in self.go.values()),
        )
        if head:
            mod.head = version

    def add_maven(
        self,
        repo: str,
        coords: str,
        version: str,
        age_days: float | None,
        *,
        jar: bool = True,
        extra: dict[str, float] | None = None,
    ) -> None:
        """`age_days` is how long ago the repository stored the files (None: their date changes on every request).
        `extra` adds files (`-sources.jar`, ...) stored that many days ago."""
        group, artifact = coords.split(":")
        art = self.maven.setdefault(
            (repo, f"{group.replace('.', '/')}/{artifact}"), MavenArtifact(repo, group, artifact)
        )
        stored = None if age_days is None else self.now - age_days * DAY
        files = {
            f"{artifact}-{version}.pom": MavenFile(
                Blob(key=f"{coords}:{version}.pom", data=make_pom(group, artifact, version, "jar" if jar else "pom")),
                stored,
            )
        }
        if jar:
            files[f"{artifact}-{version}.jar"] = MavenFile(
                Blob(key=f"{coords}:{version}.jar", data=make_jar(group, artifact, version)), stored
            )
        for suffix, age in (extra or {}).items():
            name = f"{artifact}-{version}{suffix}"
            files[name] = MavenFile(Blob(key=f"{coords}:{name}", data=make_jar(group, artifact, version + suffix)),
                                    self.now - age * DAY)  # fmt: skip
        art.versions[version] = files

    def add_crate(
        self,
        name: str,
        version: str,
        age_days: float,
        *,
        yanked: bool = False,
        pubtime: bool = True,
        deps: tuple[tuple[str, str], ...] = (),
    ) -> None:
        crate = self.crates.setdefault(name.lower(), {})
        blob = Blob(key=f"{name}@{version}.crate", data=make_crate(name, version, deps))
        when = self.now - age_days * DAY if pubtime else None
        crate[version] = CrateVersion(name, version, when, blob, yanked=yanked, deps=deps)

    def crate_line(self, cv: CrateVersion) -> bytes:
        """The index line, with crates.io's key order and compact JSON."""
        line: dict[str, object] = {
            "name": cv.name,
            "vers": cv.vers,
            "deps": [
                {
                    "name": dep,
                    "req": req,
                    "features": [],
                    "optional": False,
                    "default_features": True,
                    "target": None,
                    "kind": "normal",
                }
                for dep, req in cv.deps
            ],
            "cksum": cv.blob.digests()["sha256"],
            "features": {},
            "yanked": cv.yanked,
        }
        if cv.pubtime is not None:
            line["pubtime"] = iso_s(cv.pubtime)
        return json.dumps(line, separators=(",", ":")).encode()

    def _build(self) -> None:
        # PyPI
        self.add_pypi("alpha", "1.0.0", 60)
        self.add_pypi("alpha", "1.0.1", 45, yanked="broken build")
        self.add_pypi("alpha", "1.1.0", 30)
        self.add_pypi("alpha", "2.0.0", 1)
        self.add_pypi("brand-new", "0.1.0", 1 / 24)
        self.add_pypi("malware-pkg", "0.0.1", 40)
        self.add_pypi("partly-bad", "1.0.0", 90)
        self.add_pypi("partly-bad", "1.2.0", 60)
        self.add_pypi("partly-bad", "1.3.0", 20)
        self.add_pypi_files(
            "legacy-names", "1.0.0", 100, ["legacy_names-1.0.0-py3-none-any.whl", "Legacy_Names-1.0.0.tar.gz"]
        )
        self.add_pypi_files("legacy-names", "0.9.0", 200, ["legacy.names-0.9.0.zip"])
        # npm
        self.add_npm("left-pad-ng", "1.0.0", 100)
        self.add_npm("left-pad-ng", "1.1.0", 50, deprecated="use 1.0.0")
        self.add_npm("left-pad-ng", "2.0.0", 2, tag="latest", install_script=True)
        self.add_npm("@acme/widget", "0.1.0", 30)
        self.add_npm("@acme/widget", "0.2.0", 10, tag="latest")
        self.add_npm("@acme/widget", "0.3.0-beta.1", 3, tag="next")
        self.add_npm("malicious-npm", "1.0.0", 20, tag="latest")
        self.add_npm("tagged", "1.0.0", 200)
        self.add_npm("tagged", "1.5.0", 40)
        self.add_npm("tagged", "1.6.0-beta.1", 20, tag="beta")
        self.add_npm("tagged", "2.0.0", 1, tag="latest")
        self.add_npm("tagged", "2.1.0-rc.1", 1, tag="next")
        self.add_npm("old-sha1", "0.1.0", 3000, integrity=False)
        self.add_npm("old-sha1", "0.2.0", 1000, tag="latest")
        self.add_npm("ranged-npm", "1.0.0", 300)
        self.add_npm("ranged-npm", "1.1.0", 200)
        self.add_npm("ranged-npm", "1.2.0", 100, tag="latest")
        # Go: the mirror's storage time is the publish time; commit times are the author's and may be backdated.
        self.add_go("example.com/hello", "v1.0.0", 100)
        self.add_go("example.com/hello", "v1.1.0", 30)
        self.add_go("example.com/hello", "v1.2.0", 2, commit_age_days=2000)  # backdated commit
        self.add_go("example.com/hello", "v1.3.0-rc.1", 1)
        self.add_go("github.com/Acme/Widget", "v0.1.0", 40)
        self.add_go("github.com/Acme/Widget", "v0.2.0", 10)
        self.add_go("example.com/brandnew", "v0.1.0", 1 / 24)
        self.add_go("example.com/untagged", "v0.0.0-20250101000000-0123456789ab", 300)
        self.add_go("example.com/untagged", "v0.0.0-20260920120000-abcdef123456", 1, head=True)
        self.add_go("example.com/unstored", "v0.9.0", 200)
        self.add_go("example.com/unstored", "v1.0.0", None, commit_age_days=400)
        self.add_go("example.com/malware", "v1.0.0", 40)
        self.add_go("example.com/partly", "v1.0.0", 90)
        self.add_go("example.com/partly", "v1.1.0", 60)
        self.add_go("example.com/incompat", "v2.0.0+incompatible", 50)
        self.add_go("example.com/redirected", "v1.0.0", 50)  # its zip is served from "storage" via a 302
        self.add_go("example.com/nolm", "v1.0.0", 300)  # served without Last-Modified
        # Maven: Central (checksum headers), Google (checksum files, group index), the Plugin Portal (303s).
        self.add_maven("central", "org.example:hello", "1.0.0", 100)
        self.add_maven("central", "org.example:hello", "1.1.0", 30)
        self.add_maven("central", "org.example:hello", "1.2.0", 2)
        self.add_maven("central", "org.example:hello", "1.3.0-SNAPSHOT", 1)
        self.add_maven("central", "org.example:late-classifier", "1.0.0", 100, extra={"-extra.jar": 1})
        self.add_maven("central", "org.example:bom", "1.0.0", 100, jar=False)
        self.add_maven("central", "org.example:bom", "1.1.0", 2, jar=False)
        self.add_maven("central", "org.example:brandnew", "0.1.0", 1 / 24)
        self.add_maven("central", "org.example:migrated", "1.0.0", None)
        self.add_maven("central", "org.example:migrated", "0.9.0", None)
        self.add_maven("central", "org.example:partly", "1.0.0", 90)
        self.add_maven("central", "org.example:partly", "1.1.0", 60)
        self.add_maven("central", "io.github.evil:typosquat", "1.0.0", 40)
        self.add_maven("google", "androidx.test:core", "1.5.0", 200)
        self.add_maven("google", "androidx.test:core", "1.6.0", 3)
        self.add_maven("portal", "com.example.plugin:com.example.plugin.gradle.plugin", "1.0", 50, jar=False)
        self.add_maven("snapshots", "org.example:nightly", "2.0-SNAPSHOT", 0)
        self.add_maven("snapshots", "org.example:lib-SNAPSHOT", "1.0.0", 1)  # a release, named like a snapshot
        for odd in ("doctype", "anonymous", "prefixed"):  # see maven_metadata() in app.py
            self.add_maven("central", f"org.example:{odd}", "1.0.0", 100)
            self.add_maven("central", f"org.example:{odd}", "1.1.0", 1)
        for i in range(25):  # more new versions than one metadata evaluation looks up
            self.add_maven("central", "org.example:busy", f"2.{i}.0", 1)
        self.add_maven("central", "org.example:busy", "1.0.0", 100)
        # crates.io: index lines carry `pubtime`; names are case- and `-`/`_`-insensitive, downloads are not.
        self.add_crate("fake_hello", "1.0.0", 100)
        self.add_crate("fake_hello", "1.0.1", 90, yanked=True)  # yanked upstream
        self.add_crate("fake_hello", "1.1.0", 30)
        self.add_crate("fake_hello", "1.2.0", 2)
        self.add_crate("fake-deps", "0.1.0", 50, deps=(("fake_hello", "^1"),))
        self.add_crate("Fancy-Name", "1.0.0", 60)
        self.add_crate("brand-new-crate", "0.1.0", 1 / 24)
        self.add_crate("evil-crate", "1.0.0", 40)
        self.add_crate("rustsec-evil", "0.1.0", 50)
        self.add_crate("partly-crate", "1.0.0", 90)
        self.add_crate("partly-crate", "1.1.0", 60)
        self.add_crate("hijacked", "1.0.0", 300)
        self.add_crate("hijacked", "2.0.0", 200)
        self.add_crate("untimed", "1.0.0", 0, pubtime=False)
        if self.perf:
            self.add_pypi("big-wheel", "1.0.0", 30, big=100 * 1024 * 1024)
            for i in range(500):
                self.add_pypi("many-versions", f"1.0.{i}", 600 - i)
            for i in range(5000):
                self.add_npm("huge-packument", f"1.{i // 100}.{i % 100}", 6000 - i)
            self.npm["huge-packument"].tags["latest"] = "1.49.99"
            for i in range(500):
                self.add_go("example.com/many", f"v1.{i // 100}.{i % 100}", 600 - i)
                self.add_maven("central", "org.example:many", f"1.{i // 100}.{i % 100}", 600 - i, jar=False)
                self.add_crate("many-crate", f"1.{i // 100}.{i % 100}", 600 - i)
        for pkg in self.npm.values():
            if "latest" not in pkg.tags:
                pkg.tags["latest"] = list(pkg.versions)[-1]
        # Advisories
        n = self.now
        self.advisories = [
            Advisory(
                "osv",
                "PyPI",
                "MAL-2026-0001",
                "malware-pkg",
                n - 30 * DAY,
                ranges=[("0", None)],
                summary="Malicious code in malware-pkg (PyPI)",
            ),
            Advisory(
                "osv",
                "PyPI",
                "MAL-2026-0002",
                "typosquat-pkg",
                n - 20 * DAY,
                versions=["0.1.0", "0.1.1"],
                summary="Typosquat",
            ),
            Advisory(
                "osv", "PyPI", "PYSEC-2026-0001", "alpha", n - 10 * DAY, versions=["1.0.0"], summary="Not malware"
            ),
            Advisory(
                "osv",
                "PyPI",
                "MAL-2026-0003",
                "withdrawn-pkg",
                n - 5 * DAY,
                ranges=[("0", None)],
                withdrawn=True,
                summary="False positive",
            ),
            Advisory(
                "osv",
                "npm",
                "MAL-2026-1001",
                "malicious-npm",
                n - 15 * DAY,
                ranges=[("0", None)],
                summary="Malicious code in malicious-npm (npm)",
            ),
            Advisory(
                "osv",
                "npm",
                "MAL-2026-1002",
                "@evil/thing",
                n - 12 * DAY,
                versions=["1.0.0"],
                summary="<script>alert(1)</script> exfiltrates tokens",
            ),
            Advisory(
                "osv",
                "npm",
                "GHSA-xxxx-yyyy-zzzz",
                "left-pad-ng",
                n - 11 * DAY,
                versions=["1.0.0"],
                summary="ordinary vuln",
            ),
            Advisory(
                "github",
                "pip",
                "GHSA-aaaa-0001-0001",
                "partly-bad",
                n - 25 * DAY,
                gh_range="= 1.2.0",
                summary="partly-bad 1.2.0 was compromised",
            ),
            Advisory(
                "github",
                "npm",
                "GHSA-aaaa-0002-0002",
                "ranged-npm",
                n - 24 * DAY,
                gh_range=">= 1.1.0, < 1.2.0",
                summary="ranged-npm 1.1.x backdoored",
            ),
            Advisory(
                "github",
                "npm",
                "GHSA-aaaa-0003-0003",
                "malicious-npm",
                n - 23 * DAY,
                gh_range=">= 0",
                summary="malicious-npm",
            ),
            Advisory(
                "osv",
                "Go",
                "MAL-2026-2001",
                "example.com/malware",
                n - 14 * DAY,
                ranges=[("0", None)],
                summary="Malicious code in example.com/malware (Go)",
            ),
            Advisory(
                "github",
                "go",
                "GHSA-aaaa-0005-0005",
                "example.com/partly",
                n - 13 * DAY,
                gh_range="= 1.1.0",
                summary="example.com/partly v1.1.0 was compromised",
            ),
            Advisory(
                "osv",
                "Maven",
                "MAL-2026-3001",
                "io.github.evil:typosquat",
                n - 9 * DAY,
                ranges=[("0", None)],
                summary="Malicious code in io.github.evil:typosquat (Maven)",
            ),
            Advisory(
                "github",
                "maven",
                "GHSA-aaaa-0006-0006",
                "org.example:partly",
                n - 8 * DAY,
                gh_range="= 1.1.0",
                summary="org.example:partly 1.1.0 was compromised",
            ),
            Advisory(
                "osv",
                "crates.io",
                "MAL-2026-4001",
                "evil-crate",
                n - 7 * DAY,
                ranges=[("0", None)],
                summary="Malicious code in evil-crate (crates.io)",
            ),
            Advisory(  # covered by its MAL- alias: not a second block
                "osv",
                "crates.io",
                "RUSTSEC-2026-0002",
                "evil-crate",
                n - 7 * DAY,
                ranges=[("0.0.0-0", None)],
                summary="malicious crate `evil-crate`",
                aliases=["MAL-2026-4001"],
                categories=["malicious"],
            ),
            Advisory(  # RustSec only
                "osv",
                "crates.io",
                "RUSTSEC-2026-0001",
                "rustsec-evil",
                n - 6 * DAY,
                ranges=[("0.0.0-0", None)],
                summary="malicious crate `rustsec-evil`",
                aliases=["GHSA-rrrr-0001-0001"],
                categories=["code-execution", "malicious"],
            ),
            Advisory(  # an ordinary vulnerability: not a block
                "osv",
                "crates.io",
                "RUSTSEC-2026-0003",
                "fake_hello",
                n - 6 * DAY,
                ranges=[("0.0.0-0", "1.1.0")],
                summary="Out-of-bounds read in fake_hello",
                categories=["memory-corruption"],
            ),
            Advisory(  # malicious from 2.0.0 on, open-ended: the later versions are not malware, so not a block
                "osv",
                "crates.io",
                "RUSTSEC-2026-0004",
                "hijacked",
                n - 5 * DAY,
                ranges=[("2.0.0", None)],
                summary="hijacked 2.0.0 was published by an attacker",
                categories=["malicious"],
            ),
            Advisory(
                "github",
                "rust",
                "GHSA-aaaa-0007-0007",
                "partly-crate",
                n - 4 * DAY,
                gh_range="= 1.1.0",
                summary="partly-crate 1.1.0 was compromised",
            ),
            Advisory(
                "github",
                "npm",
                "GHSA-aaaa-0004-0004",
                "withdrawn-npm",
                n - 2 * DAY,
                gh_range=">= 0",
                withdrawn=True,
                summary="withdrawn",
            ),
        ]

    def publish(self, ecosystem: str, name: str, version: str, age_days: float | None = 0.0) -> None:
        """`age_days=None` (Go): tagged, but not on the mirror until someone asks for it."""
        if ecosystem == "pypi":
            self.add_pypi(name, version, age_days or 0.0)
        elif ecosystem == "go":
            self.add_go(name, version, age_days)
        elif ecosystem == "maven":
            self.add_maven("central", name, version, age_days)
        elif ecosystem == "cargo":
            self.add_crate(name, version, age_days or 0.0)
        else:
            self.add_npm(name, version, age_days or 0.0, tag="latest")
