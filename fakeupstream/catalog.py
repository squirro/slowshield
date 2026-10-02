"""Deterministic package catalog for the fake registry (PyPI, npm, OSV, GitHub advisories).

All times are relative to a fixed reference `now` so tests, e2e runs and perf runs are reproducible.
Small artifacts are *real* installable distributions (wheel/sdist/npm tarball, deterministic bytes);
perf-only artifacts (`big-wheel`) are raw deterministic bytes generated on the fly.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
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
class Advisory:
    source: str  # osv | github
    ecosystem: str  # PyPI | npm (OSV) / pip | npm (GitHub)
    id: str
    package: str
    modified: float
    versions: list[str] = field(default_factory=list)
    ranges: list[tuple[str | None, str | None]] = field(default_factory=list)  # (introduced, fixed)
    gh_range: str | None = None
    withdrawn: bool = False
    summary: str = ""


class Catalog:
    def __init__(self, *, now: float, seed: int = 1, perf: bool = False) -> None:
        self.now = now
        self.seed = seed
        self.perf = perf
        self.pypi: dict[str, PyProject] = {}
        self.npm: dict[str, NpmPackage] = {}
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
        if self.perf:
            self.add_pypi("big-wheel", "1.0.0", 30, big=100 * 1024 * 1024)
            for i in range(500):
                self.add_pypi("many-versions", f"1.0.{i}", 600 - i)
            for i in range(5000):
                self.add_npm("huge-packument", f"1.{i // 100}.{i % 100}", 6000 - i)
            self.npm["huge-packument"].tags["latest"] = "1.49.99"
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

    def publish(self, ecosystem: str, name: str, version: str, age_days: float = 0.0) -> None:
        if ecosystem == "pypi":
            self.add_pypi(name, version, age_days)
        else:
            self.add_npm(name, version, age_days, tag="latest")
