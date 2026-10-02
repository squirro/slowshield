"""PEP 691 (JSON simple API) project documents: parsing and the in-memory model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

import msgspec

from slowshield.ecosystems.pypi import filenames

JSON_V1 = "application/vnd.pypi.simple.v1+json"
HTML_V1 = "application/vnd.pypi.simple.v1+html"
SUPPORTED_API = (1, 4)


class _JFile(msgspec.Struct):
    filename: str
    url: str
    hashes: dict[str, str] = {}
    requires_python: str | None = msgspec.field(default=None, name="requires-python")
    size: int | None = None
    upload_time: str | None = msgspec.field(default=None, name="upload-time")
    yanked: bool | str = False
    core_metadata: bool | dict[str, str] | None = msgspec.field(default=None, name="core-metadata")
    dist_info_metadata: bool | dict[str, str] | None = msgspec.field(default=None, name="dist-info-metadata")
    data_dist_info_metadata: bool | dict[str, str] | None = msgspec.field(default=None, name="data-dist-info-metadata")
    provenance: str | None = None


class _JMeta(msgspec.Struct):
    api_version: str = msgspec.field(default="1.0", name="api-version")
    last_serial: int | None = msgspec.field(default=None, name="_last-serial")


class _JProject(msgspec.Struct):
    name: str
    files: list[_JFile] = []
    meta: _JMeta = msgspec.field(default_factory=_JMeta)
    versions: list[str] | None = None
    project_status: dict[str, Any] | None = msgspec.field(default=None, name="project-status")


_decoder = msgspec.json.Decoder(_JProject)


@dataclass(slots=True)
class PyFile:
    filename: str
    path: str  # "/packages/aa/bb/<60>/<filename>"
    blake2b_256: str
    sha256: str | None
    size: int | None
    upload_time: float | None
    upload_time_raw: str | None
    yanked: bool | str
    requires_python: str | None
    core_metadata: dict[str, str] | bool  # hashes of the PEP 658 .metadata file, True if present w/o hashes
    provenance: str | None
    version: str | None
    # Render caches (a file's JSON item / HTML anchor never changes once parsed).
    json_item: bytes | None = field(default=None, repr=False, compare=False)
    html_line: str | None = field(default=None, repr=False, compare=False)


@dataclass(slots=True)
class Project:
    name: str  # normalised
    files: list[PyFile]
    versions: list[str]
    api_version: tuple[int, int]
    status: dict[str, Any] | None
    etag: str | None
    last_serial: int | None
    raw_size: int
    by_filename: dict[str, PyFile] = field(default_factory=dict)
    skipped: int = 0  # files we cannot serve (unexpected URL layout)

    def __post_init__(self) -> None:
        self.by_filename = {f.filename: f for f in self.files}

    @property
    def quarantined(self) -> bool:
        return bool(self.status and self.status.get("status") == "quarantined")


def parse_time(raw: str | None) -> float | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.timestamp()


def _api_version(raw: str) -> tuple[int, int]:
    major, _, minor = raw.partition(".")
    try:
        return int(major), int(minor or 0)
    except ValueError:
        return (1, 0)


def _artifact_path(abs_url: str, files_url: str | None) -> str | None:
    """`/packages/...` path of a file URL, or None if it is not served from `files_url`."""
    clean = abs_url.split("#", 1)[0].split("?", 1)[0]
    if files_url is None:
        return urlsplit(clean).path
    prefix = files_url.rstrip("/")
    if not clean.startswith(prefix + "/"):
        return None
    return clean[len(prefix) :]


def parse_project(raw: bytes, *, base_url: str, name: str, etag: str | None, files_url: str | None = None) -> Project:
    """Parse a PEP 691 document. Files not hosted under `files_url` (when given) are skipped."""
    doc = _decoder.decode(raw)
    versions = list(doc.versions or [])
    files: list[PyFile] = []
    skipped = 0
    for f in doc.files:
        url = f.url if f.url.startswith(("https://", "http://")) else urljoin(base_url, f.url)
        path = _artifact_path(url, files_url)
        m = filenames.PACKAGES_PATH.match(path) if path is not None else None
        if path is None or m is None or m.group(4) != f.filename:
            skipped += 1
            continue
        blake = m.group(1) + m.group(2) + m.group(3)
        _n, version = filenames.parse(f.filename, known_versions=versions, project=name)
        meta = (
            f.core_metadata
            if f.core_metadata is not None
            else (f.dist_info_metadata if f.dist_info_metadata is not None else f.data_dist_info_metadata)
        )
        files.append(
            PyFile(
                filename=f.filename,
                path=path,
                blake2b_256=blake,
                sha256=(f.hashes.get("sha256") or None),
                size=f.size,
                upload_time=parse_time(f.upload_time),
                upload_time_raw=f.upload_time,
                yanked=f.yanked,
                requires_python=f.requires_python,
                core_metadata=meta if isinstance(meta, dict) else bool(meta),
                provenance=f.provenance,
                version=version,
            )
        )
    if not versions:
        seen: dict[str, None] = {}
        for pf in files:
            if pf.version:
                seen.setdefault(pf.version, None)
        versions = list(seen)
    return Project(
        name=name,
        files=files,
        versions=versions,
        api_version=_api_version(doc.meta.api_version),
        status=doc.project_status,
        etag=etag,
        last_serial=doc.meta.last_serial,
        raw_size=len(raw),
        skipped=skipped,
    )
