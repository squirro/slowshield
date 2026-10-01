"""Render a filtered project as PEP 691 JSON or PEP 503/691 HTML.

File URLs are relative (`../../packages/...`) so the same bytes work for host routing and for the
`/pypi` path prefix without trusting the Host header.
"""

from __future__ import annotations

from html import escape
from typing import Any

import msgspec

from slowshield.ecosystems.pypi.project import SUPPORTED_API, Project, PyFile

_enc = msgspec.json.Encoder()


def _api(project: Project) -> str:
    major, minor = min(project.api_version, SUPPORTED_API)
    return f"{major}.{minor}"


def _rel(path: str) -> str:
    return "../.." + path


def render_json(project: Project, files: list[PyFile], versions: list[str]) -> bytes:
    out_files: list[dict[str, Any]] = []
    for f in files:
        item: dict[str, Any] = {
            "filename": f.filename,
            "url": _rel(f.path),
            "hashes": {"sha256": f.sha256} if f.sha256 else {},
        }
        if f.requires_python is not None:
            item["requires-python"] = f.requires_python
        if f.core_metadata:
            item["core-metadata"] = f.core_metadata
            item["dist-info-metadata"] = f.core_metadata
        if f.yanked:
            item["yanked"] = f.yanked
        else:
            item["yanked"] = False
        if f.size is not None:
            item["size"] = f.size
        if f.upload_time_raw is not None:
            item["upload-time"] = f.upload_time_raw
        if f.provenance:
            item["provenance"] = f.provenance
        out_files.append(item)
    doc: dict[str, Any] = {"meta": {"api-version": _api(project)}, "name": project.name}
    if project.status is not None and min(project.api_version, SUPPORTED_API) >= (1, 4):
        doc["project-status"] = project.status
    doc["versions"] = versions
    doc["files"] = out_files
    return _enc.encode(doc)


def render_html(project: Project, files: list[PyFile]) -> bytes:
    name = escape(project.name)
    parts = [
        "<!DOCTYPE html>\n<html>\n<head>\n",
        f'<meta name="pypi:repository-version" content="{_api(project)}">\n',
    ]
    if project.status and isinstance(project.status.get("status"), str):
        parts.append(f'<meta name="pypi:project-status" content="{escape(project.status["status"])}">\n')
    parts.append(f"<title>Links for {name}</title>\n</head>\n<body>\n<h1>Links for {name}</h1>\n")
    for f in files:
        href = _rel(f.path) + (f"#sha256={f.sha256}" if f.sha256 else "")
        attrs = [f'href="{escape(href)}"']
        if f.requires_python:
            attrs.append(f'data-requires-python="{escape(f.requires_python)}"')
        if f.core_metadata:
            meta = (
                f"sha256={f.core_metadata['sha256']}"
                if isinstance(f.core_metadata, dict) and f.core_metadata.get("sha256")
                else "true"
            )
            attrs.append(f'data-core-metadata="{escape(meta)}"')
            attrs.append(f'data-dist-info-metadata="{escape(meta)}"')
        if f.yanked:
            reason = f.yanked if isinstance(f.yanked, str) else ""
            attrs.append(f'data-yanked="{escape(reason)}"')
        if f.provenance:
            attrs.append(f'data-provenance="{escape(f.provenance)}"')
        parts.append(f"<a {' '.join(attrs)}>{escape(f.filename)}</a><br>\n")
    parts.append("</body>\n</html>\n")
    return "".join(parts).encode()


def render_root(fmt: str) -> bytes:
    """We do not mirror the ~600k-project root index; resolvers don't need it."""
    if fmt == "json":
        return _enc.encode({"meta": {"api-version": "1.1"}, "projects": []})
    return b'<!DOCTYPE html>\n<html><head><meta name="pypi:repository-version" content="1.1"><title>Simple index</title></head><body></body></html>\n'
