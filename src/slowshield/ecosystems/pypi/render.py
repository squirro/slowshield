"""Render a filtered project as PEP 691 JSON or PEP 503/691 HTML.

File URLs are relative (`../../packages/...`) so the same bytes work for host routing and for the
`/pypi` path prefix without trusting the Host header. Each file's JSON item and HTML anchor is built
once and cached on the parsed file, so re-rendering after a policy change is a cheap join.
"""

from __future__ import annotations

from html import escape
from typing import Any

import msgspec

from slowshield.ecosystems.pypi.project import SUPPORTED_API, Project, PyFile

_enc = msgspec.json.Encoder()

# Bump when the rendered index changes for the same input. It is part of the view digest, which keys stored
# bodies and makes the ETag, so servers re-render and clients holding an older copy are not sent a 304 for it.
RENDER_REVISION = "2"


def _api(project: Project) -> str:
    major, minor = min(project.api_version, SUPPORTED_API)
    return f"{major}.{minor}"


def _rel(path: str) -> str:
    return "../.." + path


def _json_item(f: PyFile) -> bytes:
    if f.json_item is None:
        item: dict[str, Any] = {
            "filename": f.filename,
            "url": _rel(f.path),
            "hashes": {"sha256": f.sha256} if f.sha256 else {},
        }
        if f.requires_python is not None:
            item["requires-python"] = f.requires_python
        if f.core_metadata:
            item["core-metadata"] = f.core_metadata
            # PEP 714: never the old "dist-info-metadata" key. pip 22.3-23.1 (Debian 12's pip 23.0.1 among them)
            # crash on its dict value; like PyPI, repeat it only under the key those versions ignore.
            item["data-dist-info-metadata"] = f.core_metadata
        item["yanked"] = f.yanked or False
        if f.size is not None:
            item["size"] = f.size
        if f.upload_time_raw is not None:
            item["upload-time"] = f.upload_time_raw
        if f.provenance:
            item["provenance"] = f.provenance
        f.json_item = _enc.encode(item)
    return f.json_item


def _html_line(f: PyFile) -> str:
    if f.html_line is None:
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
        f.html_line = f"<a {' '.join(attrs)}>{escape(f.filename)}</a><br>\n"
    return f.html_line


def render_json(project: Project, files: list[PyFile], versions: list[str]) -> bytes:
    head: dict[str, Any] = {"meta": {"api-version": _api(project)}, "name": project.name}
    if project.status is not None and min(project.api_version, SUPPORTED_API) >= (1, 4):
        head["project-status"] = project.status
    head["versions"] = versions
    prefix = _enc.encode(head)[:-1]  # drop the closing brace, append "files"
    return b"".join((prefix, b',"files":[', b",".join(_json_item(f) for f in files), b"]}"))


def render_html(project: Project, files: list[PyFile]) -> bytes:
    name = escape(project.name)
    parts = [
        "<!DOCTYPE html>\n<html>\n<head>\n",
        f'<meta name="pypi:repository-version" content="{_api(project)}">\n',
    ]
    if project.status and isinstance(project.status.get("status"), str):
        parts.append(f'<meta name="pypi:project-status" content="{escape(project.status["status"])}">\n')
    parts.append(f"<title>Links for {name}</title>\n</head>\n<body>\n<h1>Links for {name}</h1>\n")
    parts.extend(_html_line(f) for f in files)
    parts.append("</body>\n</html>\n")
    return "".join(parts).encode()


def render_root(fmt: str) -> bytes:
    """We do not mirror the ~600k-project root index; resolvers don't need it."""
    if fmt == "json":
        return _enc.encode({"meta": {"api-version": "1.1"}, "projects": []})
    return (
        b'<!DOCTYPE html>\n<html><head><meta name="pypi:repository-version" content="1.1">'
        b"<title>Simple index</title></head><body></body></html>\n"
    )
