"""PyPI simple API proxy: metadata filtering (per-file release age, blocklist) and artifact gating."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route, Router

from slowshield import names
from slowshield.blocklist import BlockEntry, PackageBlocks
from slowshield.cache.metadata import SingleFlight
from slowshield.context import AppContext
from slowshield.ecosystems.artifacts import ArtifactRequest
from slowshield.ecosystems.pypi import filenames
from slowshield.ecosystems.pypi.project import HTML_V1, JSON_V1, Project, PyFile, parse_project
from slowshield.ecosystems.pypi.render import render_html, render_json, render_root
from slowshield.integrity import Expected
from slowshield.policy import DAY, Candidate, evaluate, retry_after
from slowshield.telemetry import instruments
from slowshield.upstream import TooLargeError, UpstreamError
from slowshield.web import accept_prefers, client_ip, error, not_found

log = logging.getLogger(__name__)

ECO = "pypi"
MAX_INDEX_BYTES = 50 * 1024 * 1024
_NOT_FOUND = object()
_FORMATS = ("text/html", HTML_V1, JSON_V1)


@dataclass(slots=True)
class View:
    project: Project
    files: list[PyFile] = field(default_factory=list)
    versions: list[str] = field(default_factory=list)
    allowed: set[str] = field(default_factory=set)  # filenames
    held: dict[str, PyFile] = field(default_factory=dict)  # filename -> file (too new)
    held_versions: set[str] = field(default_factory=set)
    blocked: dict[str, BlockEntry] = field(default_factory=dict)  # filename -> block
    fail_open: bool = False
    next_change: float = float("inf")
    package_block: BlockEntry | None = None
    rendered: dict[str, bytes] = field(default_factory=dict)
    digest: str = ""

    @property
    def everything_blocked(self) -> bool:
        return bool(self.blocked) and not self.files and not self.held


def _iso(ts: float | None) -> str | None:
    return None if ts is None else datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class PypiService:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self.flight = SingleFlight()

    # ---- upstream metadata ----------------------------------------------------------------------

    def _index_urls(self, name: str) -> list[str]:
        return [f"{m.rstrip('/')}/simple/{name}/" for m in self.ctx.cfg.raw.upstreams.pypi.mirrors]

    async def project(self, name: str) -> Project | None:
        key = ("pypi:doc", name)
        hit = self.ctx.metadata_cache.get(key, self.ctx.clock.now())
        if hit is not None:
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "hit"})
            return None if hit is _NOT_FOUND else hit
        return await self.flight.run(key, lambda: self._load(name))

    async def _load(self, name: str) -> Project | None:
        ctx = self.ctx
        key = ("pypi:doc", name)
        now = ctx.clock.now()
        ttl = ctx.cfg.raw.metadata_cache_ttl_hours * 3600
        stale = ctx.metadata_cache.get_stale(key)
        headers = {"Accept": JSON_V1}
        if isinstance(stale, Project) and stale.etag:
            headers["If-None-Match"] = stale.etag
        try:
            res = await ctx.upstream.fetch(self._index_urls(name), headers=headers, max_bytes=MAX_INDEX_BYTES)
        except TooLargeError:
            raise
        except UpstreamError:
            if isinstance(stale, Project):
                log.warning("upstream unavailable; serving stale index", extra={"package": name})
                ctx.metadata_cache.touch(key, now + 60)
                instruments.cache_requests.add(1, {"cache": "metadata", "result": "stale"})
                return stale
            raise
        if res.status == 304 and isinstance(stale, Project):
            ctx.metadata_cache.touch(key, now + ttl)
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "revalidated"})
            ctx.recorder.catalog(ECO, name)
            return stale
        instruments.cache_requests.add(1, {"cache": "metadata", "result": "miss"})
        if res.status in (404, 410):
            ctx.metadata_cache.put(key, _NOT_FOUND, 64, now + 300)
            return None
        if res.status != 200:
            raise UpstreamError(res.url, f"upstream returned {res.status}", res.status)
        ctype = res.headers.get("content-type", "")
        if not ctype.startswith(JSON_V1):
            raise UpstreamError(res.url, f"upstream does not speak the PEP 691 JSON API (got {ctype or 'no type'})")
        project = parse_project(res.body, base_url=res.url, name=name, etag=res.etag)
        ctx.metadata_cache.put(key, project, project.raw_size * 2 + 1024, now + ttl)
        published: dict[str, float | None] = {}
        yanked: dict[str, bool] = {}
        for f in project.files:
            if f.version is None:
                continue
            t = f.upload_time
            cur = published.get(f.version)
            published[f.version] = t if cur is None else (cur if t is None else min(cur, t))
            yanked[f.version] = yanked.get(f.version, True) and bool(f.yanked)
        ctx.recorder.catalog(ECO, name, [(v, published[v], yanked[v]) for v in published])
        return project

    # ---- policy -----------------------------------------------------------------------------------

    def view(self, project: Project) -> View:
        ctx = self.ctx
        now = ctx.clock.now()
        cfg = ctx.cfg
        key = ("pypi:view", project.name, project.etag or id(project), ctx.policy_key())
        hit = ctx.metadata_cache.get(key, now)
        if hit is not None:
            return hit
        blocks: PackageBlocks = ctx.blocklist.for_package(ECO, project.name)
        v = View(project=project)
        if blocks.package_block is not None:
            v.package_block = blocks.package_block
            ctx.metadata_cache.put(key, v, 256, now + 300)
            return v

        def is_blocked(version: str | None) -> bool:
            return blocks.match(ECO, version) is not None

        ev = evaluate(
            (Candidate(f, f.version, f.upload_time) for f in project.files),
            now=now,
            delay_for=lambda ver: cfg.delay_days_for(ECO, project.name, ver),
            is_blocked=is_blocked,
            fail_open=cfg.raw.fail_open,
        )
        v.files = [c.item for c in ev.allowed]
        v.allowed = {f.filename for f in v.files}
        v.held = {c.item.filename: c.item for c in ev.held}
        v.held_versions = {c.version for c in ev.held if c.version} - {f.version for f in v.files if f.version}
        for c in ev.blocked:
            entry = blocks.match(ECO, c.version)
            if entry is not None:
                v.blocked[c.item.filename] = entry
        allowed_versions = {f.version for f in v.files if f.version}
        v.versions = [ver for ver in project.versions if ver in allowed_versions]
        v.fail_open = ev.fail_open
        v.next_change = ev.next_change
        v.digest = hashlib.blake2b(
            "\n".join(sorted(v.allowed)).encode() + repr(ctx.policy_key()).encode(), digest_size=12
        ).hexdigest()
        ctx.metadata_cache.put(key, v, 512 + 64 * len(project.files), min(ev.next_change, now + 3600))
        return v

    # ---- handlers -----------------------------------------------------------------------------------

    def routes(self) -> list[Route]:
        return [
            Route("/simple", self.simple_root_redirect, methods=["GET"]),
            Route("/simple/", self.simple_root, methods=["GET"]),
            Route("/simple/{name}", self.simple_detail, methods=["GET"]),
            Route("/simple/{name}/", self.simple_detail, methods=["GET"]),
            Route("/packages/{path:path}", self.artifact, methods=["GET"]),
        ]

    def router(self) -> Router:
        return Router(self.routes(), redirect_slashes=False)

    async def simple_root_redirect(self, request: Request) -> Response:
        return RedirectResponse(request.scope.get("root_path", "") + "/simple/", status_code=301)

    async def simple_root(self, request: Request) -> Response:
        fmt = accept_prefers(request.headers.get("accept"), _FORMATS, "text/html")
        kind = "json" if fmt == JSON_V1 else "html"
        return Response(
            render_root(kind), media_type=_media(fmt), headers={"Vary": "Accept", "Cache-Control": "max-age=3600"}
        )

    async def simple_detail(self, request: Request) -> Response:
        ctx = self.ctx
        raw_name: str = request.path_params["name"]
        if not names.is_valid_pypi(raw_name):
            return not_found()
        name = names.normalize_pypi(raw_name)
        if raw_name != name or not request.url.path.endswith("/"):
            return RedirectResponse(f"{request.scope.get('root_path', '')}/simple/{name}/", status_code=301)

        blocks = ctx.blocklist.for_package(ECO, name)
        if blocks.package_block is not None:
            return self._blocked(request, name, None, blocks.package_block, kind="metadata")
        try:
            project = await self.project(name)
        except TooLargeError:
            return error(502, "upstream_error", detail="upstream index too large")
        except UpstreamError as exc:
            ctx.recorder.decision(ECO, "metadata", "upstream_error")
            return error(502, "upstream_error", detail=exc.detail)
        if project is None:
            ctx.recorder.decision(ECO, "metadata", "not_found")
            return not_found()

        v = self.view(project)
        if v.package_block is not None:
            return self._blocked(request, name, None, v.package_block, kind="metadata")
        if v.everything_blocked:
            first = next(iter(v.blocked.values()))
            return self._blocked(request, name, None, first, kind="metadata")

        fmt = accept_prefers(request.headers.get("accept"), _FORMATS, "text/html")
        etag = f'"{v.digest}-{"j" if fmt == JSON_V1 else "h"}"'
        now = ctx.clock.now()
        max_age = int(max(0, min(600, v.next_change - now)))
        headers = {
            "Vary": "Accept",
            "ETag": etag,
            "Cache-Control": f"max-age={max_age}",
            "X-SlowShield-Held-Versions": str(len(v.held_versions)),
        }
        if v.fail_open:
            headers["X-SlowShield-Fail-Open"] = "1"
        self._record_metadata(request, v)
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers=headers)
        body = v.rendered.get(fmt)
        if body is None:
            body = render_json(project, v.files, v.versions) if fmt == JSON_V1 else render_html(project, v.files)
            v.rendered[fmt] = body
        return Response(body, media_type=_media(fmt), headers=headers)

    def _record_metadata(self, request: Request, v: View) -> None:
        ctx = self.ctx
        if v.held_versions:
            instruments.versions_held.add(len(v.held_versions), {"slowshield.ecosystem": ECO})
        if v.fail_open:
            ctx.recorder.decision(ECO, "metadata", "fail_open")
            ctx.recorder.event(
                "fail_open",
                ECO,
                v.project.name,
                None,
                client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
                details={"reason": "all_versions_too_new", "versions": sorted({f.version or "" for f in v.files})[:20]},
            )
        else:
            ctx.recorder.decision(ECO, "metadata", "served")

    def _blocked(self, request: Request, name: str, version: str | None, entry: BlockEntry, *, kind: str) -> Response:
        ctx = self.ctx
        ctx.recorder.decision(ECO, kind, "blocked")
        ctx.recorder.event(
            "blocked",
            ECO,
            name,
            version,
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
            details=entry.as_json(),
        )
        return error(451, "blocked", package=name, version=version, **entry.as_json())

    async def artifact(self, request: Request) -> Response:
        ctx = self.ctx
        raw_path = request.scope.get("raw_path") or b""
        if b"%" in raw_path:
            decoded = unquote(raw_path.decode("latin-1"))
            if ".." in decoded or "\x00" in decoded:
                return not_found()
        rel = "/packages/" + request.path_params["path"]
        is_metadata = rel.endswith(".metadata")
        parent_path = rel[: -len(".metadata")] if is_metadata else rel
        m = filenames.PACKAGES_PATH.match(parent_path)
        if m is None:
            return not_found()
        filename = m.group(4)
        pname, _ver = filenames.parse(filename)
        if not pname or not names.is_valid_pypi(pname):
            return not_found()
        pname = names.normalize_pypi(pname)
        ip = client_ip(request.scope, ctx.cfg.trusted_networks)

        blocks = ctx.blocklist.for_package(ECO, pname)
        if blocks.package_block is not None:
            return self._blocked(request, pname, _ver, blocks.package_block, kind="artifact")
        try:
            project = await self.project(pname)
        except UpstreamError as exc:
            ctx.recorder.decision(ECO, "artifact", "upstream_error")
            return error(502, "upstream_error", detail=exc.detail)
        pf = project.by_filename.get(filename) if project else None
        if project is None or pf is None or pf.path != parent_path:
            ctx.recorder.decision(ECO, "artifact", "not_found")
            return not_found()

        entry = blocks.match(ECO, pf.version)
        if entry is not None:
            return self._blocked(request, pname, pf.version, entry, kind="artifact")

        cfg = ctx.cfg
        if cfg.raw.enforce_age_on_download:
            v = self.view(project)
            if filename not in v.allowed:
                if filename in v.blocked:
                    return self._blocked(request, pname, pf.version, v.blocked[filename], kind="artifact")
                return self._too_new(request, project.name, pf, ip)

        if is_metadata:
            if not pf.core_metadata:
                return not_found()
            meta_sha = pf.core_metadata.get("sha256") if isinstance(pf.core_metadata, dict) else None
            expected = Expected(sha256=meta_sha)
        else:
            expected = Expected(sha256=pf.sha256, blake2b_256=pf.blake2b_256, size=pf.size)
        files_url = cfg.raw.upstreams.pypi.files_url.rstrip("/")
        req = ArtifactRequest(
            ecosystem=ECO,
            key=rel,
            package=pname,
            version=pf.version,
            filename=filename + (".metadata" if is_metadata else ""),
            upstream_url=files_url + rel,
            expected=expected,
        )
        return await ctx.artifacts.serve(
            req,
            method=request.method,
            headers_in=dict(request.headers),
            client_ip=ip,
            size_hint=None if is_metadata else pf.size,
        )  # type: ignore[return-value]

    def _too_new(self, request: Request, name: str, pf: PyFile, ip: str | None) -> Response:
        ctx = self.ctx
        now = ctx.clock.now()
        delay = ctx.cfg.delay_days_for(ECO, name, pf.version)
        wait = retry_after(pf.upload_time, delay, now)
        ctx.recorder.decision(ECO, "artifact", "age_gated")
        ctx.recorder.event(
            "age_gate",
            ECO,
            name,
            pf.version,
            client_ip=ip,
            details={"filename": pf.filename, "published": _iso(pf.upload_time), "delay_days": delay},
        )
        age_days = None if pf.upload_time is None else round((now - pf.upload_time) / DAY, 2)
        return error(
            403,
            "age_too_new",
            headers={"Retry-After": str(wait if wait is not None else int(delay * DAY))},
            package=name,
            version=pf.version,
            filename=pf.filename,
            published=_iso(pf.upload_time),
            days_old=age_days,
            delay_days_required=delay,
            retry_after_secs=wait,
        )


def _media(fmt: str) -> str:
    return "text/html; charset=utf-8" if fmt == "text/html" else fmt


def stats(view: View) -> dict[str, Any]:
    return {
        "allowed": len(view.files),
        "held": len(view.held),
        "blocked": len(view.blocked),
        "fail_open": view.fail_open,
    }
