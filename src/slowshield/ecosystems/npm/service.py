"""npm registry proxy: packument filtering (release age, blocklist), tarball gating, safe pass-through.

Implemented as a raw ASGI app because npm's URL space (`/<name>`, `/@scope%2fname`, `/<name>/<version>`,
`/<name>/-/<file>.tgz`, `/-/...`) is easiest to dispatch by hand. Only an explicit allow-list of
registry endpoints is served; everything else is 404, so this is never an open proxy.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from slowshield import names
from slowshield import versions as V
from slowshield.blocklist import BlockEntry, PackageBlocks
from slowshield.cache.kv import Item
from slowshield.cache.metadata import SingleFlight
from slowshield.context import AppContext
from slowshield.ecosystems.artifacts import ArtifactRequest, AsgiResponse
from slowshield.ecosystems.npm import packument as P
from slowshield.integrity import Expected, parse_sri
from slowshield.policy import DAY, Candidate, evaluate, retry_after
from slowshield.telemetry import instruments
from slowshield.upstream import TooLargeError, UpstreamError
from slowshield.web import JSONResponse, accept_prefers, client_ip, error, local_http_origin, not_found, route_path

log = logging.getLogger(__name__)

ECO = "npm"
MAX_PACKUMENT_BYTES = 200 * 1024 * 1024
MAX_AUDIT_BODY = 10 * 1024 * 1024
ABBREVIATED = "application/vnd.npm.install-v1+json"
_NOT_FOUND = object()
KEEP_STALE = 7 * DAY  # stored documents outlive their TTL for revalidation and stale-if-error
SMALL_BODY = 128 << 10  # rendered bodies up to this size are also kept in process memory


# A parsed packument costs its upstream size (msgspec.Raw slices keep the bytes alive) plus ~1 KB per version
# (tracemalloc on react, next, typescript, @types/node): firebase is 30 MB + 4 MB. Bound how many a worker
# holds at once while fetching or rendering; everything else works from the Index.
HEAVY_LOADS = 2


_PASSTHROUGH_GET = ("/-/npm/v1/keys", "/-/npm/v1/attestations/")
_AUDIT_POST = ("/-/npm/v1/security/advisories/bulk", "/-/npm/v1/security/audits/quick")


@dataclass(slots=True)
class View:
    doc: P.Index
    kept: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    held: set[str] = field(default_factory=set)
    blocked: dict[str, BlockEntry] = field(default_factory=dict)
    fail_open: bool = False
    next_change: float = float("inf")
    package_block: BlockEntry | None = None
    digest: str = ""


def _iso(ts: float | None) -> str | None:
    return None if ts is None else datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class NpmService:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self.flight = SingleFlight()
        self._heavy = asyncio.Semaphore(HEAVY_LOADS)

    @property
    def upstream_bases(self) -> list[str]:
        return [m.rstrip("/") for m in self.ctx.cfg.raw.upstreams.npm.mirrors]

    # ---- ASGI dispatch ------------------------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":  # pragma: no cover - lifespan is handled by the outer app
            return
        request = Request(scope, receive)
        response = await self.dispatch(request)
        await response(scope, receive, send)

    async def dispatch(self, request: Request) -> Any:
        path = route_path(request.scope)
        method = request.method
        if path in ("", "/"):
            return JSONResponse({"db_name": "registry", "slowshield": True})
        if path.startswith("/-/"):
            return await self._special(request, path, method)
        if method not in ("GET", "HEAD"):
            return error(405, "method_not_allowed", headers={"Allow": "GET, HEAD"})
        parts = path.lstrip("/").split("/")
        # Name: "pkg" or "@scope/pkg" (the latter also arrives as "@scope%2fpkg" -> decoded by the server).
        if parts[0].startswith("@"):
            if len(parts) < 2:
                return not_found()
            name, rest = f"{parts[0]}/{parts[1]}", parts[2:]
        else:
            name, rest = parts[0], parts[1:]
        name = unquote(name)
        if not names.is_valid_npm(name):
            return not_found()
        if not rest:
            return await self.packument(request, name)
        if len(rest) == 1 and rest[0]:
            return await self.version_manifest(request, name, unquote(rest[0]))
        if len(rest) == 2 and rest[0] == "-" and rest[1].endswith(".tgz"):
            return await self.tarball(request, name, rest[1])
        return not_found()

    async def _special(self, request: Request, path: str, method: str) -> Response:
        cfg = self.ctx.cfg.raw.upstreams.npm
        if path == "/-/ping":
            return JSONResponse({})
        if method == "POST" and path in _AUDIT_POST:
            if not cfg.audit_passthrough:
                return not_found()
            body = await _read_body(request, MAX_AUDIT_BODY)
            if body is None:
                return error(413, "payload_too_large")
            hdrs = {"Content-Type": request.headers.get("content-type", "application/json")}
            if enc := request.headers.get("content-encoding"):
                hdrs["Content-Encoding"] = enc
            try:
                res = await self.ctx.upstream.post(
                    self.upstream_bases[0] + path, body, headers=hdrs, max_bytes=MAX_PACKUMENT_BYTES
                )
            except UpstreamError as exc:
                return error(502, "upstream_error", detail=exc.detail)
            return Response(
                res.body, status_code=res.status, media_type=res.headers.get("content-type", "application/json")
            )
        if method in ("GET", "HEAD") and any(
            path == p or (p.endswith("/") and path.startswith(p)) for p in _PASSTHROUGH_GET
        ):
            try:
                res = await self.ctx.upstream.fetch(
                    [b + path for b in self.upstream_bases], headers={"Accept": "application/json"}, max_bytes=16 << 20
                )
            except UpstreamError as exc:
                return error(502, "upstream_error", detail=exc.detail)
            return Response(
                res.body,
                status_code=res.status,
                media_type=res.headers.get("content-type", "application/json"),
                headers={"Cache-Control": "max-age=300"},
            )
        return not_found()

    # ---- upstream ------------------------------------------------------------------------------------
    #
    # Three representations of a package, from small to large:
    #   Index (versions, publish times, dist info): policy and every tarball request. Memory + shared store.
    #   rendered body (filtered packument): memory when small, shared store always.
    #   Packument (the parsed upstream document): only to render a body that is not stored yet, or a
    #   version manifest. Parsed from the shared store, at most HEAVY_LOADS at a time per worker.

    async def index(self, name: str) -> P.Index | None:
        key = ("npm:idx", name)
        hit = self.ctx.metadata_cache.get(key, self.ctx.clock.now())
        if hit is not None:
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "hit"})
            self.ctx.recorder.lookup(ECO, cached=True)
            return None if hit is _NOT_FOUND else hit
        return await self.flight.run(key, lambda: self._load_index(name))

    async def _load_index(self, name: str) -> P.Index | None:
        ctx = self.ctx
        stored = await ctx.metadata_store.aget(f"npm:idx:{name}")
        if stored is not None and stored.fresh(ctx.clock.now()):
            # Fetched by another worker, or by this one before a restart: no upstream request.
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "hit"})
            ctx.recorder.lookup(ECO, cached=True)
            idx = P.Index.decode(stored.value)
            ctx.metadata_cache.put(("npm:idx", name), idx, idx.weight, stored.expires)
            return idx
        async with self._heavy:
            idx, _ = await self._fetch(name, stored)
        return idx

    async def _fetch(self, name: str, stale: Item | None) -> tuple[P.Index | None, P.Packument | None]:
        """Ask upstream (conditionally when a stale index is known); store the document and its index."""
        ctx = self.ctx
        key = ("npm:idx", name)
        now = ctx.clock.now()
        ttl = ctx.cfg.raw.metadata_cache_ttl_hours * 3600
        etag = stale.meta.get("etag") if stale is not None else None
        headers = {"Accept": "application/json"}
        if etag:
            headers["If-None-Match"] = etag
        path = "/" + name.replace("/", "%2f") if name.startswith("@") else "/" + name
        ctx.recorder.lookup(ECO, cached=False)
        try:
            res = await ctx.upstream.fetch(
                [b + path for b in self.upstream_bases], headers=headers, max_bytes=MAX_PACKUMENT_BYTES
            )
        except TooLargeError:
            raise
        except UpstreamError:
            if stale is not None:
                log.warning("upstream unavailable; serving stale packument", extra={"package": name})
                idx = P.Index.decode(stale.value)
                ctx.metadata_cache.put(key, idx, idx.weight, now + 60)
                instruments.cache_requests.add(1, {"cache": "metadata", "result": "stale"})
                return idx, None
            raise
        if res.status == 304 and stale is not None:
            for k in (f"npm:idx:{name}", f"npm:doc:{name}"):
                await ctx.metadata_store.atouch(k, now + ttl, now + ttl + KEEP_STALE)
            idx = P.Index.decode(stale.value)
            ctx.metadata_cache.put(key, idx, idx.weight, now + ttl)
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "revalidated"})
            ctx.recorder.catalog(ECO, name)
            return idx, None
        instruments.cache_requests.add(1, {"cache": "metadata", "result": "miss"})
        if res.status in (404, 410):
            ctx.metadata_cache.put(key, _NOT_FOUND, 64, now + 300)
            return None, None
        if res.status != 200:
            raise UpstreamError(res.url, f"upstream returned {res.status}", res.status)
        doc = P.parse(res.body, name=name, etag=res.etag, upstream_bases=self.upstream_bases)
        idx = P.index_of(doc)
        meta = {"etag": res.etag, "content_id": doc.content_id}
        keep = now + ttl + KEEP_STALE
        await ctx.metadata_store.aput(f"npm:doc:{name}", res.body, expires=now + ttl, keep_until=keep, meta=meta)
        await ctx.metadata_store.aput(f"npm:idx:{name}", idx.encode(), expires=now + ttl, keep_until=keep, meta=meta)
        ctx.metadata_cache.put(key, idx, idx.weight, now + ttl)
        ctx.recorder.catalog(ECO, name, [(v.version, v.published, False) for v in doc.versions.values()])
        return idx, doc

    async def _document(self, idx: P.Index) -> P.Packument:
        """The full document `idx` was derived from (or a newer one, if upstream changed in between)."""
        ctx = self.ctx
        async with self._heavy:
            stored = await ctx.metadata_store.aget(f"npm:doc:{idx.name}")
            if stored is not None and stored.meta.get("content_id") == idx.content_id:
                return P.parse(stored.value, name=idx.name, etag=idx.etag, upstream_bases=self.upstream_bases)
            # Evicted from the shared store (the index outlived it): fetch it again, unconditionally.
            _, doc = await self._fetch(idx.name, None)
        if doc is None:
            raise UpstreamError(idx.name, "package document disappeared upstream")
        return doc

    async def _body(self, v: View, fmt: str, pub: str) -> bytes:
        """The rendered packument: from memory (small ones), the shared store, or rendered and stored."""
        ctx = self.ctx
        idx = v.doc
        skey = f"npm:body:{idx.name}:{fmt}:{pub}:{idx.content_id}:{v.digest}"
        mkey = ("npm:body", skey)
        now = ctx.clock.now()
        hit = ctx.metadata_cache.get(mkey, now)
        if hit is not None:
            return hit
        body, expires = await self.flight.run(mkey, lambda: self._stored_or_rendered(v, fmt, pub, skey))
        if len(body) <= SMALL_BODY:
            ctx.metadata_cache.put(mkey, body, len(body) + 256, expires)
        return body

    async def _stored_or_rendered(self, v: View, fmt: str, pub: str, skey: str) -> tuple[bytes, float]:
        ctx = self.ctx
        now = ctx.clock.now()
        stored = await ctx.metadata_store.aget(skey)
        if stored is not None and stored.fresh(now):
            return stored.value, stored.expires
        expires = min(v.next_change, now + ctx.cfg.raw.metadata_cache_ttl_hours * 3600)
        doc = await self._document(v.doc)
        if doc.content_id != v.doc.content_id:  # changed upstream meanwhile: filter the new one
            v = self.view(P.index_of(doc))
        if fmt == ABBREVIATED:
            body = P.render_abbreviated(doc, v.kept, v.tags, upstream_bases=self.upstream_bases, public_base=pub)
        else:
            body = P.render_full(doc, v.kept, v.tags, upstream_bases=self.upstream_bases, public_base=pub)
        del doc
        await ctx.metadata_store.aput(skey, body, expires=expires)
        return body, expires

    # ---- policy --------------------------------------------------------------------------------------

    def view(self, doc: P.Index) -> View:
        ctx = self.ctx
        now = ctx.clock.now()
        cfg = ctx.cfg
        key = ("npm:view", doc.name, doc.content_id, ctx.policy_key())
        hit = ctx.metadata_cache.get(key, now)
        if hit is not None:
            return hit
        blocks: PackageBlocks = ctx.blocklist.for_package(ECO, doc.name)
        v = View(doc=doc)
        if blocks.package_block is not None:
            v.package_block = blocks.package_block
            ctx.metadata_cache.put(key, v, 256, now + 300)
            return v
        ev = evaluate(
            (Candidate(info.version, info.version, info.published) for info in doc.versions.values()),
            now=now,
            delay_for=lambda ver: cfg.delay_days_for(ECO, doc.name, ver),
            is_blocked=lambda ver: blocks.match(ECO, ver) is not None,
            fail_open=cfg.raw.fail_open,
        )
        # Preserve upstream order (chronological for npmjs) for byte-stable output.
        allowed = {c.item for c in ev.allowed}
        v.kept = [ver for ver in doc.versions if ver in allowed]
        v.held = {c.item for c in ev.held}
        for c in ev.blocked:
            entry = blocks.match(ECO, c.version)
            if entry is not None:
                v.blocked[c.item] = entry
        v.tags = P.recompute_tags(doc.dist_tags, v.kept)
        v.fail_open = ev.fail_open
        v.next_change = ev.next_change
        v.digest = hashlib.blake2b(
            ("\n".join(v.kept) + repr(sorted(v.tags.items())) + repr(ctx.policy_key())).encode(), digest_size=12
        ).hexdigest()
        ctx.metadata_cache.put(key, v, 512 + 48 * len(doc.versions), min(ev.next_change, now + 3600))
        return v

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
        return error(
            451,
            "blocked",
            package=name,
            version=version,
            advisory_id=entry.advisory_id or None,
            reason=entry.reason,
            source=entry.source,
            url=entry.url,
        )

    async def _resolve(self, request: Request, name: str, kind: str) -> View | Response:
        ctx = self.ctx
        blocks = ctx.blocklist.for_package(ECO, name)
        if blocks.package_block is not None:
            return self._blocked(request, name, None, blocks.package_block, kind=kind)
        try:
            doc = await self.index(name)
        except TooLargeError:
            return error(502, "upstream_error", detail="upstream packument too large")
        except UpstreamError as exc:
            ctx.recorder.decision(ECO, kind, "upstream_error")
            return error(502, "upstream_error", detail=exc.detail)
        if doc is None:
            ctx.recorder.decision(ECO, kind, "not_found")
            return not_found()
        v = self.view(doc)
        if v.package_block is not None:
            return self._blocked(request, name, None, v.package_block, kind=kind)
        return v

    # ---- handlers --------------------------------------------------------------------------------------

    async def packument(self, request: Request, name: str) -> Response:
        ctx = self.ctx
        v = await self._resolve(request, name, "metadata")
        if not isinstance(v, View):
            return v
        doc = v.doc
        if not v.kept and v.blocked and not v.held:
            return self._blocked(request, name, None, next(iter(v.blocked.values())), kind="metadata")
        fmt = accept_prefers(request.headers.get("accept"), ("application/json", ABBREVIATED), "application/json")
        if doc.unpublished:
            fmt = "application/json"
        etag = f'"{v.digest}-{"a" if fmt == ABBREVIATED else "f"}"'
        now = ctx.clock.now()
        headers = {
            "Vary": "Accept, Accept-Encoding",
            "ETag": etag,
            "Cache-Control": f"max-age={int(max(0, min(300, v.next_change - now)))}",
            "X-SlowShield-Held-Versions": str(len(v.held)),
        }
        if v.held:
            instruments.versions_held.add(len(v.held), {"slowshield.ecosystem": ECO})
        if v.fail_open:
            headers["X-SlowShield-Fail-Open"] = "1"
            ctx.recorder.decision(ECO, "metadata", "fail_open")
            ctx.recorder.event(
                "fail_open",
                ECO,
                name,
                None,
                client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
                details={"reason": "all_versions_too_new", "versions": v.kept[-20:]},
            )
        else:
            ctx.recorder.decision(ECO, "metadata", "served")
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers=headers)
        body = await self._body(v, fmt, self.public_base(request))
        return Response(body, media_type=fmt if fmt == ABBREVIATED else "application/json", headers=headers)

    def public_base(self, request: Request) -> str:
        """Base for tarball URLs. Requests under /npm/ get `<public_url>/npm` (or http://localhost/npm when the
        client used local HTTP), so lockfiles record path URLs. Requests on a deprecated npm hostname keep that
        host (removed in 0.1)."""
        cfg = self.ctx.cfg
        via_hostname = not request.scope.get("root_path", "").endswith("/npm")
        if not cfg.raw.upstreams.npm.public_url and not via_hostname:
            local = local_http_origin(request.scope, cfg.raw.local_http, cfg.trusted_networks)
            if local:
                return f"{local}/npm"
        return cfg.npm_public_base(via_hostname=via_hostname)

    async def version_manifest(self, request: Request, name: str, spec: str) -> Response:
        v = await self._resolve(request, name, "metadata")
        if not isinstance(v, View):
            return v
        version = v.tags.get(spec, spec)
        if version not in v.kept:
            return not_found()
        try:
            doc = await self._document(v.doc)
        except UpstreamError as exc:
            return error(502, "upstream_error", detail=exc.detail)
        if version not in doc.versions:
            return not_found()
        body = P.render_version(doc, version, upstream_bases=self.upstream_bases, public_base=self.public_base(request))
        return Response(body, media_type="application/json", headers={"Cache-Control": "max-age=300"})

    async def tarball(self, request: Request, name: str, filename: str) -> AsgiResponse:
        ctx = self.ctx
        base = names.npm_basename(name)
        if not filename.startswith(base + "-"):
            return not_found()
        version = filename[len(base) + 1 : -len(".tgz")]
        if V.parse_semver(version) is None:
            return not_found()
        ip = client_ip(request.scope, ctx.cfg.trusted_networks)
        # Known malware is refused (and recorded) before anything else, even when the registry has since removed
        # the version: a lockfile pinned during an attack window must show up as a security event, not a 404.
        blocks = ctx.blocklist.for_package(ECO, name)
        entry = blocks.package_block or blocks.match(ECO, version)
        if entry is not None:
            return self._blocked(request, name, version, entry, kind="artifact")
        v = await self._resolve(request, name, "artifact")
        if not isinstance(v, View):
            return v
        info = v.doc.versions.get(version)
        tar_path = f"/{name}/-/{filename}"
        # The tarball must be the one the packument declares (by path under a configured mirror).
        declared = info is not None and (
            v.doc.by_tarball_path.get(tar_path) == version
            or bool(info.tarball and unquote(info.tarball).endswith(tar_path))
        )
        if info is None or not declared:
            ctx.recorder.decision(ECO, "artifact", "not_found")
            return not_found()
        if version in v.blocked:
            return self._blocked(request, name, version, v.blocked[version], kind="artifact")
        if ctx.cfg.raw.enforce_age_on_download and version not in v.kept:
            return self._too_new(request, name, version, info.published, ip)
        sri = parse_sri(info.integrity)
        expected = Expected(sha512=sri, sha1=None if sri else info.shasum)
        # Always fetch from a configured mirror (with its configured scheme), never from a URL the
        # packument points at: legacy `http://registry.npmjs.org/...` tarballs are upgraded this way too.
        upstream_url = self.upstream_bases[0] + tar_path
        req = ArtifactRequest(
            ecosystem=ECO,
            key=tar_path,
            package=name,
            version=version,
            filename=filename,
            upstream_url=upstream_url,
            expected=expected,
        )
        return await ctx.artifacts.serve(req, method=request.method, headers_in=dict(request.headers), client_ip=ip)

    def _too_new(self, request: Request, name: str, version: str, published: float | None, ip: str | None) -> Response:
        ctx = self.ctx
        now = ctx.clock.now()
        delay = ctx.cfg.delay_days_for(ECO, name, version)
        wait = retry_after(published, delay, now)
        ctx.recorder.decision(ECO, "artifact", "age_gated")
        ctx.recorder.event(
            "age_gate", ECO, name, version, client_ip=ip, details={"published": _iso(published), "delay_days": delay}
        )
        return error(
            403,
            "age_too_new",
            headers={"Retry-After": str(wait if wait is not None else int(delay * DAY))},
            package=name,
            version=version,
            published=_iso(published),
            days_old=None if published is None else round((now - published) / DAY, 2),
            delay_days_required=delay,
            retry_after_secs=wait,
        )


async def _read_body(request: Request, limit: int) -> bytes | None:
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)
