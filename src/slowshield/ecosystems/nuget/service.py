"""NuGet (at /nuget/): nuget.org through SlowShield, with held versions left out and age-gated, verified downloads.

SlowShield writes the service index itself and lists only what it serves: the flat container, one SemVer 2 registration
hive, vulnerability data and search. Every answer about a package comes from one snapshot of its registration
(`registration.py`), so the flat container list, the registration pages and search agree.

A version's publish time is its registration `published`, which nuget.org sets. The first plausible one SlowShield
sees is kept, so it can't move earlier. Without one (unlisted versions say 1900-01-01) the version is timed from when
SlowShield first listed it. See docs/design/nuget.md.

Refusals are plain text: 425 with Retry-After (too new), 451 (blocked, tampered). Never 403, which NuGet may read as
a credentials problem. `dotnet` shows only the status line. Upstream failures are 503.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode, urlsplit

import msgspec
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from slowshield import names
from slowshield.blocklist import BlockEntry
from slowshield.cache.metadata import SingleFlight
from slowshield.config import NugetUpstream
from slowshield.context import AppContext
from slowshield.ecosystems.artifacts import ArtifactRequest, AsgiResponse
from slowshield.ecosystems.nuget import registration as R
from slowshield.ecosystems.nuget import version as NV
from slowshield.integrity import Expected
from slowshield.policy import DAY, Candidate, evaluate, retry_after
from slowshield.telemetry import instruments
from slowshield.upstream import UpstreamError
from slowshield.web import TEXT, client_ip, local_http_origin, route_path, text_error

log = logging.getLogger(__name__)

ECO = "nuget"
KEEP_STALE = 7 * DAY  # stored documents outlive their TTL for revalidation and stale-if-error
# nuget.org opened in 2010; unlisted versions say 1900-01-01. An earlier (or a future) `published` isn't a publish time.
EARLIEST = datetime(2010, 1, 1, tzinfo=UTC).timestamp()
CLOCK_SKEW = 300.0
RETRY_SOON = {"Retry-After": "10"}
CATALOG_TTL = 30 * DAY  # a catalog leaf never changes: a new commit gets a new URL
MAX_SEARCH_TAKE = 100
SEARCH_CONCURRENCY = 8
MAX_SMALL_DOCUMENT = 16 << 20
JSON = "application/json"
_NOT_FOUND = object()
_json = msgspec.json.Encoder()
_decode = msgspec.json.Decoder()


class _StoredRegistration(msgspec.Struct):
    index: Any
    pages: dict[str, msgspec.Raw]  # views into the stored document, not copies


_decode_stored = msgspec.json.Decoder(_StoredRegistration)


@dataclass(slots=True)
class View:
    pid: str
    held: set[str] = field(default_factory=set)
    blocked: dict[str, BlockEntry] = field(default_factory=dict)
    published: dict[str, float | None] = field(default_factory=dict)
    fail_open: bool = False
    next_change: float = math.inf
    package_block: BlockEntry | None = None

    @property
    def drop(self) -> set[str]:
        return self.held | self.blocked.keys()


def _iso(ts: float | None) -> str:
    return "an unknown time" if ts is None else datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _days(value: float) -> str:
    return f"{value:g} day" + ("" if value == 1 else "s")


def nuget_error(status: int, code: str, *, headers: dict[str, str] | None = None, **fields: Any) -> Response:
    """The artifact server's errors as plain text."""
    artifact = fields.get("artifact") or "the package"
    if code == "tamper_detected":
        msg = (
            f"slowshield: {artifact} changed upstream after it was first served (tampering).\n"
            "It stays refused until an operator investigates; see Security on the SlowShield UI."
        )
    elif code == "integrity_mismatch":
        msg = f"slowshield: {artifact} failed verification: {fields.get('detail', '')}"
    elif code == "not_found":
        msg = "not found"
    else:
        msg = f"slowshield: {code.replace('_', ' ')}" + (f": {fields['detail']}" if fields.get("detail") else "")
    if status == 502:
        status, headers = 503, {**RETRY_SOON, **(headers or {})}
    return text_error(status, msg, headers=headers)


def plausible(published: float | None, now: float) -> float | None:
    """`published` if it can be a publish time: not missing, not 1900-01-01 (unlisted), not in the future."""
    return published if published is not None and EARLIEST <= published <= now + CLOCK_SKEW else None


def publish_time(published: float | None, known: Sequence[float | None], now: float) -> float:
    """The latest of the clocks known for a version: its plausible `published` now, and the stored ones (the first
    plausible `published` seen, and when it was first listed without one). Each is no earlier than the real publish
    time, so the latest is the safest. Without any clock: now."""
    clocks = [c for c in (plausible(published, now), *known) if c is not None]
    return max(clocks) if clocks else now


def _decoded(body: bytes) -> Any:
    """`body` decoded, or None if it isn't JSON."""
    try:
        return _decode.decode(body)
    except msgspec.DecodeError:
        return None


def _is_object(body: bytes) -> bool:
    """A JSON object, as a vulnerability file is (package ids to their advisories)."""
    return isinstance(_decoded(body), dict)


def _json_response(doc: Any, *, headers: dict[str, str] | None = None) -> Response:
    return Response(_json.encode(doc), media_type=JSON, headers=headers)


class NugetService:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self.flight = SingleFlight()

    @property
    def settings(self) -> NugetUpstream:
        return self.ctx.cfg.raw.upstreams.nuget

    # ---- ASGI dispatch ------------------------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":  # pragma: no cover - lifespan is handled by the outer app
            return
        request = Request(scope, receive)
        response = await self.dispatch(request)
        await response(scope, receive, send)

    async def dispatch(self, request: Request) -> Any:
        if request.method not in ("GET", "HEAD"):
            return text_error(405, "method not allowed", headers={"Allow": "GET, HEAD"})
        path = route_path(request.scope).lstrip("/")
        if path == "":
            return Response(
                b"SlowShield NuGet feed: use <this URL>v3/index.json as the package source.\n", media_type=TEXT
            )
        if not path.startswith("v3/"):
            return text_error(404, "not found")
        rest = path[3:]
        if rest == "index.json":
            return self.service_index(request)
        if rest == "query":
            return await self.search(request)
        if rest == "vulnerabilities/index.json":
            return await self.vulnerability_index(request)
        if rest.startswith("vulnerabilities/"):
            return await self.vulnerability_file(rest.removeprefix("vulnerabilities/"))
        parts = rest.split("/")
        if parts[0] == "flatcontainer" and len(parts) >= 3 and self._id(parts[1]):
            pid = parts[1]
            if len(parts) == 3 and parts[2] == "index.json":
                return await self.flat_index(request, pid)
            if len(parts) == 4 and self._version(parts[2]) and parts[3] == f"{pid}.{parts[2]}.nupkg":
                return await self.download(request, pid, parts[2])
        if parts[0] == "registration" and len(parts) >= 3 and self._id(parts[1]):
            pid = parts[1]
            if len(parts) == 3 and parts[2] == "index.json":
                return await self.registration_index(request, pid)
            if len(parts) == 3 and parts[2].endswith(".json") and self._version(parts[2][:-5]):
                return await self.registration_leaf(request, pid, parts[2][:-5])
            if len(parts) == 5 and parts[2] == "page" and parts[4].endswith(".json"):
                lower, upper = parts[3], parts[4][:-5]
                if self._version(lower) and self._version(upper):
                    return await self.registration_page(request, pid, lower, upper)
        return text_error(404, "not found")

    @staticmethod
    def _id(value: str) -> bool:
        """The id as nuget.org spells it in paths: valid and lower case. Any other spelling is a 404."""
        return names.is_valid_nuget(value) and value == value.lower()

    @staticmethod
    def _version(value: str) -> bool:
        """The version as nuget.org spells it in paths: lower-case normalized. Any other spelling is a 404."""
        return NV.canonical(value) == value

    # ---- URLs -----------------------------------------------------------------------------------------------

    def _base(self, request: Request) -> str:
        cfg = self.ctx.cfg
        local = local_http_origin(request.scope, cfg.raw.local_http, cfg.trusted_networks)
        return f"{local or cfg.public_base()}/nuget/v3/"

    def _urls(self, request: Request) -> R.Urls:
        base = self._base(request)
        return R.Urls(registration=f"{base}registration/", flat=f"{base}flatcontainer/")

    def service_index(self, request: Request) -> Response:
        """Only what SlowShield serves, at SlowShield: nuget.org's own index is never read, so the hosts it may reach
        stay the configured ones."""
        base = self._base(request)
        resources: list[dict[str, str]] = [
            {
                "@id": f"{base}flatcontainer/",
                "@type": "PackageBaseAddress/3.0.0",
                "comment": "Package versions and downloads, through SlowShield",
            },
            {
                "@id": f"{base}registration/",
                "@type": "RegistrationsBaseUrl/3.6.0",
                "comment": "Package metadata (SemVer 2.0.0 included), through SlowShield",
            },
            {
                "@id": f"{base}vulnerabilities/index.json",
                "@type": "VulnerabilityInfo/6.7.0",
                "comment": "nuget.org's vulnerability data, for NuGetAudit",
            },
        ]
        resources.extend(
            {"@id": f"{base}query", "@type": kind, "comment": "nuget.org search, through SlowShield"}
            for kind in ("SearchQueryService", "SearchQueryService/3.0.0-beta", "SearchQueryService/3.0.0-rc",
                         "SearchQueryService/3.5.0")
        )  # fmt: skip
        doc = {"version": "3.0.0", "resources": resources}
        return _json_response(doc, headers={"Cache-Control": "max-age=300"})

    # ---- upstream documents -----------------------------------------------------------------------------------

    async def _document(
        self,
        url: str,
        skey: str,
        *,
        ttl: float,
        usable: Callable[[bytes], bool],
        max_bytes: int = MAX_SMALL_DOCUMENT,
    ) -> bytes | None:
        """A small upstream document, through the metadata store: fresh -> stored copy; else revalidated with its
        ETag; upstream down, or a document that isn't `usable` -> the stored copy while there is one. None for a 404.
        Only a usable document is stored, so a broken answer is never served for a whole TTL."""
        ctx = self.ctx
        now = ctx.clock.now()
        stored = await ctx.metadata_store.aget(skey)
        if stored is not None and stored.fresh(now):
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "hit"})
            return stored.value
        headers = {"If-None-Match": stored.meta["etag"]} if stored is not None and stored.meta.get("etag") else {}
        try:
            res = await ctx.upstream.fetch(url, headers=headers, max_bytes=max_bytes)
        except UpstreamError:
            if stored is None:
                raise
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "stale"})
            return stored.value
        if res.status == 304 and stored is not None:
            await ctx.metadata_store.atouch(skey, now + ttl, now + ttl + KEEP_STALE)
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "revalidated"})
            return stored.value
        instruments.cache_requests.add(1, {"cache": "metadata", "result": "miss"})
        if res.status in (404, 410):
            return None
        if res.status != 200:
            if stored is not None:
                return stored.value
            raise UpstreamError(res.url, f"upstream returned {res.status}", res.status)
        if not usable(res.body):
            log.warning("unusable NuGet document", extra={"url": url, "stale_copy": stored is not None})
            if stored is not None:
                return stored.value
            raise UpstreamError(res.url, "unusable document")
        await ctx.metadata_store.aput(
            skey, res.body, expires=now + ttl, keep_until=now + ttl + KEEP_STALE, meta={"etag": res.etag}
        )
        return res.body

    # ---- snapshots ----------------------------------------------------------------------------------------------

    async def snapshot(self, pid: str) -> R.Snapshot | None:
        """The registration snapshot of `pid` (lower case), or None if nuget.org has no such package."""
        key = ("nuget:reg", pid)
        hit = self.ctx.metadata_cache.get(key, self.ctx.clock.now())
        if hit is not None:
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "hit"})
            self.ctx.recorder.lookup(ECO, cached=True)
            return None if hit is _NOT_FOUND else hit
        return await self.flight.run(key, lambda: self._load(pid))

    async def _load(self, pid: str) -> R.Snapshot | None:
        ctx = self.ctx
        key = ("nuget:reg", pid)
        skey = f"nuget:reg:{pid}"
        now = ctx.clock.now()
        ttl = ctx.cfg.raw.metadata_cache_ttl_hours * 3600
        stored = await ctx.metadata_store.aget(skey)
        if stored is not None and stored.fresh(now):
            # Fetched by another worker, or by this one before a restart: no upstream request.
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "hit"})
            ctx.recorder.lookup(ECO, cached=True)
            snap = self._parse_stored(pid, stored.value)
            ctx.metadata_cache.put(key, snap, snap.weight, stored.expires)
            return snap
        headers = {"If-None-Match": stored.meta["etag"]} if stored is not None and stored.meta.get("etag") else {}
        ctx.recorder.lookup(ECO, cached=False)
        base = self.settings.registration_url
        url = f"{base}{pid}/index.json"
        try:
            res = await ctx.upstream.fetch(url, headers=headers, max_bytes=R.MAX_DOCUMENT_BYTES)
            if res.status == 304 and stored is not None:
                # nuget.org rewrites the index whenever one of its pages changes, so the stored pages still hold.
                await ctx.metadata_store.atouch(skey, now + ttl, now + ttl + KEEP_STALE)
                snap = self._parse_stored(pid, stored.value)
                ctx.metadata_cache.put(key, snap, snap.weight, now + ttl)
                instruments.cache_requests.add(1, {"cache": "metadata", "result": "revalidated"})
                ctx.recorder.catalog(ECO, pid)
                return snap
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "miss"})
            if res.status in (404, 410):
                ctx.metadata_cache.put(key, _NOT_FOUND, 64, now + 300)
                return None
            if res.status != 200:
                raise UpstreamError(res.url, f"upstream returned {res.status}", res.status)
            index = _decode.decode(res.body)
            pages: dict[str, bytes] = {}
            budget = R.MAX_REGISTRATION_BYTES - len(res.body)
            for page_url in R.page_urls(index, base):
                if budget <= 0:
                    raise R.RegistrationError(f"registration larger than {R.MAX_REGISTRATION_BYTES >> 20} MB")
                page = await ctx.upstream.fetch(page_url, max_bytes=min(R.MAX_DOCUMENT_BYTES, budget))
                if page.status != 200:
                    raise UpstreamError(page.url, f"upstream returned {page.status} for a registration page")
                pages[page_url] = page.body
                budget -= len(page.body)
            snap = R.parse(pid, index, pages)
            if not snap.versions:
                # A registration without one usable version (an error page, a broken mirror) is an upstream failure:
                # caching it would make the package look empty until the TTL ends.
                raise R.RegistrationError("registration without a usable version")
        except (UpstreamError, R.RegistrationError, msgspec.DecodeError) as exc:
            if stored is None:
                if isinstance(exc, UpstreamError):
                    raise
                raise UpstreamError(url, f"unusable registration: {exc}") from exc
            log.warning("serving a stale NuGet registration", extra={"package": pid, "error": str(exc)})
            snap = self._parse_stored(pid, stored.value)
            ctx.metadata_cache.put(key, snap, snap.weight, now + 60)
            instruments.cache_requests.add(1, {"cache": "metadata", "result": "stale"})
            return snap
        body = _json.encode({"index": msgspec.Raw(res.body), "pages": {u: msgspec.Raw(b) for u, b in pages.items()}})
        await ctx.metadata_store.aput(
            skey, body, expires=now + ttl, keep_until=now + ttl + KEEP_STALE, meta={"etag": res.etag}
        )
        ctx.metadata_cache.put(key, snap, snap.weight, now + ttl)
        self._record(snap)
        return snap

    @staticmethod
    def _parse_stored(pid: str, body: bytes) -> R.Snapshot:
        doc = _decode_stored.decode(body)
        return R.parse(pid, doc.index, doc.pages)

    # ---- publish times -----------------------------------------------------------------------------------

    def _times(self, pid: str) -> dict[str, list[float | None]]:
        """version -> [first plausible `published` seen, first listed], shared by all workers through the database."""
        key = ("nuget:times", pid)
        now = self.ctx.clock.now()
        hit = self.ctx.metadata_cache.get(key, now)
        if hit is not None:
            return hit
        rows = self.ctx.db.readers.query(
            "SELECT version, published, first_listed FROM package_versions WHERE ecosystem = ? AND name = ? "
            "AND (published IS NOT NULL OR first_listed IS NOT NULL)",
            (ECO, pid),
        )
        times = {r[0]: [r[1], r[2]] for r in rows}
        self.ctx.metadata_cache.put(key, times, 256 + 96 * len(times), now + 300)
        return times

    @staticmethod
    def _plausible(leaf: R.Leaf, now: float) -> float | None:
        return plausible(leaf.published, now)

    def _record(self, snap: R.Snapshot) -> None:
        """Keep each version's first plausible `published`, or, for a version that never had one, when it was first
        listed; and whether it is unlisted. A version that had a plausible `published` and is unlisted later (its
        `published` turns into 1900-01-01) keeps that time: unlisting doesn't start the clock again."""
        ctx = self.ctx
        now = ctx.clock.now()
        times = self._times(snap.id)
        rows: list[tuple[Any, ...]] = []
        untimed = 0
        for leaf in snap.versions.values():
            pub = self._plausible(leaf, now)
            known = times.setdefault(leaf.version, [None, None])
            listed_now = None
            if pub is not None:
                known[0] = known[0] or pub
            elif known[0] is None:
                untimed += 1
                known[1] = known[1] or now
                listed_now = now
            rows.append((ECO, snap.id, leaf.version, pub, listed_now, int(not leaf.listed)))
        if untimed:
            log.warning("NuGet versions without a usable publish time", extra={"package": snap.id, "versions": untimed})

        def op(conn: Any) -> None:
            conn.executemany(
                "INSERT INTO package_versions (ecosystem, name, version, published, first_listed, yanked) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (ecosystem, name, version) DO UPDATE SET "
                "published = coalesce(package_versions.published, excluded.published), "
                "first_listed = coalesce(package_versions.first_listed, "
                "CASE WHEN package_versions.published IS NULL THEN excluded.first_listed END), "
                "yanked = excluded.yanked",
                rows,
            )

        ctx.recorder.catalog(ECO, snap.id)
        ctx.db.writer.enqueue(op)

    def _published(self, leaf: R.Leaf, times: dict[str, list[float | None]], now: float) -> float:
        return publish_time(leaf.published, times.get(leaf.version, ()), now)

    # ---- policy -------------------------------------------------------------------------------------------

    def view(self, snap: R.Snapshot) -> View:
        ctx = self.ctx
        cfg = ctx.cfg
        now = ctx.clock.now()
        key = ("nuget:view", snap.id, snap.content_id, ctx.policy_key())
        hit = ctx.metadata_cache.get(key, now)
        if hit is not None:
            return hit
        v = View(pid=snap.id)
        blocks = ctx.blocklist.for_package(ECO, snap.id)
        if blocks.package_block is not None:
            v.package_block = blocks.package_block
            ctx.metadata_cache.put(key, v, 256, now + 300)
            return v
        times = self._times(snap.id)
        v.published = {ver: self._published(leaf, times, now) for ver, leaf in snap.versions.items()}
        ev = evaluate(
            (Candidate(ver, ver, v.published[ver]) for ver in snap.versions),
            now=now,
            delay_for=lambda ver: cfg.delay_days_for(ECO, snap.id, ver),
            is_blocked=lambda ver: blocks.match(ECO, ver) is not None,
            fail_open=cfg.fail_open_for(ECO),
        )
        v.held = {c.item for c in ev.held}
        for c in ev.blocked:
            entry = blocks.match(ECO, c.version)
            if entry is not None:
                v.blocked[c.item] = entry
        v.fail_open = ev.fail_open
        v.next_change = ev.next_change
        ctx.metadata_cache.put(key, v, 512 + 96 * len(snap.versions), min(ev.next_change, now + 3600))
        return v

    async def _resolve(self, request: Request, pid: str, kind: str) -> tuple[R.Snapshot, View] | Response:
        ctx = self.ctx
        blocks = ctx.blocklist.for_package(ECO, pid)
        if blocks.package_block is not None:
            return self._blocked(request, pid, None, blocks.package_block, kind=kind)
        try:
            snap = await self.snapshot(pid)
        except UpstreamError as exc:
            ctx.recorder.decision(ECO, kind, "upstream_error")
            return text_error(503, f"slowshield: nuget.org is unavailable for {pid}: {exc.detail}", headers=RETRY_SOON)
        if snap is None:
            ctx.recorder.decision(ECO, kind, "not_found")
            return text_error(404, "not found")
        v = self.view(snap)
        if v.package_block is not None:
            return self._blocked(request, pid, None, v.package_block, kind=kind)
        return snap, v

    async def _metadata(self, request: Request, pid: str) -> tuple[R.Snapshot, View, dict[str, str]] | Response:
        """A snapshot and its view for a metadata answer, with the headers every such answer carries."""
        ctx = self.ctx
        resolved = await self._resolve(request, pid, "metadata")
        if isinstance(resolved, Response):
            return resolved
        snap, v = resolved
        if v.blocked and len(v.blocked) == len(snap.versions):
            return self._blocked(request, pid, None, next(iter(v.blocked.values())), kind="metadata")
        now = ctx.clock.now()
        headers = {
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
                pid,
                None,
                client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
                details={"reason": "all_versions_too_new", "versions": list(snap.versions)[-20:]},
            )
        else:
            ctx.recorder.decision(ECO, "metadata", "served")
        return snap, v, headers

    @staticmethod
    def _with_etag(request: Request, doc: Any, headers: dict[str, str]) -> Response:
        body = _json.encode(doc)
        etag = '"' + hashlib.blake2b(body, digest_size=12).hexdigest() + '"'
        headers = {**headers, "ETag": etag}
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers=headers)
        return Response(body, media_type=JSON, headers=headers)

    # ---- metadata handlers ---------------------------------------------------------------------------------

    async def flat_index(self, request: Request, pid: str) -> Response:
        got = await self._metadata(request, pid)
        if isinstance(got, Response):
            return got
        snap, v, headers = got
        return self._with_etag(request, {"versions": snap.served(v.drop)}, headers)

    async def registration_index(self, request: Request, pid: str) -> Response:
        got = await self._metadata(request, pid)
        if isinstance(got, Response):
            return got
        snap, v, headers = got
        return self._with_etag(request, R.render_index(snap, v.drop, self._urls(request)), headers)

    async def registration_page(self, request: Request, pid: str, lower: str, upper: str) -> Response:
        got = await self._metadata(request, pid)
        if isinstance(got, Response):
            return got
        snap, v, headers = got
        return self._with_etag(request, R.render_page(snap, v.drop, self._urls(request), lower, upper), headers)

    async def registration_leaf(self, request: Request, pid: str, version: str) -> Response:
        got = await self._metadata(request, pid)
        if isinstance(got, Response):
            return got
        snap, v, headers = got
        if version not in snap.versions or version in v.drop:
            return text_error(404, "not found")
        return self._with_etag(request, R.render_leaf(snap, version, self._urls(request)), headers)

    # ---- downloads -----------------------------------------------------------------------------------------

    async def download(self, request: Request, pid: str, version: str) -> AsgiResponse:
        ctx = self.ctx
        # Known malware is refused (and recorded) before anything else, even when nuget.org has deleted the package
        # since: a project pinned during an attack window must show up as a security event, not a 404.
        blocks = ctx.blocklist.for_package(ECO, pid)
        entry = blocks.package_block or blocks.match(ECO, version)
        if entry is not None:
            return self._blocked(request, pid, version, entry, kind="artifact")
        resolved = await self._resolve(request, pid, "artifact")
        if isinstance(resolved, Response):
            return resolved
        snap, v = resolved
        leaf = snap.versions.get(version)
        if leaf is None:
            ctx.recorder.decision(ECO, "artifact", "not_found")
            return text_error(404, f"not found: {pid} {version} is not in the nuget.org registration")
        if version in v.blocked:
            return self._blocked(request, pid, version, v.blocked[version], kind="artifact")
        if ctx.cfg.raw.enforce_age_on_download and version in v.held:
            return self._too_new(request, snap, v, version)
        expected = Expected()
        if request.method != "HEAD":
            got = await self._package_hash(pid, leaf)
            if isinstance(got, Response):
                ctx.recorder.decision(ECO, "artifact", "upstream_error")
                return got
            expected = got
        filename = f"{pid}.{version}.nupkg"
        path = f"{pid}/{version}/{filename}"
        art = ArtifactRequest(
            ecosystem=ECO,
            key=f"/{path}",
            package=pid,
            version=version,
            filename=filename,
            upstream_url=self.settings.flat_container_url + path,
            expected=expected,
            content_type="application/octet-stream",
            error=nuget_error,
            published=v.published.get(version),
        )
        return await ctx.artifacts.serve(
            art,
            method=request.method,
            headers_in=dict(request.headers),
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
        )

    async def _package_hash(self, pid: str, leaf: R.Leaf) -> Expected | Response:
        """The `packageHash` (SHA512) and `packageSize` from the version's catalog leaf, which only nuget.org's
        catalog carries. Without them nothing is served."""
        url = leaf.catalog_url or ""
        base = self.settings.catalog_url
        if not url.startswith(base) or "?" in url or "#" in url or ".." in urlsplit(url).path:
            log.warning("NuGet catalog leaf outside the configured catalog", extra={"package": pid, "url": url})
            return text_error(503, f"slowshield: no usable catalog entry for {pid} {leaf.version}", headers=RETRY_SOON)

        def usable(body: bytes) -> bool:
            return not isinstance(R.package_hash(_decoded(body), pid, leaf.version), str)

        try:
            body = await self._document(url, f"nuget:catalog:{url.removeprefix(base)}", ttl=CATALOG_TTL, usable=usable)
            doc = _decode.decode(body) if body is not None else None
        except (UpstreamError, msgspec.DecodeError) as exc:
            detail = exc.detail if isinstance(exc, UpstreamError) else "unreadable catalog entry"
            return text_error(503, f"slowshield: the nuget.org catalog is unavailable: {detail}", headers=RETRY_SOON)
        got = R.package_hash(doc, pid, leaf.version)
        if isinstance(got, str):
            log.warning("unusable NuGet catalog entry", extra={"package": pid, "version": leaf.version, "url": url})
            return text_error(503, f"slowshield: {pid} {leaf.version}: {got}", headers=RETRY_SOON)
        digest, size = got
        return Expected(sha512=digest, size=size)

    # ---- search --------------------------------------------------------------------------------------------

    async def search(self, request: Request) -> Response:
        """nuget.org search with held and blocked versions removed from each result. A result with nothing left, a
        package blocked as a whole, and one whose registration can't be read are dropped (fail closed)."""
        ctx = self.ctx
        params: list[tuple[str, str]] = []
        for k, raw in request.query_params.multi_items():
            value = raw
            if k == "take":
                try:
                    value = str(max(0, min(MAX_SEARCH_TAKE, int(raw))))
                except ValueError:
                    value = str(MAX_SEARCH_TAKE)
            params.append((k, value))
        url = self.settings.search_url + ("?" + urlencode(params) if params else "")
        try:
            res = await ctx.upstream.fetch(url, max_bytes=MAX_SMALL_DOCUMENT)
        except UpstreamError as exc:
            ctx.recorder.decision(ECO, "metadata", "upstream_error")
            return text_error(503, f"slowshield: nuget.org search is unavailable: {exc.detail}", headers=RETRY_SOON)
        if res.status == 400:
            return text_error(400, "bad search query")
        if res.status != 200:
            return text_error(503, f"slowshield: nuget.org search returned {res.status}", headers=RETRY_SOON)
        try:
            doc = _decode.decode(res.body)
        except msgspec.DecodeError:
            doc = None
        if not isinstance(doc, dict) or not isinstance(doc.get("data", []), list):
            return text_error(503, "slowshield: nuget.org search sent an unreadable answer", headers=RETRY_SOON)
        urls = self._urls(request)
        sem = asyncio.Semaphore(SEARCH_CONCURRENCY)
        results = doc.get("data", [])

        async def judge(result: Any) -> dict[str, Any] | None:
            async with sem:
                return await self._search_result(result, urls)

        kept = [r for r in await asyncio.gather(*(judge(r) for r in results)) if r is not None]
        dropped = len(results) - len(kept)
        doc["data"] = kept
        total = doc.get("totalHits")
        if isinstance(total, int):
            doc["totalHits"] = max(len(kept), total - dropped)
        context = doc.get("@context")
        if isinstance(context, dict) and "@base" in context:
            doc["@context"] = {**context, "@base": urls.registration}
        ctx.recorder.decision(ECO, "metadata", "served")
        return _json_response(doc, headers={"Cache-Control": "no-store"})

    async def _search_result(self, result: Any, urls: R.Urls) -> dict[str, Any] | None:
        if not isinstance(result, dict) or not isinstance(result.get("id"), str):
            return None
        pid = result["id"].lower()
        if not names.is_valid_nuget(pid) or self.ctx.blocklist.for_package(ECO, pid).package_block is not None:
            return None
        try:
            snap = await self.snapshot(pid)
        except UpstreamError:
            return None
        if snap is None:
            return None
        v = self.view(snap)
        if v.package_block is not None:
            return None
        drop = v.drop
        versions: list[dict[str, Any]] = []
        for item in result.get("versions") or []:
            if not isinstance(item, dict) or not isinstance(item.get("version"), str):
                continue
            ver = NV.canonical(item["version"])
            if ver is None or ver not in snap.versions or ver in drop:
                continue  # a version SlowShield has no publish time for is held too
            versions.append({**item, "@id": urls.leaf(pid, ver)})
        if not versions:
            return None
        newest = max(versions, key=lambda item: snap.versions[NV.canonical(item["version"]) or ""].key)
        out = dict(result)
        out["@id"] = out["registration"] = urls.index(pid)
        out["versions"] = versions
        out["version"] = newest["version"]
        return out

    # ---- vulnerability data ---------------------------------------------------------------------------------

    def _vulnerability_files(self, doc: Any) -> dict[str, str]:
        """upstream file URL -> its path under /nuget/v3/vulnerabilities/, for the files the index lists on the
        index's own host. An index without one is unusable: served, it would be an empty feed, and NuGetAudit would
        find nothing to warn about."""
        origin = urlsplit(self.settings.vulnerability_url)
        out: dict[str, str] = {}
        if not isinstance(doc, list):
            return out
        for entry in doc:
            url = entry.get("@id") if isinstance(entry, dict) else None
            if not isinstance(url, str):
                continue
            parts = urlsplit(url)
            if (parts.scheme, parts.netloc) != (origin.scheme, origin.netloc) or parts.query or ".." in parts.path:
                continue
            out[url] = parts.path.lstrip("/")
        return out

    async def _vulnerability_doc(self) -> Any:
        ttl = self.ctx.cfg.raw.metadata_cache_ttl_hours * 3600
        body = await self._document(
            self.settings.vulnerability_url,
            "nuget:vuln:index",
            ttl=ttl,
            usable=lambda b: bool(self._vulnerability_files(_decoded(b))),
        )
        if body is None:
            raise UpstreamError(self.settings.vulnerability_url, "no vulnerability index")
        return _decode.decode(body)

    async def vulnerability_index(self, request: Request) -> Response:
        try:
            doc = await self._vulnerability_doc()
        except UpstreamError, msgspec.DecodeError:
            return text_error(503, "slowshield: nuget.org's vulnerability data is unavailable", headers=RETRY_SOON)
        files = self._vulnerability_files(doc)
        if not files:  # a copy stored before it was checked
            return text_error(503, "slowshield: nuget.org's vulnerability data is unavailable", headers=RETRY_SOON)
        base = f"{self._base(request)}vulnerabilities/"
        out = [
            {**entry, "@id": base + files[entry["@id"]]}
            for entry in doc
            if isinstance(entry, dict) and entry.get("@id") in files
        ]
        return _json_response(out, headers={"Cache-Control": "max-age=300"})

    async def vulnerability_file(self, path: str) -> Response:
        """A file the current vulnerability index lists; nothing else on that host."""
        try:
            doc = await self._vulnerability_doc()
        except UpstreamError, msgspec.DecodeError:
            return text_error(503, "slowshield: nuget.org's vulnerability data is unavailable", headers=RETRY_SOON)
        url = next((u for u, p in self._vulnerability_files(doc).items() if p == path), None)
        if url is None:
            return text_error(404, "not found")
        try:
            body = await self._document(url, f"nuget:vuln:{path}", ttl=CATALOG_TTL, usable=_is_object)
        except UpstreamError:
            return text_error(503, "slowshield: nuget.org's vulnerability data is unavailable", headers=RETRY_SOON)
        if body is None:
            return text_error(404, "not found")
        return Response(body, media_type=JSON, headers={"Cache-Control": "max-age=3600"})

    # ---- refusals -----------------------------------------------------------------------------------------

    def _too_new(self, request: Request, snap: R.Snapshot, v: View, version: str) -> Response:
        ctx = self.ctx
        now = ctx.clock.now()
        published = v.published.get(version)
        delay = ctx.cfg.delay_days_for(ECO, snap.id, version)
        wait = retry_after(published, delay, now)
        ctx.recorder.decision(ECO, "artifact", "age_gated")
        ctx.recorder.event(
            "age_gate",
            ECO,
            snap.id,
            version,
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
            details={"published": None if published is None else _iso(published), "delay_days": delay},
        )
        if published is None:
            when = f"SlowShield could not establish when it was published, so it counts as newer than {_days(delay)}."
            until = "Try again later."
        else:
            when = f"It was published {_iso(published)} ({(now - published) / DAY:.1f} days ago); "
            when += f"this proxy requires {_days(delay)}."
            until = f"It becomes available at {_iso(published + delay * DAY)}."
        older = self._older_allowed(snap, v, version)
        use = f"Use an older version ({older})" if older else "Use an older version"
        return text_error(
            425,
            f"slowshield: {snap.id} {version} is too new.\n{when}\n{until}\n"
            f"{use}, or ask your SlowShield administrator for an exception.",
            headers={"Retry-After": str(wait if wait is not None else int(delay * DAY))},
        )

    @staticmethod
    def _older_allowed(snap: R.Snapshot, v: View, version: str) -> str | None:
        """The newest listed version below `version` that would be served now."""
        top = snap.versions[version].key
        drop = v.drop
        allowed = [leaf for ver, leaf in snap.versions.items() if ver not in drop and leaf.listed and leaf.key < top]
        return max(allowed, key=lambda leaf: leaf.key).version if allowed else None

    def _blocked(self, request: Request, pid: str, version: str | None, entry: BlockEntry, *, kind: str) -> Response:
        ctx = self.ctx
        ctx.recorder.decision(ECO, kind, "blocked")
        ctx.recorder.event(
            "blocked",
            ECO,
            pid,
            version,
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
            details=entry.as_json(),
        )
        what = f"{pid} {version}" if version and not entry.package_level else pid
        return text_error(451, "\n".join(entry.explain(what)))
