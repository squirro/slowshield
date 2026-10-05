"""Maven repositories at /maven/<repo-id>/: version metadata filtered by release age and the blocklist, age-gated
files verified against the repository's checksums, and `/maven/all/` routing Maven Central and Google Maven behind
one URL (Maven sends a whole build through one mirror). See docs/design/maven.md.

A file's publish time is its `Last-Modified` on the repository (only on a 200); a version's is its `.pom`'s. A second
clock is when SlowShield first saw the version listed in the upstream metadata; the earlier of the two counts, so a
repository that rewrites its files in bulk doesn't hold every version back again. Too-new files get `425 Too Early`:
Maven and Gradle show only the status line, re-request a 425 on every build, and cache a 404 (so upstream failures are
503, never 404).
"""

from __future__ import annotations

import email.utils
import hashlib
import logging
import math
import re
import xml.etree.ElementTree as ET  # only Google's group index, with DOCTYPE refused
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.types import Receive, Scope, Send

from slowshield import versions as V
from slowshield.blocklist import BlockEntry
from slowshield.cache.metadata import SingleFlight
from slowshield.config import MavenRepo
from slowshield.context import AppContext
from slowshield.ecosystems.artifacts import ArtifactRecord, ArtifactRequest, AsgiResponse
from slowshield.ecosystems.maven import layout as L
from slowshield.ecosystems.maven import metadata as MD
from slowshield.integrity import Expected
from slowshield.policy import DAY, is_old_enough, retry_after
from slowshield.telemetry import instruments
from slowshield.upstream import FetchResult, StreamResponse, UpstreamError
from slowshield.web import TEXT, client_ip, route_path, text_error

log = logging.getLogger(__name__)

ECO = "maven"
TOO_EARLY = 425
XML = "text/xml"
MAX_METADATA_BYTES = 16 << 20
MAX_SIDECAR_BYTES = 4096
MAX_INDEX_BYTES = 8 << 20
PROBE_LIMIT = 20  # versions without a known publish time looked up per metadata evaluation
EARLIEST = datetime(2002, 1, 1, tzinfo=UTC).timestamp()  # Maven Central's first year: anything earlier is bogus
CLOCK_SKEW = 300.0
KEEP_STALE = 7 * DAY
SIDECAR_TTL = 30 * DAY  # checksum files of released files never change
INDEX_TTL = DAY  # Google's group index
CONTENT_TYPES = {
    ".pom": XML,
    ".xml": XML,
    ".jar": "application/java-archive",
    ".module": "application/json",
    ".json": "application/json",
    ".asc": "text/plain",
}
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256_IN_PATH = re.compile(r"/([0-9a-f]{64})/")


class _Absent:
    """The repository does not have this version."""


ABSENT = _Absent()


@dataclass(frozen=True, slots=True)
class Repo:
    id: str  # the origin: central, google, gradle-plugins or an operator repository (never "all")
    url: str
    snapshots: bool


@dataclass(frozen=True, slots=True)
class Fetched:
    body: bytes
    content_id: str
    fresh: bool  # just fetched from upstream (not from the store)


@dataclass(frozen=True, slots=True)
class Gone:
    status: int
    body: bytes


@dataclass(slots=True)
class View:
    listed: list[str] = field(default_factory=list)
    held: set[str] = field(default_factory=set)
    blocked: dict[str, BlockEntry] = field(default_factory=dict)
    fail_open: bool = False
    complete: bool = True
    next_change: float = math.inf
    package_block: BlockEntry | None = None
    body: bytes = b""


def _iso(ts: float | None) -> str:
    return "an unknown time" if ts is None else datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _days(value: float) -> str:
    return f"{value:g} day" + ("" if value == 1 else "s")


def _earliest(*clocks: float | None) -> float | None:
    """Both clocks are upper bounds of the real publish time, so the earlier one is too."""
    known = [c for c in clocks if c is not None]
    return min(known) if known else None


def maven_error(status: int, code: str, *, headers: dict[str, str] | None = None, **fields: Any) -> Response:
    """The artifact server's errors as plain text (Maven and Gradle only show the status line; curl shows this)."""
    artifact = fields.get("artifact") or "the file"
    if code == "tamper_detected":
        msg = f"slowshield: {artifact} changed upstream after it was first served (tampering)."
    elif code == "integrity_mismatch":
        msg = f"slowshield: {artifact} failed verification: {fields.get('detail', '')}"
    elif code == "not_found":
        msg = "not found"
    else:
        msg = f"slowshield: {code.replace('_', ' ')}" + (f": {fields['detail']}" if fields.get("detail") else "")
    if status == 502:
        status = 503  # never a status Maven could cache; 502 isn't cached either, but 503 says "try again"
    return text_error(status, msg, headers=headers)


class MavenService:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self.flight = SingleFlight()

    @property
    def settings(self) -> Any:
        return self.ctx.cfg.raw.upstreams.maven

    def _repo(self, repo_id: str) -> Repo | None:
        cfg: MavenRepo | None = self.settings.repository(repo_id)
        return None if cfg is None else Repo(repo_id, cfg.url.rstrip("/"), cfg.snapshots)

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
        repo_id, _, rel = route_path(request.scope).lstrip("/").partition("/")
        if not repo_id:
            return Response(b"SlowShield Maven repositories: /maven/all/, /maven/central/, ...\n", media_type=TEXT)
        mreq = L.parse(rel)
        if mreq is None or (repo_id != "all" and self._repo(repo_id) is None):
            return text_error(404, "not found")
        if mreq.kind == "passthrough":
            return await self._passthrough(request, await self._origin(repo_id, mreq), mreq)
        repo = await self._origin(repo_id, mreq)
        if repo is None:
            return text_error(404, "not found")
        blocks = self.ctx.blocklist.for_package(ECO, mreq.name)
        kind = "metadata" if mreq.kind == "metadata" else "artifact"
        entry = blocks.package_block or (blocks.match(ECO, mreq.version) if mreq.version else None)
        if entry is not None:
            return self._blocked(request, mreq.name, mreq.version, entry, kind=kind)
        if mreq.snapshot:
            # Snapshots change by design: no release-age check, no fingerprint. Operator repositories only.
            return await self._passthrough(request, repo, mreq) if repo.snapshots else text_error(404, "not found")
        if mreq.kind == "metadata":
            return await self.metadata(request, repo, mreq)
        if mreq.kind == "checksum":
            return await self.checksum(request, repo, mreq)
        return await self.file(request, repo, mreq)

    async def _origin(self, repo_id: str, mreq: L.MavenRequest) -> Repo | None:
        """`all` is Google Maven for the groups Google lists in its index, Maven Central for everything else."""
        if repo_id != "all":
            return self._repo(repo_id)
        if mreq.group and mreq.group in await self._google_groups():
            return self._repo("google")
        return self._repo("central")

    async def _google_groups(self) -> frozenset[str]:
        key = ("maven:google-groups",)
        hit = self.ctx.metadata_cache.get(key, self.ctx.clock.now())
        if hit is not None:
            return hit
        return await self.flight.run(key, self._load_google_groups)

    async def _load_google_groups(self) -> frozenset[str]:
        ctx = self.ctx
        google = self._repo("google")
        now = ctx.clock.now()
        skey = "maven:google-groups"
        stored = await ctx.metadata_store.aget(skey)
        body = stored.value if stored is not None and stored.fresh(now) else None
        if body is None and google is not None:
            try:
                res = await ctx.upstream.fetch(f"{google.url}/master-index.xml", max_bytes=MAX_INDEX_BYTES)
                if res.status == 200:
                    body = res.body
                    await ctx.metadata_store.aput(skey, body, expires=now + INDEX_TTL, keep_until=now + 30 * DAY)
            except UpstreamError as exc:
                log.warning("Google Maven group index unavailable", extra={"error": exc.detail})
            if body is None and stored is not None:
                body = stored.value  # stale beats routing Google's groups to Central
        groups: frozenset[str] = frozenset()
        if body and b"<!DOCTYPE" not in body.upper():
            try:
                groups = frozenset(_local(el.tag) for el in ET.fromstring(body))  # noqa: S314 - no DOCTYPE
            except ET.ParseError:
                log.warning("Google Maven group index unreadable")
        ctx.metadata_cache.put(("maven:google-groups",), groups, 64 * len(groups) + 256, now + (3600 if groups else 60))
        return groups

    def _url(self, repo: Repo, rel: str) -> str:
        return f"{repo.url}/{rel}"

    # ---- publish times --------------------------------------------------------------------------------

    def _times(self, name: str) -> dict[str, list[float | None]]:
        """version -> [published (.pom Last-Modified), first listed], shared by all workers through the database."""
        key = ("maven:times", name)
        now = self.ctx.clock.now()
        hit = self.ctx.metadata_cache.get(key, now)
        if hit is not None:
            return hit
        rows = self.ctx.db.readers.query(
            "SELECT version, published, first_listed FROM package_versions WHERE ecosystem = ? AND name = ? "
            "AND (published IS NOT NULL OR first_listed IS NOT NULL)",
            (ECO, name),
        )
        times = {r[0]: [r[1], r[2]] for r in rows}
        self.ctx.metadata_cache.put(key, times, 256 + 96 * len(times), now + 300)
        return times

    def _learned(self, name: str, version: str, published: float) -> None:
        times = self.ctx.metadata_cache.get_stale(("maven:times", name))
        if isinstance(times, dict):
            times.setdefault(version, [None, None])[0] = published
        self.ctx.recorder.catalog(ECO, name, [(version, published, False)])

    def _listed(self, name: str, versions: tuple[str, ...]) -> None:
        """Record when SlowShield first saw these versions listed upstream (the second clock)."""
        times = self._times(name)
        now = self.ctx.clock.now()
        new = [v for v in versions if times.get(v, [None, None])[1] is None]
        if not new:
            return
        for v in new:
            times.setdefault(v, [None, None])[1] = now

        def op(conn: Any) -> None:
            conn.executemany(
                "INSERT INTO package_versions (ecosystem, name, version, first_listed) VALUES (?, ?, ?, ?) "
                "ON CONFLICT (ecosystem, name, version) DO UPDATE SET "
                "first_listed = coalesce(package_versions.first_listed, excluded.first_listed)",
                [(ECO, name, v, now) for v in new],
            )

        self.ctx.recorder.catalog(ECO, name)
        self.ctx.db.writer.enqueue(op)

    def _stored_at(self, status: int, headers: dict[str, str]) -> float:
        """When the repository stored the file it answered 200 for: its Last-Modified. Without a plausible one the
        clock starts now, when SlowShield first sees the file (the 200 proves it exists)."""
        now = self.ctx.clock.now()
        raw = headers.get("last-modified") if status == 200 else None
        try:
            ts = email.utils.parsedate_to_datetime(raw).timestamp() if raw else None
        except TypeError, ValueError:
            ts = None
        if ts is None or not EARLIEST <= ts <= now + CLOCK_SKEW:
            return now
        return ts

    async def _pom_time(self, repo: Repo, mreq: L.MavenRequest, version: str) -> float | _Absent:
        """The version's publish time: one HEAD of its .pom, once per version."""
        known = self._times(mreq.name).get(version, [None, None])[0]
        if known is not None:
            return known
        key = ("maven:pom", repo.id, mreq.name, version)
        return await self.flight.run(key, lambda: self._probe_pom(repo, mreq, version))

    async def _probe_pom(self, repo: Repo, mreq: L.MavenRequest, version: str) -> float | _Absent:
        group_path = (mreq.group or "").replace(".", "/")
        url = self._url(repo, f"{group_path}/{mreq.artifact}/{version}/{mreq.artifact}-{version}.pom")
        res = await self.ctx.upstream.fetch(url, max_bytes=0, method="HEAD")
        result = {200: "on_mirror", 404: "not_found", 410: "not_found"}.get(res.status, "error")
        instruments.publish_time_lookups.add(1, {"slowshield.ecosystem": ECO, "result": result})
        if res.status in (404, 410):
            return ABSENT
        if res.status != 200:
            raise UpstreamError(res.url, f"upstream returned {res.status}", res.status)
        published = self._stored_at(res.status, res.headers)
        self._learned(mreq.name, version, published)
        return published

    def _delay(self, name: str, version: str) -> float:
        return self.ctx.cfg.delay_days_for(ECO, name, version)

    # ---- metadata ---------------------------------------------------------------------------------------

    async def _fetch_metadata(self, repo: Repo, rel: str) -> Fetched | Gone:
        key = ("maven:md", repo.id, rel)
        hit = self.ctx.metadata_cache.get(key, self.ctx.clock.now())
        if hit is not None:
            self.ctx.recorder.lookup(ECO, cached=True)
            return hit
        return await self.flight.run(key, lambda: self._load_metadata(repo, rel))

    async def _load_metadata(self, repo: Repo, rel: str) -> Fetched | Gone:
        ctx = self.ctx
        key = ("maven:md", repo.id, rel)
        skey = f"maven:md:{repo.id}:{rel}"
        now = ctx.clock.now()
        ttl = ctx.cfg.raw.metadata_cache_ttl_hours * 3600
        stored = await ctx.metadata_store.aget(skey)

        def keep(fetched: Fetched, expires: float) -> Fetched:
            ctx.metadata_cache.put(key, fetched, 512 + len(fetched.body), expires)
            return fetched

        if stored is not None and stored.fresh(now):
            ctx.recorder.lookup(ECO, cached=True)
            return keep(Fetched(stored.value, stored.meta.get("content_id", ""), False), stored.expires)
        headers = {}
        if stored is not None and stored.meta.get("etag"):
            headers["If-None-Match"] = stored.meta["etag"]
        ctx.recorder.lookup(ECO, cached=False)
        try:
            res = await ctx.upstream.fetch(self._url(repo, rel), headers=headers, max_bytes=MAX_METADATA_BYTES)
        except UpstreamError:
            if stored is None:
                raise
            log.warning("upstream unavailable; serving stale Maven metadata", extra={"path": rel})
            return keep(Fetched(stored.value, stored.meta.get("content_id", ""), False), now + 60)
        if res.status == 304 and stored is not None:
            await ctx.metadata_store.atouch(skey, now + ttl, now + ttl + KEEP_STALE)
            return keep(Fetched(stored.value, stored.meta.get("content_id", ""), False), now + ttl)
        if res.status in (404, 410):
            gone = Gone(res.status, res.body[:2048])
            ctx.metadata_cache.put(key, gone, 256, now + 300)
            return gone
        if res.status != 200:
            raise UpstreamError(res.url, f"upstream returned {res.status}", res.status)
        content_id = hashlib.blake2b(res.body, digest_size=12).hexdigest()
        meta = {"etag": res.etag, "content_id": content_id}
        await ctx.metadata_store.aput(skey, res.body, expires=now + ttl, keep_until=now + ttl + KEEP_STALE, meta=meta)
        return keep(Fetched(res.body, content_id, True), now + ttl)

    async def metadata(self, request: Request, repo: Repo, mreq: L.MavenRequest) -> Response:
        ctx = self.ctx
        try:
            doc = await self._fetch_metadata(repo, mreq.base)
        except UpstreamError as exc:
            ctx.recorder.decision(ECO, "metadata", "upstream_error")
            return text_error(503, f"slowshield: upstream error: {exc.detail}", headers={"Retry-After": "60"})
        if isinstance(doc, Gone):
            ctx.recorder.decision(ECO, "metadata", "not_found")
            return text_error(404, "not found")
        md = MD.parse(doc.body)
        if md is None or md.group != mreq.group or md.artifact != mreq.artifact:
            return self._metadata_response(doc.body, mreq.algo)  # group-level plugin lists and the like: unchanged
        if doc.fresh:
            self._listed(mreq.name, md.versions)
        v = await self.view(repo, mreq, md, doc.content_id)
        if v.package_block is not None:
            return self._blocked(request, mreq.name, None, v.package_block, kind="metadata")
        if v.held:
            instruments.versions_held.add(len(v.held), {"slowshield.ecosystem": ECO})
        if v.fail_open:
            ctx.recorder.decision(ECO, "metadata", "fail_open")
            ctx.recorder.event(
                "fail_open",
                ECO,
                mreq.name,
                None,
                client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
                details={"reason": "all_versions_too_new", "versions": v.listed[-20:]},
            )
        else:
            ctx.recorder.decision(ECO, "metadata", "served")
        now = ctx.clock.now()
        headers = {
            "Cache-Control": f"max-age={int(max(0, min(300, v.next_change - now)))}",
            "X-SlowShield-Held-Versions": str(len(v.held)),
        }
        if v.fail_open:
            headers["X-SlowShield-Fail-Open"] = "1"
        return self._metadata_response(v.body, mreq.algo, headers)

    def _metadata_response(self, body: bytes, algo: str | None, headers: dict[str, str] | None = None) -> Response:
        """The metadata, or one of its checksum files: computed from this very body, so they always match."""
        if algo is not None:
            return Response(hashlib.new(algo, body, usedforsecurity=False).hexdigest().encode(), media_type=TEXT)
        checksums = {
            "X-Checksum-Sha1": hashlib.sha1(body, usedforsecurity=False).hexdigest(),
            "X-Checksum-MD5": hashlib.md5(body, usedforsecurity=False).hexdigest(),
        }
        return Response(body, media_type=XML, headers={**checksums, **(headers or {})})

    async def view(self, repo: Repo, mreq: L.MavenRequest, md: MD.Metadata, content_id: str) -> View:
        key = ("maven:view", repo.id, mreq.name, content_id, self.ctx.policy_key())
        hit = self.ctx.metadata_cache.get(key, self.ctx.clock.now())
        if hit is not None:
            return hit
        return await self.flight.run(key, lambda: self._evaluate(repo, mreq, md, key))

    async def _evaluate(self, repo: Repo, mreq: L.MavenRequest, md: MD.Metadata, key: tuple[Any, ...]) -> View:
        """Newest first, in Maven's version order, until a version is old enough. Versions below it are listed unless
        known to be too new: every file request is checked on its own anyway."""
        ctx = self.ctx
        now = ctx.clock.now()
        v = View()
        blocks = ctx.blocklist.for_package(ECO, mreq.name)
        if blocks.package_block is not None:
            v.package_block = blocks.package_block
            ctx.metadata_cache.put(key, v, 256, now + 300)
            return v
        candidates: list[str] = []
        for ver in md.versions:
            entry = blocks.match(ECO, ver)
            if entry is not None:
                v.blocked[ver] = entry
            elif not (V.is_prerelease(ECO, ver) and not repo.snapshots):
                candidates.append(ver)
        times = self._times(mreq.name)
        held: set[str] = set()

        def published(ver: str) -> float | None:
            t = times.get(ver, [None, None])
            return _earliest(t[0], t[1])

        def hold(ver: str, at: float | None) -> None:
            held.add(ver)
            if at is not None:
                v.next_change = min(v.next_change, at + self._delay(mreq.name, ver) * DAY)

        probes = 0
        found = False
        for ver in sorted(candidates, key=lambda x: V.sort_key(ECO, x), reverse=True):
            at = published(ver)
            if (at is None or not is_old_enough(at, self._delay(mreq.name, ver), now)) and times.get(ver, [None, None])[
                0
            ] is None:
                if probes >= PROBE_LIMIT:
                    v.complete = False
                    continue
                probes += 1
                try:
                    got = await self._pom_time(repo, mreq, ver)
                except UpstreamError:
                    v.complete = False
                    continue
                if isinstance(got, _Absent):
                    hold(ver, None)
                    continue
                at = published(ver)
            if at is not None and is_old_enough(at, self._delay(mreq.name, ver), now):
                found = True
                break
            hold(ver, at)
        for ver in candidates:
            # Below the chosen version, only a known .pom date holds a version: a first-listed time alone is just
            # "SlowShield saw it now", which says nothing about how old it is.
            at = published(ver)
            if (
                ver not in held
                and times.get(ver, [None, None])[0] is not None
                and at is not None
                and not is_old_enough(at, self._delay(mreq.name, ver), now)
            ):
                hold(ver, at)
        if not found and v.complete and held and ctx.cfg.fail_open_for(ECO):
            v.fail_open = True
            held = set()
        v.held = held
        v.listed = [ver for ver in candidates if ver not in held]
        order = sorted(v.listed, key=lambda x: V.sort_key(ECO, x))
        latest = md.latest if md.latest in v.listed else (order[-1] if order else None)
        releases = [x for x in order if not V.is_prerelease(ECO, x)]
        release = md.release if md.release in v.listed else (releases[-1] if releases else None)
        v.body = MD.render(md, set(v.listed), latest, release)
        ctx.metadata_cache.put(key, v, 512 + len(v.body) + 64 * len(md.versions), min(v.next_change, now + 300))
        return v

    async def _fails_open(self, repo: Repo, mreq: L.MavenRequest) -> bool:
        """True when no version of the artifact is old enough yet (only if fail-open is on for Maven)."""
        if not self.ctx.cfg.fail_open_for(ECO):
            return False
        group_path = (mreq.group or "").replace(".", "/")
        try:
            doc = await self._fetch_metadata(repo, f"{group_path}/{mreq.artifact}/{L.METADATA}")
        except UpstreamError:
            return False
        if isinstance(doc, Gone):
            return False
        md = MD.parse(doc.body)
        return md is not None and (await self.view(repo, mreq, md, doc.content_id)).fail_open

    # ---- files ------------------------------------------------------------------------------------------

    async def _judge(
        self, request: Request, repo: Repo, mreq: L.MavenRequest, at: float | None, *, kind: str
    ) -> Response | None:
        """None when a file (or version) published at `at` may be served now; otherwise the refusal."""
        ctx = self.ctx
        if not ctx.cfg.raw.enforce_age_on_download:
            return None
        version = mreq.version or ""
        delay = self._delay(mreq.name, version)
        if at is not None and is_old_enough(at, delay, ctx.clock.now()):
            return None
        if await self._fails_open(repo, mreq):
            ctx.recorder.decision(ECO, kind, "fail_open")
            ctx.recorder.event(
                "fail_open",
                ECO,
                mreq.name,
                version,
                client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
                details={"reason": "all_versions_too_new"},
            )
            return None
        return self._too_new(request, mreq.name, version, at, delay, kind=kind, file=mreq.filename)

    def _known_too_new(self, request: Request, repo: Repo, mreq: L.MavenRequest) -> float | None:
        """The version's publish time when SlowShield already knows it; None if unknown."""
        t = self._times(mreq.name).get(mreq.version or "", [None, None])
        return _earliest(t[0], t[1]) if t[0] is not None else None

    async def file(self, request: Request, repo: Repo, mreq: L.MavenRequest) -> AsgiResponse:
        ctx = self.ctx
        version = mreq.version or ""
        listed = self._times(mreq.name).get(version, [None, None])[1]
        known = self._known_too_new(request, repo, mreq)
        if known is not None:
            # A version known to be too new is refused before any upstream request.
            refusal = await self._judge(request, repo, mreq, known, kind="artifact")
            if refusal is not None:
                return refusal
        key = f"/{repo.id}/{mreq.rel}"
        art = ArtifactRequest(
            ecosystem=ECO,
            key=key,
            package=mreq.name,
            version=version,
            filename=mreq.filename or mreq.rel.rsplit("/", 1)[-1],
            upstream_url=self._url(repo, mreq.rel),
            expected=Expected(),
            content_type=_content_type(mreq.rel),
            error=maven_error,
            hit_headers=_hit_headers,
        )
        is_pom = mreq.filename == f"{mreq.artifact}-{version}.pom"

        async def on_upstream(up: StreamResponse) -> Response | dict[str, str] | None:
            stored = self._stored_at(up.status, up.headers)
            if is_pom and self._times(mreq.name).get(version, [None, None])[0] is None:
                self._learned(mreq.name, version, stored)  # the version's publish time, from this very GET
            refusal = await self._judge(request, repo, mreq, _earliest(stored, listed), kind="artifact")
            if refusal is not None:
                return refusal
            return await self._expect(repo, mreq, art, up.url, up.headers)

        art.on_upstream = on_upstream
        if request.method == "HEAD":
            return await self._head(request, repo, mreq, art, listed, is_pom=is_pom)
        return await ctx.artifacts.serve(
            art,
            method=request.method,
            headers_in=dict(request.headers),
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
        )

    async def _expect(
        self, repo: Repo, mreq: L.MavenRequest, art: ArtifactRequest, url: str, headers: dict[str, str]
    ) -> dict[str, str]:
        """The repository's own checksum for the file: Central's x-checksum-sha1 header, the Plugin Portal's sha256 in
        the path it redirected to, else the file's .sha1. Returns the checksum headers to send on."""
        sha1 = (headers.get("x-checksum-sha1") or "").strip().lower()
        if path_sha256 := _SHA256_IN_PATH.search(urlsplit(url).path):
            art.expected.sha256 = path_sha256.group(1)
        if not _SHA1.match(sha1) and art.expected.sha256 is None:
            sha1 = await self._sidecar_sha1(repo, mreq.rel) or ""
        out: dict[str, str] = {}
        if _SHA1.match(sha1):
            art.expected.sha1 = sha1
            art.upstream_digest = sha1
            out["X-Checksum-Sha1"] = sha1
        md5 = (headers.get("x-checksum-md5") or "").strip().lower()
        if re.fullmatch(r"[0-9a-f]{32}", md5):
            out["X-Checksum-MD5"] = md5
        return out

    async def _sidecar(self, repo: Repo, rel: str) -> FetchResult | None:
        """A checksum file from upstream (cached: they never change for released files). None if there is none."""
        ctx = self.ctx
        skey = f"maven:sum:{repo.id}:{rel}"
        now = ctx.clock.now()
        stored = await ctx.metadata_store.aget(skey)
        if stored is not None and stored.fresh(now):
            return FetchResult(200, dict(stored.meta.get("headers", {})), stored.value, rel, "cache")
        res = await ctx.upstream.fetch(self._url(repo, rel), max_bytes=MAX_SIDECAR_BYTES)
        if res.status == 200:
            meta = {"headers": {k: v for k, v in res.headers.items() if k == "last-modified"}}
            await ctx.metadata_store.aput(skey, res.body, expires=now + SIDECAR_TTL, meta=meta)
            return res
        if res.status in (404, 410):
            return None
        raise UpstreamError(res.url, f"upstream returned {res.status}", res.status)

    async def _sidecar_sha1(self, repo: Repo, rel: str) -> str | None:
        try:
            res = await self._sidecar(repo, f"{rel}.sha1")
        except UpstreamError as exc:
            log.warning("Maven checksum file unavailable", extra={"path": rel, "error": exc.detail})
            return None
        if res is None:
            return None
        text = res.body.decode("ascii", "replace").strip().split()  # "<sha1>" or "<sha1>  <filename>"
        return text[0].lower() if text and _SHA1.match(text[0].lower()) else None

    async def _head(
        self, request: Request, repo: Repo, mreq: L.MavenRequest, art: ArtifactRequest, listed: float | None, *,
        is_pom: bool,
    ) -> AsgiResponse:  # fmt: skip
        """HEAD answers what a GET would: Gradle HEADs a .jar to see whether a pom-packaged module has one."""
        ctx = self.ctx
        rec = ctx.artifacts.record_for(ECO, art.key)
        if rec is not None and ctx.artifact_cache.lookup(rec.sha256) is not None:
            return await ctx.artifacts.serve(art, method="HEAD", headers_in={}, client_ip=None)
        try:
            res = await ctx.upstream.fetch(art.upstream_url, max_bytes=0, method="HEAD")
        except UpstreamError as exc:
            return maven_error(503, "upstream_error", detail=exc.detail)
        if res.status in (404, 410):
            return text_error(404, "not found")
        if res.status != 200:
            return maven_error(503, "upstream_error", detail=f"upstream returned {res.status}")
        stored = self._stored_at(res.status, res.headers)
        if is_pom and self._times(mreq.name).get(mreq.version or "", [None, None])[0] is None:
            self._learned(mreq.name, mreq.version or "", stored)
        refusal = await self._judge(request, repo, mreq, _earliest(stored, listed), kind="artifact")
        if refusal is not None:
            return refusal
        headers = {"Content-Type": art.content_type}
        if res.headers.get("content-length", "").isdigit():
            headers["Content-Length"] = res.headers["content-length"]
        sha1 = (res.headers.get("x-checksum-sha1") or "").lower()
        if _SHA1.match(sha1):
            headers["X-Checksum-Sha1"] = sha1
        return Response(status_code=200, headers=headers)

    async def checksum(self, request: Request, repo: Repo, mreq: L.MavenRequest) -> Response:
        """A file's checksum file, gated like the file: from the verified download when there was one, else from
        upstream."""
        ctx = self.ctx
        known = self._known_too_new(request, repo, mreq)
        if known is not None:
            refusal = await self._judge(request, repo, mreq, known, kind="artifact")
            if refusal is not None:
                return refusal
        if mreq.algo == "sha1":
            rec: ArtifactRecord | None = ctx.artifacts.record_for(ECO, f"/{repo.id}/{mreq.base}")
            if rec is not None and rec.upstream_digest and _SHA1.match(rec.upstream_digest) and not rec.tampered:
                return Response(rec.upstream_digest.encode(), media_type=TEXT)
        try:
            res = await self._sidecar(repo, mreq.rel)
        except UpstreamError as exc:
            return text_error(503, f"slowshield: upstream error: {exc.detail}", headers={"Retry-After": "60"})
        if res is None:
            return text_error(404, "not found")
        listed = self._times(mreq.name).get(mreq.version or "", [None, None])[1]
        refusal = await self._judge(
            request, repo, mreq, _earliest(self._stored_at(200, res.headers), listed), kind="artifact"
        )
        return refusal or Response(res.body, media_type=TEXT, headers={"Cache-Control": "max-age=86400"})

    async def _passthrough(self, request: Request, repo: Repo | None, mreq: L.MavenRequest) -> Response:
        """Unchanged, without release-age checks: archetype catalogs, and snapshots on operator repositories."""
        if repo is None:
            return text_error(404, "not found")
        ctx = self.ctx
        url = self._url(repo, mreq.rel)
        try:
            cm = ctx.upstream.stream(url)
            up = await cm.__aenter__()
        except UpstreamError as exc:
            return text_error(503, f"slowshield: upstream error: {exc.detail}", headers={"Retry-After": "60"})
        if up.status != 200:
            await cm.__aexit__(None, None, None)
            return text_error(404 if up.status in (404, 410) else 503, "not found" if up.status in (404, 410) else
                              f"slowshield: upstream returned {up.status}")  # fmt: skip

        async def body() -> Any:
            try:
                async for chunk in up.chunks():
                    if chunk:
                        yield bytes(chunk)
            finally:
                await cm.__aexit__(None, None, None)

        headers = {"Cache-Control": "no-cache"}
        if up.content_length is not None:
            headers["Content-Length"] = str(up.content_length)
        if request.method == "HEAD":
            await cm.__aexit__(None, None, None)
            return Response(status_code=200, headers=headers, media_type=_content_type(mreq.rel))
        return StreamingResponse(body(), media_type=_content_type(mreq.rel), headers=headers)

    # ---- refusals -------------------------------------------------------------------------------------------

    def _too_new(
        self, request: Request, name: str, version: str, published: float | None, delay: float, *, kind: str,
        file: str | None,
    ) -> Response:  # fmt: skip
        ctx = self.ctx
        now = ctx.clock.now()
        wait = retry_after(published, delay, now)
        ctx.recorder.decision(ECO, kind, "age_gated")
        ctx.recorder.event(
            "age_gate",
            ECO,
            name,
            version,
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
            details={"file": file, "published": None if published is None else _iso(published), "delay_days": delay},
        )
        if published is None:
            when = f"SlowShield could not establish when it was published, so it counts as newer than {_days(delay)}."
            until = "Try again later."
        else:
            when = f"It was published {_iso(published)} ({(now - published) / DAY:.1f} days ago); "
            when += f"this proxy requires {_days(delay)}."
            until = f"It becomes available at {_iso(published + delay * DAY)}."
        return text_error(
            TOO_EARLY,
            f"slowshield: {name}:{version} is too new.\n{when}\n{until}\n"
            "Use an older version, or ask your SlowShield administrator for an exception.",
            headers={"Retry-After": str(wait if wait is not None else int(delay * DAY))},
        )

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
        what = f"{name}:{version}" if version and not entry.package_level else name
        lines = [f"slowshield: {what} is blocked as known malware."]
        lines.append("Advisory: " + " ".join(p for p in (entry.advisory_id, f"({entry.source})", entry.url or "") if p))
        if entry.reason:
            lines.append(entry.reason.splitlines()[0][:300])
        return text_error(451, "\n".join(lines))


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _content_type(rel: str) -> str:
    dot = rel.rfind(".")
    return CONTENT_TYPES.get(rel[dot:] if dot >= 0 else "", "application/octet-stream")


def _hit_headers(rec: ArtifactRecord) -> dict[str, str]:
    digest = (rec.upstream_digest or "").lower()
    return {"X-Checksum-Sha1": digest} if _SHA1.match(digest) else {}
