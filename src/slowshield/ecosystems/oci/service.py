"""OCI container images: the distribution API at /v2/, pull only (docs/design/oci.md).

- A tag resolves to the newest digest it has pointed to for at least the delay, and isn't blocked: `nginx:latest` keeps
  working, about a week behind. The candidates are SlowShield's own history (`oci_tags`) and the registry's.
- A digest pin is judged by the earliest time any tag pointed to it, its parent index's time, or the registry's own
  time for it; failing all, when SlowShield first saw it. Pins that are too new are refused, not downgraded.
- With nothing old enough, a tag is refused, except during the first `default_delay_days` after this instance started
  serving images: it has no history yet, so the current digest is served and recorded as fail-open.
- Every refusal is `403 DENIED` with the reason in the message, `Retry-After` and `X-SlowShield-Reason`: containerd
  only shows an error body after a 403, and a 404 would send containerd and classic Docker to the next host.
- Manifests are checked against their digests and stored by digest; a stored one is re-checked with a free `HEAD` at
  most every 5 minutes, so a registry takedown propagates. Blobs are streamed and checked: image configs (a few KB,
  known from the manifests served) go to the main cache, layers to the separate layer store if it has a budget, else
  nowhere.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from slowshield.blocklist import BlockEntry, PackageBlocks
from slowshield.cache.metadata import SingleFlight
from slowshield.config import LoadedConfig
from slowshield.context import AppContext
from slowshield.ecosystems.artifacts import ArtifactRecord, ArtifactRequest, AsgiResponse
from slowshield.ecosystems.oci import reference as R
from slowshield.ecosystems.oci.registry import (
    DigestMismatch,
    Manifest,
    Registry,
    RegistryClient,
    registries,
)
from slowshield.ecosystems.oci.times import MAX_LISTING_BYTES, Times
from slowshield.integrity import Expected
from slowshield.policy import DAY, is_old_enough, retry_after
from slowshield.upstream import UpstreamError
from slowshield.web import JSONResponse, client_ip, route_path

log = logging.getLogger(__name__)

ECO = "oci"
TAG_TTL = 300.0  # a tag's upstream digest is asked for again after this long
RECHECK = 300.0  # a stored manifest is checked to still exist upstream at most this often
HISTORY_RETRY = 600.0  # a registry time that couldn't be read is asked for again after this long
MANIFEST_TTL = 30 * DAY  # manifests are immutable: kept by digest
RECORDED_MAX = 100_000  # manifests a worker remembers having catalogued
API = {"Docker-Distribution-API-Version": "registry/2.0"}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _short(digest: str) -> str:
    return digest[:19] + "…"


def _ago(seconds: float) -> str:
    return f"{seconds / 3600:.1f} hours" if seconds < DAY else f"{seconds / DAY:.1f} days"


def _days(value: float) -> str:
    return f"{value:g} day" + ("" if value == 1 else "s")


def oci_error(
    status: int, code: str, message: str, *, reason: str | None = None, headers: dict[str, str] | None = None
) -> Response:
    """An error in the distribution spec's format, which clients print (`denied: <message>`)."""
    h = {"Cache-Control": "no-store", **API, **(headers or {})}
    if reason:
        h["X-SlowShield-Reason"] = reason
    return JSONResponse({"errors": [{"code": code, "message": message}]}, status_code=status, headers=h)


def blob_error(status: int, code: str, *, headers: dict[str, str] | None = None, **fields: Any) -> Response:
    """The artifact server's errors, for blobs."""
    artifact = fields.get("artifact") or "the blob"
    if code == "tamper_detected":
        msg = f"slowshield: {artifact} changed upstream after it was first served (tampering)."
        return oci_error(403, "DENIED", msg, reason="tampered", headers=headers)
    if code == "not_found":
        return oci_error(404, "BLOB_UNKNOWN", "blob unknown to the registry", headers=headers)
    detail = fields.get("detail") or code.replace("_", " ")
    retry = {"Retry-After": "10", **(headers or {})}
    return oci_error(503, "UNAVAILABLE", f"slowshield: {detail}", reason=code, headers=retry)


GONE = Manifest("", "", b"", 0)  # what body() returns for a manifest the registry took down


def delay_days(cfg: LoadedConfig, repo: str, digest: str, tag: str | None = None) -> float:
    """Exceptions for a digest win over those for a tag, which win over those for the repository."""
    if tag and cfg.has_version_rules(ECO, repo):
        by_digest = cfg.delay_days_for(ECO, repo, digest)
        if by_digest != cfg.delay_days_for(ECO, repo):
            return by_digest
        return cfg.delay_days_for(ECO, repo, tag)
    return cfg.delay_days_for(ECO, repo, digest)


@dataclass(slots=True)
class Resolved:
    digest: str
    held: int = 0  # newer tag moves held back
    fail_open: bool = False
    published: float | None = None


@dataclass(frozen=True, slots=True)
class TagRow:
    digest: str
    first_seen: float
    registry_time: float | None

    @property
    def time(self) -> float:
        """When the tag got this digest: the earlier clock, as both are no earlier than the real moment."""
        return self.first_seen if self.registry_time is None else min(self.first_seen, self.registry_time)


class OciService:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self.client = RegistryClient(ctx)
        self.times = Times(ctx, self.client)
        self.flight = SingleFlight()
        self.registries = registries(ctx)
        self._since: float | None = None
        self._checked: dict[tuple[str, str], float] = {}
        self._asked: dict[tuple[str, str], float] = {}  # (repository, tag) -> when its registry history was read
        self._recorded: set[tuple[str, str]] = set()  # manifests this worker has catalogued (or found catalogued)

    @property
    def layer_store(self) -> bool:
        return "layers" in self.ctx.artifacts.stores

    # ---- ASGI dispatch ------------------------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":  # pragma: no cover - lifespan is handled by the outer app
            return
        request = Request(scope, receive)
        response = await self.dispatch(request)
        await response(scope, receive, send)

    async def dispatch(self, request: Request) -> Any:
        path = route_path(request.scope)
        if path in ("", "/"):
            # No auth challenge: SlowShield authenticates upstream itself.
            return JSONResponse({}, headers={**API, "Cache-Control": "no-store"})
        if request.method not in ("GET", "HEAD"):
            return oci_error(405, "UNSUPPORTED", "slowshield serves pulls only", headers={"Allow": "GET, HEAD"})
        req = R.parse(path, request.query_params.get("ns"))
        if req is None:
            return oci_error(404, "NAME_INVALID", "not a repository path this proxy serves")
        reg = self.registries.get(req.registry)
        if reg is None:
            return oci_error(
                403,
                "DENIED",
                f"slowshield: the registry {req.registry} is not configured on this proxy.",
                reason="registry_not_configured",
            )
        if req.kind == "manifests":
            return await self.manifest(request, reg, req)
        if req.kind == "blobs":
            return await self.blob(request, reg, req)
        return await self.listing(request, reg, req)

    # ---- state ---------------------------------------------------------------------------------------

    async def since(self) -> float:
        """When this instance started serving images: its tag history starts then."""
        if self._since is None:
            raw = self.ctx.db.meta("oci_since")
            if raw is None:
                now = self.ctx.clock.now()
                await self.ctx.db.writer.run(
                    lambda c: c.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('oci_since', ?)", (str(now),))
                )
                raw = self.ctx.db.meta("oci_since") or str(now)
            self._since = float(raw)
        return self._since

    async def fails_open(self) -> bool:
        cfg = self.ctx.cfg
        if not cfg.fail_open_for(ECO):
            return False
        return self.ctx.clock.now() - await self.since() < cfg.raw.default_delay_days * DAY

    def tag_rows(self, repo: str, tag: str) -> list[TagRow]:
        rows = self.ctx.db.readers.query(
            "SELECT digest, first_seen, registry_time FROM oci_tags WHERE repository = ? AND tag = ?", (repo, tag)
        )
        return [TagRow(r[0], float(r[1]), None if r[2] is None else float(r[2])) for r in rows]

    def digest_row(self, repo: str, digest: str) -> tuple[float, float | None, float | None, float | None] | None:
        """(first_seen, stored, gone, checked) of a manifest, if known."""
        row = self.ctx.db.readers.one(
            "SELECT first_seen, stored, gone, checked FROM oci_digests WHERE repository = ? AND digest = ?",
            (repo, digest),
        )
        return None if row is None else (float(row[0]), row[1], row[2], row[3])

    def delay(self, repo: str, digest: str, tag: str | None = None) -> float:
        return delay_days(self.ctx.cfg, repo, digest, tag)

    # ---- tags ----------------------------------------------------------------------------------------

    async def current(self, reg: Registry, req: R.Request) -> str | None:
        """The digest the tag points to upstream now (a HEAD, shared for TAG_TTL), or None if it doesn't exist."""
        key = ("oci:tag", req.repository, req.reference)
        now = self.ctx.clock.now()
        hit = self.ctx.metadata_cache.get(key, now)
        if hit is not None:
            return hit or None
        return await self.flight.run(key, lambda: self._load_current(reg, req, key))

    async def _load_current(self, reg: Registry, req: R.Request, key: tuple[str, ...]) -> str | None:
        ctx = self.ctx
        now = ctx.clock.now()
        skey = f"oci:tag:{req.repository}:{req.reference}"
        stored = await ctx.metadata_store.aget(skey)
        if stored is not None and stored.fresh(now):
            digest = stored.value.decode()
        else:
            ctx.recorder.lookup(ECO, cached=False)
            m = await self.client.manifest(reg, req.path, req.reference, head=True)
            digest = m.digest if m is not None else ""
            await ctx.metadata_store.aput(skey, digest.encode(), expires=now + TAG_TTL, keep_until=now + DAY)
        ctx.metadata_cache.put(key, digest, 256, now + TAG_TTL)
        return digest or None

    async def remember(self, reg: Registry, req: R.Request, current: str) -> None:
        """Record that the tag points to `current` (and, the first time, what the registry says about its history)."""
        repo, tag = req.repository, req.reference
        known = {r.digest: r for r in self.tag_rows(repo, tag)}
        now = self.ctx.clock.now()
        row = known.get(current)
        if row is not None and (
            row.registry_time is not None
            or reg.times == "none"
            or now - self._asked.get((repo, tag), 0.0) < HISTORY_RETRY
        ):
            return
        self._asked[(repo, tag)] = now
        history = await self.times.tag_history(reg, req.path, tag)
        if row is not None and not history:
            return
        rows: list[tuple[str, str, str, float, float | None, float]] = [(repo, tag, d, now, t, now) for d, t in history]
        if current not in {d for d, _ in history}:
            rows.append((repo, tag, current, now, None, now))

        def op(conn: Any) -> None:
            conn.executemany(
                "INSERT INTO oci_tags (repository, tag, digest, first_seen, registry_time, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (repository, tag, digest) DO UPDATE SET "
                "registry_time = coalesce(oci_tags.registry_time, excluded.registry_time), "
                "last_seen = excluded.last_seen",
                rows,
            )

        # Written before answering: the client's next request (by digest) may reach another worker.
        await self.ctx.db.writer.run(op)
        times = {r[2]: (r[4] if r[4] is not None else r[3]) for r in rows}
        self.ctx.recorder.catalog(ECO, repo, [(d, min(t, now), False) for d, t in times.items()])

    async def resolve(
        self, request: Request, reg: Registry, req: R.Request, blocks: PackageBlocks
    ) -> Resolved | Response:
        """The digest to serve for a tag: the newest one it pointed to that is old enough and not blocked."""
        ctx = self.ctx
        repo, tag = req.repository, req.reference
        now = ctx.clock.now()
        try:
            current = await self.current(reg, req)
        except UpstreamError as exc:
            if not self.tag_rows(repo, tag):
                ctx.recorder.decision(ECO, "metadata", "upstream_error")
                return self._unavailable(f"the registry {reg.name} is unavailable ({exc.detail})")
            current = None  # serve from history while the registry is down
        if current is not None:
            await self.remember(reg, req, current)
        rows = self.tag_rows(repo, tag)
        if not rows:
            ctx.recorder.decision(ECO, "metadata", "not_found")
            return oci_error(404, "MANIFEST_UNKNOWN", f"manifest unknown: {repo}:{tag}")
        gone = {
            d
            for (d,) in ctx.db.readers.query(
                "SELECT digest FROM oci_digests WHERE repository = ? AND gone IS NOT NULL", (repo,)
            )
        }
        blocked: dict[str, BlockEntry] = {}
        candidates: list[TagRow] = []
        for row in rows:
            entry = blocks.match(ECO, row.digest)
            if entry is not None:
                blocked[row.digest] = entry
            elif row.digest not in gone:
                candidates.append(row)
        ready = [c for c in candidates if is_old_enough(c.time, self.delay(repo, c.digest, tag), now)]
        if ready:
            chosen = max(ready, key=lambda c: c.time)
            held = sum(1 for c in candidates if c.time > chosen.time)
            return Resolved(chosen.digest, held, published=chosen.time)
        if not candidates:  # every digest the tag pointed to is blocked or was taken down
            if blocked:
                digest, entry = next(iter(blocked.items()))
                return self._blocked(request, repo, digest, entry, tag=tag)
            return self._taken_down(request, repo, current or rows[0].digest)
        latest = max(candidates, key=lambda c: c.time)
        if (latest.digest == current or current is None) and await self.fails_open():
            ctx.recorder.decision(ECO, "metadata", "fail_open")
            ctx.recorder.event(
                "fail_open",
                ECO,
                repo,
                latest.digest,
                client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
                details={"reason": "no_history_yet", "tag": tag},
            )
            return Resolved(latest.digest, fail_open=True, published=latest.time)
        return self._too_new(request, repo, latest.digest, latest.time, self.delay(repo, latest.digest, tag), tag=tag)

    # ---- digests -------------------------------------------------------------------------------------

    def tagged_time(self, repo: str, digest: str) -> float | None:
        """The earliest time any tag pointed to `digest`."""
        rows = self.ctx.db.readers.query(
            "SELECT first_seen, registry_time FROM oci_tags WHERE repository = ? AND digest = ?", (repo, digest)
        )
        times = [TagRow(digest, float(r[0]), None if r[1] is None else float(r[1])).time for r in rows]
        return min(times) if times else None

    async def published(self, reg: Registry, req: R.Request, digest: str) -> float:
        """When `digest` was published, as far as anyone can tell: the earliest of the times a tag pointed to it, its
        parent index's, the registry's own, and SlowShield's first sight."""
        repo = req.repository
        clocks = [self.tagged_time(repo, digest)]
        for (parent,) in self.ctx.db.readers.query(
            "SELECT parent FROM oci_children WHERE repository = ? AND child = ?", (repo, digest)
        ):
            clocks.append(self.tagged_time(repo, parent))
            info = self.digest_row(repo, parent)
            if info is not None:
                clocks.extend(info[:2])
        info = self.digest_row(repo, digest)
        if info is None:
            now = self.ctx.clock.now()
            stored = None if any(c is not None for c in clocks) else await self.times.digest_time(reg, req.path, digest)
            await self.ctx.db.writer.run(
                lambda c: c.execute(
                    "INSERT OR IGNORE INTO oci_digests (repository, digest, first_seen, stored) VALUES (?, ?, ?, ?)",
                    (repo, digest, now, stored),
                )
            )
            info = (now, stored, None, None)
        clocks.extend(info[:2])
        return min(float(c) for c in clocks if c is not None)

    async def judge(self, request: Request, reg: Registry, req: R.Request, digest: str) -> Resolved | Response:
        ctx = self.ctx
        repo = req.repository
        published = await self.published(reg, req, digest)
        if is_old_enough(published, self.delay(repo, digest), ctx.clock.now()):
            return Resolved(digest, published=published)
        if await self.fails_open() and self.tagged_time(repo, digest) is None:
            ctx.recorder.decision(ECO, "metadata", "fail_open")
            ctx.recorder.event(
                "fail_open",
                ECO,
                repo,
                digest,
                client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
                details={"reason": "no_history_yet"},
            )
            return Resolved(digest, fail_open=True, published=published)
        return self._too_new(request, repo, digest, published, self.delay(repo, digest))

    # ---- manifests -----------------------------------------------------------------------------------

    async def manifest(self, request: Request, reg: Registry, req: R.Request) -> Response:
        ctx = self.ctx
        repo = req.repository
        blocks = ctx.blocklist.for_package(ECO, repo)
        entry = blocks.package_block or blocks.match(ECO, req.reference)
        if entry is not None:
            digest, tag = (req.reference, None) if req.is_digest else (None, req.reference)
            return self._blocked(request, repo, digest, entry, tag=tag)
        if req.is_digest:
            verdict = await self.judge(request, reg, req, req.reference)
        else:
            verdict = await self.resolve(request, reg, req, blocks)
        if isinstance(verdict, Response):
            return verdict
        try:
            m = await self.body(reg, req, verdict.digest, head=request.method == "HEAD")
        except DigestMismatch as exc:
            ctx.recorder.decision(ECO, "metadata", "integrity_mismatch")
            ctx.recorder.event(
                "integrity_mismatch",
                ECO,
                repo,
                verdict.digest,
                client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
                details={"problems": [exc.detail]},
            )
            return self._unavailable(f"the registry sent a manifest that doesn't match its digest ({exc.detail})")
        except UpstreamError as exc:
            ctx.recorder.decision(ECO, "metadata", "upstream_error")
            return self._unavailable(f"the registry {reg.name} is unavailable ({exc.detail})")
        if m is None:
            ctx.recorder.decision(ECO, "metadata", "not_found")
            return oci_error(404, "MANIFEST_UNKNOWN", f"manifest unknown: {repo}@{verdict.digest}")
        if m is GONE:
            return self._taken_down(request, repo, verdict.digest)
        if not verdict.fail_open:
            ctx.recorder.decision(ECO, "metadata", "served")
        headers = {
            **API,
            "Docker-Content-Digest": m.digest,
            "ETag": f'"{m.digest}"',
            "Content-Length": str(m.size),
            "Cache-Control": "max-age=60" if not req.is_digest else "max-age=31536000, immutable",
            "X-SlowShield-Held-Versions": str(verdict.held),
        }
        if verdict.fail_open:
            headers["X-SlowShield-Fail-Open"] = "1"
        body = b"" if request.method == "HEAD" else m.body
        return Response(body, media_type=m.media_type, headers=headers)

    async def body(self, reg: Registry, req: R.Request, digest: str, *, head: bool) -> Manifest | None:
        """The manifest `digest`, from the shared store or the registry; GONE once the registry took it down."""
        ctx = self.ctx
        repo = req.repository
        now = ctx.clock.now()
        skey = f"oci:manifest:{repo}@{digest}"
        stored = await ctx.metadata_store.aget(skey)
        if stored is not None and stored.value:
            m = Manifest(digest, str(stored.meta.get("media_type") or ""), stored.value, len(stored.value))
            if await self._still_there(reg, req, digest, now) is False:
                return GONE
        else:
            fetched = await self.client.manifest(reg, req.path, digest, head=head)
            if fetched is None:
                return None
            m = fetched
            if m.body:
                await ctx.metadata_store.aput(
                    skey,
                    m.body,
                    expires=now + MANIFEST_TTL,
                    keep_until=now + MANIFEST_TTL,
                    meta={"media_type": m.media_type},
                )
            self._checked[(repo, digest)] = now
        await self._record_manifest(repo, m, now)
        return m

    async def _still_there(self, reg: Registry, req: R.Request, digest: str, now: float) -> bool | None:
        """Whether the registry still serves a stored manifest (asked at most every RECHECK seconds). None: unknown."""
        repo = req.repository
        if now - self._checked.get((repo, digest), 0.0) < RECHECK:
            return None
        info = self.digest_row(repo, digest)
        if info is not None and info[2] is not None:
            return False
        if info is not None and info[3] is not None and now - float(info[3]) < RECHECK:
            self._checked[(repo, digest)] = float(info[3])
            return None
        try:
            m = await self.client.manifest(reg, req.path, digest, head=True)
        except UpstreamError:
            return None  # the registry is down: keep serving
        self._checked[(repo, digest)] = now
        gone = now if m is None else None

        def op(conn: Any) -> None:
            conn.execute(
                "INSERT INTO oci_digests (repository, digest, first_seen, checked, gone) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT (repository, digest) DO UPDATE SET checked = excluded.checked, "
                "gone = coalesce(oci_digests.gone, excluded.gone)",
                (repo, digest, now, now, gone),
            )

        await self.ctx.db.writer.run(op)
        return m is not None

    async def _record_manifest(self, repo: str, m: Manifest, now: float) -> None:
        """Catalogue a manifest (its type, its children, whether it names a config) once per worker: a warm pull
        must not wait for the database writer. The worker that fetched it wrote this before answering."""
        if (repo, m.digest) in self._recorded:
            return
        if len(self._recorded) > RECORDED_MAX:
            self._recorded.clear()
        config = m.config()
        if config:  # a config is cached like a package file; layers are not (blob())
            await self.ctx.metadata_store.aput(f"oci:config:{config}", b"1", expires=now + MANIFEST_TTL)
        children = m.children()
        rows = [(repo, child, m.digest) for child in children]

        def op(conn: Any) -> None:
            conn.execute(
                "INSERT INTO oci_digests (repository, digest, media_type, first_seen) VALUES (?, ?, ?, ?) "
                "ON CONFLICT (repository, digest) DO UPDATE SET media_type = coalesce(oci_digests.media_type, "
                "excluded.media_type)",
                (repo, m.digest, m.media_type or None, now),
            )
            if rows:
                conn.executemany(
                    "INSERT OR IGNORE INTO oci_children (repository, child, parent) VALUES (?, ?, ?)", rows
                )

        # Written before answering: the client asks for the platform manifests next, maybe from another worker.
        await self.ctx.db.writer.run(op)
        self._recorded.add((repo, m.digest))

    # ---- blobs and listings ------------------------------------------------------------------------------

    async def blob(self, request: Request, reg: Registry, req: R.Request) -> AsgiResponse:
        ctx = self.ctx
        digest = req.reference
        try:
            headers = await self.client.auth(reg, req.path)
        except UpstreamError as exc:
            ctx.recorder.decision(ECO, "artifact", "upstream_error")
            return self._unavailable(f"the registry {reg.name} is unavailable ({exc.detail})")

        is_config = await ctx.metadata_store.aget(f"oci:config:{digest}") is not None

        def store(_size: int | None) -> str | None:
            if is_config:
                return "main"
            return "layers" if self.layer_store else None

        def hit_headers(_rec: ArtifactRecord) -> dict[str, str]:
            return {**API, "Docker-Content-Digest": digest}

        async def on_upstream(_up: Any) -> dict[str, str]:
            return {**API, "Docker-Content-Digest": digest}

        art = ArtifactRequest(
            ecosystem=ECO,
            key=f"/blobs/{digest}",
            package=req.repository,
            version=None,
            filename=digest,
            upstream_url=self.client.blob_url(reg, req.path, digest),
            expected=Expected(sha256=digest.removeprefix("sha256:")),
            content_type="application/octet-stream",
            error=blob_error,
            hit_headers=hit_headers,
            on_upstream=on_upstream,
            upstream_headers=headers,
            store=store,
        )
        return await ctx.artifacts.serve(
            art,
            method=request.method,
            headers_in=dict(request.headers),
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
        )

    async def listing(self, request: Request, reg: Registry, req: R.Request) -> Response:
        """`tags/list` and `referrers/<digest>`, passed through (the `Link` to the next page points back here)."""
        if req.kind == "tags":
            query = "&".join(f"{k}={v}" for k, v in request.query_params.items() if k in ("n", "last"))
            sub = "tags/list" + (f"?{query}" if query else "")
        else:
            query = "&".join(f"{k}={v}" for k, v in request.query_params.items() if k == "artifactType")
            sub = f"referrers/{req.reference}" + (f"?{query}" if query else "")
        try:
            res = await self.client.request(reg, req.path, sub, max_bytes=MAX_LISTING_BYTES)
        except UpstreamError as exc:
            return self._unavailable(f"the registry {reg.name} is unavailable ({exc.detail})")
        if res.status in (404, 410):
            code = "NAME_UNKNOWN" if req.kind == "tags" else "MANIFEST_UNKNOWN"
            return oci_error(404, code, f"{req.kind} unknown: {req.repository}")
        if res.status != 200:
            return self._unavailable(f"the registry {reg.name} returned {res.status}")
        headers = {**API, "Cache-Control": "max-age=60"}
        link = res.headers.get("link")
        if link:
            mine = request.url.path.rsplit("/tags/list", 1)[0].rsplit("/referrers/", 1)[0] + "/"
            headers["Link"] = link.replace(f"/v2/{req.path}/", mine)
        return Response(res.body, media_type=res.headers.get("content-type", "application/json"), headers=headers)

    # ---- refusals ----------------------------------------------------------------------------------------

    def _unavailable(self, detail: str) -> Response:
        return oci_error(
            503, "UNAVAILABLE", f"slowshield: {detail}", reason="upstream_error", headers={"Retry-After": "10"}
        )

    def _too_new(
        self, request: Request, repo: str, digest: str, published: float, delay: float, *, tag: str | None = None
    ) -> Response:
        ctx = self.ctx
        now = ctx.clock.now()
        wait = retry_after(published, delay, now)
        ctx.recorder.decision(ECO, "metadata", "age_gated")
        ctx.recorder.event(
            "age_gate",
            ECO,
            repo,
            digest,
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
            details={"tag": tag, "published": _iso(published), "delay_days": delay},
        )
        what = f"{repo}:{tag} ({_short(digest)})" if tag else f"{repo}@{_short(digest)}"
        msg = (
            f"slowshield: {what} is too new. It was pushed {_iso(published)} ({_ago(now - published)} ago); "
            f"this proxy requires {_days(delay)}. It becomes available at {_iso(published + delay * DAY)}. "
            "Use an older tag or digest, or ask your SlowShield administrator for an exception."
        )
        retry = wait if wait is not None else int(delay * DAY)
        return oci_error(403, "DENIED", msg, reason="too_new", headers={"Retry-After": str(max(retry, 1))})

    def _blocked(
        self, request: Request, repo: str, digest: str | None, entry: BlockEntry, *, tag: str | None
    ) -> Response:
        ctx = self.ctx
        ctx.recorder.decision(ECO, "metadata", "blocked")
        ctx.recorder.event(
            "blocked",
            ECO,
            repo,
            digest,
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
            details={**entry.as_json(), "tag": tag},
        )
        what = repo if entry.package_level or not digest else f"{repo}@{_short(digest)}"
        if tag and not entry.package_level and not digest:
            what = f"{repo}:{tag}"
        return oci_error(403, "DENIED", " ".join(entry.explain(what)), reason="blocked")

    def _taken_down(self, request: Request, repo: str, digest: str) -> Response:
        ctx = self.ctx
        ctx.recorder.decision(ECO, "metadata", "blocked")
        ctx.recorder.event(
            "blocked",
            ECO,
            repo,
            digest,
            client_ip=client_ip(request.scope, ctx.cfg.trusted_networks),
            details={"reason": "removed by the registry", "source": "registry"},
        )
        msg = f"slowshield: {repo}@{_short(digest)} was removed by the registry, so this proxy doesn't serve it either."
        return oci_error(403, "DENIED", msg, reason="taken_down")
