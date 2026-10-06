"""Serving artifacts (wheels, sdists, npm tarballs, Go modules): cache hit -> zero-copy file; miss -> verified stream.

On a miss the body is streamed to the client while being hashed and teed into the cache. The final
chunk is held back until every digest has been checked, so a client never receives a complete
tampered file: on mismatch the response is aborted mid-stream (the client sees a truncated body
against the announced Content-Length), the event is recorded and the temp file discarded.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from pathlib import Path

from starlette.responses import FileResponse, Response
from starlette.types import Receive, Scope, Send

from slowshield.cache.artifacts import ArtifactCache, TeeFile
from slowshield.clock import Clock
from slowshield.db import Database
from slowshield.integrity import Expected, StreamVerifier
from slowshield.legacy import LEGACY_DIGEST
from slowshield.recorder import Recorder
from slowshield.upstream import StreamResponse, Upstream, UpstreamError
from slowshield.web import error

log = logging.getLogger(__name__)

IMMUTABLE_CACHE_CONTROL = "public, max-age=86400"


class IntegrityAbort(Exception):
    """Raised inside a streaming body to abort the response without completing it.

    If nothing has been sent yet (small artifacts arrive in one chunk), `response` is sent instead
    so the client gets an explicit error rather than a reset connection.
    """

    def __init__(self, key: str, response: Response) -> None:
        super().__init__(key)
        self.response = response


@dataclass(slots=True)
class ArtifactRequest:
    ecosystem: str
    key: str  # stable artifact identity, e.g. "/packages/aa/bb/<hash>/f.whl" or "/pkg/-/pkg-1.0.0.tgz"
    package: str
    version: str | None
    filename: str
    upstream_url: str
    expected: Expected
    content_type: str = "application/octet-stream"
    # A check that needs the whole body (the Go zip `h1:` hashes the files inside the zip): called with the
    # spooled temp file before the final chunk is released; returns a problem description, or None.
    check_file: Callable[[Path], str | None] | None = None
    upstream_digest: str | None = None  # recorded when `expected` carries no sha256/sha512
    error: Callable[..., Response] = field(default=error)  # error responses, in the format the client reads
    # Called once the upstream response has arrived, before anything is sent: may fill `expected` from its headers
    # and URL, and returns a refusal (sent instead; nothing is streamed) or extra response headers.
    on_upstream: Callable[[StreamResponse], Awaitable[Response | dict[str, str] | None]] | None = None
    # Extra headers for a cache hit, from what was recorded on the first download.
    hit_headers: Callable[[ArtifactRecord], dict[str, str]] | None = None
    published: float | None = None  # when the registry stored the file, if known: recorded for later cache hits
    upstream_headers: dict[str, str] = field(default_factory=dict)  # e.g. a registry token (never sent to a CDN)
    # Which store keeps a verified body, from its Content-Length: "main" (the default), "layers" (the separate OCI
    # layer store), or None (streamed and checked, not stored).
    store: Callable[[int | None], str | None] | None = None


@dataclass(slots=True)
class ArtifactRecord:
    sha256: str | None
    size: int | None
    tampered: bool
    legacy: bool = False
    upstream_digest: str | None = None
    published: float | None = None


class StreamedArtifact:
    """Minimal ASGI response that guarantees cleanup (unlike a bare async generator)."""

    def __init__(
        self,
        status: int,
        headers: dict[str, str],
        body: AsyncIterator[bytes],
        on_close: Callable[[], Awaitable[None]],
    ) -> None:
        self.status = status
        self.headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()]
        self.body = body
        self.on_close = on_close

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        started = False
        try:
            try:
                async for chunk in self.body:
                    if not chunk:
                        # HTTP/2 upstreams (registry.npmjs.org) end with an empty DATA frame. Forwarding it as
                        # more_body=True after Content-Length is reached makes the server log a transport error.
                        continue
                    if not started:
                        await send({"type": "http.response.start", "status": self.status, "headers": self.headers})
                        started = True
                    await send({"type": "http.response.body", "body": bytes(chunk), "more_body": True})
            except IntegrityAbort as abort:
                if started:
                    raise  # mid-stream: abort the connection (the final chunk was withheld)
                await abort.response(scope, receive, send)
                return
            if not started:
                await send({"type": "http.response.start", "status": self.status, "headers": self.headers})
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        finally:
            aclose = getattr(self.body, "aclose", None)
            if aclose is not None:
                await aclose()
            await self.on_close()


AsgiResponse = Response | StreamedArtifact


def _tamper_response(req: ArtifactRequest) -> Response:
    return req.error(
        451,
        "tamper_detected",
        artifact=req.key,
        stored_sha256=req.expected.tofu_sha256,
        detail="this artifact changed upstream after it was first served; see the security events page",
    )


class ArtifactServer:
    def __init__(
        self,
        *,
        db: Database,
        cache: ArtifactCache,
        upstream: Upstream,
        recorder: Recorder,
        clock: Clock,
        layers: ArtifactCache | None = None,
    ) -> None:
        self.db = db
        self.cache = cache
        self.stores = {"main": cache, **({"layers": layers} if layers is not None else {})}
        self.upstream = upstream
        self.recorder = recorder
        self.clock = clock

    def record_for(self, ecosystem: str, key: str) -> ArtifactRecord | None:
        row = self.db.readers.one(
            "SELECT sha256, size, tampered, upstream_digest, published FROM artifacts WHERE ecosystem = ? AND path = ?",
            (ecosystem, key),
        )
        if row is None:
            return None
        return ArtifactRecord(
            row[0], row[1], bool(row[2]), legacy=row[3] == LEGACY_DIGEST, upstream_digest=row[3], published=row[4]
        )

    async def serve(
        self,
        req: ArtifactRequest,
        *,
        method: str,
        headers_in: dict[str, str],
        client_ip: str | None,
        size_hint: int | None = None,
    ) -> Response | StreamedArtifact:
        rec = self.record_for(req.ecosystem, req.key)
        if rec is not None and rec.tampered:
            self.recorder.decision(req.ecosystem, "artifact", "tampered")
            return req.error(
                451,
                "tamper_detected",
                artifact=req.key,
                stored_sha256=rec.sha256,
                detail="this artifact changed upstream after it was first served; see the security events page",
            )
        if rec is not None and rec.sha256:
            req.expected.tofu_sha256 = rec.sha256

        cached = None
        for store in self.stores.values():
            cached = store.lookup(rec.sha256 if rec else None)
            if cached is not None:
                break
        if cached is not None:
            self.recorder.decision(req.ecosystem, "artifact", "served")
            if method != "HEAD":
                self.recorder.download(req.ecosystem, req.package, req.version, cached.size, cache_hit=True)
            extra = req.hit_headers(rec) if req.hit_headers is not None and rec is not None else {}
            return FileResponse(
                cached.path,
                media_type=cached.content_type or req.content_type,
                headers={
                    "Cache-Control": IMMUTABLE_CACHE_CONTROL,
                    "ETag": f'"{cached.sha256}"',
                    "X-SlowShield-Cache": "hit",
                    **extra,
                },
                filename=None,
                stat_result=None,
            )

        if method == "HEAD":
            size = size_hint or (rec.size if rec else None)
            h = {
                "Content-Type": req.content_type,
                "Cache-Control": IMMUTABLE_CACHE_CONTROL,
                "X-SlowShield-Cache": "miss",
            }
            if size is not None:
                h["Content-Length"] = str(size)
            return Response(status_code=200, headers=h)

        stack = AsyncExitStack()
        try:
            up: StreamResponse = await stack.enter_async_context(
                self.upstream.stream(req.upstream_url, headers=req.upstream_headers)
            )
        except UpstreamError as exc:
            await stack.aclose()
            self.recorder.decision(req.ecosystem, "artifact", "upstream_error")
            return req.error(502, "upstream_error", detail=exc.detail)
        if up.status in (404, 410):
            await stack.aclose()
            self.recorder.decision(req.ecosystem, "artifact", "not_found")
            return req.error(404, "not_found")
        if not 200 <= up.status < 300:
            await stack.aclose()
            self.recorder.decision(req.ecosystem, "artifact", "upstream_error")
            return req.error(502, "upstream_error", detail=f"upstream returned {up.status}")

        extra: dict[str, str] = {}
        if req.on_upstream is not None:
            try:
                verdict = await req.on_upstream(up)
            except BaseException:
                await stack.aclose()
                raise
            if isinstance(verdict, Response):
                await stack.aclose()
                return verdict
            extra = verdict or {}
        size = req.expected.size or up.content_length
        if req.expected.size is None and up.content_length is not None:
            req.expected.size = up.content_length
        content_type = req.content_type
        out_headers = {
            "Content-Type": content_type,
            "Cache-Control": IMMUTABLE_CACHE_CONTROL,
            "X-SlowShield-Cache": "miss",
            **extra,
        }
        if size is not None:
            out_headers["Content-Length"] = str(size)
        verifier = StreamVerifier(req.expected)
        store = req.store(size) if req.store is not None else "main"
        target = self.stores.get(store) if store else None
        tee = target.open_tee() if target is not None else None
        state = {"verified": False, "delivered": False}

        async def body() -> AsyncIterator[bytes]:
            pending: bytes | None = None
            async for chunk in up.chunks():
                verifier.update(chunk)
                if tee is not None:
                    tee.write(chunk)
                if pending is not None:
                    yield pending
                pending = chunk
            problems = verifier.problems()
            if req.check_file is not None and tee is not None and not problems:
                problem = await asyncio.to_thread(req.check_file, tee.path)
                if problem:
                    problems.append(problem)
            if verifier.tofu_mismatch():
                independently_verified = not problems and bool(
                    req.expected.sha256 or req.expected.sha512 or req.expected.blake2b_256
                )
                if rec is not None and rec.legacy and independently_verified:
                    # Imported fingerprint from the Rust version may be an error page's hash.
                    await self._correct_legacy(req, verifier)
                else:
                    await self._tamper(req, verifier, client_ip, problems)
                    raise IntegrityAbort(req.key, _tamper_response(req))
            if problems:
                await self._integrity_mismatch(req, verifier, client_ip, problems)
                raise IntegrityAbort(
                    req.key,
                    req.error(502, "integrity_mismatch", artifact=req.key, detail="; ".join(problems)),
                )
            stored = await self._remember(req, verifier)
            if stored is not None and stored != verifier.sha256:
                # Someone else stored different bytes for the same artifact a moment ago.
                req.expected.tofu_sha256 = stored
                await self._tamper(req, verifier, client_ip, ["concurrent first fetch saw different bytes"])
                raise IntegrityAbort(req.key, _tamper_response(req))
            state["verified"] = True
            if pending is not None:
                yield pending
            state["delivered"] = True

        started = time.perf_counter()

        async def on_close() -> None:
            await stack.aclose()
            await self._finish(
                req,
                tee,
                verifier,
                content_type,
                verified=state["verified"],
                delivered=state["delivered"],
                target=target,
            )
            log.debug(
                "artifact streamed",
                extra={"artifact": req.key, "bytes": verifier.size, "seconds": round(time.perf_counter() - started, 3)},
            )

        return StreamedArtifact(200, out_headers, body(), on_close)

    async def _finish(
        self,
        req: ArtifactRequest,
        tee: TeeFile | None,
        verifier: StreamVerifier,
        content_type: str,
        *,
        verified: bool,
        delivered: bool,
        target: ArtifactCache | None = None,
    ) -> None:
        """Verified bytes are cached even if the client went away; only delivered ones count as served."""
        if not verified:
            if tee is not None:
                tee.abort()
            return
        if delivered:
            self.recorder.decision(req.ecosystem, "artifact", "served")
            self.recorder.download(req.ecosystem, req.package, req.version, verifier.size, cache_hit=False)
        if tee is not None:
            await (target or self.cache).commit(tee, verifier.sha256, content_type)

    async def _remember(self, req: ArtifactRequest, verifier: StreamVerifier) -> str | None:
        """Insert-or-keep the TOFU digest; returns the digest now on record."""
        now = self.clock.now()
        sha = verifier.sha256
        e = req.expected
        digest = e.sha256 or (e.sha512.hex() if e.sha512 else None) or req.upstream_digest

        def op(conn):  # type: ignore[no-untyped-def]
            conn.execute(
                "INSERT INTO artifacts (ecosystem, path, package, version, filename, sha256, upstream_digest, size, "
                "first_seen, last_seen, published) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (ecosystem, path) DO UPDATE SET last_seen = excluded.last_seen, "
                "sha256 = coalesce(artifacts.sha256, excluded.sha256), size = coalesce(artifacts.size, excluded.size), "
                "upstream_digest = coalesce(artifacts.upstream_digest, excluded.upstream_digest), "
                "published = coalesce(artifacts.published, excluded.published)",
                (
                    req.ecosystem,
                    req.key,
                    req.package,
                    req.version,
                    req.filename,
                    sha,
                    digest,
                    verifier.size,
                    now,
                    now,
                    req.published,
                ),
            )
            row = conn.execute(
                "SELECT sha256 FROM artifacts WHERE ecosystem = ? AND path = ?", (req.ecosystem, req.key)
            ).fetchone()
            return row[0] if row else None

        return await self.db.writer.run(op)

    async def _correct_legacy(self, req: ArtifactRequest, verifier: StreamVerifier) -> None:
        log.warning(
            "replacing imported legacy checksum that disagrees with the registry digest",
            extra={"artifact": req.key, "legacy_sha256": req.expected.tofu_sha256, "sha256": verifier.sha256},
        )
        sha = verifier.sha256
        e = req.expected
        digest = e.sha256 or (e.sha512.hex() if e.sha512 else None) or req.upstream_digest

        def op(conn):  # type: ignore[no-untyped-def]
            conn.execute(
                "UPDATE artifacts SET sha256 = ?, upstream_digest = ?, size = ? WHERE ecosystem = ? AND path = ?",
                (sha, digest, verifier.size, req.ecosystem, req.key),
            )

        await self.db.writer.run(op)
        req.expected.tofu_sha256 = sha

    async def _tamper(
        self, req: ArtifactRequest, verifier: StreamVerifier, client_ip: str | None, problems: list[str]
    ) -> None:
        stored = req.expected.tofu_sha256

        def op(conn):  # type: ignore[no-untyped-def]
            conn.execute(
                "UPDATE artifacts SET tampered = 1, last_seen = ? WHERE ecosystem = ? AND path = ?",
                (self.clock.now(), req.ecosystem, req.key),
            )

        await self.db.writer.run(op)
        self.recorder.decision(req.ecosystem, "artifact", "tampered")
        self.recorder.event(
            "tampered",
            req.ecosystem,
            req.package,
            req.version,
            client_ip=client_ip,
            details={
                "artifact": req.key,
                "stored_sha256": stored,
                "observed_sha256": verifier.sha256,
                "problems": problems,
            },
        )

    async def _integrity_mismatch(
        self, req: ArtifactRequest, verifier: StreamVerifier, client_ip: str | None, problems: list[str]
    ) -> None:
        self.recorder.decision(req.ecosystem, "artifact", "integrity_mismatch")
        self.recorder.event(
            "integrity_mismatch",
            req.ecosystem,
            req.package,
            req.version,
            client_ip=client_ip,
            details={"artifact": req.key, "observed_sha256": verifier.sha256, "problems": problems},
        )
