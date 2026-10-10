"""Package files through the leader (`shieldwall.via_leader`): a follower's cache miss asks its leader first, so the
wall downloads each file from the registry once and the leader's cache serves the rest.

Only files with a content address go this way (a sha256 from the index or from this instance's first download,
or npm's sha512), and only requests that need no credentials and no registry headers. Metadata never does:
evidence comes from the registry directly. The follower checks every byte as if it came from the registry; bytes
that don't match are an integrity failure of the leader, never a tamper flag on the file. When the leader can't
answer, the request goes to the registry and the leader is skipped for a minute.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from urllib.parse import quote, urlencode

from slowshield.clock import Clock
from slowshield.shieldwall import signing
from slowshield.shieldwall.identity import Identity
from slowshield.shieldwall.transport import Transport, TransportError

log = logging.getLogger(__name__)

PATH = "/_shieldwall/v1/blob"
PAUSE = 60.0  # seconds the leader is skipped after it failed to answer


class LeaderStream:
    """What `ArtifactServer` reads from an upstream response, served by the leader."""

    def __init__(self, status: int, headers: dict[str, str], chunks: AsyncIterator[bytes], url: str) -> None:
        self.status = status
        self.headers = headers
        self.url = url
        self.http_version = "leader"
        self._chunks = chunks

    @property
    def content_length(self) -> int | None:
        raw = self.headers.get("content-length")
        return int(raw) if raw and raw.isdigit() else None

    def chunks(self) -> AsyncIterator[bytes]:
        return self._chunks


class ViaLeader:
    def __init__(self, identity: Identity, leader_url: str, transport: Transport, clock: Clock) -> None:
        self.identity = identity
        self.base = leader_url.rstrip("/")
        self.transport = transport
        self.clock = clock
        self.active = False  # paired and confirmed (refreshed from the database by every worker)
        self._paused_until = 0.0

    def usable(self) -> bool:
        return self.active and time.monotonic() >= self._paused_until

    def pause(self, reason: str) -> None:
        if time.monotonic() >= self._paused_until:
            log.warning("fetching through the leader failed: going to the registry", extra={"error": reason})
        self._paused_until = time.monotonic() + PAUSE

    @asynccontextmanager
    async def stream(self, url: str, *, sha256: str | None, sha512: str | None) -> AsyncIterator[LeaderStream]:
        """The file at `url`, from the leader. Raises TransportError when the leader can't serve it."""
        params = {"url": url, **({"sha256": sha256} if sha256 else {}), **({"sha512": sha512} if sha512 else {})}
        query = urlencode(params, quote_via=quote, safe="")
        headers = signing.sign_request(self.identity, "GET", PATH, query, b"", now=self.clock.now())
        async with self.transport.stream(f"{self.base}{PATH}?{query}", headers) as (status, hdrs, chunks):
            if status != 200:
                raise TransportError(f"the leader answered {status}")

            async def guarded() -> AsyncIterator[bytes]:
                try:
                    async for chunk in chunks:
                        yield chunk
                except Exception as exc:
                    self.pause(f"broke off mid-file: {type(exc).__name__}")
                    raise

            yield LeaderStream(status, hdrs, guarded(), url)
