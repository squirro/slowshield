"""HTTP between a follower and its leader: one small client, only ever pointed at the configured leader URL.

Swappable for tests (`Send`): the integration tests run a leader app in-process and hand the follower a sender that
calls it directly.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from pyreqwest.client import Client, ClientBuilder
from pyreqwest.exceptions import PyreqwestError

log = logging.getLogger(__name__)

MAX_RESPONSE = 32 << 20  # a sync response, a snapshot page


class TransportError(Exception):
    pass


@dataclass(slots=True)
class Reply:
    status: int
    headers: dict[str, str]  # lower-case names
    body: bytes


Send = Callable[[str, str, dict[str, str], bytes, float], Awaitable[Reply]]
Stream = Callable[[str, dict[str, str]], "AsyncIterator[tuple[int, dict[str, str], AsyncIterator[bytes]]]"]


class Transport:
    """Requests to the leader. `timeout` is the whole exchange (a long poll waits up to 25 s)."""

    def __init__(self, user_agent: str, ca_file: str | None = None) -> None:
        builder = (
            ClientBuilder()
            .user_agent(user_agent)
            .http2(True)
            .follow_redirects(False)
            .connect_timeout(timedelta(seconds=3))
            .pool_idle_timeout(timedelta(seconds=90))
            .gzip(True)
        )
        pem = Path(ca_file).read_bytes() if ca_file else b""
        if pem.strip():  # an empty file (the Compose placeholder) adds nothing
            builder = builder.add_root_certificate_pem(pem)
        self.client: Client = builder.build()

    async def close(self) -> None:
        try:
            await self.client.close()
        except Exception:  # pragma: no cover
            log.debug("closing the shield wall client failed", exc_info=True)

    async def send(self, method: str, url: str, headers: dict[str, str], body: bytes, limit: float) -> Reply:
        """`limit`: seconds for the whole exchange."""
        try:
            builder = self.client.request(method, url).headers(headers).timeout(timedelta(seconds=limit))
            if body:
                builder = builder.body_bytes(body)
            async with builder.build_streamed() as resp:
                data = bytearray()
                reader = resp.body_reader
                while (chunk := await reader.read_chunk()) is not None:
                    data += chunk
                    if len(data) > MAX_RESPONSE:
                        raise TransportError(f"{url}: response too large")
                return Reply(resp.status, {k.lower(): v for k, v in resp.headers.items()}, bytes(data))
        except PyreqwestError as exc:
            raise TransportError(f"{url}: {type(exc).__name__}") from exc

    @asynccontextmanager
    async def stream(
        self, url: str, headers: dict[str, str], *, header_timeout: float = 5.0
    ) -> AsyncIterator[tuple[int, dict[str, str], AsyncIterator[bytes]]]:
        """A streamed GET (package files via the leader). Fails fast: the caller falls back to the registry."""
        try:
            req = self.client.get(url).headers(headers).timeout(timedelta(minutes=30)).build_streamed()
            async with req as resp:

                async def chunks() -> AsyncIterator[bytes]:
                    reader = resp.body_reader
                    while (chunk := await reader.read_chunk()) is not None:
                        yield bytes(chunk)

                yield resp.status, {k.lower(): v for k, v in resp.headers.items()}, chunks()
        except PyreqwestError as exc:
            raise TransportError(f"{url}: {type(exc).__name__}") from exc
