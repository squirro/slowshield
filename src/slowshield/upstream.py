"""Upstream HTTP access (pyreqwest: Rust reqwest/hyper, HTTP/2).

Two clients: one for metadata (transparent gzip/br/zstd, bounded body size) and one for artifacts
(identity encoding so we hash exactly the bytes the registry serves). Redirects are never followed
automatically; they are only followed within the configured upstream hosts (exact names, or `*` patterns for
CDNs such as `*.data.mcr.microsoft.com`), so this can never be turned into an open proxy. A redirect to another
host never carries the `Authorization` header: registry tokens stay with the registry.
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import time
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import urljoin, urlsplit

from opentelemetry.trace import SpanKind, Status, StatusCode
from pyreqwest.client import Client, ClientBuilder
from pyreqwest.exceptions import PyreqwestError

from slowshield.telemetry import instruments

log = logging.getLogger(__name__)

_REDIRECTS = {301, 302, 303, 307, 308}
_CREDENTIALS = frozenset({"authorization", "cookie"})


def redirected(url: str, location: str, headers: dict[str, str]) -> tuple[str, dict[str, str]]:
    """The redirect target, and the headers to send there: without credentials once the host changes."""
    target = urljoin(url, location)
    if (urlsplit(target).hostname or "").lower() != (urlsplit(url).hostname or "").lower():
        headers = {k: v for k, v in headers.items() if k.lower() not in _CREDENTIALS}
    return target, headers


class UpstreamError(Exception):
    def __init__(self, url: str, detail: str, status: int | None = None) -> None:
        super().__init__(f"{detail} ({url})")
        self.url = url
        self.detail = detail
        self.status = status


class TooLargeError(UpstreamError):
    pass


@dataclass(slots=True)
class FetchResult:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str
    http_version: str

    @property
    def etag(self) -> str | None:
        return self.headers.get("etag")


def _headers(resp: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in resp.headers.items():
        k = key.lower()
        if k not in out:
            out[k] = value
    return out


class StreamResponse:
    """Thin wrapper over a streamed pyreqwest response."""

    def __init__(self, resp: Any, url: str) -> None:
        self._resp = resp
        self.status: int = resp.status
        self.headers = _headers(resp)
        self.url = url
        self.http_version: str = resp.version

    @property
    def content_length(self) -> int | None:
        raw = self.headers.get("content-length")
        return int(raw) if raw and raw.isdigit() else None

    async def chunks(self) -> AsyncIterator[bytes]:
        reader = self._resp.body_reader
        while True:
            chunk = await reader.read_chunk()
            if chunk is None:
                return
            yield chunk


class Upstream:
    def __init__(
        self,
        *,
        user_agent: str,
        allowed_hosts: Iterable[str],
        connect_timeout: float = 5.0,
        read_timeout: float = 30.0,
        metadata_timeout: float = 60.0,
    ) -> None:
        hosts = {h.lower() for h in allowed_hosts}
        self.allowed_hosts = {h for h in hosts if "*" not in h}
        self.allowed_patterns = tuple(sorted(h for h in hosts if "*" in h))
        self._metadata_timeout = timedelta(seconds=metadata_timeout)

        def base() -> ClientBuilder:
            return (
                ClientBuilder()
                .user_agent(user_agent)
                .http2(True)
                .follow_redirects(False)
                .connect_timeout(timedelta(seconds=connect_timeout))
                .read_timeout(timedelta(seconds=read_timeout))
                .pool_idle_timeout(timedelta(seconds=90))
                .pool_max_idle_per_host(32)
                .tcp_nodelay(True)
                .https_only(False)
            )

        self.meta: Client = base().gzip(True).brotli(True).zstd(True).deflate(True).build()
        self.raw: Client = base().gzip(False).brotli(False).zstd(False).deflate(False).build()

    async def close(self) -> None:
        for c in (self.meta, self.raw):
            try:
                await c.close()
            except Exception:  # pragma: no cover
                log.debug("closing upstream client failed", exc_info=True)

    def _allowed(self, url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        return host in self.allowed_hosts or any(fnmatch.fnmatchcase(host, p) for p in self.allowed_patterns)

    async def fetch(
        self,
        urls: str | list[str],
        *,
        headers: dict[str, str] | None = None,
        max_bytes: int,
        kind: str = "metadata",
        attempts_per_mirror: int = 2,
        method: str = "GET",
    ) -> FetchResult:
        """GET (or HEAD, with an empty body) with mirror failover. 2xx/304/404/410 are returned; other outcomes
        try the next mirror."""
        candidates = [urls] if isinstance(urls, str) else list(urls)
        last: UpstreamError | None = None
        for url in candidates:
            for attempt in range(attempts_per_mirror):
                try:
                    res = await self._get_once(url, headers or {}, max_bytes, kind, method)
                except TooLargeError:
                    raise
                except UpstreamError as exc:
                    last = exc
                    if attempt + 1 < attempts_per_mirror:
                        await asyncio.sleep(0.2 * (attempt + 1))
                    continue
                if res.status < 500 and res.status != 429:
                    return res
                last = UpstreamError(url, f"upstream returned {res.status}", res.status)
                if attempt + 1 < attempts_per_mirror:
                    await asyncio.sleep(0.2 * (attempt + 1))
        raise last or UpstreamError(",".join(candidates), "no upstream configured")

    async def _get_once(
        self, url: str, headers: dict[str, str], max_bytes: int, kind: str, method: str = "GET"
    ) -> FetchResult:
        for _hop in range(4):
            if not self._allowed(url):
                raise UpstreamError(url, "redirect to a host that is not a configured upstream")
            started = time.perf_counter()
            host = urlsplit(url).hostname or ""
            status_code = 0
            with instruments.tracer.start_as_current_span(
                method, kind=SpanKind.CLIENT, attributes={"url.full": url, "server.address": host}
            ) as span:
                try:
                    builder = self.meta.head(url) if method == "HEAD" else self.meta.get(url)
                    req = builder.headers(headers).timeout(self._metadata_timeout).build_streamed()
                    async with req as resp:
                        status_code = resp.status
                        hdrs = _headers(resp)
                        if status_code in _REDIRECTS and "location" in hdrs:
                            url, headers = redirected(url, hdrs["location"], headers)
                            continue
                        body = b"" if method == "HEAD" else await _read_limited(resp, max_bytes, url)
                        span.set_attribute("http.response.status_code", status_code)
                        span.set_attribute("network.protocol.version", resp.version)
                        if status_code >= 500:
                            span.set_status(Status(StatusCode.ERROR))
                        return FetchResult(status_code, hdrs, body, url, resp.version)
                except PyreqwestError as exc:
                    span.record_exception(exc)
                    span.set_status(Status(StatusCode.ERROR, type(exc).__name__))
                    raise UpstreamError(url, type(exc).__name__) from exc
                finally:
                    instruments.http_client_duration.record(
                        time.perf_counter() - started,
                        {
                            "server.address": host,
                            "http.request.method": method,
                            "http.response.status_code": status_code,
                            "slowshield.kind": kind,
                        },
                    )
        raise UpstreamError(url, "too many redirects")

    @asynccontextmanager
    async def stream(self, url: str, *, headers: dict[str, str] | None = None) -> AsyncIterator[StreamResponse]:
        """Streamed artifact GET (no decompression). Caller must check `.status`."""
        headers = dict(headers or {})
        for _hop in range(4):
            if not self._allowed(url):
                raise UpstreamError(url, "redirect to a host that is not a configured upstream")
            started = time.perf_counter()
            host = urlsplit(url).hostname or ""
            status_code = 0
            span_cm = instruments.tracer.start_as_current_span(
                "GET", kind=SpanKind.CLIENT, attributes={"url.full": url, "server.address": host}
            )
            span = span_cm.__enter__()
            try:
                try:
                    req = self.raw.get(url).headers(headers).build_streamed()
                    cm = req
                    resp = await cm.__aenter__()
                except PyreqwestError as exc:
                    span.record_exception(exc)
                    span.set_status(Status(StatusCode.ERROR, type(exc).__name__))
                    raise UpstreamError(url, type(exc).__name__) from exc
                try:
                    status_code = resp.status
                    span.set_attribute("http.response.status_code", status_code)
                    hdrs = _headers(resp)
                    if status_code in _REDIRECTS and "location" in hdrs:
                        url, headers = redirected(url, hdrs["location"], headers)
                        continue
                    try:
                        yield StreamResponse(resp, url)
                    except PyreqwestError as exc:
                        span.record_exception(exc)
                        span.set_status(Status(StatusCode.ERROR, type(exc).__name__))
                        raise UpstreamError(url, type(exc).__name__) from exc
                    return
                finally:
                    await cm.__aexit__(None, None, None)
            finally:
                instruments.http_client_duration.record(
                    time.perf_counter() - started,
                    {
                        "server.address": host,
                        "http.request.method": "GET",
                        "http.response.status_code": status_code,
                        "slowshield.kind": "artifact",
                    },
                )
                span_cm.__exit__(None, None, None)
        raise UpstreamError(url, "too many redirects")

    async def post(
        self, url: str, body: bytes, *, headers: dict[str, str] | None = None, max_bytes: int
    ) -> FetchResult:
        if not self._allowed(url):
            raise UpstreamError(url, "not a configured upstream")
        try:
            req = self.meta.post(url).headers(headers or {}).body_bytes(body).build_streamed()
            async with req as resp:
                data = await _read_limited(resp, max_bytes, url)
                return FetchResult(resp.status, _headers(resp), data, url, resp.version)
        except PyreqwestError as exc:
            raise UpstreamError(url, type(exc).__name__) from exc


async def _read_limited(resp: Any, max_bytes: int, url: str) -> bytes:
    parts: list[Any] = []
    total = 0
    reader = resp.body_reader
    while True:
        chunk = await reader.read_chunk()
        if chunk is None:
            break
        total += len(chunk)
        if total > max_bytes:
            raise TooLargeError(url, f"response exceeds {max_bytes} bytes")
        parts.append(chunk)
    return b"".join(parts)
