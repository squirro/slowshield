"""The compact index `/versions` file: a copy of rubygems.org's, with every info checksum written as zeros.

`/versions` names every gem (`<name> <versions> <md5 of /info/<name>>`), about 24 MB. Bundler reads it to learn
which gems exist and uses the md5 only to decide whether to ask for `info/<name>` again. SlowShield serves filtered
info files, so it can't pass rubygems.org's md5s on: a Bundler cache filled from rubygems.org has files with exactly
those MD5s and would be used instead of asking SlowShield. Zeros never match a file, so Bundler always asks (with
`If-None-Match`). The column has a fixed width, so the served file is as long as rubygems.org's and stays
append-only between its monthly rebuilds: clients keep appending with `Range` requests (docs/design/rubygems.md).

The copy lives in `<data_dir>/rubygems/`: the upstream bytes (to check rubygems.org's `Repr-Digest` after an
append), the served bytes, and `state.json` with their size and digests. One worker updates it at a time (an
`flock`), at most once a minute; every worker serves it. A rebuild is written as a new generation of files, so a
response that is being sent keeps reading the file it started with.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import fcntl
import hashlib
import json
import logging
import os
import re
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

from slowshield.upstream import Upstream, UpstreamError

log = logging.getLogger(__name__)

MAX_VERSIONS_BYTES = 256 << 20
REFRESH_EVERY = 60.0  # rubygems.org's max-age for /versions
ZEROS = b"0" * 32
_MD5_COLUMN = re.compile(rb" [0-9a-f]{32}\n")
_CONTENT_RANGE = re.compile(r"^bytes (\d+)-(\d+)/(\d+|\*)$")
CHUNK = 1 << 20


def zero_checksums(data: bytes) -> bytes:
    """`data` with the md5 at the end of every complete line replaced by zeros. Line by line, so the result for a
    file is the result for its first part followed by the result for the rest, when the parts split at a line end."""
    return _MD5_COLUMN.sub(b" " + ZEROS + b"\n", data)


def complete_lines(data: bytes) -> bytes:
    """`data` up to its last line end: a line still being written is taken on the next update."""
    return data[: data.rfind(b"\n") + 1]


def sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def parse_digest(headers: dict[str, str]) -> str | None:
    """The base64 sha-256 from `Repr-Digest` or `Digest`, in RFC 9530 (`sha-256=:…:`) or rubygems.org's quoted form."""
    for name in ("repr-digest", "digest"):
        for part in headers.get(name, "").split(","):
            algo, _, value = part.strip().partition("=")
            if algo.strip().lower() == "sha-256" and value:
                return value.strip().strip(":").strip('"')
    return None


@dataclasses.dataclass(frozen=True, slots=True)
class Snapshot:
    """One state of the served file: its generation, size and digests."""

    generation: int
    size: int
    md5: str  # hex, the ETag
    sha256: str  # base64, the Repr-Digest
    upstream_etag: str | None
    upstream_sha256: str  # base64, of the upstream bytes
    checked: float  # when rubygems.org was last asked

    @property
    def etag(self) -> str:
        return f'"{self.md5}"'

    @property
    def repr_digest(self) -> str:
        return f"sha-256=:{self.sha256}:"


class VersionsFile:
    def __init__(self, directory: Path, upstream: Upstream, url: str, now: Callable[[], float]) -> None:
        self.dir = directory
        self.upstream = upstream
        self.url = url
        self.now = now
        self._lock = asyncio.Lock()

    # ---- files -------------------------------------------------------------------------------------------------

    def _path(self, kind: str, generation: int) -> Path:
        return self.dir / f"{kind}.{generation}"

    def _read_state(self) -> Snapshot | None:
        try:
            d = json.loads((self.dir / "state.json").read_bytes())
            snap = Snapshot(**d)
        except OSError, ValueError, TypeError:
            return None
        return snap if self._path("served", snap.generation).exists() else None

    def _write_state(self, snap: Snapshot) -> None:
        tmp = self.dir / f"state.json.{os.getpid()}.tmp"
        tmp.write_text(json.dumps(dataclasses.asdict(snap)))
        tmp.replace(self.dir / "state.json")

    @contextlib.contextmanager
    def _file_lock(self, blocking: bool) -> Any:
        self.dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.dir / "lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            except BlockingIOError:
                yield False
                return
            try:
                yield True
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    # ---- reading -----------------------------------------------------------------------------------------------

    async def snapshot(self) -> Snapshot:
        """The current copy, updated from rubygems.org first when it is more than a minute old. While rubygems.org
        can't be reached, the last copy; without one, UpstreamError."""
        snap = await asyncio.to_thread(self._read_state)
        if snap is not None and self.now() - snap.checked < REFRESH_EVERY:
            return snap
        async with self._lock:
            snap = await asyncio.to_thread(self._read_state)
            if snap is not None and self.now() - snap.checked < REFRESH_EVERY:
                return snap
            try:
                return await self._refresh(snap)
            except UpstreamError as exc:
                if snap is None:
                    raise
                log.warning("rubygems.org /versions unavailable; serving the last copy", extra={"error": exc.detail})
                return snap

    async def _refresh(self, snap: Snapshot | None) -> Snapshot:
        lock = self._file_lock(blocking=snap is None)
        got = await asyncio.to_thread(lock.__enter__)
        try:
            if not got and snap is not None:  # another worker is updating: serve what there is
                return snap
            current = await asyncio.to_thread(self._read_state)
            if current is not None and self.now() - current.checked < REFRESH_EVERY:
                return current
            if current is not None:
                appended = await self._append(current)
                if appended is not None:
                    return appended
            return await self._replace()
        finally:
            await asyncio.to_thread(lock.__exit__, None, None, None)

    async def _append(self, snap: Snapshot) -> Snapshot | None:
        """Ask for the bytes after the copy. None when the whole file has to be fetched again."""
        headers = {"Range": f"bytes={snap.size - 1}-", "Accept-Encoding": "identity"}
        if snap.upstream_etag:
            headers["If-None-Match"] = snap.upstream_etag
        res = await self.upstream.fetch(self.url, headers=headers, max_bytes=MAX_VERSIONS_BYTES)
        if res.status == 304:
            new = dataclasses.replace(snap, checked=self.now())
            await asyncio.to_thread(self._write_state, new)
            return new
        if res.status != 206:
            if res.status == 200:
                return await self._store_full(res.body, res.headers)
            if res.status == 416:
                return None
            raise UpstreamError(res.url, f"upstream returned {res.status}", res.status)
        m = _CONTENT_RANGE.match(res.headers.get("content-range", ""))
        if m is None or int(m.group(1)) != snap.size - 1 or not res.body:
            return None
        return await asyncio.to_thread(self._write_append, snap, res.body, res.headers)

    def _write_append(self, snap: Snapshot, body: bytes, headers: dict[str, str]) -> Snapshot | None:
        up_path, served_path = self._path("upstream", snap.generation), self._path("served", snap.generation)
        upstream = up_path.read_bytes()[: snap.size]
        if len(upstream) != snap.size or upstream[-1:] != body[:1]:
            return None  # rebuilt upstream: the byte before the new ones is not the one the copy ends with
        tail = complete_lines(body[1:])
        full = upstream + tail
        expected = parse_digest(headers)
        if expected is not None and len(tail) == len(body) - 1 and expected != sha256_b64(full):
            log.info("rubygems.org /versions changed beyond an append; fetching it whole")
            return None
        served_tail = zero_checksums(tail)
        # A crash between the writes leaves files longer than the state says: cut them back before appending.
        for path, data in ((up_path, tail), (served_path, served_tail)):
            with path.open("r+b") as f:
                f.truncate(snap.size)
                f.seek(snap.size)
                f.write(data)
        served = served_path.read_bytes()[: len(full)]
        new = Snapshot(
            generation=snap.generation,
            size=len(full),
            md5=hashlib.md5(served, usedforsecurity=False).hexdigest(),
            sha256=sha256_b64(served),
            upstream_etag=headers.get("etag") if len(tail) == len(body) - 1 else None,
            upstream_sha256=sha256_b64(full),
            checked=self.now(),
        )
        self._write_state(new)
        return new

    async def _replace(self) -> Snapshot:
        res = await self.upstream.fetch(self.url, headers={"Accept-Encoding": "identity"}, max_bytes=MAX_VERSIONS_BYTES)
        if res.status != 200:
            raise UpstreamError(res.url, f"upstream returned {res.status}", res.status)
        return await self._store_full(res.body, res.headers)

    async def _store_full(self, body: bytes, headers: dict[str, str]) -> Snapshot:
        return await asyncio.to_thread(self._write_full, body, headers)

    def _write_full(self, body: bytes, headers: dict[str, str]) -> Snapshot:
        data = complete_lines(body)
        if not data:
            raise UpstreamError(self.url, "upstream sent an empty /versions")
        expected = parse_digest(headers)
        if expected is not None and len(data) == len(body) and expected != sha256_b64(data):
            raise UpstreamError(self.url, "/versions does not match its Repr-Digest")
        served = zero_checksums(data)
        old = self._read_state()
        generation = (old.generation + 1) if old is not None else 1
        self._path("upstream", generation).write_bytes(data)
        self._path("served", generation).write_bytes(served)
        new = Snapshot(
            generation=generation,
            size=len(data),
            md5=hashlib.md5(served, usedforsecurity=False).hexdigest(),
            sha256=sha256_b64(served),
            upstream_etag=headers.get("etag") if len(data) == len(body) else None,
            upstream_sha256=sha256_b64(data),
            checked=self.now(),
        )
        self._write_state(new)
        for path in self.dir.iterdir():  # earlier generations; a response still reading one keeps its descriptor
            kind, _, gen = path.name.partition(".")
            if kind in ("upstream", "served") and gen.isdigit() and int(gen) != generation:
                path.unlink(missing_ok=True)
        log.info("rubygems.org /versions fetched", extra={"bytes": len(data), "generation": generation})
        return new

    # ---- serving -----------------------------------------------------------------------------------------------

    def open(self, snap: Snapshot) -> Any:
        """The served file of `snap`, open for reading (FileNotFoundError once a rebuild removed it)."""
        return self._path("served", snap.generation).open("rb")


async def read_range(f: Any, start: int, end: int) -> AsyncIterator[bytes]:
    """Bytes [start, end) of an open file, in chunks, closing it at the end."""
    try:
        pos = start
        while pos < end:
            n = min(CHUNK, end - pos)
            chunk = await asyncio.to_thread(_pread, f, pos, n)
            if not chunk:
                break
            pos += len(chunk)
            yield chunk
    finally:
        f.close()


def _pread(f: Any, pos: int, n: int) -> bytes:
    return os.pread(f.fileno(), n, pos)
