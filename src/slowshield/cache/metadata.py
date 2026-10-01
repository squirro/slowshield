"""Bytes-weighted in-memory LRU for upstream metadata and rendered responses."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Hashable
from dataclasses import dataclass
from typing import Generic, TypeVar

V = TypeVar("V")


@dataclass(slots=True)
class Entry(Generic[V]):
    value: V
    size: int
    expires: float  # monotonic-independent: wall-clock seconds from the injected Clock


class LRUCache(Generic[V]):
    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max(1, max_bytes)
        self._data: OrderedDict[Hashable, Entry[V]] = OrderedDict()
        self.bytes = 0
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def __len__(self) -> int:
        return len(self._data)

    def get(self, key: Hashable, now: float) -> V | None:
        e = self._data.get(key)
        if e is None:
            self.misses += 1
            return None
        if e.expires <= now:
            self.misses += 1
            return None
        self._data.move_to_end(key)
        self.hits += 1
        return e.value

    def get_stale(self, key: Hashable) -> V | None:
        """Return an entry even if expired (for revalidation / stale-if-error)."""
        e = self._data.get(key)
        return None if e is None else e.value

    def put(self, key: Hashable, value: V, size: int, expires: float) -> None:
        old = self._data.pop(key, None)
        if old is not None:
            self.bytes -= old.size
        if size > self.max_bytes:
            return
        self._data[key] = Entry(value, size, expires)
        self.bytes += size
        while self.bytes > self.max_bytes and self._data:
            _, ev = self._data.popitem(last=False)
            self.bytes -= ev.size
            self.evictions += 1

    def touch(self, key: Hashable, expires: float) -> None:
        e = self._data.get(key)
        if e is not None:
            e.expires = expires
            self._data.move_to_end(key)

    def invalidate(self, key: Hashable) -> None:
        old = self._data.pop(key, None)
        if old is not None:
            self.bytes -= old.size

    def clear(self) -> None:
        self._data.clear()
        self.bytes = 0


class SingleFlight:
    """Coalesce concurrent loads of the same key into one upstream request."""

    def __init__(self) -> None:
        self._inflight: dict[Hashable, asyncio.Future[object]] = {}

    async def run(self, key: Hashable, fn: Callable[[], Awaitable[V]]) -> V:
        while (fut := self._inflight.get(key)) is not None:
            try:
                return await asyncio.shield(fut)  # type: ignore[return-value]
            except asyncio.CancelledError:
                if fut.cancelled():  # the leader was cancelled: take over
                    continue
                raise
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._inflight[key] = fut
        try:
            value = await fn()
        except asyncio.CancelledError:
            fut.cancel()
            raise
        except Exception as exc:
            fut.set_exception(exc)
            fut.exception()  # mark retrieved; waiters re-raise it via shield()
            raise
        else:
            fut.set_result(value)
            return value
        finally:
            self._inflight.pop(key, None)
