"""Blocklist lookups backed by SQLite with a small per-process cache.

Rows come from threat feeds. A row with neither `version` nor `version_range` blocks the whole
package; otherwise it blocks one exact version or a comparator range. The in-process cache is keyed by
(ecosystem, name) and dropped whenever `meta.blocklist_generation` changes (feeds bump it on commit),
which `refresh_generation()` checks at most once per second.
"""

from __future__ import annotations

import sqlite3
import time
from collections import OrderedDict
from dataclasses import dataclass

from slowshield import versions
from slowshield.db import Database


@dataclass(frozen=True, slots=True)
class BlockEntry:
    ecosystem: str
    name: str
    version: str | None
    version_range: str | None
    source: str
    advisory_id: str
    reason: str | None
    url: str | None

    @property
    def package_level(self) -> bool:
        return self.version is None and versions.range_is_everything(self.version_range)

    def matches(self, version: str | None) -> bool:
        if self.package_level:
            return True
        if version is None:
            return False
        if self.version is not None:
            return versions.canonical(self.ecosystem, version) == versions.canonical(self.ecosystem, self.version)
        return self.version_range is not None and versions.in_range(self.ecosystem, version, self.version_range)

    def as_json(self) -> dict[str, str | None]:
        return {
            "advisory_id": self.advisory_id or None,
            "reason": self.reason,
            "source": self.source,
            "url": self.url,
        }


class PackageBlocks:
    """All active blocks for one package, with fast exact-version lookups."""

    __slots__ = ("_exact", "_package", "_ranges", "entries")

    def __init__(self, ecosystem: str, entries: list[BlockEntry]) -> None:
        self.entries = entries
        self._package = next((e for e in entries if e.package_level), None)
        self._exact: dict[str, BlockEntry] = {}
        self._ranges: list[BlockEntry] = []
        for e in entries:
            if e.package_level:
                continue
            if e.version is not None:
                self._exact.setdefault(versions.canonical(ecosystem, e.version), e)
            else:
                self._ranges.append(e)

    @property
    def package_block(self) -> BlockEntry | None:
        return self._package

    def __bool__(self) -> bool:
        return bool(self.entries)

    def match(self, ecosystem: str, version: str | None) -> BlockEntry | None:
        if self._package is not None:
            return self._package
        if version is None or not (self._exact or self._ranges):
            return None
        hit = self._exact.get(versions.canonical(ecosystem, version))
        if hit is not None:
            return hit
        for e in self._ranges:
            if e.matches(version):
                return e
        return None


_EMPTY = PackageBlocks("", [])


class Blocklist:
    def __init__(self, db: Database, *, max_entries: int = 50_000) -> None:
        self._db = db
        self._cache: OrderedDict[tuple[str, str], PackageBlocks] = OrderedDict()
        self._max = max_entries
        self._generation: str | None = None
        self._checked = 0.0

    @property
    def generation(self) -> str:
        if self._generation is None:
            self.refresh_generation(force=True)
        return self._generation or "0"

    def refresh_generation(self, *, force: bool = False) -> bool:
        now = time.monotonic()
        if not force and now - self._checked < 1.0:
            return False
        self._checked = now
        try:
            gen = self._db.meta("blocklist_generation") or "0"
        except sqlite3.Error:
            return False
        if gen != self._generation:
            self._generation = gen
            self._cache.clear()
            return True
        return False

    def for_package(self, ecosystem: str, name: str) -> PackageBlocks:
        self.refresh_generation()
        key = (ecosystem, name)
        hit = self._cache.get(key)
        if hit is not None:
            self._cache.move_to_end(key)
            return hit
        rows = self._db.readers.query(
            "SELECT ecosystem, name, version, version_range, source, advisory_id, reason, url "
            "FROM blocklist WHERE ecosystem = ? AND name = ? AND withdrawn IS NULL",
            (ecosystem, name),
        )
        blocks = PackageBlocks(ecosystem, [BlockEntry(*tuple(r)) for r in rows]) if rows else _EMPTY
        self._cache[key] = blocks
        if len(self._cache) > self._max:
            self._cache.popitem(last=False)
        return blocks

    def counts(self) -> dict[tuple[str, str], int]:
        rows = self._db.readers.query(
            "SELECT source, ecosystem, count(*) FROM blocklist WHERE withdrawn IS NULL GROUP BY source, ecosystem"
        )
        return {(r[0], r[1]): r[2] for r in rows}


def bump_generation(conn: sqlite3.Connection) -> None:
    conn.execute("UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'blocklist_generation'")
