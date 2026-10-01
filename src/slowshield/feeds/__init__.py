"""Threat feeds: status model, blocklist upserts and the scheduler (runs on the leader worker only)."""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol

from slowshield.blocklist import bump_generation
from slowshield.telemetry import instruments

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class BlockSpec:
    ecosystem: str
    name: str
    version: str | None = None
    version_range: str | None = None


@dataclass(slots=True)
class Advisory:
    source: str
    advisory_id: str
    specs: list[BlockSpec]
    reason: str | None
    url: str | None
    withdrawn: bool = False


@dataclass(slots=True)
class FeedStatus:
    name: str
    title: str
    requires_token: bool
    enabled: bool = False
    reason: str = "disabled"  # ok | disabled | missing_token | error
    last_attempt: float | None = None
    last_success: float | None = None
    last_error: str | None = None
    entries: int = 0
    running: bool = False
    fix: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class Feed(Protocol):
    name: str
    title: str
    requires_token: bool

    def configured(self) -> tuple[bool, str]:
        """(enabled, reason) from the current config/secrets."""
        ...

    async def sync(self) -> int:
        """Pull changes and apply them; returns the number of advisories changed."""
        ...


FIX_GITHUB_TOKEN = (
    "Create a GitHub token (a fine-grained personal access token with no extra permissions is enough; "
    "it only reads the public advisory database) and pass it as GITHUB_TOKEN, or mount it as a file and set "
    "GITHUB_TOKEN_FILE (Docker/Podman/Kubernetes secret). Restart SlowShield afterwards."
)


def apply_advisories(conn: sqlite3.Connection, advisories: Iterable[Advisory], now: float) -> int:
    """Replace the blocklist rows of each advisory with its current specs. Returns rows changed."""
    changed = 0
    for adv in advisories:
        if adv.withdrawn:
            cur = conn.execute(
                "UPDATE blocklist SET withdrawn = ?, updated = ? WHERE source = ? AND advisory_id = ? AND withdrawn IS NULL",
                (now, now, adv.source, adv.advisory_id),
            )
            changed += cur.rowcount
            continue
        existing = {
            (r[1], r[2], r[3], r[4]): r[0]
            for r in conn.execute(
                "SELECT id, ecosystem, name, version, version_range FROM blocklist WHERE source = ? AND advisory_id = ?",
                (adv.source, adv.advisory_id),
            )
        }
        wanted = {(s.ecosystem, s.name, s.version, s.version_range) for s in adv.specs}
        stale = [rid for key, rid in existing.items() if key not in wanted]
        if stale:
            conn.executemany("DELETE FROM blocklist WHERE id = ?", [(r,) for r in stale])
            changed += len(stale)
        for eco, name, ver, rng in wanted:
            if (eco, name, ver, rng) in existing:
                conn.execute(
                    "UPDATE blocklist SET reason = ?, url = ?, updated = ?, withdrawn = NULL WHERE id = ?",
                    (adv.reason, adv.url, now, existing[(eco, name, ver, rng)]),
                )
                continue
            cur = conn.execute(
                "INSERT OR IGNORE INTO blocklist (ecosystem, name, version, version_range, source, advisory_id, reason, url, "
                "first_seen, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (eco, name, ver, rng, adv.source, adv.advisory_id, adv.reason, adv.url, now, now),
            )
            changed += cur.rowcount
    if changed:
        bump_generation(conn)
    return changed


def save_state(conn: sqlite3.Connection, source: str, **fields: Any) -> None:
    cols = ", ".join(fields)
    placeholders = ", ".join("?" for _ in fields)
    updates = ", ".join(f"{k} = excluded.{k}" for k in fields)
    conn.execute(
        f"INSERT INTO feed_state (source, {cols}) VALUES (?, {placeholders}) "
        f"ON CONFLICT (source) DO UPDATE SET {updates}",
        (source, *fields.values()),
    )


def load_state(conn: sqlite3.Connection, source: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT watermark, etag, last_attempt, last_success, last_error, entries, details FROM feed_state WHERE source = ?",
        (source,),
    ).fetchone()
    if row is None:
        return {}
    keys = ("watermark", "etag", "last_attempt", "last_success", "last_error", "entries", "details")
    return dict(zip(keys, tuple(row), strict=True))


class FeedScheduler:
    def __init__(self, ctx: Any, feeds: list[Feed]) -> None:
        self.ctx = ctx
        self.feeds = feeds
        for f in feeds:
            ctx.feeds[f.name] = FeedStatus(name=f.name, title=f.title, requires_token=f.requires_token)
        self.refresh_status()
        self._register_metrics()

    def refresh_status(self) -> None:
        """Recompute enabled/reason from config and pull last-run info from the DB (any worker)."""
        for f in self.feeds:
            st: FeedStatus = self.ctx.feeds[f.name]
            enabled, reason = f.configured()
            st.enabled, st.reason = enabled, reason
            st.fix = FIX_GITHUB_TOKEN if reason == "missing_token" else None
            try:
                state = load_state(self.ctx.db.readers.get(), f.name)
            except sqlite3.Error:
                state = {}
            st.last_attempt = state.get("last_attempt")
            st.last_success = state.get("last_success")
            st.last_error = state.get("last_error")
            st.entries = state.get("entries") or 0
            if enabled and st.last_error and (st.last_success or 0) < (st.last_attempt or 0):
                st.reason = "error"

    def _register_metrics(self) -> None:
        def enabled() -> list[tuple[float, dict[str, str | int | float | bool]]]:
            return [(1.0 if s.enabled else 0.0, {"feed": s.name, "reason": s.reason}) for s in self.ctx.feeds.values()]

        def last_success() -> list[tuple[float, dict[str, str | int | float | bool]]]:
            return [(s.last_success, {"feed": s.name}) for s in self.ctx.feeds.values() if s.last_success]

        def blocklist() -> list[tuple[float, dict[str, str | int | float | bool]]]:
            return [(float(n), {"source": src, "slowshield.ecosystem": eco}) for (src, eco), n in self._counts.items()]

        self._counts: dict[tuple[str, str], int] = {}
        instruments.observe("slowshield.feed.enabled", enabled, unit="1", description="1 if the feed is active.")
        instruments.observe(
            "slowshield.feed.last_success.timestamp",
            last_success,
            unit="s",
            description="UNIX time of the last good sync.",
        )
        instruments.observe(
            "slowshield.blocklist.entries", blocklist, unit="{entry}", description="Active blocklist rows."
        )

    def refresh_counts(self) -> None:
        try:
            self._counts = self.ctx.blocklist.counts()
        except sqlite3.Error:
            pass

    async def run_once(self) -> None:
        for f in self.feeds:
            st: FeedStatus = self.ctx.feeds[f.name]
            enabled, reason = f.configured()
            st.enabled, st.reason = enabled, reason
            if not enabled:
                continue
            st.running = True
            started = time.perf_counter()
            now = self.ctx.clock.now()
            try:
                changed = await f.sync()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                msg = f"{type(exc).__name__}: {exc}"[:500]
                log.error("feed sync failed", extra={"feed": f.name, "error": msg})
                instruments.feed_errors.add(1, {"feed": f.name})
                instruments.feed_sync_duration.record(
                    time.perf_counter() - started, {"feed": f.name, "outcome": "error"}
                )
                await self.ctx.db.writer.run(
                    lambda c, n=f.name, m=msg, t=now: save_state(c, n, last_attempt=t, last_error=m)
                )
                st.reason, st.last_error, st.last_attempt = "error", msg, now
            else:
                instruments.feed_sync_duration.record(time.perf_counter() - started, {"feed": f.name, "outcome": "ok"})
                if changed:
                    instruments.feed_changes.add(changed, {"feed": f.name})
                    log.info("feed applied changes", extra={"feed": f.name, "changed": changed})
                st.reason, st.last_error = "ok", None
            finally:
                st.running = False
            self.refresh_status()
        await asyncio.to_thread(self.refresh_counts)

    async def run_forever(self) -> None:
        while True:
            await self.run_once()
            interval = self.ctx.cfg.raw.feeds.poll_interval_minutes * 60
            await asyncio.sleep(interval)

    async def follow(self, interval: float = 30.0) -> None:
        """Non-leader workers: keep status (UI + gauges) fresh from the DB."""
        while True:
            await asyncio.sleep(interval)
            self.refresh_status()
            await asyncio.to_thread(self.refresh_counts)
