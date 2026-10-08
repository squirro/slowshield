"""A follower's side of a shield wall: discover and pin the leader, wait for the operator's confirmation, join, then
keep syncing: reports go up from the outbox, policy and changes come down.

Runs on the worker that holds the leader lock (one per instance). Every other worker only reads the state this
writes. When the leader can't be reached, nothing here blocks anything: the instance keeps running on its own, the
outbox grows, and the next successful sync catches up.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import socket
from dataclasses import dataclass
from typing import Any

import msgspec

from slowshield import __version__
from slowshield.context import AppContext
from slowshield.recorder import Batch
from slowshield.shieldwall import signing
from slowshield.shieldwall.identity import Identity, key_hash
from slowshield.shieldwall.join import JoinString, leader_url_problem, proof
from slowshield.shieldwall.leader import PROTOCOL
from slowshield.shieldwall.runtime import refresh
from slowshield.shieldwall.transport import Reply, Send, Transport, TransportError
from slowshield.telemetry import instruments

log = logging.getLogger(__name__)

SYNC_WAIT = 25  # seconds the leader may hold a sync open (long poll)
OUTBOX_PER_SYNC = 200  # entries; each is one flush (5 s of statistics) or a backfill chunk
BACKFILL_ROWS = 5000  # rows per backfill entry
SYNC_LOG_KEEP = 40 * 86400
NO_JOIN = "not paired yet: joining needs the join string from the leader (SLOWSHIELD_JOIN)"


@dataclass(slots=True)
class LeaderState:
    leader_id: str
    url: str
    pubkey: bytes
    name: str | None
    join_token: str
    state: str
    confirmed_by: str | None
    policy_version: int
    cursor: int
    last_sync: float | None
    last_error: str | None


def read_state(conn: Any) -> LeaderState | None:
    r = conn.execute(
        "SELECT leader_id, url, pubkey, name, join_token, state, confirmed_by, policy_version, cursor, last_sync, "
        "last_error FROM shieldwall_leader WHERE id = 1"
    ).fetchone()
    return LeaderState(*r) if r else None


class FollowerService:
    def __init__(self, ctx: AppContext, identity: Identity, send: Send | None = None) -> None:
        self.ctx = ctx
        self.identity = identity
        sw = ctx.cfg.raw.shieldwall
        # Only discovery and joining need it: a paired follower syncs with the leader it stored.
        self.join = JoinString.parse(sw.join) if sw.join else None
        self._transport: Transport | None = None
        if send is None:
            self._transport = Transport(f"SlowShield/{__version__}", sw.leader_ca_file)
            send = self._transport.send
        self.send: Send = send
        self.backoff = 5.0

    async def close(self) -> None:
        if self._transport is not None:
            await self._transport.close()

    # ---- the loop ------------------------------------------------------------------------------------

    async def run(self) -> None:
        while True:
            try:
                pause = await self.step()
                self.backoff = 5.0
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # the leader is down or misbehaving: run on, retry later
                instruments.shieldwall_syncs.add(1, {"result": "error"})
                await self._error(str(exc) or type(exc).__name__)
                pause = self.backoff
                self.backoff = min(self.backoff * 2, 300.0)
            await asyncio.sleep(pause)

    async def _error(self, msg: str) -> None:
        msg = msg[:300]
        log.warning("shield wall sync failed", extra={"error": msg})
        now = self.ctx.clock.now()

        def op(conn: Any) -> None:
            if not conn.execute(
                "UPDATE shieldwall_leader SET last_error = ?, last_attempt = ? WHERE id = 1", (msg, now)
            ).rowcount:  # the leader hasn't been reached yet: the Shield wall page shows this instead
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES ('shieldwall_error', ?) ON CONFLICT (key) DO UPDATE SET "
                    "value = excluded.value",
                    (msg,),
                )

        await self.ctx.db.writer.run(op)

    async def step(self) -> float:
        """One round; returns seconds until the next."""
        state = await asyncio.to_thread(lambda: read_state(self.ctx.db.readers.get()))
        join = self.join
        if join is None:
            if state is None or state.state in ("pending", "detached"):  # not paired, and no join string to pair
                await self._error(NO_JOIN)
                return 300.0
        elif state is None or state.join_token != join.token_id or state.state == "detached":
            state = await self.discover(join, state)
        if state.state == "pending":
            if state.confirmed_by is None:
                return 2.0  # waiting for the Join click on the Shield wall page
            assert join is not None  # noqa: S101 - a pending follower without one returned above
            await self.enroll(join, state)
            return 0.0
        if state.state == "active":
            more = await self.sync(state)
            return 0.0 if more else 1.0
        return 30.0  # removed, key changed or join failed: shown in the UI, nothing to do until reconfigured

    # ---- discovery and joining ---------------------------------------------------------------------------

    async def discover(self, join: JoinString, current: LeaderState | None) -> LeaderState:
        """Fetch the leader's identity and pin it if it matches the join string's key hash."""
        url = join.url + "/.well-known/slowshield-shieldwall"
        reply = await self.send("GET", url, {"Accept": "application/json"}, b"", 10.0)
        if reply.status != 200:
            raise TransportError(f"{url}: HTTP {reply.status}")
        doc = json.loads(reply.body)
        pubkey = base64.b64decode(doc["pubkey"], validate=True)
        if key_hash(pubkey) != join.key_hash:
            raise TransportError("the leader's key doesn't match the join string: refusing to pair")
        if pubkey == self.identity.public_key:
            raise TransportError("the join string points at this instance itself")
        if PROTOCOL not in doc.get("protocol", []):
            raise TransportError(
                f"the leader speaks shield wall protocol {doc.get('protocol')}, this instance {PROTOCOL}"
            )
        now = self.ctx.clock.now()
        auto = self.ctx.cfg.raw.shieldwall.join_confirm == "auto"
        name = str(doc.get("name", ""))[:100] or None

        def op(conn: Any) -> LeaderState:
            existing = read_state(conn)
            if existing is not None and existing.pubkey == pubkey and existing.state == "active":
                # The same leader with a new join string (a re-deploy): stay paired.
                conn.execute("UPDATE shieldwall_leader SET join_token = ?, url = ? WHERE id = 1",
                             (join.token_id, join.url))  # fmt: skip
            elif existing is not None and existing.state == "active" and existing.pubkey != pubkey:
                conn.execute(
                    "UPDATE shieldwall_leader SET state = 'key_changed', last_error = ? WHERE id = 1",
                    ("the join string names a different leader; pairing again needs a new instance",),
                )
            else:
                conn.execute("DELETE FROM shieldwall_leader")
                conn.execute(
                    "INSERT INTO shieldwall_leader (id, leader_id, url, pubkey, name, join_token, state, discovered, "
                    "confirmed_by) VALUES (1, ?, ?, ?, ?, ?, 'pending', ?, ?)",
                    (str(doc["instance"]), join.url, pubkey, name, join.token_id, now,
                     "auto" if auto else None),
                )  # fmt: skip
            state = read_state(conn)
            assert state is not None  # noqa: S101 - just written
            return state

        return await self.ctx.db.writer.run(op)

    async def enroll(self, join: JoinString, state: LeaderState) -> None:
        sw = self.ctx.cfg.raw.shieldwall
        now = self.ctx.clock.now()
        created = int(now)
        body = json.dumps({
            "protocol": PROTOCOL,
            "token": join.token_id,
            "created": created,
            "proof": proof(join.secret, self.identity.public_key, state.leader_id, created),
            "pubkey": base64.b64encode(self.identity.public_key).decode(),
            "name": sw.name or socket.gethostname(),
            "location": sw.location,
            "labels": sw.labels,
            "version": __version__,
        }).encode()  # fmt: skip
        reply = await self._signed(state, "POST", "/_shieldwall/v1/join", "", body, limit=30.0)
        if reply.status != 200:
            detail = _detail(reply)
            await self.ctx.db.writer.run(
                lambda conn: conn.execute(
                    "UPDATE shieldwall_leader SET state = 'join_failed', last_error = ? WHERE id = 1", (detail,)
                )
            )
            log.error("joining the shield wall failed", extra={"error": detail})
            return
        doc = json.loads(reply.body)

        head = int(doc.get("head", 0))
        oci_since = doc.get("oci_since")

        def op(conn: Any) -> None:
            # The history snapshot and the switch to `active` are one transaction; from here on, every flush also
            # goes into the outbox (recorder.flush checks the state in its own transaction).
            _backfill(conn, now, packages=not doc.get("known"))
            conn.execute(
                "UPDATE shieldwall_leader SET state = 'active', paired = ?, name = coalesce(name, ?), cursor = 0, "
                "boot_head = ?, policy_version = 0, policy = NULL, last_error = NULL WHERE id = 1",
                (now, str(doc.get("leader_name") or "")[:100] or None, head),
            )
            # Changes up to `head` are the leader's past (the bootstrap); later ones fall under the late-news rule.
            conn.execute("DELETE FROM shieldwall_sync_log")
            conn.execute("DELETE FROM shieldwall_pending")
            conn.execute("INSERT INTO shieldwall_sync_log (ts, head) VALUES (?, ?)", (now, head))
            if isinstance(oci_since, (int, float)) and oci_since < now:
                # The leader has served images for longer: no fail-open window here for what it has seen.
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES ('oci_since', ?) ON CONFLICT (key) DO UPDATE SET "
                    "value = CAST(min(CAST(meta.value AS REAL), CAST(excluded.value AS REAL)) AS TEXT)",
                    (str(float(oci_since)),),
                )

        await self.ctx.db.writer.run(op)
        log.info("joined the shield wall", extra={"leader": state.leader_id, "url": state.url})

    # ---- syncing -------------------------------------------------------------------------------------

    async def sync(self, state: LeaderState) -> bool:
        ctx = self.ctx
        sw = ctx.cfg.raw.shieldwall
        entries = await asyncio.to_thread(self._outbox)
        lag = (await ctx.db.readers.aquery("SELECT count(*) FROM shieldwall_outbox"))[0][0]
        body = json.dumps({
            "status": {
                "version": __version__, "location": sw.location, "labels": sw.labels, "outbox_lag": lag,
                "time": ctx.clock.now(), "policy_version": state.policy_version,
            },
            "outbox": entries,
            "cursor": state.cursor,
            "policy_version": state.policy_version,
        }, separators=(",", ":")).encode()  # fmt: skip
        wait = 0 if entries else SYNC_WAIT
        reply = await self._signed(state, "POST", "/_shieldwall/v1/sync", f"wait={wait}", body, limit=wait + 15.0)
        # Only the paired leader can remove this instance: an unsigned "removed" is just another failure.
        if reply.status == 403 and "signature" in reply.headers and _detail(reply) == "removed":
            await ctx.db.writer.run(
                lambda conn: conn.execute(
                    "UPDATE shieldwall_leader SET state = 'removed', last_error = ? WHERE id = 1",
                    ("removed from the shield wall by the leader",),
                )
            )
            log.warning("removed from the shield wall by the leader")
            return False
        if reply.status != 200:
            raise TransportError(f"sync: HTTP {reply.status} {_detail(reply)}")
        doc = json.loads(reply.body)
        instruments.shieldwall_syncs.add(1, {"result": "ok"})
        now = ctx.clock.now()
        from slowshield.shieldwall.apply import apply_sync

        local = ctx.config.local
        sent = entries[-1]["seq"] if entries else 0
        me = self.identity.id
        await ctx.db.writer.run(lambda conn: apply_sync(conn, local, doc, now, sent=sent, me=me))
        await refresh(ctx)  # a stricter policy applies on this worker now, on the others within a second
        return bool(doc.get("more")) or len(entries) >= OUTBOX_PER_SYNC

    def _outbox(self) -> list[dict[str, Any]]:
        rows = self.ctx.db.readers.query(
            "SELECT seq, kind, body FROM shieldwall_outbox ORDER BY seq LIMIT ?", (OUTBOX_PER_SYNC,)
        )
        out, size = [], 0
        for seq, kind, body in rows:
            size += len(body)
            if out and size > (4 << 20):
                break
            out.append({"seq": seq, "kind": kind, "body": body})
        return out

    async def _signed(
        self, state: LeaderState, method: str, path: str, query: str, body: bytes, *, limit: float
    ) -> Reply:
        problem = leader_url_problem(state.url)  # the stored URL too: nothing goes to a leader in plain text
        if problem:
            raise TransportError(problem)
        now = self.ctx.clock.now()
        headers = signing.sign_request(self.identity, method, path, query, body, now=now)
        headers["Content-Type"] = "application/json"
        url = state.url + path + (f"?{query}" if query else "")
        reply = await self.send(method, url, headers, body, limit)
        if reply.status in (200, 403) and "signature" in reply.headers:  # a signed 403 is a removal
            try:
                signing.verify_response(
                    reply.headers, reply.status, reply.body, request_signature=headers["Signature"],
                    public_key=state.pubkey, now=self.ctx.clock.now(),
                )  # fmt: skip
            except signing.SignatureError as exc:
                raise TransportError(f"the leader's answer isn't signed by the paired leader: {exc}") from exc
        elif reply.status == 200:
            raise TransportError("the leader's answer isn't signed")
        return reply


def _detail(reply: Reply) -> str:
    try:
        doc = json.loads(reply.body)
    except ValueError:
        return f"HTTP {reply.status}"
    if not isinstance(doc, dict):
        return f"HTTP {reply.status}"
    return str(doc.get("detail") or doc.get("error") or reply.status)[:300]


def _backfill(conn: Any, now: float, *, packages: bool = True) -> None:
    """This instance's history so far, queued for the leader once, in chunks: the statistics tables as they are
    (not re-derived), its retained events, the first fingerprint of every file it served (for the leader to compare)
    and, unless the leader has them from an earlier pairing, the packages it served (their counts only add up)."""

    def rows(sql: str) -> list[tuple[Any, ...]]:
        return [tuple(r) for r in conn.execute(sql).fetchall()]

    dl = "SELECT bucket, ecosystem, package, version, serves, cache_hits, bytes, cache_bytes, leader_bytes FROM {} " \
         "WHERE instance = ''"  # fmt: skip
    parts: dict[str, list[tuple[Any, ...]]] = {
        "five": rows(dl.format("downloads_5min")),
        "hourly": rows(dl.format("downloads_hourly")),
        "daily": rows(dl.format("downloads_daily")),
        "decisions": rows("SELECT bucket, ecosystem, kind, decision, count FROM decisions_5min WHERE instance = ''"),
        "decisions_hourly": rows(
            "SELECT bucket, ecosystem, kind, decision, count FROM decisions_hourly WHERE instance = ''"
        ),
        "lookups": rows("SELECT bucket, ecosystem, source, count FROM lookups_5min WHERE instance = ''"),
        "lookups_hourly": rows("SELECT bucket, ecosystem, source, count FROM lookups_hourly WHERE instance = ''"),
        "events": rows(
            "SELECT ts, type, ecosystem, package, version, client_ip, count, details FROM events WHERE instance = '' "
            "ORDER BY ts"
        ),
    }
    if packages:
        parts["packages"] = rows(
            "SELECT ecosystem, name, first_served, last_served, serves, cache_hits, bytes FROM packages "
            "WHERE first_served IS NOT NULL"
        )
        parts["versions"] = rows(
            "SELECT ecosystem, name, version, first_served, last_served, serves, bytes FROM package_versions "
            "WHERE first_served IS NOT NULL"
        )
    for field, table_rows in parts.items():
        for i in range(0, len(table_rows), BACKFILL_ROWS):
            batch = Batch(derive=False, **{field: table_rows[i : i + BACKFILL_ROWS]})
            conn.execute(
                "INSERT INTO shieldwall_outbox (created, kind, body) VALUES (?, 'stats', ?)",
                (now, msgspec.json.encode(batch).decode()),
            )
    fingerprints = rows(
        "SELECT ecosystem, path, sha256, first_seen, package, version FROM artifacts WHERE sha256 IS NOT NULL"
    )
    for i in range(0, len(fingerprints), BACKFILL_ROWS):
        conn.execute(
            "INSERT INTO shieldwall_outbox (created, kind, body) VALUES (?, 'fingerprints', ?)",
            (now, json.dumps(fingerprints[i : i + BACKFILL_ROWS])),
        )
