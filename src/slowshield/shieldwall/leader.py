"""The leader's side of a shield wall: pairing, reports from followers, and what followers take from it.

Followers dial out to these endpoints; the leader never connects to them. Every request is signed by a known
follower (join: by the key it brings, plus the invitation's proof), every response by the leader.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import time
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack
from functools import partial
from typing import Any

import msgspec
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route, Router

from slowshield import __version__
from slowshield.config import LoadedConfig
from slowshield.context import AppContext
from slowshield.ecosystems.artifacts import IntegrityAbort, StreamedArtifact
from slowshield.recorder import Batch, write_batch
from slowshield.shieldwall import signing
from slowshield.shieldwall.identity import Identity, instance_id
from slowshield.shieldwall.join import proof_ok
from slowshield.telemetry import instruments
from slowshield.upstream import UpstreamError

log = logging.getLogger(__name__)

PROTOCOL = 1
MAX_BODY = 8 << 20
MAX_WAIT = 25.0
CHANGES_PER_SYNC = 500
STATS_TABLES = (
    "downloads_5min", "downloads_hourly", "downloads_daily", "decisions_5min", "decisions_hourly", "lookups_5min",
    "lookups_hourly",
)  # fmt: skip
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SHA512 = re.compile(r"[0-9a-f]{128}")


def well_known(identity: Identity, cfg: LoadedConfig) -> dict[str, Any]:
    sw = cfg.raw.shieldwall
    return {
        "protocol": [PROTOCOL],
        "instance": identity.id,
        "name": instance_name(cfg),
        "location": sw.location,
        "role": sw.role,
        "pubkey": base64.b64encode(identity.public_key).decode(),
        "version": __version__,
    }


def instance_name(cfg: LoadedConfig) -> str:
    import socket

    return cfg.raw.shieldwall.name or socket.gethostname()


# ---- policy ---------------------------------------------------------------------------------------------


def policy_body(cfg: LoadedConfig) -> dict[str, Any]:
    """What followers take from the leader's config: delays, exceptions and the fail-open settings. Upstreams,
    caches, privacy settings and the shield wall settings themselves never leave the leader."""
    raw = cfg.raw
    return {
        "default_delay_days": raw.default_delay_days,
        "fail_open": raw.fail_open,
        "enforce_age_on_download": raw.enforce_age_on_download,
        "fail_open_by_ecosystem": {
            eco: getattr(raw.upstreams, eco).fail_open
            for eco in ("pypi", "npm", "go", "maven", "cargo", "oci")
            if getattr(raw.upstreams, eco).fail_open is not None
        },
        "exceptions": [
            {"ecosystem": e.ecosystem, "package": e.package, "version": e.version, "delay_days": e.delay_days}
            for e in raw.exceptions
        ],
    }


def current_policy(conn: Any, cfg: LoadedConfig, now: float, *, seen: int = 0) -> dict[str, Any]:
    """The policy bundle with a version that only grows: bumped whenever its content changes, and past `seen`, the
    version a follower already has (a leader restored from a backup would otherwise send versions it ignores)."""
    body = policy_body(cfg)
    digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    row = conn.execute("SELECT value FROM meta WHERE key = 'shieldwall_policy'").fetchone()
    state: dict[str, Any] = json.loads(row[0]) if row else {"version": 0, "digest": ""}
    if state["digest"] != digest or int(state["version"]) < seen:
        state = {"version": max(int(state["version"]), seen) + 1, "digest": digest, "issued": now}
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('shieldwall_policy', ?) ON CONFLICT (key) DO UPDATE SET value = "
            "excluded.value",
            (json.dumps(state),),
        )
    return {"version": state["version"], "issued": state.get("issued", now), **body}


# ---- changes followers take ---------------------------------------------------------------------------------


def change_rows(conn: Any, after: int, limit: int) -> tuple[list[dict[str, Any]], bool]:
    rows = conn.execute(
        "SELECT seq, dataset, key FROM shieldwall_changes WHERE seq > ? ORDER BY seq LIMIT ?", (after, limit + 1)
    ).fetchall()
    more = len(rows) > limit
    out: list[dict[str, Any]] = []
    for seq, dataset, key in rows[:limit]:
        row = _change_row(conn, dataset, key)
        if row is not None:
            out.append({"seq": seq, "dataset": dataset, "row": row})
        else:
            out.append({"seq": seq, "dataset": "noop", "row": {}})
    return out, more


def _change_row(conn: Any, dataset: str, key: str) -> dict[str, Any] | None:
    if dataset == "block":
        r = conn.execute(
            "SELECT id, ecosystem, name, version, version_range, source, advisory_id, reason, url, withdrawn "
            "FROM blocklist WHERE id = ?",
            (int(key),),
        ).fetchone()
        if r is None:  # deleted (a [[blocks]] entry removed): the follower lifts its copy
            return {"id": int(key), "deleted": True}
        return dict(zip(("id", "ecosystem", "name", "version", "version_range", "source", "advisory_id", "reason",
                         "url", "withdrawn"), r, strict=True))  # fmt: skip
    if dataset == "tamper":
        eco, _, path = key.partition("\n")
        r = conn.execute(
            "SELECT package, version, filename FROM artifacts WHERE ecosystem = ? AND path = ?", (eco, path)
        ).fetchone()
        return {"ecosystem": eco, "path": path, "package": r[0], "version": r[1], "filename": r[2]} if r else None
    if dataset == "gone":
        repo, _, digest = key.partition("\n")
        r = conn.execute("SELECT gone FROM oci_digests WHERE repository = ? AND digest = ?", (repo, digest)).fetchone()
        return {"repository": repo, "digest": digest, "gone": r[0]} if r and r[0] is not None else None
    if dataset == "tag":
        repo, tag, digest = key.split("\n", 2)
        r = conn.execute(
            "SELECT first_seen, registry_time FROM oci_tags WHERE repository = ? AND tag = ? AND digest = ?",
            (repo, tag, digest),
        ).fetchone()
        return (
            {"repository": repo, "tag": tag, "digest": digest, "first_seen": r[0], "registry_time": r[1]} if r else None
        )
    if dataset == "listed":
        eco, name, version = key.split("\n", 2)
        r = conn.execute(
            "SELECT first_listed FROM package_versions WHERE ecosystem = ? AND name = ? AND version = ?",
            (eco, name, version),
        ).fetchone()
        return {"ecosystem": eco, "name": name, "version": version, "first_listed": r[0]} if r and r[0] else None
    return None


# ---- applying what followers report ----------------------------------------------------------------------


def apply_outbox(conn: Any, member: str, hwm: int, entries: list[dict[str, Any]], now: float) -> int:
    """Apply outbox entries in order, each exactly once: anything at or below the member's high-water mark was
    applied by an earlier (maybe retried) sync. Returns the new mark."""
    for entry in sorted(entries, key=lambda e: e["seq"]):
        seq = int(entry["seq"])
        if seq <= hwm:
            continue
        kind = entry.get("kind")
        if kind == "stats":
            write_batch(conn, msgspec.json.decode(entry["body"], type=Batch), instance=member)
        elif kind == "fingerprints":
            for eco, path, sha256, first_seen, package, version in json.loads(entry["body"]):
                conn.execute(
                    "INSERT OR IGNORE INTO shieldwall_fingerprints (ecosystem, path, instance, sha256, first_seen) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (eco, path, member, sha256, first_seen),
                )
                _compare_fingerprint(conn, member, (eco, path, package, version), sha256=sha256, now=now)
        hwm = seq
    return hwm


def _compare_fingerprint(
    conn: Any, member: str, file: tuple[str, str, str, str | None], *, sha256: str, now: float
) -> None:
    """Two instances that saw different bytes for the same immutable file: one of them was served something else.
    The file is flagged here, which flags it on every follower, even where this leader never served it."""
    eco, path, package, version = file
    mine = conn.execute("SELECT sha256 FROM artifacts WHERE ecosystem = ? AND path = ?", (eco, path)).fetchone()
    others = {
        r[0]
        for r in conn.execute(
            "SELECT sha256 FROM shieldwall_fingerprints WHERE ecosystem = ? AND path = ? AND instance != ?",
            (eco, path, member),
        )
    }
    if mine and mine[0]:
        others.add(mine[0])
    if others and others != {sha256}:
        details = {
            "artifact": path,
            "reason": "instances saw different bytes",
            "fingerprints": sorted({*others, sha256}),
        }
        conn.execute(
            "INSERT INTO events (ts, type, ecosystem, package, version, count, details, instance) "
            "VALUES (?, 'tampered', ?, ?, ?, 1, ?, ?)",
            (now, eco, package, version, json.dumps(details), member),
        )
        conn.execute(
            "INSERT INTO artifacts (ecosystem, path, package, version, filename, first_seen, last_seen, tampered) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 1) ON CONFLICT (ecosystem, path) DO UPDATE SET tampered = 1",
            (eco, path, package, version, path.rsplit("/", 1)[-1], now, now),
        )


# ---- the service --------------------------------------------------------------------------------------------


class LeaderService:
    def __init__(self, ctx: AppContext, identity: Identity) -> None:
        self.ctx = ctx
        self.identity = identity

    def routes(self) -> list[Route]:
        return [
            Route("/join", self.join, methods=["POST"]),
            Route("/sync", self.sync, methods=["POST"]),
            Route("/blob", self.blob, methods=["GET"]),
        ]

    def router(self) -> Router:
        return Router(self.routes(), redirect_slashes=False)

    def _reply(self, request_sig: str, payload: dict[str, Any], status: int = 200) -> Response:
        body = json.dumps(payload, separators=(",", ":")).encode()
        headers = signing.sign_response(
            self.identity, status, body, request_signature=request_sig, now=self.ctx.clock.now()
        )
        return Response(body, status_code=status, media_type="application/json", headers=headers)

    async def _body(self, request: Request) -> bytes | None:
        """The request body, read no further than MAX_BODY (None: too large). Read before the sender is known."""
        if int(request.headers.get("content-length") or 0) > MAX_BODY:
            return None
        body = bytearray()
        async for chunk in request.stream():
            body += chunk
            if len(body) > MAX_BODY:
                return None
        return bytes(body)

    async def join(self, request: Request) -> Response:
        ctx = self.ctx
        now = ctx.clock.now()
        body = await self._body(request)
        if body is None:
            return JSONResponse({"error": "too_large"}, status_code=413)
        headers = {k.lower(): v for k, v in request.headers.items()}
        try:
            doc = json.loads(body)
            pubkey = base64.b64decode(doc["pubkey"], validate=True)
            signed = signing.verify_request(
                headers, "POST", request.url.path, request.url.query, body, public_key=pubkey, now=now
            )
        except (ValueError, KeyError, TypeError, signing.SignatureError) as exc:
            return JSONResponse({"error": "bad_request", "detail": str(exc)}, status_code=400)
        member = instance_id(pubkey)
        if signed.keyid != member:
            return JSONResponse({"error": "bad_request", "detail": "key id doesn't match the key"}, status_code=400)
        if member == self.identity.id:
            return JSONResponse({"error": "bad_request", "detail": "that is this leader's own key"}, status_code=400)
        token_id = str(doc.get("token", ""))
        created = int(doc.get("created", 0))
        claimed = str(doc.get("proof", ""))
        name = str(doc.get("name", ""))[:100] or member
        location = str(doc.get("location", ""))[:100]
        labels = doc.get("labels") if isinstance(doc.get("labels"), dict) else {}

        def op(conn: Any) -> tuple[int, dict[str, Any]]:
            tok = conn.execute(
                "SELECT secret, expires, used, revoked, name, location FROM shieldwall_tokens WHERE id = ?", (token_id,)
            ).fetchone()
            if tok is None or tok[0] is None or tok[2] is not None or tok[3] is not None:
                return 403, {"error": "invalid_token", "detail": "unknown or already used invitation"}
            if tok[1] < now:
                return 403, {"error": "expired_token", "detail": "the invitation expired: issue a new one"}
            if abs(now - created) > signing.MAX_SKEW or not proof_ok(tok[0], pubkey, self.identity.id, created,
                                                                     claimed):  # fmt: skip
                return 403, {"error": "invalid_token", "detail": "the invitation's proof doesn't match"}
            final_name = tok[4] or name
            final_location = tok[5] or location
            known = conn.execute("SELECT 1 FROM shieldwall_members WHERE id = ?", (member,)).fetchone() is not None
            if known:  # joining again: its history comes again with the snapshot, so the old copy goes
                for table in STATS_TABLES:
                    conn.execute(f"DELETE FROM {table} WHERE instance = ?", (member,))
                conn.execute("DELETE FROM events WHERE instance = ?", (member,))
            conn.execute(
                "INSERT INTO shieldwall_members (id, pubkey, name, location, labels, version, protocol, state, joined, "
                "token, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?) ON CONFLICT (id) DO UPDATE SET "
                "name = excluded.name, location = excluded.location, labels = excluded.labels, version = "
                "excluded.version, protocol = excluded.protocol, state = 'active', token = excluded.token, "
                "last_seen = excluded.last_seen, inbox_hwm = 0",
                (member, pubkey, final_name, final_location, json.dumps(labels), str(doc.get("version", ""))[:40],
                 PROTOCOL, now, token_id, now),
            )  # fmt: skip
            conn.execute("UPDATE shieldwall_tokens SET used = ?, member = ?, secret = NULL WHERE id = ?",
                         (now, member, token_id))  # fmt: skip
            head = conn.execute("SELECT coalesce(max(seq), 0) FROM shieldwall_changes").fetchone()[0]
            since = conn.execute("SELECT value FROM meta WHERE key = 'oci_since'").fetchone()
            return 200, {"member": member, "member_name": final_name, "leader": self.identity.id, "known": known,
                         "leader_name": instance_name(ctx.cfg), "head": head,
                         "oci_since": float(since[0]) if since else None}  # fmt: skip

        status, payload = await ctx.db.writer.run(op)
        if status != 200:
            return JSONResponse(payload, status_code=status)
        log.info("shield wall member joined", extra={"member": member, "member_name": payload["member_name"]})
        return self._reply(signed.signature, payload)

    async def _member(self, request: Request, body: bytes) -> tuple[Any, signing.Signed] | Response:
        headers = {k.lower(): v for k, v in request.headers.items()}
        keyid = signing.keyid_of(headers)
        row = None
        if keyid:
            row = await self.ctx.db.readers.aone(
                "SELECT id, pubkey, state, inbox_hwm FROM shieldwall_members WHERE id = ?", (keyid,)
            )
        if row is None:
            return JSONResponse({"error": "unknown_member"}, status_code=403)
        try:
            signed = signing.verify_request(
                headers, request.method, request.url.path, request.url.query, body, public_key=row[1],
                now=self.ctx.clock.now(),
            )  # fmt: skip
        except signing.SignatureError as exc:
            return JSONResponse({"error": "bad_signature", "detail": str(exc)}, status_code=403)
        if row[2] != "active":
            return self._reply(signed.signature, {"error": "removed", "state": row[2]}, status=403)
        return row, signed

    async def sync(self, request: Request) -> Response:
        ctx = self.ctx
        body = await self._body(request)
        if body is None:
            return JSONResponse({"error": "too_large"}, status_code=413)
        got = await self._member(request, body)
        if isinstance(got, Response):
            return got
        row, signed = got
        member = row[0]
        try:
            doc = json.loads(body)
            cursor = int(doc.get("cursor", 0))
            policy_version = int(doc.get("policy_version", 0))
            entries = list(doc.get("outbox", []))
            status = doc.get("status", {}) if isinstance(doc.get("status"), dict) else {}
        except (ValueError, TypeError) as exc:
            return self._reply(signed.signature, {"error": "bad_request", "detail": str(exc)}, status=400)
        wait = min(max(float(request.query_params.get("wait", "0") or 0), 0.0), MAX_WAIT)
        cfg = ctx.cfg

        def apply(conn: Any) -> int:
            now = ctx.clock.now()
            hwm = conn.execute("SELECT inbox_hwm FROM shieldwall_members WHERE id = ?", (member,)).fetchone()[0]
            hwm = apply_outbox(conn, member, hwm, entries, now)
            conn.execute(
                "UPDATE shieldwall_members SET inbox_hwm = ?, last_seen = ?, status = ?, policy_version = ?, version = "
                "coalesce(?, version) WHERE id = ?",
                (hwm, now, json.dumps(status)[:4000], policy_version, str(status.get("version", ""))[:40] or None,
                 member),
            )  # fmt: skip
            return hwm

        ack = await ctx.db.writer.run(apply)
        deadline = time.monotonic() + wait
        policy = await ctx.db.writer.run(lambda conn: current_policy(conn, cfg, ctx.clock.now(), seen=policy_version))
        while True:
            head = (await ctx.db.readers.aquery("SELECT coalesce(max(seq), 0) FROM shieldwall_changes"))[0][0]
            if head > cursor or policy["version"] != policy_version or time.monotonic() >= deadline:
                break
            await asyncio.sleep(1.0)
            if ctx.cfg is not cfg:  # the config was reloaded: maybe a new policy
                cfg = ctx.cfg
                policy = await ctx.db.writer.run(partial(current_policy, cfg=cfg, now=ctx.clock.now()))
        changes, more = await asyncio.to_thread(self._changes, cursor)
        payload = {
            "ack": ack,
            "head": head,
            "changes": changes,
            "more": more,
            "time": ctx.clock.now(),
            "policy": policy if policy["version"] != policy_version else None,
            "leader": {"id": self.identity.id, "name": instance_name(cfg), "version": __version__},
        }
        return self._reply(signed.signature, payload)

    def _changes(self, cursor: int) -> tuple[list[dict[str, Any]], bool]:
        conn = self.ctx.db.readers.get()
        return change_rows(conn, cursor, CHANGES_PER_SYNC)

    async def blob(self, request: Request) -> Response | StreamedArtifact:
        """A package file for a follower, by content address: from the cache, or fetched from the registry (only
        configured upstream hosts) and cached if the bytes match. The follower checks them again either way."""
        ctx = self.ctx
        got = await self._member(request, b"")
        if isinstance(got, Response):
            return got
        q = request.query_params
        sha256, sha512, url = q.get("sha256", "").lower(), q.get("sha512", "").lower(), q.get("url", "")
        if (sha256 and not _SHA256.fullmatch(sha256)) or (sha512 and not _SHA512.fullmatch(sha512)):
            return JSONResponse({"error": "bad_request", "detail": "malformed digest"}, status_code=400)
        if not (sha256 or sha512) or not url.startswith(("https://", "http://")):
            return JSONResponse({"error": "bad_request", "detail": "a digest and a URL are required"}, status_code=400)
        known = sha256 or await self._alias("sha512", sha512)
        for store in ctx.artifacts.stores.values():
            hit = store.lookup(known) if known else None
            if hit is not None:
                instruments.shieldwall_blobs.add(1, {"result": "hit"})
                return FileResponse(hit.path, media_type="application/octet-stream",
                                    headers={"X-SlowShield-Cache": "hit"}, stat_result=None)  # fmt: skip
        stack = AsyncExitStack()
        try:
            up = await stack.enter_async_context(ctx.upstream.stream(url))
        except UpstreamError as exc:
            await stack.aclose()
            return JSONResponse({"error": "upstream_error", "detail": exc.detail}, status_code=502)
        if up.status != 200:
            await stack.aclose()
            return JSONResponse({"error": "upstream_error", "detail": f"upstream returned {up.status}"},
                                status_code=502)  # fmt: skip
        instruments.shieldwall_blobs.add(1, {"result": "miss"})
        tee = ctx.artifact_cache.open_tee()
        h256, h512 = hashlib.sha256(), hashlib.sha512() if sha512 else None
        state = {"ok": False}

        async def body() -> AsyncIterator[bytes]:
            pending: bytes | None = None
            async for chunk in up.chunks():
                h256.update(chunk)
                if h512 is not None:
                    h512.update(chunk)
                if tee is not None:
                    tee.write(chunk)
                if pending is not None:
                    yield pending
                pending = chunk
            if (sha256 and h256.hexdigest() != sha256) or (h512 is not None and h512.hexdigest() != sha512):
                raise IntegrityAbort(url, JSONResponse({"error": "integrity_mismatch"}, status_code=502))
            state["ok"] = True
            if pending is not None:
                yield pending

        async def on_close() -> None:
            await stack.aclose()
            if tee is None:
                return
            if not state["ok"]:
                tee.abort()
                return
            digest = h256.hexdigest()
            await ctx.artifact_cache.commit(tee, digest, None)
            if h512 is not None:
                await ctx.db.writer.run(
                    lambda conn: conn.execute(
                        "INSERT OR IGNORE INTO shieldwall_blobs (alg, digest, sha256) VALUES ('sha512', ?, ?)",
                        (sha512, digest),
                    )
                )

        headers = {"Content-Type": "application/octet-stream", "X-SlowShield-Cache": "miss"}
        if up.content_length is not None:
            headers["Content-Length"] = str(up.content_length)
        return StreamedArtifact(200, headers, body(), on_close)

    async def _alias(self, alg: str, digest: str) -> str | None:
        row = await self.ctx.db.readers.aone(
            "SELECT sha256 FROM shieldwall_blobs WHERE alg = ? AND digest = ?", (alg, digest)
        )
        return row[0] if row else None
