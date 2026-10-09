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
import math
import re
import sqlite3
import time
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack
from functools import partial
from typing import Any

import msgspec
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route, Router

from slowshield import __version__, names
from slowshield.config import ECOSYSTEMS, LoadedConfig
from slowshield.context import AppContext
from slowshield.ecosystems.artifacts import IntegrityAbort, StreamedArtifact
from slowshield.recorder import Batch, write_batch
from slowshield.shieldwall import signing, wire
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
    """The policy bundle with a version that only grows: bumped whenever its content changes, or when a follower
    reports a version past it, `seen` (a leader restored from a backup would otherwise send versions it ignores).

    A bump goes to the current Unix time, or one past the last version if that is later. What a follower reports
    only triggers a bump and never sets the number, so no follower can push the version towards the bound every
    follower's report is held to (wire.MAX_SEQ), and a restored leader still moves past its followers at once."""
    body = policy_body(cfg)
    digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    row = conn.execute("SELECT value FROM meta WHERE key = 'shieldwall_policy'").fetchone()
    state: dict[str, Any] = json.loads(row[0]) if row else {"version": 0, "digest": ""}
    if state["digest"] != digest or int(state["version"]) < seen:
        state = {"version": max(int(state["version"]) + 1, int(now)), "digest": digest, "issued": now}
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('shieldwall_policy', ?) ON CONFLICT (key) DO UPDATE SET value = "
            "excluded.value",
            (json.dumps(state),),
        )
    return {"version": state["version"], "issued": state.get("issued", now), **body}


# ---- changes followers take ---------------------------------------------------------------------------------


def change_rows(conn: Any, after: int, limit: int, member: str) -> tuple[list[dict[str, Any]], bool]:
    """Changes after `after` for `member`. A flag for one follower goes to that follower only (and tells nobody
    else which files it served)."""
    rows = conn.execute(
        "SELECT seq, dataset, key FROM shieldwall_changes WHERE seq > ? ORDER BY seq LIMIT ?", (after, limit + 1)
    ).fetchall()
    more = len(rows) > limit
    out: list[dict[str, Any]] = []
    for seq, dataset, key in rows[:limit]:
        mine = dataset != "flag" or key.rsplit("\n", 1)[-1] == member
        row = _change_row(conn, dataset, key) if mine else None
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
    if dataset == "flag":
        eco, path, member = key.split("\n", 2)
        r = conn.execute(
            "SELECT package, version, sha256 FROM shieldwall_fingerprints WHERE ecosystem = ? AND path = ? AND "
            "instance = ? AND flagged IS NOT NULL",
            (eco, path, member),
        ).fetchone()
        if r is None:
            return None
        return {"instance": member, "ecosystem": eco, "path": path, "package": r[0], "version": r[1], "sha256": r[2]}
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


# What an entry's own data can raise. Anything else (a locked or full database) fails the whole sync, which the
# follower retries.
_MALFORMED = (ValueError, TypeError, KeyError, ArithmeticError, msgspec.MsgspecError, sqlite3.IntegrityError)


def apply_outbox(conn: Any, member: str, hwm: int, entries: list[dict[str, Any]], now: float) -> int:
    """Apply outbox entries in order, each exactly once: anything at or below the member's high-water mark was
    applied by an earlier (maybe retried) sync. Returns the new mark.

    An entry that can't be applied is undone, logged and passed: retried, it would fail again and hold up everything
    the follower reports after it."""
    for entry in sorted(entries, key=lambda e: e["seq"]):
        seq = int(entry["seq"])
        if seq <= hwm:
            continue
        conn.execute("SAVEPOINT outbox_entry")
        try:
            _apply_entry(conn, member, entry, now)
        except _MALFORMED as exc:
            conn.execute("ROLLBACK TO outbox_entry")
            log.warning("skipped a report that can't be applied", extra={"member": member, "seq": seq,
                        "kind": entry.get("kind"), "error": str(exc)[:300]})  # fmt: skip
        conn.execute("RELEASE outbox_entry")
        hwm = seq
    return hwm


def _apply_entry(conn: Any, member: str, entry: dict[str, Any], now: float) -> None:
    kind = entry.get("kind")
    if kind == "stats":
        # Integers past 64 bits get through msgspec and fail when SQLite binds them: the entry is passed then.
        write_batch(conn, msgspec.json.decode(entry["body"], type=Batch), instance=member)
    elif kind == "fingerprints":
        items = wire.loads(entry["body"])
        if not isinstance(items, list):
            raise TypeError("fingerprints: expected a list")
        for item in items:
            _take_fingerprint(conn, member, item, now)


_HEX64 = re.compile(r"[0-9a-f]{64}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# A Go module path takes up to 1024 characters (names.GO_MAX_LEN, the longest name any ecosystem allows) and twice
# that in an artifact path once its upper case is `!`-escaped, plus the escaped version.
_MAX_PATH = 8192
_MAX_NAME = names.GO_MAX_LEN


def _text_ok(value: Any, limit: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit and _CONTROL.search(value) is None


def _fingerprint(item: Any, now: float) -> tuple[str, str, str, float, str, str | None] | None:
    """A reported fingerprint, checked: (ecosystem, path, sha256, first_seen, package, version). It can't have been
    seen after `now` (beyond the clock skew signatures allow)."""
    if not isinstance(item, list) or len(item) != 6:
        return None
    eco, path, sha256, first_seen, package, version = item
    # The range also refuses NaN, the infinities and integers too large for a float, without converting them.
    ok = (
        eco in ECOSYSTEMS and _text_ok(path, _MAX_PATH)
        and isinstance(sha256, str) and _HEX64.fullmatch(sha256) is not None
        and isinstance(first_seen, (int, float)) and not isinstance(first_seen, bool)
        and 0 <= first_seen <= now + signing.MAX_SKEW and _text_ok(package, _MAX_NAME)
        and (version is None or _text_ok(version, _MAX_NAME))
    )  # fmt: skip
    return (eco, path, sha256, float(first_seen), package, version) if ok else None


def _take_fingerprint(conn: Any, member: str, item: Any, now: float) -> None:
    """A follower's first fingerprint of a file it served. The leader can't see what a follower served, so what it
    reports is evidence about that follower only, and it is checked against what the leader knows itself: when the
    leader has a record of the file, the follower must name the same package and version for it."""
    fp = _fingerprint(item, now)
    if fp is None:
        log.warning("ignored a malformed fingerprint", extra={"member": member})
        return
    eco, path, sha256, first_seen, package, version = fp
    mine = conn.execute(
        "SELECT sha256, package, version FROM artifacts WHERE ecosystem = ? AND path = ? AND sha256 IS NOT NULL",
        (eco, path),
    ).fetchone()
    if mine is not None and (mine[1], mine[2]) != (package, version):
        log.warning(
            "refused a fingerprint that names another package than the leader's record of the file",
            extra={"member": member, "ecosystem": eco, "artifact": path},
        )
        return
    added = conn.execute(
        "INSERT OR IGNORE INTO shieldwall_fingerprints (ecosystem, path, instance, sha256, first_seen, package, "
        "version) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (eco, path, member, sha256, first_seen, package, version),
    ).rowcount
    if added:
        _compare_fingerprint(conn, member, (eco, path, package, version), sha256=sha256,
                             leader_sha256=mine[0] if mine else None, now=now)  # fmt: skip


def _compare_fingerprint(
    conn: Any, member: str, file: tuple[str, str, str, str | None], *, sha256: str, leader_sha256: str | None,
    now: float,
) -> None:  # fmt: skip
    """A follower saw other bytes for an immutable file than this leader did: one of them was served something
    else. A follower's word is never enough to refuse a file everywhere (it could be lying), so the file is refused
    on that follower only, and only if that follower has those very bytes on record (apply._flag). Followers that
    disagree among themselves, where this leader has no fingerprint of its own, are recorded for the operator on the
    leader's own timeline: the leader can't tell which of them is right, so none of them is named as the culprit."""
    eco, path, package, version = file
    instance = member
    if leader_sha256 is not None:
        if leader_sha256 == sha256:
            return
        conn.execute(
            "UPDATE shieldwall_fingerprints SET flagged = ? WHERE ecosystem = ? AND path = ? AND instance = ?",
            (now, eco, path, member),
        )
        conn.execute(
            "INSERT OR REPLACE INTO shieldwall_changes (dataset, key, ts) VALUES ('flag', ?, ?)",
            (f"{eco}\n{path}\n{member}", now),
        )
        kind = "tampered"
        details: dict[str, Any] = {
            "artifact": path, "reason": "this instance saw different bytes than the leader", "observed_sha256": sha256,
            "stored_sha256": leader_sha256,
        }  # fmt: skip
    else:
        seen = dict(
            conn.execute(
                "SELECT f.instance, f.sha256 FROM shieldwall_fingerprints f WHERE f.ecosystem = ? AND f.path = ?",
                (eco, path),
            ).fetchall()
        )
        if len(set(seen.values())) < 2:
            return
        names = dict(conn.execute("SELECT id, name FROM shieldwall_members").fetchall())
        kind, instance = "integrity_mismatch", ""
        details = {
            "artifact": path, "reason": "instances saw different bytes; the leader has none of its own to compare",
            "problems": [f"{names.get(i, i)}: {s}" for i, s in sorted(seen.items())],
        }  # fmt: skip
    conn.execute(
        "INSERT INTO events (ts, type, ecosystem, package, version, count, details, instance) "
        "VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
        (now, kind, eco, package, version, json.dumps(details), instance),
    )


# ---- the service --------------------------------------------------------------------------------------------


def _entries(value: Any) -> list[dict[str, Any]]:
    """The outbox entries a sync carries, each with a sequence number, a kind and a body."""
    if not isinstance(value, list):
        raise TypeError("outbox: expected a list")
    for entry in value:
        if not (isinstance(entry, dict) and isinstance(entry.get("kind"), str) and isinstance(entry.get("body"), str)):
            raise TypeError("outbox: malformed entry")
        wire.seq(entry.get("seq"))
    return value


def _wait(text: str) -> float:
    """How long a sync may be held open: up to MAX_WAIT, and not at all for anything that isn't a number."""
    try:
        wait = float(text or 0)
    except ValueError:
        return 0.0
    return min(max(wait, 0.0), MAX_WAIT) if math.isfinite(wait) else 0.0


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
            doc = wire.loads(body)
            pubkey = base64.b64decode(doc["pubkey"], validate=True)
            signed = signing.verify_request(
                headers, "POST", request.url.path, request.url.query, body, public_key=pubkey, now=now
            )
            created = int(doc.get("created", 0))
        except (ValueError, KeyError, TypeError, signing.SignatureError) as exc:
            return JSONResponse({"error": "bad_request", "detail": str(exc)}, status_code=400)
        member = instance_id(pubkey)
        if signed.keyid != member:
            return JSONResponse({"error": "bad_request", "detail": "key id doesn't match the key"}, status_code=400)
        if member == self.identity.id:
            return JSONResponse({"error": "bad_request", "detail": "that is this leader's own key"}, status_code=400)
        token_id = str(doc.get("token", ""))
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
            doc = wire.loads(body)
            if not isinstance(doc, dict):
                raise TypeError("expected an object")
            cursor = wire.seq(doc.get("cursor", 0))
            policy_version = wire.seq(doc.get("policy_version", 0))
            entries = _entries(doc.get("outbox", []))
            status = doc.get("status", {}) if isinstance(doc.get("status"), dict) else {}
        except (ValueError, TypeError) as exc:
            return self._reply(signed.signature, {"error": "bad_request", "detail": str(exc)}, status=400)
        wait = _wait(request.query_params.get("wait", ""))
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
        changes, more = await asyncio.to_thread(self._changes, cursor, member)
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

    def _changes(self, cursor: int, member: str) -> tuple[list[dict[str, Any]], bool]:
        conn = self.ctx.db.readers.get()
        return change_rows(conn, cursor, CHANGES_PER_SYNC, member)

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
        """The sha256 this leader computed for a file it knows by another digest. Only ever a content address: the
        cache finds files by it, so nothing else may reach a file path."""
        row = await self.ctx.db.readers.aone(
            "SELECT sha256 FROM shieldwall_blobs WHERE alg = ? AND digest = ?", (alg, digest)
        )
        return row[0] if row and _SHA256.fullmatch(row[0]) else None
