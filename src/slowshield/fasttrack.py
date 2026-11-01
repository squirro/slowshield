"""Fast-tracks: a held-back version released before its delay is up (docs/authentication.md).

An Admin grants one directly, with a reason. A User asks for one, with a reason, and a second person (another User or
an Admin) approves or rejects it, with theirs. Only the release-age delay is lifted: blocks (advisories, operator
blocks) and tamper checks still apply when the version is served, so a version that turns out to be malware later is
refused all the same.

Active fast-tracks become part of the policy on every worker (`ConfigHolder.set_fast_tracks`): the worker that made
the change at once, the others within seconds (`meta.fast_track_generation`).
"""

from __future__ import annotations

import asyncio
import sqlite3
from dataclasses import dataclass
from typing import Any

from slowshield.auth import Principal
from slowshield.auth.store import audit

MAX_MESSAGE = 1000


class FastTrackError(ValueError):
    """Why a fast-track can't be made; the message is shown to the person."""


@dataclass(frozen=True, slots=True)
class Change:
    id: int
    state: str


def message(text: str | None) -> str:
    """A reason is required, and kept short and printable."""
    clean = " ".join((text or "").split())
    if len(clean) < 3:
        raise FastTrackError("Leave a message: why should this version skip its delay?")
    if len(clean) > MAX_MESSAGE:
        raise FastTrackError(f"The message is too long (at most {MAX_MESSAGE} characters).")
    return clean


def tampered(conn: sqlite3.Connection, eco: str, name: str, version: str) -> bool:
    """Whether SlowShield saw this version tampered with: a file whose bytes changed (`artifacts.tampered`), or a
    tamper or integrity event for it, which is how a container image digest that didn't match is remembered."""
    row = conn.execute(
        "SELECT EXISTS (SELECT 1 FROM artifacts WHERE ecosystem = ? AND package = ? AND version = ? AND tampered = 1) "
        "OR EXISTS (SELECT 1 FROM events WHERE ecosystem = ? AND package = ? AND version = ? "
        "AND type IN ('tampered', 'integrity_mismatch'))",
        (eco, name, version, eco, name, version),
    ).fetchone()
    return bool(row[0])


def still_clean(conn: sqlite3.Connection, eco: str, name: str, version: str, blocklist_generation: str) -> None:
    """In the transaction that grants or approves: nothing changed since the checks before it. A blocklist update in
    between (a feed sync) means checking again; a tamper mark means no."""
    row = conn.execute("SELECT value FROM meta WHERE key = 'blocklist_generation'").fetchone()
    if (row[0] if row else "0") != blocklist_generation:
        raise FastTrackError("The blocklist changed just now: please try again.")
    if tampered(conn, eco, name, version):
        raise FastTrackError("This version was detected as tampered; a fast-track can't release it.")


def _bump(conn: sqlite3.Connection) -> None:
    conn.execute("UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'fast_track_generation'")


def _open(conn: sqlite3.Connection, eco: str, name: str, version: str) -> tuple[Any, ...] | None:
    """The open request or active fast-track for a version: (id, state). Plain tuples: this runs on the writer."""
    return conn.execute(
        "SELECT id, state FROM fast_tracks WHERE ecosystem = ? AND package = ? AND version = ? "
        "AND state IN ('pending', 'active')",
        (eco, name, version),
    ).fetchone()


def create(
    conn: sqlite3.Connection,
    *,
    eco: str,
    name: str,
    version: str,
    who: Principal,
    text: str,
    now: float,
    client_ip: str | None,
    blocklist_generation: str,
) -> Change:
    """An Admin's fast-track (active at once) or a User's request (pending until someone else approves)."""
    still_clean(conn, eco, name, version, blocklist_generation)
    existing = _open(conn, eco, name, version)
    if existing is not None:
        raise FastTrackError(
            "This version is fast-tracked already."
            if existing[1] == "active"
            else "This version has a request waiting already: approve or reject it."
        )
    grant = who.can("admin")
    state = "active" if grant else "pending"
    cur = conn.execute(
        "INSERT INTO fast_tracks (ecosystem, package, version, state, requested_by, requester, requested_at, "
        "request_message, decided_by, decider, decided_at, decision_message) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (eco, name, version, state, who.user_id, who.label, now, text,
         who.user_id if grant else None, who.label if grant else None, now if grant else None,
         text if grant else None),
    )  # fmt: skip
    if grant:
        _bump(conn)
    audit(conn, now=now, action="fasttrack_granted" if grant else "fasttrack_requested", principal=who,
          target=f"{eco}/{name}@{version}", details={"message": text}, client_ip=client_ip)  # fmt: skip
    return Change(int(cur.lastrowid or 0), state)


def decide(
    conn: sqlite3.Connection,
    *,
    track_id: int,
    action: str,
    who: Principal,
    text: str,
    now: float,
    client_ip: str | None,
    blocklist_generation: str | None = None,
) -> tuple[str, str, str]:
    """Approve or reject a pending request (not one's own), or revoke an active fast-track (Admins). Returns the
    version it was for."""
    row = conn.execute(
        "SELECT ecosystem, package, version, state, requested_by FROM fast_tracks WHERE id = ?", (track_id,)
    ).fetchone()
    if row is None:
        raise FastTrackError("No such fast-track.")
    target, state_now, requested_by = (row[0], row[1], row[2]), row[3], row[4]
    if action in ("approve", "reject"):
        if state_now != "pending":
            raise FastTrackError("This request was decided already.")
        if requested_by is not None and requested_by == who.user_id:
            raise FastTrackError("Someone else has to approve or reject your own request.")
        if action == "approve" and blocklist_generation is not None:
            still_clean(conn, *target, blocklist_generation)
        state = "active" if action == "approve" else "rejected"
        conn.execute(
            "UPDATE fast_tracks SET state = ?, decided_by = ?, decider = ?, decided_at = ?, decision_message = ? "
            "WHERE id = ? AND state = 'pending'",
            (state, who.user_id, who.label, now, text, track_id),
        )
        if state == "active":
            _bump(conn)
    elif action == "revoke":
        if not who.can("admin"):
            raise FastTrackError("Only an Admin can revoke a fast-track.")
        if state_now not in ("active", "pending"):
            raise FastTrackError("This fast-track isn't active.")
        conn.execute(
            "UPDATE fast_tracks SET state = 'revoked', revoked_by = ?, revoker = ?, revoked_at = ?, revoke_message = ? "
            "WHERE id = ?",
            (who.user_id, who.label, now, text, track_id),
        )
        _bump(conn)
    else:
        raise FastTrackError("Unknown action.")
    verb = {"approve": "approved", "reject": "rejected", "revoke": "revoked"}[action]
    audit(conn, now=now, action=f"fasttrack_{verb}", principal=who, target="{}/{}@{}".format(*target),
          details={"message": text, "request": track_id}, client_ip=client_ip)  # fmt: skip
    return target


def active(conn: sqlite3.Connection) -> frozenset[tuple[str, str, str]]:
    rows = conn.execute("SELECT ecosystem, package, version FROM fast_tracks WHERE state = 'active'").fetchall()
    return frozenset((r[0], r[1], r[2]) for r in rows)


def for_package(conn: sqlite3.Connection, eco: str, name: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM fast_tracks WHERE ecosystem = ? AND package = ? ORDER BY requested_at DESC LIMIT 100",
        (eco, name),
    ).fetchall()


def listing(conn: sqlite3.Connection, states: tuple[str, ...], limit: int = 200) -> list[sqlite3.Row]:
    marks = ",".join("?" for _ in states)
    return conn.execute(
        f"SELECT * FROM fast_tracks WHERE state IN ({marks}) ORDER BY coalesce(revoked_at, decided_at, requested_at) "
        "DESC LIMIT ?",
        (*states, limit),
    ).fetchall()


class Refresher:
    """Keeps one worker's policy in step with the active fast-tracks."""

    def __init__(self, ctx: Any) -> None:
        self.ctx = ctx
        self._generation: str | None = None

    async def refresh(self, *, force: bool = False) -> bool:
        db = self.ctx.db

        def read() -> tuple[str, frozenset[tuple[str, str, str]] | None]:
            conn = db.readers.get()
            row = conn.execute("SELECT value FROM meta WHERE key = 'fast_track_generation'").fetchone()
            gen = row[0] if row else "0"
            if gen == self._generation and not force:
                return gen, None
            return gen, active(conn)

        gen, keys = await asyncio.to_thread(read)
        self._generation = gen
        if keys is None:
            return False
        return self.ctx.config.set_fast_tracks(keys)
