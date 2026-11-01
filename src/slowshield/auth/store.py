"""Users, UI sessions and the audit log in SQLite (migration 0009). Functions take a connection, so writes go through
the single writer (`db.writer.run(partial(...))`) and reads through the per-thread readers."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Any

from slowshield.auth import Principal

DAY = 86400.0
LAST_SEEN_EVERY = 60.0  # a session's last_seen is written at most once a minute


def session_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


@dataclass(frozen=True, slots=True)
class Identity:
    """What a sign-in established, whatever the provider."""

    provider: str
    issuer: str
    subject: str
    email: str | None
    email_verified: bool
    name: str | None
    role: str
    role_source: str


@dataclass(frozen=True, slots=True)
class Session:
    principal: Principal
    host: str
    expires: float
    last_seen: float
    last_recheck: float
    id_token: str | None


@dataclass(frozen=True, slots=True)
class Upserted:
    user_id: int
    disabled: bool
    previous_role: str | None  # None: first sign-in


def upsert_user(conn: sqlite3.Connection, ident: Identity, now: float) -> Upserted:
    """Create the user at first sign-in, update name, email and role at every later one. A disabled user is left as
    it is."""
    row = conn.execute(
        "SELECT id, disabled, role FROM users WHERE instance = '' AND issuer = ? AND subject = ?",
        (ident.issuer, ident.subject),
    ).fetchone()
    if row is None:
        cur = conn.execute(
            "INSERT INTO users (provider, issuer, subject, email, email_verified, name, role, role_source, "
            "first_login, last_login) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ident.provider, ident.issuer, ident.subject, ident.email, int(ident.email_verified), ident.name,
             ident.role, ident.role_source, now, now),
        )  # fmt: skip
        return Upserted(int(cur.lastrowid or 0), False, None)
    user_id, disabled = int(row[0]), row[1] is not None
    if not disabled:
        conn.execute(
            "UPDATE users SET email = ?, email_verified = ?, name = ?, role = ?, role_source = ?, last_login = ? "
            "WHERE id = ?",
            (ident.email, int(ident.email_verified), ident.name, ident.role, ident.role_source, now, user_id),
        )
    return Upserted(user_id, disabled, str(row[2]))


def create_session(
    conn: sqlite3.Connection,
    *,
    token: str,
    user_id: int,
    host: str,
    idp_sid: str | None,
    id_token: str | None,
    now: float,
    hours: float,
    replaces: str | None = None,
) -> None:
    """A new session (a new ID at every sign-in and recheck: no fixation). A recheck keeps the absolute expiry of the
    session it replaces."""
    expires = now + hours * 3600
    if replaces:
        old = conn.execute("SELECT expires, created FROM ui_sessions WHERE id_hash = ?", (replaces,)).fetchone()
        conn.execute("DELETE FROM ui_sessions WHERE id_hash = ?", (replaces,))
        if old is not None:
            expires = min(expires, float(old[0]))
    conn.execute(
        "INSERT INTO ui_sessions (id_hash, user_id, host, idp_sid, id_token, created, expires, last_seen, "
        "last_recheck) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (session_hash(token), user_id, host, idp_sid, id_token, now, expires, now, now),
    )


def load_session(conn: sqlite3.Connection, token: str, now: float) -> Session | None:
    row = conn.execute(
        "SELECT s.id_hash, s.host, s.expires, s.last_seen, s.last_recheck, s.id_token, u.id, u.role, u.name, u.email "
        "FROM ui_sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.id_hash = ? AND s.expires > ? AND u.disabled IS NULL",
        (session_hash(token), now),
    ).fetchone()
    if row is None:
        return None
    principal = Principal(role=row[7], user_id=int(row[6]), name=row[8], email=row[9], session=row[0])
    return Session(principal, row[1], float(row[2]), float(row[3]), float(row[4]), row[5])


def defer_recheck(conn: sqlite3.Connection, id_hash: str, at: float) -> None:
    conn.execute("UPDATE ui_sessions SET last_recheck = ? WHERE id_hash = ?", (at, id_hash))


def touch(conn: sqlite3.Connection, id_hash: str, now: float) -> None:
    conn.execute("UPDATE ui_sessions SET last_seen = ? WHERE id_hash = ?", (now, id_hash))


def delete_session(conn: sqlite3.Connection, id_hash: str) -> None:
    conn.execute("DELETE FROM ui_sessions WHERE id_hash = ?", (id_hash,))


def set_disabled(conn: sqlite3.Connection, user_id: int, disabled: bool, now: float) -> bool:
    """Disable (sessions dropped at once) or enable a user. Returns whether anything changed."""
    if disabled:
        changed = conn.execute(
            "UPDATE users SET disabled = ? WHERE id = ? AND instance = '' AND disabled IS NULL", (now, user_id)
        ).rowcount
        conn.execute("DELETE FROM ui_sessions WHERE user_id = ?", (user_id,))
        return bool(changed)
    return bool(
        conn.execute(
            "UPDATE users SET disabled = NULL WHERE id = ? AND instance = '' AND disabled IS NOT NULL", (user_id,)
        ).rowcount
    )


def logout_all(conn: sqlite3.Connection) -> int:
    return conn.execute("DELETE FROM ui_sessions").rowcount


def audit(
    conn: sqlite3.Connection,
    *,
    now: float,
    action: str,
    principal: Principal | None = None,
    actor: str | None = None,
    target: str | None = None,
    details: dict[str, Any] | None = None,
    client_ip: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO audit_log (ts, user_id, actor, action, target, details, client_ip) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            now,
            principal.user_id if principal is not None else None,
            actor or (principal.label if principal is not None and principal.signed_in else None),
            action,
            target,
            json.dumps(details, separators=(",", ":"), sort_keys=True) if details else None,
            client_ip,
        ),
    )


def retention(conn: sqlite3.Connection, now: float, *, audit_days: float, ip_days: float) -> None:
    conn.execute("DELETE FROM ui_sessions WHERE expires <= ?", (now,))
    conn.execute("DELETE FROM audit_log WHERE ts < ?", (now - audit_days * DAY,))
    conn.execute("UPDATE audit_log SET client_ip = NULL WHERE client_ip IS NOT NULL AND ts < ?", (now - ip_days * DAY,))


def active_sessions(conn: sqlite3.Connection, now: float) -> int:
    return int(conn.execute("SELECT count(*) FROM ui_sessions WHERE expires > ?", (now,)).fetchone()[0])
