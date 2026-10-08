"""An instance's shield wall role at runtime: set up at startup, and every worker kept current with what the leader
decided (the policy overlay, whether files may come from the leader)."""

from __future__ import annotations

import logging
from functools import partial
from pathlib import Path
from typing import Any

from slowshield.context import AppContext
from slowshield.shieldwall.identity import Identity
from slowshield.shieldwall.policy import Bundle, effective

log = logging.getLogger(__name__)

OUTBOX_KEEP = 30 * 86400.0  # reports the leader never took (it was gone that long) are dropped after this


def identity(ctx: AppContext) -> Identity | None:
    """This instance's shield wall key, created on first use. A standalone instance has none."""
    if ctx.cfg.raw.shieldwall.role == "standalone":
        return None
    return Identity.load_or_create(Path(ctx.cfg.raw.data_dir))


def stored_role(conn: Any) -> str | None:
    """The role the last start recorded (`set_role`); an instance without a configured role keeps it."""
    row = conn.execute("SELECT value FROM meta WHERE key = 'shieldwall_role'").fetchone()
    return row[0] if row else None


def stored_leader_url(conn: Any) -> str | None:
    """The leader a follower found with its join string: a paired follower syncs with it without one."""
    row = conn.execute("SELECT url FROM shieldwall_leader WHERE id = 1").fetchone()
    return row[0] if row else None


def set_role(conn: Any, role: str, now: float) -> None:
    """Record the role where the change-capture triggers read it. A leader starts its change log with everything
    followers take, so the first follower gets the whole past (the bootstrap). An instance that is no longer a
    follower stops queueing reports."""
    row = conn.execute("SELECT value FROM meta WHERE key = 'shieldwall_role'").fetchone()
    previous = row[0] if row else "standalone"
    if previous != role:
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('shieldwall_role', ?) ON CONFLICT (key) DO UPDATE SET value = "
            "excluded.value",
            (role,),
        )
    if role == "leader" and previous != "leader":
        for sql in (
            "SELECT 'block', CAST(id AS TEXT) FROM blocklist WHERE source IN ('config', 'github') "
            "AND withdrawn IS NULL",
            "SELECT 'tamper', ecosystem || char(10) || path FROM artifacts WHERE tampered = 1",
            "SELECT 'gone', repository || char(10) || digest FROM oci_digests WHERE gone IS NOT NULL",
            "SELECT 'tag', repository || char(10) || tag || char(10) || digest FROM oci_tags",
            "SELECT 'listed', ecosystem || char(10) || name || char(10) || version FROM package_versions "
            "WHERE first_listed IS NOT NULL",
        ):
            conn.execute(
                f"INSERT OR IGNORE INTO shieldwall_changes (dataset, key, ts) SELECT *, ? FROM ({sql})", (now,)
            )
    if role != "follower":
        conn.execute("UPDATE shieldwall_leader SET state = 'detached' WHERE state IN ('pending', 'active')")
        conn.execute("DELETE FROM shieldwall_outbox")


async def refresh(ctx: AppContext) -> bool:
    """Bring this worker up to date with the follower state the shield wall loop wrote. Returns whether the config
    changed."""
    if ctx.cfg.raw.shieldwall.role != "follower":
        return False
    row = await ctx.db.readers.aone("SELECT state, policy FROM shieldwall_leader WHERE id = 1")
    state, policy = (row[0], row[1]) if row else (None, None)
    via = ctx.artifacts.via
    if via is not None:
        via.active = state == "active"
    if policy is None or state in ("removed", "detached"):
        changed = ctx.config.set_overlay(None, None)
    else:
        changed = ctx.config.set_overlay(policy, partial(effective, bundle=Bundle.from_json(policy)))
    if changed:
        log.info("leader policy applied", extra={"generation": ctx.cfg.generation, "leader_policy": policy is not None})
    return changed


async def housekeeping(ctx: AppContext) -> None:
    """A follower's periodic chores, leader or not: due hold-downs apply, very old reports go."""
    from slowshield.shieldwall.apply import promote_due

    now = ctx.clock.now()

    def op(conn: Any) -> None:
        promote_due(conn, now)
        conn.execute("DELETE FROM shieldwall_outbox WHERE created < ?", (now - OUTBOX_KEEP,))

    await ctx.db.writer.run(op)


def retention(conn: Any, now: float) -> None:
    """Shield wall bookkeeping that runs out: a leader's used or expired invitations."""
    conn.execute("DELETE FROM shieldwall_tokens WHERE expires < ?", (now - 7 * 86400,))
