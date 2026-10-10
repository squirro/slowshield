"""What a follower takes from its leader, applied by trust class (docs/design/shieldwall.md, "Down").

One sync response is applied in one transaction, together with the bookkeeping: acknowledged outbox entries go,
the sync is logged for the late-news rule, the cursor moves.

- **Tightening applies at once:** new blocks, takedowns, tamper flags, a stricter policy.
- **Loosening is bounded:** a looser policy waits an hour (the stricter of old and new applies meanwhile), a block
  the leader lifts stays for a day, and an observation time from the leader counts no further back than the
  late-news rule allows.
- **Some things never come from the leader:** upstreams, caches, privacy settings, its own shield wall settings. They
  aren't in the bundle, and nothing here would apply them.
"""

from __future__ import annotations

import json
import logging
import math
from typing import Any

from slowshield.blocklist import bump_generation
from slowshield.config import ECOSYSTEMS, LoadedConfig
from slowshield.shieldwall.policy import POLICY_HOLD, Bundle, BundleError, loosens, tightest

log = logging.getLogger(__name__)

GRACE = 600.0  # the leader's batched writer and clock skew
MAX_OUTAGE_CREDIT = 86400.0  # how far back an entry logged during an outage can be dated
UNBLOCK_HOLD = 86400.0  # a block the leader lifts stays this long
SYNC_LOG_KEEP = 40 * 86400.0
_TEXT = 300


def apply_sync(conn: Any, cfg: LoadedConfig, doc: dict[str, Any], now: float, *, sent: int, me: str) -> int:
    """Apply one sync response. `cfg` is this instance's own config (not the merged one), `sent` the last outbox
    entry the request carried (0: none), `me` this instance's ID. Returns the new cursor."""
    problem = acknowledge(conn, int(doc.get("ack", 0)), sent)
    head = int(doc.get("head", 0))
    row = conn.execute("SELECT cursor, boot_head FROM shieldwall_leader WHERE id = 1").fetchone()
    cursor, boot_head = int(row[0]), int(row[1])
    if isinstance(doc.get("policy"), dict):
        receive_policy(conn, cfg, doc["policy"], now)
    own_github = cfg.github_token is not None and cfg.raw.feeds.github_advisory.enabled
    blocks = False
    for change in doc.get("changes") or []:
        seq = int(change["seq"])
        if seq <= cursor:
            continue
        dataset, data = change.get("dataset"), change.get("row") or {}
        try:
            if dataset == "block":
                blocks |= _block(conn, data, now, own_github=own_github)
            elif dataset == "tamper":
                _tamper(conn, data, now)
            elif dataset == "flag" and data.get("instance") == me:
                _flag(conn, data, now)
            elif dataset == "gone":
                _gone(conn, data, now)
            elif dataset in ("tag", "listed"):
                claimed = float(data["first_seen" if dataset == "tag" else "first_listed"])
                when = credited(conn, claimed, seq, now, boot_head=boot_head)
                (_tag if dataset == "tag" else _listed)(conn, data, when)
        except (KeyError, TypeError, ValueError) as exc:
            log.warning("skipped a change from the leader", extra={"dataset": dataset, "seq": seq,
                                                                          "error": str(exc)})  # fmt: skip
        cursor = seq
    if blocks:
        bump_generation(conn)
    _log_sync(conn, now, head)
    leader = doc.get("leader")
    leader_name = str(leader.get("name") or "")[:100] or None if isinstance(leader, dict) else None
    conn.execute(
        "UPDATE shieldwall_leader SET cursor = ?, last_sync = ?, last_attempt = ?, last_error = ?, "
        "name = coalesce(?, name) WHERE id = 1",
        (cursor, now, now, problem, leader_name),
    )
    promote_due(conn, now)
    return cursor


def acknowledge(conn: Any, ack: int, sent: int) -> str | None:
    """Delete the reports the leader acknowledged. Returns what was wrong with the acknowledgement, if anything.

    The leader applies what a request carries and acknowledges its high-water mark, which is never past the last
    entry the request carried (`sent`). One that is (a buggy leader, or one that was taken over) is refused, and
    the whole outbox stays: deleting "up to the ack" would erase reports that were never sent. With nothing sent,
    there is nothing to delete, and the mark the leader returns is just its own."""
    if not sent:
        return None
    if ack > sent:
        log.error(
            "refused the leader's acknowledgement: it names reports this instance never sent; keeping the outbox",
            extra={"ack": ack, "sent": sent},
        )
        return f"the leader acknowledged report {ack}, but this instance sent up to {sent}: kept every report"
    conn.execute("DELETE FROM shieldwall_outbox WHERE seq <= ?", (ack,))
    return None


# ---- the late-news rule -----------------------------------------------------------------------------------


def credited(conn: Any, claimed: float, seq: int, now: float, *, boot_head: int) -> float:
    """The time an observation from the leader is credited with: its claim, but no earlier than the last sync at
    which the leader's change log didn't have it yet (less a grace), and no earlier than a day ago. Changes from
    before pairing are the bootstrap, trusted as they are."""
    if not math.isfinite(claimed):
        raise ValueError("observation time is not a number")
    claimed = min(claimed, now)
    if seq <= boot_head:
        return claimed
    last_without = conn.execute("SELECT max(ts) FROM shieldwall_sync_log WHERE head < ?", (seq,)).fetchone()[0]
    floor = now if last_without is None else float(last_without) - GRACE
    return min(max(claimed, floor, now - MAX_OUTAGE_CREDIT), now)


def _log_sync(conn: Any, now: float, head: int) -> None:
    last = conn.execute("SELECT ts, head FROM shieldwall_sync_log ORDER BY ts DESC LIMIT 1").fetchone()
    if last is not None and int(last[1]) == head:
        conn.execute("UPDATE shieldwall_sync_log SET ts = ? WHERE ts = ?", (now, last[0]))
    else:
        conn.execute("INSERT OR REPLACE INTO shieldwall_sync_log (ts, head) VALUES (?, ?)", (now, head))
    # The newest entry always stays: it is what bounds the changes logged during an outage.
    conn.execute(
        "DELETE FROM shieldwall_sync_log WHERE ts < ? AND ts < (SELECT max(ts) FROM shieldwall_sync_log)",
        (now - SYNC_LOG_KEEP,),
    )


# ---- policy -------------------------------------------------------------------------------------------------


def receive_policy(conn: Any, cfg: LoadedConfig, doc: dict[str, Any], now: float) -> None:
    try:
        bundle = Bundle.parse(doc)
    except BundleError as exc:
        log.error("ignored a policy from the leader", extra={"error": str(exc)})
        conn.execute("UPDATE shieldwall_leader SET last_error = ? WHERE id = 1", (f"policy ignored: {exc}",))
        return
    row = conn.execute("SELECT policy_version, policy FROM shieldwall_leader WHERE id = 1").fetchone()
    if bundle.version <= int(row[0]):
        return  # an old bundle (a leader restored from backup): never roll back
    oci = cfg.raw.upstreams.oci
    conn.execute("DELETE FROM shieldwall_pending WHERE kind = 'policy'")
    applied = Bundle.from_json(row[1]) if row[1] else None
    looser = loosens(applied, bundle, oci) if applied is not None else []
    if applied is None or not looser:
        new = bundle  # tighter or equal, or the first bundle after pairing (trusted as the bootstrap)
    else:
        new = tightest(applied, bundle, oci)
        due = now + POLICY_HOLD
        conn.execute(
            "INSERT INTO shieldwall_pending (kind, key, due, body) VALUES ('policy', '', ?, ?)", (due, bundle.to_json())
        )
        log.warning("the leader loosened the policy: applies in an hour", extra={"changes": looser[:20]})
    conn.execute(
        "UPDATE shieldwall_leader SET policy_version = ?, policy = ? WHERE id = 1", (bundle.version, new.to_json())
    )


def promote_due(conn: Any, now: float) -> bool:
    """Apply what has waited out its hold-down. Returns whether anything changed."""
    due = conn.execute("SELECT kind, key, body FROM shieldwall_pending WHERE due <= ?", (now,)).fetchall()
    unblocked = 0
    for kind, key, body in due:
        if kind == "policy":
            conn.execute("UPDATE shieldwall_leader SET policy = ? WHERE id = 1", (body,))
            log.info("the leader's looser policy applies now", extra={"version": Bundle.from_json(body).version})
        elif kind == "unblock":
            unblocked += conn.execute(
                "UPDATE blocklist SET withdrawn = ?, updated = ? WHERE source = 'leader' AND leader_id = ? "
                "AND withdrawn IS NULL",
                (now, now, int(key)),
            ).rowcount
        conn.execute("DELETE FROM shieldwall_pending WHERE kind = ? AND key = ?", (kind, key))
    if unblocked:
        bump_generation(conn)
    return bool(due)


# ---- changes ----------------------------------------------------------------------------------------------------


def _text(value: Any, limit: int = _TEXT) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError("expected text")
    return value[:limit]


def _name(value: Any) -> str:
    text = _text(value)
    if not text:
        raise ValueError("empty name")
    return text


def _url(value: Any) -> str | None:
    text = _text(value, 500)
    return text if text and text.startswith(("https://", "http://")) else None


def _block(conn: Any, row: dict[str, Any], now: float, *, own_github: bool) -> bool:
    """A block from the leader joins this instance's own (as a `leader` row). Returns whether the active set grew."""
    lid = int(row["id"])
    mine = conn.execute(
        "SELECT id, withdrawn FROM blocklist WHERE source = 'leader' AND leader_id = ?", (lid,)
    ).fetchone()
    if row.get("deleted") or row.get("withdrawn") is not None:
        if mine is not None and mine[1] is None:  # lifted on the leader: stays here for a day
            conn.execute(
                "INSERT OR IGNORE INTO shieldwall_pending (kind, key, due) VALUES ('unblock', ?, ?)",
                (str(lid), now + UNBLOCK_HOLD),
            )
        return False
    source = row["source"]
    if source not in ("config", "github") or (source == "github" and own_github):
        return False  # this instance reads GitHub's advisories itself
    eco = row["ecosystem"]
    if eco not in ECOSYSTEMS:
        raise ValueError(f"unknown ecosystem {eco!r}")
    name, version, version_range = _name(row["name"]), _text(row.get("version")), _text(row.get("version_range"))
    advisory = (_text(row.get("advisory_id")) or "") if source == "github" else ""
    reason, url = _text(row.get("reason"), 2000), _url(row.get("url"))
    conn.execute("DELETE FROM shieldwall_pending WHERE kind = 'unblock' AND key = ?", (str(lid),))
    if mine is None:
        mine = conn.execute(
            "SELECT id, withdrawn FROM blocklist WHERE source = 'leader' AND ecosystem = ? AND name = ? "
            "AND ifnull(version, '') = ifnull(?, '') AND ifnull(version_range, '') = ifnull(?, '') AND advisory_id = ?",
            (eco, name, version, version_range, advisory),
        ).fetchone()
    if mine is not None:
        conn.execute(
            "UPDATE blocklist SET leader_id = ?, reason = ?, url = ?, withdrawn = NULL, updated = ? WHERE id = ?",
            (lid, reason, url, now, mine[0]),
        )
        return mine[1] is not None
    conn.execute(
        "INSERT INTO blocklist (ecosystem, name, version, version_range, source, advisory_id, reason, url, "
        "first_seen, updated, leader_id) VALUES (?, ?, ?, ?, 'leader', ?, ?, ?, ?, ?, ?)",
        (eco, name, version, version_range, advisory, reason, url, now, now, lid),
    )
    return True


def _tamper(conn: Any, row: dict[str, Any], now: float) -> None:
    """The leader saw different bytes for this file than it (or another instance) saw first: refuse it here too."""
    eco = row["ecosystem"]
    if eco not in ECOSYSTEMS:
        raise ValueError(f"unknown ecosystem {eco!r}")
    path, package = _name(row["path"]), _name(row["package"])
    version, filename = _text(row.get("version")), _text(row.get("filename")) or path.rsplit("/", 1)[-1]
    flagged = conn.execute(
        "INSERT INTO artifacts (ecosystem, path, package, version, filename, first_seen, last_seen, tampered) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1) ON CONFLICT (ecosystem, path) DO UPDATE SET tampered = 1 "
        "WHERE artifacts.tampered = 0",
        (eco, path, package, version, filename, now, now),
    ).rowcount
    if flagged:
        conn.execute(
            "INSERT INTO events (ts, type, ecosystem, package, version, count, details, instance) "
            "VALUES (?, 'tampered', ?, ?, ?, 1, ?, '')",
            (now, eco, package, version, json.dumps({"artifact": path, "reason": "flagged by the shield wall leader"})),
        )


def _flag(conn: Any, row: dict[str, Any], now: float) -> None:
    """The leader saw other bytes for a file than this instance did: refuse this instance's copy."""
    eco, path = row["ecosystem"], _name(row["path"])
    if eco not in ECOSYSTEMS:
        raise ValueError(f"unknown ecosystem {eco!r}")
    flagged = conn.execute(
        "UPDATE artifacts SET tampered = 1 WHERE ecosystem = ? AND path = ? AND sha256 = ? AND tampered = 0",
        (eco, path, _name(row["sha256"])),
    ).rowcount
    if flagged:
        details = {"artifact": path, "reason": "the leader saw different bytes for this file"}
        conn.execute(
            "INSERT INTO events (ts, type, ecosystem, package, version, count, details, instance) "
            "VALUES (?, 'tampered', ?, ?, ?, 1, ?, '')",
            (now, eco, _name(row["package"]), _text(row.get("version")), json.dumps(details)),
        )


def _gone(conn: Any, row: dict[str, Any], now: float) -> None:
    gone = min(float(row["gone"]), now)
    conn.execute(
        "INSERT INTO oci_digests (repository, digest, first_seen, gone) VALUES (?, ?, ?, ?) "
        "ON CONFLICT (repository, digest) DO UPDATE SET gone = min(coalesce(oci_digests.gone, excluded.gone), "
        "excluded.gone)",
        (_name(row["repository"]), _name(row["digest"]), now, gone),
    )


def _tag(conn: Any, row: dict[str, Any], when: float) -> None:
    conn.execute(
        "INSERT INTO oci_tags (repository, tag, digest, first_seen, last_seen) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT (repository, tag, digest) DO UPDATE SET "
        "first_seen = min(oci_tags.first_seen, excluded.first_seen)",
        (_name(row["repository"]), _name(row["tag"]), _name(row["digest"]), when, when),
    )


def _listed(conn: Any, row: dict[str, Any], when: float) -> None:
    eco = row["ecosystem"]
    if eco not in ECOSYSTEMS:
        raise ValueError(f"unknown ecosystem {eco!r}")
    conn.execute(
        "INSERT INTO package_versions (ecosystem, name, version, first_listed) VALUES (?, ?, ?, ?) "
        "ON CONFLICT (ecosystem, name, version) DO UPDATE SET "
        "first_listed = min(coalesce(package_versions.first_listed, excluded.first_listed), excluded.first_listed)",
        (eco, _name(row["name"]), _name(row["version"]), when),
    )
