"""`slowshield shieldwall ...`: invitations and members on a leader, the pairing on a follower.

Runs next to the server (in its container: `docker exec slowshield slowshield shieldwall invite`), on the same database.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path

from slowshield import config as config_mod
from slowshield.db import connect, migrate
from slowshield.shieldwall.identity import Identity, key_hash
from slowshield.shieldwall.join import TOKEN_TTL, JoinString, new_token


def _open(args: argparse.Namespace) -> tuple[config_mod.LoadedConfig, sqlite3.Connection]:
    cfg = config_mod.load(Path(args.config) if args.config else None)
    migrate(cfg.db_path)
    return cfg, connect(cfg.db_path)


def _ago(ts: float | None) -> str:
    if not ts:
        return "never"
    s = int(time.time() - ts)
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= n:
            return f"{s // n}{unit} ago"
    return f"{max(s, 0)}s ago"


def cmd_invite(args: argparse.Namespace) -> int:
    cfg, conn = _open(args)
    if cfg.raw.shieldwall.role != "leader":
        print(
            "this instance isn't a shield wall leader: set SLOWSHIELD_SHIELDWALL_ROLE=leader, restart it, then invite",
            file=sys.stderr,
        )
        return 2
    url = (args.url or cfg.raw.public_url or "").rstrip("/")
    if not url.startswith(("https://", "http://")):
        print("the leader needs a URL followers reach: set SLOWSHIELD_PUBLIC_URL or pass --url", file=sys.stderr)
        return 2
    minutes = max(1, min(args.minutes, 60))
    identity = Identity.load_or_create(Path(cfg.raw.data_dir))
    token_id, secret = new_token()
    now = time.time()
    conn.execute(
        "INSERT INTO shieldwall_tokens (id, secret, created, expires, name, location) VALUES (?, ?, ?, ?, ?, ?)",
        (token_id, secret, now, now + minutes * 60, args.name, args.location),
    )
    join = JoinString(url, key_hash(identity.public_key), token_id, secret)
    if args.quiet:
        print(join)
        return 0
    print(f"Join string (valid {minutes} minutes, once):\n\n  {join}\n")
    print("On the new instance, set it and start SlowShield:\n")
    print(f"  SLOWSHIELD_JOIN='{join}'\n")
    print("Its Shield wall page then asks to confirm this leader. Check that the fingerprint matches:\n")
    print(f"  {identity.fingerprint}")
    return 0


def cmd_members(args: argparse.Namespace) -> int:
    _cfg, conn = _open(args)
    rows = conn.execute(
        "SELECT id, name, location, labels, version, state, joined, last_seen, status FROM shieldwall_members "
        "ORDER BY name"
    ).fetchall()
    if args.json:
        print(json.dumps([dict(zip(("id", "name", "location", "labels", "version", "state", "joined", "last_seen"),
                                    r[:8], strict=True)) for r in rows], indent=2))  # fmt: skip
        return 0
    if not rows:
        print("no followers yet: `slowshield shieldwall invite` prints a join string")
        return 0
    print(f"{'ID':<18} {'NAME':<24} {'LOCATION':<16} {'STATE':<8} {'VERSION':<12} LAST SEEN")
    for r in rows:
        print(f"{r[0]:<18} {r[1][:24]:<24} {(r[2] or '')[:16]:<16} {r[5]:<8} {(r[4] or '')[:12]:<12} {_ago(r[7])}")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    _cfg, conn = _open(args)
    rows = conn.execute(
        "SELECT id, name FROM shieldwall_members WHERE (id = ? OR name = ?) AND state = 'active'",
        (args.member, args.member),
    ).fetchall()
    if len(rows) != 1:
        print(f"{'no' if not rows else 'more than one'} active follower {args.member!r}", file=sys.stderr)
        return 1
    conn.execute("UPDATE shieldwall_members SET state = 'removed' WHERE id = ?", (rows[0][0],))
    print(f"removed {rows[0][1]} ({rows[0][0]}): its next sync is refused, and it runs on its own from then on")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    cfg, conn = _open(args)
    sw = cfg.raw.shieldwall
    out: dict[str, object] = {"role": sw.role}
    if sw.role != "standalone":
        identity = Identity.load_or_create(Path(cfg.raw.data_dir))
        out |= {"instance": identity.id, "fingerprint": identity.fingerprint}
    if sw.role == "leader":
        out["followers"] = dict(
            conn.execute("SELECT state, count(*) FROM shieldwall_members GROUP BY state").fetchall()
        )
        out["open_invitations"] = conn.execute(
            "SELECT count(*) FROM shieldwall_tokens WHERE used IS NULL AND revoked IS NULL AND expires > ?",
            (time.time(),),
        ).fetchone()[0]
    if sw.role == "follower":
        r = conn.execute(
            "SELECT leader_id, url, name, state, confirmed_by, policy_version, last_sync, last_error "
            "FROM shieldwall_leader"
        ).fetchone()
        keys = ("id", "url", "name", "state", "confirmed_by", "policy_version", "last_sync", "last_error")
        out["leader"] = dict(zip(keys, r, strict=True)) if r else None
        out["outbox"] = conn.execute("SELECT count(*) FROM shieldwall_outbox").fetchone()[0]
    print(json.dumps(out, indent=2))
    return 0


def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    wall = sub.add_parser("shieldwall", help="one leader, many followers: invitations, members, status")
    ssub = wall.add_subparsers(dest="shieldwall_cmd", required=True)

    p = ssub.add_parser("invite", help="print a single-use join string for a new follower (leader)")
    p.add_argument("--name", help="the follower's name on the leader (default: what the follower reports)")
    p.add_argument("--location", help="the follower's location on the leader (default: what it reports)")
    p.add_argument("--url", help="the URL followers reach this leader at (default: public_url)")
    p.add_argument("--minutes", type=int, default=int(TOKEN_TTL // 60), help="validity, 1 to 60 (default 10)")
    p.add_argument("--quiet", "-q", action="store_true", help="print only the join string")
    p.add_argument("--config")
    p.set_defaults(fn=cmd_invite)

    p = ssub.add_parser("members", help="list followers (leader)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--config")
    p.set_defaults(fn=cmd_members)

    p = ssub.add_parser("remove", help="remove a follower: it keeps running, on its own (leader)")
    p.add_argument("member", help="the follower's ID or name")
    p.add_argument("--config")
    p.set_defaults(fn=cmd_remove)

    p = ssub.add_parser("status", help="this instance's role, key fingerprint and pairing")
    p.add_argument("--config")
    p.set_defaults(fn=cmd_status)
