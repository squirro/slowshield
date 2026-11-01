"""`slowshield auth ...` and `slowshield users ...`: the client key for private_key_jwt, and the people who signed in.

Runs next to the server (in its container: `docker exec slowshield slowshield users list`), on the same database.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from slowshield import config as config_mod
from slowshield.auth import jose, store
from slowshield.db import connect, migrate


def _open(args: argparse.Namespace) -> sqlite3.Connection:
    cfg = config_mod.load(Path(args.config) if args.config else None)
    migrate(cfg.db_path)
    return connect(cfg.db_path)


def cmd_client_cert(args: argparse.Namespace) -> int:
    """Print the certificate (and JWK) to register at the IdP for private_key_jwt. With --new, create the key first."""
    path = Path(args.key)
    if args.new:
        if path.exists():
            print(f"{path} exists already; not overwriting a key", file=sys.stderr)
            return 2
        key = jose.new_key(args.new)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(jose.key_pem(key))
        print(f"wrote a new {args.new.upper()} key to {path} (mode 0600)", file=sys.stderr)
    try:
        client = jose.load_client_key(path.read_bytes())
    except (OSError, jose.JoseError) as exc:
        print(f"{path}: {exc}", file=sys.stderr)
        return 2
    cert = jose.self_signed(client.key, args.name, args.days, datetime.datetime.now(datetime.UTC))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    if args.jwk:
        print(json.dumps({"keys": [{**client.public_jwk(), "kid": client.kid, "use": "sig", "alg": client.alg}]}))
    else:
        print(pem, end="")
    print(
        f"\nkey {client.alg}, kid {client.kid}, certificate valid {args.days} days. Register it as the client's "
        "certificate (Keycloak: Credentials > Signed JWT, Keys > Import; Okta: public keys; Entra ID: Certificates). "
        "Entra ID also wants it in the key file: append it to the key.",
        file=sys.stderr,
    )
    return 0


def cmd_hash_password(args: argparse.Namespace) -> int:
    """SLOWSHIELD_AUTH_PASSWORD_HASH for a password: asked twice on a terminal, else read from stdin."""
    import getpass

    from slowshield.auth.password import make_hash

    if sys.stdin.isatty():
        first = getpass.getpass("Password: ")
        if getpass.getpass("Again: ") != first:
            print("the passwords differ", file=sys.stderr)
            return 2
    else:
        first = sys.stdin.readline().rstrip("\n")
    if len(first) < 12:
        print("use a password of 12 characters or more (SHA-256 is fast to guess at)", file=sys.stderr)
        return 2
    print(make_hash(first))
    return 0


def _when(ts: float | None) -> str:
    return "—" if not ts else datetime.datetime.fromtimestamp(ts, datetime.UTC).strftime("%Y-%m-%d %H:%M")


def cmd_users_list(args: argparse.Namespace) -> int:
    conn = _open(args)
    rows = conn.execute(
        "SELECT id, instance, coalesce(name, ''), coalesce(email, ''), role, role_source, last_login, disabled "
        "FROM users ORDER BY last_login DESC"
    ).fetchall()
    if args.json:
        keys = ("id", "instance", "name", "email", "role", "role_source", "last_login", "disabled")
        print(json.dumps([dict(zip(keys, r, strict=True)) for r in rows], indent=2))
        return 0
    if not rows:
        print("nobody has signed in yet")
        return 0
    for r in rows:
        state = " DISABLED" if r[7] else ""
        where = f" [{r[1]}]" if r[1] else ""
        print(f"{r[0]:>5}  {r[4]:<6}  {r[3] or r[2]:<40}  last {_when(r[6])}  ({r[5]}){where}{state}")
    return 0


def cmd_users_disable(args: argparse.Namespace, disabled: bool) -> int:
    conn = _open(args)
    now = time.time()
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT coalesce(email, name, id) FROM users WHERE id = ? AND instance = ''", (args.id,))
        target = row.fetchone()
        if target is None:
            conn.execute("ROLLBACK")
            print(f"no user {args.id} on this instance", file=sys.stderr)
            return 2
        changed = store.set_disabled(conn, args.id, disabled, now)
        if changed:
            action = "user_disabled" if disabled else "user_enabled"
            store.audit(conn, now=now, action=action, actor="cli", target=str(target[0]))
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    word = "disabled" if disabled else "enabled"
    print(f"user {args.id} {word}" if changed else f"user {args.id} was {word} already")
    return 0


def cmd_users_logout_all(args: argparse.Namespace) -> int:
    conn = _open(args)
    conn.execute("BEGIN IMMEDIATE")
    try:
        n = store.logout_all(conn)
        store.audit(conn, now=time.time(), action="logout_all", actor="cli", details={"sessions": n})
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    print(f"ended {n} session(s); everyone signs in again")
    return 0


def add_parsers(sub: argparse._SubParsersAction) -> None:
    auth = sub.add_parser("auth", help="UI sign-in: the client key for private_key_jwt, the password hash")
    asub = auth.add_subparsers(dest="auth_cmd", required=True)
    p = asub.add_parser("client-cert", help="print a certificate for the client key, to register at the IdP")
    p.add_argument("--key", required=True, help="the key file (SLOWSHIELD_OIDC_CLIENT_KEY_FILE)")
    p.add_argument("--new", choices=("ec", "rsa"), help="create the key first (EC P-256; RSA for Entra ID)")
    p.add_argument("--name", default="slowshield", help="the certificate's common name")
    p.add_argument("--days", type=int, default=730)
    p.add_argument("--jwk", action="store_true", help="print a JWKS instead of a certificate")
    p.set_defaults(fn=cmd_client_cert)
    p = asub.add_parser("hash-password", help="print SLOWSHIELD_AUTH_PASSWORD_HASH for a password (password sign-in)")
    p.set_defaults(fn=cmd_hash_password)

    users = sub.add_parser("users", help="people who signed in to the UI")
    usub = users.add_subparsers(dest="users_cmd", required=True)
    p = usub.add_parser("list", help="list users and their roles")
    p.add_argument("--config")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_users_list)
    for name, flag in (("disable", True), ("enable", False)):
        p = usub.add_parser(name, help=f"{name} a user on this instance" + (" (ends their sessions)" if flag else ""))
        p.add_argument("id", type=int)
        p.add_argument("--config")
        p.set_defaults(fn=lambda a, flag=flag: cmd_users_disable(a, flag))
    p = usub.add_parser("logout-all", help="end every UI session")
    p.add_argument("--config")
    p.set_defaults(fn=cmd_users_logout_all)
