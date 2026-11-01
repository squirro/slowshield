"""Password sign-in (SLOWSHIELD_AUTH=password): one local Admin, for single-user deployments where an IdP is overkill.

The stored hash is scrypt from Python's standard library, with OWASP's parameters (N=2^17, r=8, p=1: 128 MiB and a
fraction of a second per check):

    scrypt:<N>:<r>:<p>:<salt, hex>:<32-byte key, hex>

`slowshield auth hash-password` makes one, and so does a line of `python3` (docs/authentication.md#password-sign-in).

Failed sign-ins are counted in the database, so every worker sees the same counts: at most `PER_ADDRESS` from one
client address and `OVERALL` from all addresses together in `WINDOW`. Each worker checks one password at a time; a
second attempt while one is being checked is turned away rather than queued.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3

PER_ADDRESS = 10  # failed sign-ins from one client address ...
OVERALL = 50  # ... or from everyone together ...
WINDOW = 900.0  # ... in this many seconds, before sign-in waits

N, R, P = 2**17, 8, 1  # OWASP's minimum for scrypt
SCRYPT = re.compile(r"scrypt:(\d{1,8}):(\d{1,2}):(\d{1,2}):([0-9a-fA-F]{16,128}):([0-9a-fA-F]{64})")
MAX_MEMORY = 1 << 30  # what a hash may make one check cost


def problem(stored: str) -> str | None:
    """Why a configured hash can't be used, or None."""
    m = SCRYPT.fullmatch(stored)
    if m is None:
        return "expected scrypt:<N>:<r>:<p>:<salt>:<64 hex digits>"
    n, r, p = int(m[1]), int(m[2]), int(m[3])
    if n < 2**14 or n & (n - 1) or not 1 <= r <= 32 or not 1 <= p <= 16 or 128 * n * r > MAX_MEMORY:
        return "scrypt parameters out of range (N a power of two from 2^14, r 1-32, p 1-16, at most 1 GiB)"
    return None


def make_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    key = _scrypt(password, salt, N, R, P)
    return f"scrypt:{N}:{R}:{P}:{salt.hex()}:{key.hex()}"


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, maxmem=256 * n * r + (1 << 20), dklen=32)


def verify(stored: str, password: str) -> bool:
    """Constant-time comparison against a hash `problem` accepts; anything else never matches."""
    m = SCRYPT.fullmatch(stored)
    if m is None or problem(stored) is not None:
        return False
    key = _scrypt(password, bytes.fromhex(m[4]), int(m[1]), int(m[2]), int(m[3]))
    return hmac.compare_digest(key.hex(), m[5].lower())


def fingerprint(username: str, stored: str) -> str:
    """Changes when the account does: sessions from before a new password (or username) end."""
    return hashlib.sha256(f"{username}\n{stored}".encode()).hexdigest()


def same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ---- failed attempts, shared by every worker ----------------------------------------------------------------------


def _address_key(address: str) -> str:
    """Kept only as a hash, and only for WINDOW: the cap needs to tell addresses apart, not to know them."""
    return hashlib.sha256(address.encode()).hexdigest()[:32]


def throttled(conn: sqlite3.Connection, address: str, now: float) -> bool:
    since = now - WINDOW
    mine = conn.execute(
        "SELECT count(*) FROM login_failures WHERE address = ? AND ts > ?", (_address_key(address), since)
    ).fetchone()[0]
    if mine >= PER_ADDRESS:
        return True
    return conn.execute("SELECT count(*) FROM login_failures WHERE ts > ?", (since,)).fetchone()[0] >= OVERALL


def failed(conn: sqlite3.Connection, address: str, now: float) -> None:
    conn.execute("DELETE FROM login_failures WHERE ts <= ?", (now - WINDOW,))
    conn.execute("INSERT INTO login_failures (address, ts) VALUES (?, ?)", (_address_key(address), now))


def succeeded(conn: sqlite3.Connection, address: str) -> None:
    conn.execute("DELETE FROM login_failures WHERE address = ?", (_address_key(address),))
