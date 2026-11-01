"""Password sign-in (SLOWSHIELD_AUTH=password): one local Admin, for single-user deployments where an IdP is overkill.

The stored hash is scrypt from Python's standard library, with OWASP's parameters (N=2^17, r=8, p=1: 128 MiB and a
fraction of a second per check):

    scrypt:<N>:<r>:<p>:<salt, hex>:<32-byte key, hex>

`slowshield auth hash-password` makes one, and so does a line of `python3` (docs/authentication.md#password-sign-in).
The older `sha256:<salt>:<hex of SHA-256(salt + password)>` still works, with a warning: SHA-256 is fast, so a hash
that leaks is easy to guess at. Failed attempts are slowed down and capped per client address either way.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from collections import deque

FAILURES = 10  # failed sign-ins per client address ...
WINDOW = 900.0  # ... in this many seconds, before it has to wait

N, R, P = 2**17, 8, 1  # OWASP's minimum for scrypt
SCRYPT = re.compile(r"scrypt:(\d{1,8}):(\d{1,2}):(\d{1,2}):([0-9a-fA-F]{16,128}):([0-9a-fA-F]{64})")
SHA256 = re.compile(r"sha256:[A-Za-z0-9._-]{8,128}:[0-9a-fA-F]{64}")
MAX_MEMORY = 1 << 30  # what a hash may make one check cost


def problem(stored: str) -> str | None:
    """Why a configured hash can't be used, or None."""
    if SHA256.fullmatch(stored):
        return None
    m = SCRYPT.fullmatch(stored)
    if m is None:
        return "expected scrypt:<N>:<r>:<p>:<salt>:<64 hex digits> (or the older sha256:<salt>:<64 hex digits>)"
    n, r, p = int(m[1]), int(m[2]), int(m[3])
    if n < 2**14 or n & (n - 1) or not 1 <= r <= 32 or not 1 <= p <= 16 or 128 * n * r > MAX_MEMORY:
        return "scrypt parameters out of range (N a power of two from 2^14, r 1-32, p 1-16, at most 1 GiB)"
    return None


def weak(stored: str) -> bool:
    return stored.startswith("sha256:")


def make_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    key = _scrypt(password, salt, N, R, P)
    return f"scrypt:{N}:{R}:{P}:{salt.hex()}:{key.hex()}"


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, maxmem=256 * n * r + (1 << 20), dklen=32)


def verify(stored: str, password: str) -> bool:
    """Constant-time comparison against a hash `problem` accepts; anything else never matches."""
    if m := SCRYPT.fullmatch(stored):
        if problem(stored) is not None:
            return False
        key = _scrypt(password, bytes.fromhex(m[4]), int(m[1]), int(m[2]), int(m[3]))
        return hmac.compare_digest(key.hex(), m[5].lower())
    if SHA256.fullmatch(stored):
        _, salt, digest = stored.split(":")
        return hmac.compare_digest(hashlib.sha256((salt + password).encode()).hexdigest(), digest.lower())
    return False


def same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


class Throttle:
    """Failed sign-ins per client address, in this worker's memory."""

    def __init__(self, limit: int = FAILURES, window: float = WINDOW) -> None:
        self.limit, self.window = limit, window
        self._failures: dict[str, deque[float]] = {}

    def _recent(self, key: str, now: float) -> deque[float]:
        q = self._failures.setdefault(key, deque())
        while q and q[0] < now - self.window:
            q.popleft()
        return q

    def blocked(self, key: str) -> bool:
        return len(self._recent(key, time.monotonic())) >= self.limit

    def failed(self, key: str) -> None:
        if len(self._failures) > 10_000:  # bounded: forget everyone rather than grow
            self._failures.clear()
        self._recent(key, time.monotonic()).append(time.monotonic())

    def succeeded(self, key: str) -> None:
        self._failures.pop(key, None)
