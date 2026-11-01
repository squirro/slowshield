"""Password sign-in (SLOWSHIELD_AUTH=password): one local Admin, for single-user deployments where an IdP is overkill.

The stored hash is `sha256:<salt>:<hex of SHA-256(salt + password)>`, so anyone can make one with `openssl` on Linux or
macOS (docs/authentication.md#password-sign-in) or with `slowshield auth hash-password`. SHA-256 is fast: a stolen hash
is only as safe as the password is long, so use a long random one. Failed attempts are slowed down and capped per
client address.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import deque

FAILURES = 10  # failed sign-ins per client address ...
WINDOW = 900.0  # ... in this many seconds, before it has to wait


def make_hash(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    return f"sha256:{salt}:{hashlib.sha256((salt + password).encode()).hexdigest()}"


def verify(stored: str, password: str) -> bool:
    scheme, _, rest = stored.partition(":")
    salt, _, digest = rest.partition(":")
    if scheme != "sha256" or not salt or len(digest) != 64:
        return False
    computed = hashlib.sha256((salt + password).encode()).hexdigest()
    return hmac.compare_digest(computed, digest.lower())


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
