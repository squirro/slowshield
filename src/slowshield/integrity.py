"""Streaming digests and trust-on-first-use (TOFU) bookkeeping."""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Expected:
    """Digests the bytes must match. Hex for sha256/blake2b_256/sha1, raw bytes for sha512 (SRI)."""

    sha256: str | None = None  # from the index (PyPI) or our TOFU record
    tofu_sha256: str | None = None
    blake2b_256: str | None = None  # PyPI path component
    sha512: bytes | None = None  # npm dist.integrity
    sha1: str | None = None  # npm dist.shasum (legacy)
    size: int | None = None


def parse_sri(integrity: str | None) -> bytes | None:
    """`sha512-<base64>` -> raw digest (other algorithms are ignored)."""
    if not integrity:
        return None
    for token in integrity.split():
        algo, _, b64 = token.partition("-")
        if algo == "sha512" and b64:
            try:
                return base64.b64decode(b64, validate=True)
            except ValueError:
                return None
    return None


@dataclass(slots=True)
class StreamVerifier:
    expected: Expected
    _sha256: Any = field(default_factory=hashlib.sha256)
    _blake: Any = None
    _sha512: Any = None
    _sha1: Any = None
    size: int = 0

    def __post_init__(self) -> None:
        e = self.expected
        if e.blake2b_256:
            self._blake = hashlib.blake2b(digest_size=32)
        if e.sha512:
            self._sha512 = hashlib.sha512()
        if e.sha1 and not e.sha512:
            self._sha1 = hashlib.sha1(usedforsecurity=False)

    def update(self, chunk: bytes) -> None:
        self.size += len(chunk)
        self._sha256.update(chunk)
        if self._blake is not None:
            self._blake.update(chunk)
        if self._sha512 is not None:
            self._sha512.update(chunk)
        if self._sha1 is not None:
            self._sha1.update(chunk)

    @property
    def sha256(self) -> str:
        return self._sha256.hexdigest()

    def problems(self) -> list[str]:
        """Empty when every expectation holds; otherwise human-readable mismatch descriptions."""
        e = self.expected
        out: list[str] = []
        got = self.sha256
        if e.size is not None and e.size != self.size:
            out.append(f"size {self.size} != expected {e.size}")
        if e.sha256 and not hmac.compare_digest(got, e.sha256.lower()):
            out.append("sha256 does not match the upstream index")
        if (
            e.blake2b_256
            and self._blake is not None
            and not hmac.compare_digest(self._blake.hexdigest(), e.blake2b_256)
        ):
            out.append("blake2b-256 does not match the artifact path")
        if e.sha512 and self._sha512 is not None and not hmac.compare_digest(self._sha512.digest(), e.sha512):
            out.append("sha512 does not match dist.integrity")
        if self._sha1 is not None and e.sha1 and not hmac.compare_digest(self._sha1.hexdigest(), e.sha1.lower()):
            out.append("sha1 does not match dist.shasum")
        return out

    def tofu_mismatch(self) -> bool:
        e = self.expected
        return bool(e.tofu_sha256) and not hmac.compare_digest(self.sha256, e.tofu_sha256 or "")
