"""An instance's Ed25519 identity: created once in <data_dir>/shieldwall/identity.key, never sent anywhere.

The instance ID and the fingerprints people compare are derived from the public key, so a key can't be swapped
without every peer noticing.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


def b32(data: bytes) -> str:
    return base64.b32encode(data).decode().rstrip("=").lower()


def key_hash(public_key: bytes) -> str:
    """What a join string pins: 26 base32 characters (128 bits) of the key's SHA-256."""
    return b32(hashlib.sha256(public_key).digest()[:16])


def instance_id(public_key: bytes) -> str:
    """A short, stable name for an instance: `s` and 16 base32 characters (80 bits) of the key's SHA-256."""
    return "s" + b32(hashlib.sha256(public_key).digest()[:10])


def fingerprint(public_key: bytes) -> str:
    """The key hash in groups of four, for people to compare (leader UI, follower banner, CLI)."""
    h = key_hash(public_key)
    return "-".join(h[i : i + 4] for i in range(0, len(h), 4))


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature, ValueError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class Identity:
    private: Ed25519PrivateKey
    public_key: bytes

    @property
    def id(self) -> str:
        return instance_id(self.public_key)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_key)

    def sign(self, message: bytes) -> bytes:
        return self.private.sign(message)

    @classmethod
    def load_or_create(cls, data_dir: Path) -> Identity:
        """The key in <data_dir>/shieldwall/identity.key, created (mode 0600) on first use. Losing it means re-pairing.
        Workers may race to create it: the key is written to a temporary file and linked into place, which fails if
        another worker got there first, so every worker ends up with the same key."""
        path = data_dir / "shieldwall" / "identity.key"
        if not path.is_file():
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            raw = Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            tmp = path.with_name(f".identity.{os.getpid()}.{secrets.token_hex(4)}")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(raw)
                    f.flush()
                    os.fsync(f.fileno())
                try:
                    os.link(tmp, path)
                except FileExistsError:
                    pass
            finally:
                tmp.unlink(missing_ok=True)
        raw = path.read_bytes()
        if len(raw) != 32:
            raise ValueError(f"{path} is not an Ed25519 key (expected 32 bytes)")
        private = Ed25519PrivateKey.from_private_bytes(raw)
        return cls(private, private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
