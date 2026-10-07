"""Join strings: how an operator pairs a follower with a leader, k3s-style.

    ssj1:https://slowshield-hq.example.com#<leader key hash>.<token id>.<secret>

The leader's CLI prints one; the operator puts it into the follower's environment. The follower trusts nothing but
the key hash: it fetches the leader's public key from the URL and refuses unless it matches. The secret proves the
follower was invited; the proof binds it to the follower's own key, so a copied request can't be replayed with
another key. Tokens are single-use and expire after minutes.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

from slowshield.shieldwall.identity import b32

PREFIX = "ssj1:"
TOKEN_TTL = 600.0  # seconds: a join string is meant to be used right away
_JOIN = re.compile(
    r"^ssj1:(https?://[A-Za-z0-9.\-:\[\]]+(?:/[A-Za-z0-9._~%/-]*)?)#([a-z2-7]{26})\.([a-z2-7]{8})\.([a-z2-7]{26})$"
)


class JoinStringError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class JoinString:
    url: str  # the leader's base URL, without a trailing slash
    key_hash: str
    token_id: str
    secret: str

    def __str__(self) -> str:
        return f"{PREFIX}{self.url}#{self.key_hash}.{self.token_id}.{self.secret}"

    @classmethod
    def parse(cls, text: str) -> JoinString:
        m = _JOIN.match(text.strip())
        if m is None:
            raise JoinStringError("not a SlowShield join string (ssj1:<url>#<key>.<token>.<secret>)")
        return cls(m.group(1).rstrip("/"), m.group(2), m.group(3), m.group(4))


def new_token() -> tuple[str, str]:
    """(token id, secret)."""
    return b32(secrets.token_bytes(5)), b32(secrets.token_bytes(16))


def proof(secret: str, follower_key: bytes, leader_id: str, created: int) -> str:
    msg = b"slowshield-join-v1\n" + follower_key + b"\n" + leader_id.encode() + b"\n" + str(created).encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def proof_ok(secret: str, follower_key: bytes, leader_id: str, created: int, claimed: str) -> bool:
    return hmac.compare_digest(proof(secret, follower_key, leader_id, created), claimed)
