"""Signed HTTP messages between shield wall instances: a small profile of RFC 9421 (HTTP Message Signatures) with
Ed25519.

Requests sign the method, path, query and body digest (RFC 9530 `Content-Digest`); responses sign their status and
body digest and the request's signature, so a recorded response can't be replayed as the answer to a new request.
TLS keeps the traffic confidential; authenticity doesn't depend on it, so it survives Caddy, an ingress or Tailscale
Serve terminating TLS in front of the app.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass

from slowshield.shieldwall.identity import Identity, verify

LABEL = "ss"
MAX_SKEW = 300  # seconds either way; clocks are assumed to be NTP-synced
_PARAMS = re.compile(r'^ss=\(([^)]*)\);created=(\d+);keyid="([a-z0-9]{1,64})";alg="ed25519"$')
_SIG = re.compile(r"^ss=:([A-Za-z0-9+/=]+):$")
_REQ_COMPONENTS = '"@method" "@path" "@query" "content-digest"'
_RESP_COMPONENTS = '"@status" "content-digest" "signature";req'


class SignatureError(Exception):
    """A missing, malformed, stale or wrong signature. The message is safe to return to the caller."""


def content_digest(body: bytes) -> str:
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def _params(components: str, created: int, keyid: str) -> str:
    return f'({components});created={created};keyid="{keyid}";alg="ed25519"'


def _request_base(method: str, path: str, query: str, digest: str, params: str) -> bytes:
    return (
        f'"@method": {method.upper()}\n"@path": {path}\n"@query": ?{query}\n"content-digest": {digest}\n'
        f'"@signature-params": {params}'
    ).encode()


def _response_base(status: int, digest: str, request_signature: str, params: str) -> bytes:
    return (
        f'"@status": {status}\n"content-digest": {digest}\n"signature";req: {request_signature}\n'
        f'"@signature-params": {params}'
    ).encode()


def sign_request(identity: Identity, method: str, path: str, query: str, body: bytes, *, now: float) -> dict[str, str]:
    """Headers for a request: Content-Digest, Signature-Input, Signature. `query` without the leading `?`."""
    digest = content_digest(body)
    params = _params(_REQ_COMPONENTS, int(now), identity.id)
    sig = identity.sign(_request_base(method, path, query, digest, params))
    return {
        "Content-Digest": digest,
        "Signature-Input": f"{LABEL}={params}",
        "Signature": f"{LABEL}=:{base64.b64encode(sig).decode()}:",
    }


def sign_response(
    identity: Identity, status: int, body: bytes, *, request_signature: str, now: float
) -> dict[str, str]:
    digest = content_digest(body)
    params = _params(_RESP_COMPONENTS, int(now), identity.id)
    sig = identity.sign(_response_base(status, digest, request_signature, params))
    return {
        "Content-Digest": digest,
        "Signature-Input": f"{LABEL}={params}",
        "Signature": f"{LABEL}=:{base64.b64encode(sig).decode()}:",
    }


@dataclass(frozen=True, slots=True)
class Signed:
    keyid: str
    created: int
    signature: str  # the raw Signature header, to bind the response to


def _parse(headers: dict[str, str], components: str, now: float) -> tuple[str, int, bytes, str]:
    raw_input = headers.get("signature-input", "")
    raw_sig = headers.get("signature", "")
    m = _PARAMS.match(raw_input)
    s = _SIG.match(raw_sig)
    if m is None or s is None:
        raise SignatureError("missing or malformed signature")
    if m.group(1) != components:
        raise SignatureError("signature covers the wrong components")
    created = int(m.group(2))
    if abs(now - created) > MAX_SKEW:
        raise SignatureError("signature too old or from the future (check the clocks)")
    try:
        sig = base64.b64decode(s.group(1), validate=True)
    except ValueError as exc:
        raise SignatureError("malformed signature") from exc
    return m.group(3), created, sig, raw_input.removeprefix(f"{LABEL}=")


def keyid_of(headers: dict[str, str]) -> str | None:
    """The claimed signer, to look up its key before verifying. Headers are lower-case."""
    m = _PARAMS.match(headers.get("signature-input", ""))
    return m.group(3) if m else None


def verify_request(
    headers: dict[str, str], method: str, path: str, query: str, body: bytes, *, public_key: bytes, now: float
) -> Signed:
    """Check a request signed by `public_key`. Headers are lower-case. Raises SignatureError."""
    keyid, created, sig, params = _parse(headers, _REQ_COMPONENTS, now)
    digest = content_digest(body)
    if headers.get("content-digest") != digest:
        raise SignatureError("content digest doesn't match the body")
    if not verify(public_key, sig, _request_base(method, path, query, digest, params)):
        raise SignatureError("bad signature")
    return Signed(keyid, created, headers["signature"])


def verify_response(
    headers: dict[str, str], status: int, body: bytes, *, request_signature: str, public_key: bytes, now: float
) -> Signed:
    keyid, created, sig, params = _parse(headers, _RESP_COMPONENTS, now)
    digest = content_digest(body)
    if headers.get("content-digest") != digest:
        raise SignatureError("content digest doesn't match the body")
    if not verify(public_key, sig, _response_base(status, digest, request_signature, params)):
        raise SignatureError("bad response signature")
    return Signed(keyid, created, headers.get("signature", ""))
