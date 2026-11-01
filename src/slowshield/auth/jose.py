"""The little of JOSE that UI sign-in needs, on `cryptography` (already a dependency): verify an ID token's signature
against the IdP's JWKS, and sign SlowShield's own client assertion (private_key_jwt).

Deliberately narrow: compact JWS only, RS256, PS256 and ES256 only. `none`, HMAC and everything else are refused
before any key is looked at, and a key is only used with the algorithm family of its own type.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.x509.oid import NameOID

ALGORITHMS = frozenset({"RS256", "PS256", "ES256"})
MAX_TOKEN = 64 << 10


class JoseError(ValueError):
    """A token or key SlowShield won't accept; the message says why (for logs and the audit log, never a secret)."""


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or any(c in text for c in "+/= \n"):
        raise JoseError("not base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError as exc:
        raise JoseError("not base64url") from exc


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int(value: Any) -> int:
    return int.from_bytes(b64url_decode(value), "big")


@dataclass(frozen=True, slots=True)
class Jws:
    header: dict[str, Any]
    claims: dict[str, Any]
    signing_input: bytes
    signature: bytes

    @property
    def alg(self) -> str:
        return str(self.header.get("alg"))

    @property
    def kid(self) -> str | None:
        kid = self.header.get("kid")
        return kid if isinstance(kid, str) else None


def parse(token: str) -> Jws:
    """Split and decode a compact JWS. Nothing is trusted yet: the caller verifies before reading the claims."""
    if not isinstance(token, str) or len(token) > MAX_TOKEN:
        raise JoseError("token missing or too large")
    parts = token.split(".")
    if len(parts) != 3:
        raise JoseError("not a compact JWS")
    try:
        header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError) as exc:
        raise JoseError("malformed token") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise JoseError("malformed token")
    if header.get("alg") not in ALGORITHMS:
        raise JoseError(f"algorithm {header.get('alg')!r} is not accepted")
    if "crit" in header:
        raise JoseError("critical header parameters are not supported")
    return Jws(header, claims, f"{parts[0]}.{parts[1]}".encode("ascii"), b64url_decode(parts[2]))


PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey


def public_key(jwk: dict[str, Any]) -> PublicKey:
    """An RSA (2048 bits or more) or EC P-256 public key from a JWK."""
    kty = jwk.get("kty")
    try:
        if kty == "RSA":
            key = rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
            if key.key_size < 2048:
                raise JoseError("RSA key shorter than 2048 bits")
            return key
        if kty == "EC" and jwk.get("crv") == "P-256":
            x, y = b64url_decode(jwk["x"]), b64url_decode(jwk["y"])
            if len(x) != 32 or len(y) != 32:
                raise JoseError("bad P-256 coordinates")
            return ec.EllipticCurvePublicNumbers(int.from_bytes(x), int.from_bytes(y), ec.SECP256R1()).public_key()
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, JoseError):
            raise
        raise JoseError("malformed JWK") from exc
    raise JoseError(f"unsupported key type {kty!r}")


def _fits(alg: str, jwk: dict[str, Any]) -> bool:
    """A key is only ever used with algorithms of its own type, and with its own `alg` and `use` when it names them."""
    if jwk.get("use") not in (None, "sig") or jwk.get("alg") not in (None, alg):
        return False
    ops = jwk.get("key_ops")
    if isinstance(ops, list) and "verify" not in ops:
        return False
    return (jwk.get("kty") == "EC" and alg == "ES256") or (jwk.get("kty") == "RSA" and alg in ("RS256", "PS256"))


def candidates(jws: Jws, keys: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The JWKS keys this token may be verified with: the one its `kid` names, or, without a `kid`, every fitting
    key."""
    fitting = [k for k in keys if isinstance(k, dict) and _fits(jws.alg, k)]
    if jws.kid is not None:
        return [k for k in fitting if k.get("kid") == jws.kid]
    return fitting


def verify(jws: Jws, jwk: dict[str, Any]) -> bool:
    if not _fits(jws.alg, jwk):
        return False
    key = public_key(jwk)
    try:
        if jws.alg == "ES256":
            if not isinstance(key, ec.EllipticCurvePublicKey) or len(jws.signature) != 64:
                return False
            r, s = int.from_bytes(jws.signature[:32]), int.from_bytes(jws.signature[32:])
            key.verify(encode_dss_signature(r, s), jws.signing_input, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, rsa.RSAPublicKey):
            pad = (
                padding.PKCS1v15()
                if jws.alg == "RS256"
                else padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256.digest_size)
            )
            key.verify(jws.signature, jws.signing_input, pad, hashes.SHA256())
        else:
            return False
    except InvalidSignature:
        return False
    return True


# ---- SlowShield's own key (private_key_jwt) ------------------------------------------------------------------------

PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


@dataclass(frozen=True, slots=True)
class ClientKey:
    """The client's signing key, and its certificate when the key file carries one (Entra ID asks for `x5t#S256`)."""

    key: PrivateKey
    certificate: x509.Certificate | None = None

    @property
    def alg(self) -> str:
        return "ES256" if isinstance(self.key, ec.EllipticCurvePrivateKey) else "RS256"

    def public_jwk(self) -> dict[str, str]:
        pub = self.key.public_key()
        if isinstance(pub, ec.EllipticCurvePublicKey):
            n = pub.public_numbers()
            return {"kty": "EC", "crv": "P-256", "x": b64url(n.x.to_bytes(32)), "y": b64url(n.y.to_bytes(32))}
        rn = pub.public_numbers()
        return {"kty": "RSA", "e": b64url(_bytes(rn.e)), "n": b64url(_bytes(rn.n))}

    @property
    def kid(self) -> str:
        """RFC 7638 thumbprint: what Keycloak derives from an imported certificate or key, so the `kid` matches."""
        jwk = self.public_jwk()
        members = ("crv", "kty", "x", "y") if jwk["kty"] == "EC" else ("e", "kty", "n")
        canonical = json.dumps({m: jwk[m] for m in members}, separators=(",", ":"), sort_keys=True)
        return b64url(hashlib.sha256(canonical.encode()).digest())

    def sign(self, claims: dict[str, Any]) -> str:
        header: dict[str, Any] = {"alg": self.alg, "typ": "JWT", "kid": self.kid}
        if self.certificate is not None:
            der = self.certificate.public_bytes(serialization.Encoding.DER)
            header["x5t#S256"] = b64url(hashlib.sha256(der).digest())
            header["x5t"] = b64url(hashlib.sha1(der).digest())  # noqa: S324 - a certificate thumbprint, Entra ID's
        signing_input = f"{_json64(header)}.{_json64(claims)}".encode("ascii")
        if isinstance(self.key, ec.EllipticCurvePrivateKey):
            r, s = decode_dss_signature(self.key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
            signature = r.to_bytes(32) + s.to_bytes(32)
        else:
            signature = self.key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input.decode('ascii')}.{b64url(signature)}"

    def assertion(self, client_id: str, audience: str, now: float) -> str:
        """RFC 7523 client assertion, valid for a minute, used once (`jti`)."""
        return self.sign({"iss": client_id, "sub": client_id, "aud": audience, "jti": secrets.token_urlsafe(24),
                          "iat": int(now), "nbf": int(now) - 5, "exp": int(now) + 60})  # fmt: skip


def _bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8 or 1)


def _json64(obj: dict[str, Any]) -> str:
    return b64url(json.dumps(obj, separators=(",", ":")).encode())


def load_client_key(pem: bytes) -> ClientKey:
    """A PEM private key, EC P-256 or RSA of 2048 bits or more, optionally followed by its certificate."""
    try:
        key = serialization.load_pem_private_key(_pem_block(pem, b"PRIVATE KEY"), password=None)
    except (ValueError, TypeError) as exc:
        raise JoseError("the key file holds no unencrypted PEM private key") from exc
    if isinstance(key, ec.EllipticCurvePrivateKey):
        if not isinstance(key.curve, ec.SECP256R1):
            raise JoseError("EC keys must be P-256")
    elif isinstance(key, rsa.RSAPrivateKey):
        if key.key_size < 2048:
            raise JoseError("RSA keys must have 2048 bits or more")
    else:
        raise JoseError("the key must be EC P-256 or RSA")
    cert = None
    if b"-----BEGIN CERTIFICATE-----" in pem:
        try:
            cert = x509.load_pem_x509_certificate(_pem_block(pem, b"CERTIFICATE"))
        except ValueError as exc:
            raise JoseError("the certificate in the key file can't be read") from exc
        spki = serialization.PublicFormat.SubjectPublicKeyInfo
        der = serialization.Encoding.DER
        if cert.public_key().public_bytes(der, spki) != key.public_key().public_bytes(der, spki):
            raise JoseError("the certificate in the key file is for another key")
    return ClientKey(key, cert)


def _pem_block(pem: bytes, label: bytes) -> bytes:
    """The first PEM block whose label ends with `label` (PRIVATE KEY covers EC PRIVATE KEY and RSA PRIVATE KEY)."""
    start = 0
    while (begin := pem.find(b"-----BEGIN ", start)) != -1:
        line_end = pem.find(b"-----", begin + 11)
        name = pem[begin + 11 : line_end]
        end_marker = b"-----END " + name + b"-----"
        end = pem.find(end_marker, line_end)
        if end == -1:
            break
        if name.endswith(label):
            return pem[begin : end + len(end_marker)]
        start = end + len(end_marker)
    raise JoseError(f"no PEM {label.decode()} block")


def new_key(kind: str) -> PrivateKey:
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return ec.generate_private_key(ec.SECP256R1())


def key_pem(key: PrivateKey) -> bytes:
    pkcs8 = serialization.PrivateFormat.PKCS8
    return key.private_bytes(serialization.Encoding.PEM, pkcs8, serialization.NoEncryption())


def self_signed(key: PrivateKey, common_name: str, days: int, now: datetime.datetime) -> x509.Certificate:
    """A certificate for the client key, to upload to the IdP (Keycloak, Okta and Entra ID take certificates)."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .sign(key, hashes.SHA256())
    )
