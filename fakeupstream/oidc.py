"""A fake OpenID Connect provider at /oidc, for UI sign-in tests: discovery, JWKS, authorize (with PAR), token, userinfo
and logout. Control at /_control/oidc (JSON merged into the settings) and /_control/oidc-log.

Its settings shape it like each IdP SlowShield documents: Keycloak (PAR, RFC 9207 `iss`, end session), Okta (PAR, end
session), Entra ID (no PAR, no `email_verified`, group overage) or Google (no PAR, no end session, `hd`). It can also
hand out bad tokens: wrong audience, issuer or nonce, expired, `alg: none`, HS256, an unknown key, a bad signature.

Independent of SlowShield's own JOSE code on purpose: it signs and checks with `cryptography` directly.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

CLIENT_ID = "slowshield"
CLIENT_SECRET = "fake-client-secret"  # noqa: S105 - a test fixture


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _int_b64(n: int) -> str:
    return _b64(n.to_bytes((n.bit_length() + 7) // 8))


# Generated once per process: key generation is the slow part, and a reset needn't change the keys.
_KEYS: dict[str, Any] = {
    "rsa-1": rsa.generate_private_key(public_exponent=65537, key_size=2048),
    "rsa-2": rsa.generate_private_key(public_exponent=65537, key_size=2048),
    "ec-1": ec.generate_private_key(ec.SECP256R1()),
}


def _jwk(kid: str) -> dict[str, Any]:
    pub = _KEYS[kid].public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        n = pub.public_numbers()
        return {"kty": "RSA", "kid": kid, "use": "sig", "e": _int_b64(n.e), "n": _int_b64(n.n)}
    n = pub.public_numbers()
    return {"kty": "EC", "kid": kid, "use": "sig", "crv": "P-256", "x": _b64(n.x.to_bytes(32)),
            "y": _b64(n.y.to_bytes(32))}  # fmt: skip


def _sign(header: dict[str, Any], claims: dict[str, Any], kid: str) -> str:
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(claims).encode())}".encode()
    alg = header["alg"]
    if alg == "none":
        return signing_input.decode() + "."
    if alg == "HS256":  # the "public key as an HMAC secret" confusion attack
        secret = json.dumps(_jwk("rsa-1")).encode()
        return signing_input.decode() + "." + _b64(hmac.new(secret, signing_input, hashlib.sha256).digest())
    key = _KEYS[kid]
    if alg == "ES256":
        r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32) + s.to_bytes(32)
    elif alg == "PS256":
        sig = key.sign(signing_input, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    else:
        sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return signing_input.decode() + "." + _b64(sig)


def defaults() -> dict[str, Any]:
    return {
        "sub": "alice",
        "claims": {
            "email": "alice@example.com",
            "email_verified": True,
            "name": "Alice Example",
            "slowshield_roles": ["SlowShield Admins"],
        },
        "userinfo_only": [],  # claim names left out of the ID token (only from userinfo)
        "par": True,  # advertise PAR
        "require_par": False,
        "iss_param": True,  # RFC 9207
        "end_session": True,
        "logged_in": True,  # the IdP session: prompt=none answers login_required when False
        "error": None,  # the authorization response is this error
        "alg": "RS256",
        "kid": "rsa-1",
        "jwks": ["rsa-1", "ec-1"],
        "bad": None,  # wrong_aud wrong_iss wrong_nonce expired future_nbf alg_none hs256 unknown_kid bad_sig extra_aud
        "client_jwk": None,  # the client's public key, for private_key_jwt
    }


class OidcState:
    def __init__(self) -> None:
        self.settings = defaults()
        self.codes: dict[str, dict[str, Any]] = {}
        self.requests: dict[str, dict[str, str]] = {}  # PAR request_uri -> parameters
        self.access: dict[str, dict[str, Any]] = {}
        self.log: list[dict[str, Any]] = []
        self.sessions = 0


def routes(state: Any) -> list[Route]:
    """`state.oidc` is an OidcState; `state.catalog.now + state.clock_offset` is the time."""

    def st() -> OidcState:
        return state.oidc

    def now() -> float:
        return state.catalog.now + state.clock_offset

    def issuer(request: Request) -> str:
        return str(request.base_url).rstrip("/") + "/oidc"

    def record(kind: str, **data: Any) -> None:
        st().log.append({"kind": kind, **data})

    async def discovery(request: Request) -> Response:
        s, iss = st().settings, issuer(request)
        doc: dict[str, Any] = {
            "issuer": iss,
            "authorization_endpoint": f"{iss}/auth",
            "token_endpoint": f"{iss}/token",
            "jwks_uri": f"{iss}/jwks",
            "userinfo_endpoint": f"{iss}/userinfo",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256", "PS256"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
        }
        if s["par"]:
            doc["pushed_authorization_request_endpoint"] = f"{iss}/par"
            doc["require_pushed_authorization_requests"] = s["require_par"]
        if s["iss_param"]:
            doc["authorization_response_iss_parameter_supported"] = True
        if s["end_session"]:
            doc["end_session_endpoint"] = f"{iss}/logout"
        return JSONResponse(doc)

    async def jwks(request: Request) -> Response:
        record("jwks")
        return JSONResponse({"keys": [_jwk(k) for k in st().settings["jwks"]]})

    def client_ok(request: Request, form: dict[str, str], audience: str) -> bool:
        """client_secret_basic, or a private_key_jwt assertion signed by the registered key."""
        auth = request.headers.get("authorization", "")
        if auth.startswith("Basic "):
            user, _, password = base64.b64decode(auth[6:]).decode().partition(":")
            ok = unquote(user) == CLIENT_ID and unquote(password) == CLIENT_SECRET
            record("client_auth", method="client_secret_basic", ok=ok)
            return ok
        assertion = form.get("client_assertion")
        jwk = st().settings["client_jwk"]
        if not assertion or jwk is None:
            record("client_auth", method="none", ok=False)
            return False
        ok, why = _check_assertion(assertion, jwk, audience, now())
        record("client_auth", method="private_key_jwt", ok=ok, why=why)
        return ok

    async def par(request: Request) -> Response:
        form = await _form(request)
        if not client_ok(request, {k: str(v) for k, v in form.items()}, f"{issuer(request)}/token"):
            return JSONResponse({"error": "invalid_client"}, 401)
        uri = "urn:ietf:params:oauth:request_uri:" + secrets.token_urlsafe(12)
        params = {k: str(v) for k, v in form.items() if not k.startswith("client_assertion")}
        st().requests[uri] = params
        record("par", params=params)
        return JSONResponse({"request_uri": uri, "expires_in": 60}, 201)

    async def authorize(request: Request) -> Response:
        s = st().settings
        q = dict(request.query_params)
        if "request_uri" in q:
            params = st().requests.pop(q["request_uri"], None)
            if params is None or q.get("client_id") != CLIENT_ID:
                return PlainTextResponse("unknown request_uri", 400)
        elif s["require_par"]:
            return PlainTextResponse("PAR required", 400)
        else:
            params = q
        record("authorize", params=params, via_par="request_uri" in q)
        if params.get("client_id") != CLIENT_ID or params.get("response_type") != "code":
            return PlainTextResponse("bad client or response type", 400)
        if params.get("code_challenge_method") != "S256" or not params.get("code_challenge"):
            return PlainTextResponse("PKCE S256 required", 400)
        back: dict[str, str] = {"state": params.get("state", "")}
        if s["iss_param"]:
            back["iss"] = issuer(request) if s["bad"] != "wrong_iss_param" else "https://evil.example"
        if s["error"]:
            back["error"] = s["error"]
        elif params.get("prompt") == "none" and not s["logged_in"]:
            back["error"] = "login_required"
        else:
            code = secrets.token_urlsafe(16)
            st().codes[code] = {"nonce": params.get("nonce"), "challenge": params["code_challenge"],
                                "redirect_uri": params.get("redirect_uri")}  # fmt: skip
            back["code"] = code
            st().sessions += 1
        return RedirectResponse(params.get("redirect_uri", "/") + "?" + urlencode(back), 302)

    async def token(request: Request) -> Response:
        s = st().settings
        form = await _form(request)
        record("token", form={k: v for k, v in form.items() if k != "client_assertion"})
        if not client_ok(request, form, f"{issuer(request)}/token"):
            return JSONResponse({"error": "invalid_client"}, 401)
        grant = st().codes.pop(form.get("code", ""), None)
        if grant is None or form.get("grant_type") != "authorization_code":
            return JSONResponse({"error": "invalid_grant"}, 400)
        if form.get("redirect_uri") != grant["redirect_uri"]:
            return JSONResponse({"error": "invalid_grant", "error_description": "redirect_uri"}, 400)
        verifier = form.get("code_verifier", "")
        if _b64(hashlib.sha256(verifier.encode()).digest()) != grant["challenge"]:
            return JSONResponse({"error": "invalid_grant", "error_description": "PKCE"}, 400)
        t, iss, bad = now(), issuer(request), s["bad"]
        claims = {k: v for k, v in s["claims"].items() if k not in s["userinfo_only"]}
        id_claims: dict[str, Any] = {
            **claims,
            "iss": "https://evil.example" if bad == "wrong_iss" else iss,
            "sub": s["sub"],
            "aud": "someone-else" if bad == "wrong_aud" else [CLIENT_ID, "other"] if bad == "extra_aud" else CLIENT_ID,
            "exp": int(t) - 600 if bad == "expired" else int(t) + 300,
            "iat": int(t) - 900 if bad == "expired" else int(t),
            "auth_time": int(t),
            "nonce": "not-the-nonce" if bad == "wrong_nonce" else grant["nonce"],
            "sid": f"sid-{st().sessions}",
        }
        if bad != "extra_aud":
            id_claims["azp"] = CLIENT_ID
        if bad == "future_nbf":
            id_claims["nbf"] = int(t) + 3600
        alg = {"alg_none": "none", "hs256": "HS256"}.get(bad or "", s["alg"])
        kid = "ec-1" if alg == "ES256" else s["kid"]
        header = {"alg": alg, "typ": "JWT", "kid": "nobody" if bad == "unknown_kid" else kid}
        id_token = _sign(header, id_claims, kid)
        if bad == "bad_sig":
            head, _body, sig = id_token.split(".")
            id_token = f"{head}.{_b64(json.dumps({**id_claims, 'sub': 'mallory'}).encode())}.{sig}"
        access = secrets.token_urlsafe(16)
        st().access[access] = {"sub": s["sub"], **s["claims"]}
        return JSONResponse({"access_token": access, "token_type": "Bearer", "expires_in": 300, "id_token": id_token})

    async def userinfo(request: Request) -> Response:
        auth = request.headers.get("authorization", "")
        claims = st().access.get(auth.removeprefix("Bearer "))
        record("userinfo", ok=claims is not None)
        if claims is None:
            return JSONResponse({"error": "invalid_token"}, 401)
        return JSONResponse(claims)

    async def logout(request: Request) -> Response:
        record("logout", params=dict(request.query_params))
        st().settings["logged_in"] = False
        return PlainTextResponse("signed out at the fake IdP")

    async def ctl(request: Request) -> Response:
        st().settings.update(await request.json())
        return JSONResponse(st().settings)

    async def ctl_log(request: Request) -> Response:
        return JSONResponse(st().log)

    return [
        Route("/oidc/.well-known/openid-configuration", discovery),
        Route("/oidc/jwks", jwks),
        Route("/oidc/auth", authorize),
        Route("/oidc/par", par, methods=["POST"]),
        Route("/oidc/token", token, methods=["POST"]),
        Route("/oidc/userinfo", userinfo),
        Route("/oidc/logout", logout),
        Route("/_control/oidc", ctl, methods=["POST"]),
        Route("/_control/oidc-log", ctl_log, methods=["GET", "POST"]),
    ]


async def _form(request: Request) -> dict[str, str]:
    return dict(parse_qsl((await request.body()).decode()))


def _check_assertion(assertion: str, jwk: dict[str, Any], audience: str, t: float) -> tuple[bool, str]:
    try:
        head64, body64, sig64 = assertion.split(".")
        header, claims = json.loads(_unb64(head64)), json.loads(_unb64(body64))
        signing_input, sig = f"{head64}.{body64}".encode(), _unb64(sig64)
        if jwk["kty"] == "EC":
            pub = ec.EllipticCurvePublicNumbers(
                int.from_bytes(_unb64(jwk["x"])), int.from_bytes(_unb64(jwk["y"])), ec.SECP256R1()
            ).public_key()
            if header.get("alg") != "ES256":
                return False, "alg"
            der = encode_dss_signature(int.from_bytes(sig[:32]), int.from_bytes(sig[32:]))
            pub.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        else:
            pub = rsa.RSAPublicNumbers(int.from_bytes(_unb64(jwk["e"])), int.from_bytes(_unb64(jwk["n"]))).public_key()
            if header.get("alg") != "RS256":
                return False, "alg"
            pub.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except ValueError, KeyError, InvalidSignature:
        return False, "signature"
    if claims.get("iss") != CLIENT_ID or claims.get("sub") != CLIENT_ID:
        return False, "iss/sub"
    if claims.get("aud") != audience:
        return False, "aud"
    if not claims.get("jti") or not t - 60 <= claims.get("exp", 0) - 60 <= t + 60:
        return False, "exp"
    if header.get("kid") != jwk.get("kid", header.get("kid")):
        return False, "kid"
    return True, "ok"
