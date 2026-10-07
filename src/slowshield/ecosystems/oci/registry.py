"""Talking to OCI registries: Bearer tokens, manifests checked against their digests, and blob URLs.

Tokens follow the registry's own challenge (`WWW-Authenticate: Bearer realm=...,service=...`): anonymous, or with a
username and access token for the token service (Docker Hub), scoped to pulling one repository, and cached until
shortly before they expire. Every manifest's bytes must hash to the digest asked for, or to the
`Docker-Content-Digest` the registry announced (public.ecr.aws announces none: then the hash is the digest).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from slowshield.cache.metadata import SingleFlight
from slowshield.context import AppContext
from slowshield.ecosystems.oci.reference import DIGEST
from slowshield.upstream import FetchResult, UpstreamError

log = logging.getLogger(__name__)

INDEX_TYPES = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")
IMAGE_TYPES = ("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json")
ACCEPT = ", ".join((*INDEX_TYPES, *IMAGE_TYPES))
MAX_MANIFEST_BYTES = 4 << 20  # the distribution spec's limit
TOKEN_MARGIN = 30.0  # a token is renewed this long before it expires
_PARAM = re.compile(r'(\w+)="([^"]*)"')


class DigestMismatch(UpstreamError):
    """The registry sent bytes that don't hash to the digest asked for or announced."""


@dataclass(frozen=True, slots=True)
class Registry:
    name: str  # canonical: docker.io
    url: str  # API base, without the trailing /
    times: str
    times_url: str | None
    basic: str | None  # `Basic ...` for its token service, from username and token_file


def registries(ctx: AppContext) -> dict[str, Registry]:
    """The configured registries by every name clients may use for them (aliases included)."""
    out: dict[str, Registry] = {}
    for name, r in ctx.cfg.raw.upstreams.oci.all_registries().items():
        basic = None
        if r.username and r.token_file:
            secret = Path(r.token_file).read_text(encoding="utf-8").strip()
            basic = "Basic " + base64.b64encode(f"{r.username}:{secret}".encode()).decode()
        times_url = r.times_url.rstrip("/") if r.times_url else None
        reg = Registry(name, r.url.rstrip("/"), r.times, times_url, basic)
        for n in (name, *r.aliases):
            out[n.lower()] = reg
    return out


@dataclass(frozen=True, slots=True)
class Manifest:
    digest: str
    media_type: str
    body: bytes  # empty for a HEAD
    size: int  # of the body (from Content-Length for a HEAD)

    @property
    def is_index(self) -> bool:
        return self.media_type in INDEX_TYPES

    def config(self) -> str:
        """The config blob of an image manifest ("" for an index)."""
        if self.is_index or not self.body:
            return ""
        try:
            digest = str(json.loads(self.body).get("config", {}).get("digest", ""))
        except ValueError, AttributeError:
            return ""
        return digest if DIGEST.fullmatch(digest) else ""

    def children(self) -> list[str]:
        """The digests an index lists (its platform and attestation manifests)."""
        if not self.is_index or not self.body:
            return []
        try:
            doc = json.loads(self.body)
        except ValueError:
            return []
        return [
            m["digest"]
            for m in doc.get("manifests", [])
            if isinstance(m, dict) and DIGEST.fullmatch(str(m.get("digest")))
        ]


def bearer(header: str) -> tuple[str, str | None] | None:
    """(realm, service) of a Bearer challenge, or None."""
    if not header.lower().startswith("bearer"):
        return None
    params = dict(_PARAM.findall(header))
    realm = params.get("realm")
    return (realm, params.get("service")) if realm else None


def media_type(res: FetchResult) -> str:
    mt = res.headers.get("content-type", "").split(";", 1)[0].strip()
    if mt in (*INDEX_TYPES, *IMAGE_TYPES) or not res.body:
        return mt
    try:  # some registries send application/json: the manifest says what it is
        declared = json.loads(res.body).get("mediaType")
    except ValueError, AttributeError:
        declared = None
    return declared if isinstance(declared, str) and declared else mt


class RegistryClient:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self.flight = SingleFlight()
        self._challenges: dict[str, tuple[str, str | None] | None] = {}  # registry -> challenge (None: open)
        self._tokens: dict[tuple[str, str], tuple[str, float]] = {}
        self.ratelimit: dict[str, str] = {}  # registry -> its last `ratelimit-remaining` header

    async def auth(self, reg: Registry, path: str) -> dict[str, str]:
        """The Authorization header for pulling `path` from `reg`, if it needs one."""
        hit = self._tokens.get((reg.name, path))
        if hit is not None and hit[1] > self.ctx.clock.now() + TOKEN_MARGIN:
            return {"Authorization": f"Bearer {hit[0]}"}
        if reg.name not in self._challenges:
            await self.flight.run(("oci:challenge", reg.name), lambda: self._challenge(reg))
        challenge = self._challenges.get(reg.name)
        if challenge is None:
            return {}
        token = await self.flight.run(("oci:token", reg.name, path), lambda: self._token(reg, path, challenge))
        return {"Authorization": f"Bearer {token}"}

    async def _challenge(self, reg: Registry) -> None:
        res = await self.ctx.upstream.fetch(f"{reg.url}/v2/", max_bytes=64 << 10)
        self._challenges[reg.name] = bearer(res.headers.get("www-authenticate", "")) if res.status == 401 else None

    async def _token(self, reg: Registry, path: str, challenge: tuple[str, str | None]) -> str:
        realm, service = challenge
        query: dict[str, str] = {"scope": f"repository:{path}:pull"}
        if service:
            query["service"] = service
        url = realm + ("&" if "?" in realm else "?") + urlencode(query)
        res = await self.ctx.upstream.fetch(
            url, headers={"Authorization": reg.basic} if reg.basic else {}, max_bytes=1 << 20
        )
        if res.status != 200:
            raise UpstreamError(url, f"token service returned {res.status}", res.status)
        try:
            doc: dict[str, Any] = json.loads(res.body)
            token = str(doc.get("token") or doc.get("access_token") or "")
            ttl = float(doc.get("expires_in") or 60)
        except ValueError, TypeError, AttributeError:
            token, ttl = "", 0.0
        if not token:
            raise UpstreamError(url, "token service sent no token")
        self._tokens[(reg.name, path)] = (token, self.ctx.clock.now() + max(ttl, TOKEN_MARGIN + 30))
        return token

    async def request(
        self, reg: Registry, path: str, sub: str, *, method: str = "GET", accept: str | None = None, max_bytes: int
    ) -> FetchResult:
        """`<registry>/v2/<path>/<sub>` with a token; after a 401 (an expired token) once more with a new one."""
        url = f"{reg.url}/v2/{path}/{sub}"
        res = await self._send(reg, path, url, method=method, accept=accept, max_bytes=max_bytes)
        if res.status == 401:
            self._tokens.pop((reg.name, path), None)
            challenge = bearer(res.headers.get("www-authenticate", ""))
            if challenge is not None:
                self._challenges[reg.name] = challenge
            res = await self._send(reg, path, url, method=method, accept=accept, max_bytes=max_bytes)
        return res

    async def _send(
        self, reg: Registry, path: str, url: str, *, method: str, accept: str | None, max_bytes: int
    ) -> FetchResult:
        headers = await self.auth(reg, path)
        if accept:
            headers["Accept"] = accept
        res = await self.ctx.upstream.fetch(url, headers=headers, max_bytes=max_bytes, method=method)
        if "ratelimit-remaining" in res.headers:
            self.ratelimit[reg.name] = res.headers["ratelimit-remaining"]
        return res

    def remaining(self) -> list[tuple[float, dict[str, str | int | float | bool]]]:
        """Pulls each registry last said were left (Docker Hub: `ratelimit-remaining: 87;w=21600`), for a gauge."""
        out: list[tuple[float, dict[str, str | int | float | bool]]] = []
        for name, value in self.ratelimit.items():
            try:
                out.append((float(value.split(";", 1)[0]), {"registry": name}))
            except ValueError:
                continue
        return out

    async def manifest(self, reg: Registry, path: str, ref: str, *, head: bool = False) -> Manifest | None:
        """The manifest `ref` (a tag or digest) names, or None if the registry has none. With `head`, only its digest
        and type (a HEAD, which Docker Hub doesn't count as a pull), unless the registry announces no digest."""
        res = await self.request(
            reg, path, f"manifests/{ref}", method="HEAD" if head else "GET", accept=ACCEPT, max_bytes=MAX_MANIFEST_BYTES
        )
        if res.status in (404, 410):
            return None
        if res.status != 200:
            raise UpstreamError(res.url, f"registry returned {res.status}", res.status)
        announced = res.headers.get("docker-content-digest", "")
        announced = announced if DIGEST.fullmatch(announced) else ""
        if head:
            digest = announced or (ref if DIGEST.fullmatch(ref) else "")
            size = res.headers.get("content-length", "")
            if digest and size.isdigit():
                return Manifest(digest, media_type(res), b"", int(size))
            return await self.manifest(reg, path, ref)
        computed = "sha256:" + hashlib.sha256(res.body).hexdigest()
        expected = ref if DIGEST.fullmatch(ref) else announced
        if expected and computed != expected:
            raise DigestMismatch(res.url, f"manifest bytes hash to {computed}, not {expected}")
        return Manifest(computed, media_type(res), res.body, len(res.body))

    def blob_url(self, reg: Registry, path: str, digest: str) -> str:
        return f"{reg.url}/v2/{path}/blobs/{digest}"
