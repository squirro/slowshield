"""When a tag got a digest, according to the registry (docs/design/oci.md, "Publish time").

The image's own `created` field is set by whoever builds it, and no registry sends `Last-Modified` on manifests, so
these come from each registry's API:
- hub: Docker Hub's API, `tag_last_pushed` of a tag's current digest (`/v2/namespaces/<ns>/repositories/<repo>/tags`).
- quay: Quay's tag history, every digest a tag pointed to with `start_ts` (`/api/v1/repository/<repo>/tag/`).
- gcr: the `manifest` map gcr.io and Artifact Registry add to `tags/list`: `timeUploadedMs` per digest.
- mcr: MCR's catalog, `lastModifiedDate` per tag (`/api/v1/catalog/<repo>/tags`).
GHCR and public.ecr.aws expose nothing anonymously: there, SlowShield's own first sight is the only clock.

Listings are cached for an hour in the shared metadata store; an unreachable source means "unknown", never an error.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any
from urllib.parse import quote

from slowshield.context import AppContext
from slowshield.ecosystems.oci.reference import DIGEST
from slowshield.ecosystems.oci.registry import Registry, RegistryClient
from slowshield.upstream import UpstreamError

log = logging.getLogger(__name__)

TTL = 3600.0
EARLIEST = datetime(2013, 1, 1).timestamp()  # Docker's first release: anything earlier is not a push time
CLOCK_SKEW = 300.0
MAX_LISTING_BYTES = 64 << 20  # gcr.io/distroless/static lists 22,844 digests
HUB_PAGES = 3  # Docker Hub tags looked at for a digest (100 each, newest first)


def _ts(raw: Any) -> float | None:
    if isinstance(raw, (int, float)):
        return float(raw)
    if not isinstance(raw, str) or not raw:
        return None
    if raw.isdigit():
        return float(raw)
    try:
        head, _, frac = raw.partition(".")
        if frac:  # MCR writes 7 fractional digits; Python reads up to 6
            digits = len(frac) - len(frac.lstrip("0123456789"))
            raw = f"{head}.{frac[: min(digits, 6)]}{frac[digits:]}"
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00").replace(" -0000", "+00:00"))
    except ValueError:
        return None
    return dt.timestamp() if dt.tzinfo else None


class Times:
    def __init__(self, ctx: AppContext, client: RegistryClient) -> None:
        self.ctx = ctx
        self.client = client

    def _plausible(self, ts: float | None) -> float | None:
        return ts if ts is not None and EARLIEST <= ts <= self.ctx.clock.now() + CLOCK_SKEW else None

    async def tag_history(self, reg: Registry, path: str, tag: str) -> list[tuple[str, float]]:
        """(digest, when the tag got it) as far as the registry tells, oldest first."""
        try:
            if reg.times == "hub":
                rows = await self._hub_tag(reg, path, tag)
            elif reg.times == "quay":
                rows = await self._quay_tag(reg, path, tag)
            elif reg.times == "gcr":
                rows = [(d, t) for d, t, tags in await self._gcr(reg, path) if tag in tags]
            elif reg.times == "mcr":
                rows = [(d, t) for d, t, name in await self._mcr(reg, path) if name == tag]
            else:
                return []
        except UpstreamError as exc:
            log.warning("registry time source unavailable", extra={"registry": reg.name, "error": exc.detail})
            return []
        out = [(d, p) for d, t in rows if DIGEST.fullmatch(d) and (p := self._plausible(t)) is not None]
        return sorted(out, key=lambda r: r[1])

    async def digest_time(self, reg: Registry, path: str, digest: str) -> float | None:
        """The registry's earliest time for `digest` (any tag that points or pointed to it, or its upload)."""
        try:
            if reg.times == "hub":
                times = [t for d, t in await self._hub_tags(reg, path) if d == digest]
            elif reg.times == "gcr":
                times = [t for d, t, _ in await self._gcr(reg, path) if d == digest]
            elif reg.times == "mcr":
                times = [t for d, t, _ in await self._mcr(reg, path) if d == digest]
            else:
                return None
        except UpstreamError as exc:
            log.warning("registry time source unavailable", extra={"registry": reg.name, "error": exc.detail})
            return None
        plausible = [p for t in times if (p := self._plausible(t)) is not None]
        return min(plausible) if plausible else None

    # ---- sources -------------------------------------------------------------------------------------------

    async def _cached(self, key: str, load: Any) -> Any:
        store = self.ctx.metadata_store
        now = self.ctx.clock.now()
        stored = await store.aget(key)
        if stored is not None and stored.fresh(now):
            return json.loads(stored.value)
        value = await load()
        await store.aput(key, json.dumps(value).encode(), expires=now + TTL)
        return value

    async def _get_json(self, url: str, *, max_bytes: int = 4 << 20) -> Any:
        res = await self.ctx.upstream.fetch(
            url, headers={"Accept": "application/json"}, max_bytes=max_bytes, kind="feed"
        )
        if res.status in (404, 410):
            return None
        if res.status != 200:
            raise UpstreamError(res.url, f"time source returned {res.status}", res.status)
        try:
            return json.loads(res.body)
        except ValueError as exc:
            raise UpstreamError(res.url, "time source sent no JSON") from exc

    def _hub_repo(self, reg: Registry, path: str) -> str:
        ns, _, repo = path.partition("/")
        return f"{reg.times_url}/v2/namespaces/{quote(ns)}/repositories/{quote(repo, safe='')}"

    async def _hub_tag(self, reg: Registry, path: str, tag: str) -> list[tuple[str, float | None]]:
        async def load() -> list[Any]:
            doc = await self._get_json(f"{self._hub_repo(reg, path)}/tags/{quote(tag, safe='')}")
            return [[doc.get("digest") or "", _ts(doc.get("tag_last_pushed"))]] if isinstance(doc, dict) else []

        return [(d, t) for d, t in await self._cached(f"oci:times:hub:{path}:{tag}", load)]

    async def _hub_tags(self, reg: Registry, path: str) -> list[tuple[str, float | None]]:
        async def load() -> list[Any]:
            rows: list[Any] = []
            url: str | None = f"{self._hub_repo(reg, path)}/tags?page_size=100&ordering=last_updated"
            for _ in range(HUB_PAGES):
                if url is None:
                    break
                doc = await self._get_json(url)
                if not isinstance(doc, dict):
                    break
                rows.extend([t.get("digest") or "", _ts(t.get("tag_last_pushed"))] for t in doc.get("results", []))
                nxt = doc.get("next")
                url = nxt if isinstance(nxt, str) and nxt.startswith(f"{reg.times_url}/") else None
            return rows

        return [(d, t) for d, t in await self._cached(f"oci:times:hubtags:{path}", load)]

    async def _quay_tag(self, reg: Registry, path: str, tag: str) -> list[tuple[str, float | None]]:
        async def load() -> list[Any]:
            url = (
                f"{reg.times_url}/api/v1/repository/{path}/tag/"
                f"?specificTag={quote(tag, safe='')}&onlyActiveTags=false&limit=100"
            )
            doc = await self._get_json(url)
            tags = doc.get("tags", []) if isinstance(doc, dict) else []
            return [[t.get("manifest_digest") or "", _ts(t.get("start_ts"))] for t in tags if t.get("name") == tag]

        return [(d, t) for d, t in await self._cached(f"oci:times:quay:{path}:{tag}", load)]

    async def _gcr(self, reg: Registry, path: str) -> list[tuple[str, float | None, list[str]]]:
        async def load() -> list[Any]:
            res = await self.client.request(reg, path, "tags/list", max_bytes=MAX_LISTING_BYTES)
            if res.status != 200:
                return []
            try:
                manifest = json.loads(res.body).get("manifest") or {}
            except ValueError, AttributeError:
                return []
            return [
                [d, (_ts(m.get("timeUploadedMs")) or 0) / 1000 or None, list(m.get("tag") or [])]
                for d, m in manifest.items()
                if isinstance(m, dict)
            ]

        return [(d, t, tags) for d, t, tags in await self._cached(f"oci:times:gcr:{reg.name}/{path}", load)]

    async def _mcr(self, reg: Registry, path: str) -> list[tuple[str, float | None, str]]:
        async def load() -> list[Any]:
            doc = await self._get_json(
                f"{reg.times_url}/api/v1/catalog/{path}/tags?reg=mar", max_bytes=MAX_LISTING_BYTES
            )
            entries = doc if isinstance(doc, list) else []
            return [[e.get("digest") or "", _ts(e.get("lastModifiedDate")), e.get("name") or ""] for e in entries]

        return [(d, t, n) for d, t, n in await self._cached(f"oci:times:mcr:{path}", load)]
