"""GitHub Advisory Database (malware advisories) for every served ecosystem via the REST API. Requires a token.

`GET /advisories?type=malware&ecosystem=<eco>&sort=updated&direction=asc&updated=>=<watermark>`,
following `Link: rel="next"` cursors. Withdrawn advisories are fetched separately (`is_withdrawn=true`)
so their blocks are lifted.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import quote

import msgspec

from slowshield import versions
from slowshield.ecosystems import ECOSYSTEMS as REGISTRY
from slowshield.ecosystems import normalize
from slowshield.feeds import Advisory, BlockSpec, apply_advisories, load_state, save_state
from slowshield.upstream import UpstreamError

log = logging.getLogger(__name__)

ECOSYSTEMS = {e.github: e.id for e in REGISTRY.values()}  # GitHub name -> ours
MAX_PAGES = 200
PER_PAGE = 100
_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')


class _Pkg(msgspec.Struct):
    ecosystem: str = ""
    name: str = ""


class _Vuln(msgspec.Struct):
    package: _Pkg | None = None
    vulnerable_version_range: str | None = None


class GhAdvisory(msgspec.Struct):
    ghsa_id: str
    summary: str | None = None
    html_url: str | None = None
    updated_at: str = ""
    withdrawn_at: str | None = None
    vulnerabilities: list[_Vuln] = []


_decoder = msgspec.json.Decoder(list[GhAdvisory])


def to_advisory(a: GhAdvisory) -> Advisory:
    specs: list[BlockSpec] = []
    for vuln in a.vulnerabilities:
        if vuln.package is None or not vuln.package.name:
            continue
        eco = ECOSYSTEMS.get(vuln.package.ecosystem.lower())
        if eco is None:
            continue
        name = normalize(eco, vuln.package.name)
        rng = (vuln.vulnerable_version_range or "").strip()
        exact = versions.exact_version(rng)
        if exact is not None:
            specs.append(BlockSpec(eco, name, version=exact))
        elif versions.range_is_everything(rng):
            specs.append(BlockSpec(eco, name))
        else:
            specs.append(BlockSpec(eco, name, version_range=rng))
    return Advisory(
        source="github",
        advisory_id=a.ghsa_id,
        specs=specs,
        reason=a.summary,
        url=a.html_url or f"https://github.com/advisories/{a.ghsa_id}",
        withdrawn=bool(a.withdrawn_at) or not specs,
    )


class GithubFeed:
    name = "github"
    title = "GitHub Advisory Database (malware)"
    requires_token = True

    def __init__(self, ctx: Any) -> None:
        self.ctx = ctx

    def configured(self) -> tuple[bool, str]:
        cfg = self.ctx.cfg
        if not cfg.raw.feeds.github_advisory.enabled:
            return False, "disabled"
        if not cfg.github_token:
            return False, "missing_token"
        return True, "ok"

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": f"Bearer {self.ctx.cfg.github_token}",
        }

    async def sync(self) -> int:
        changed = 0
        now = self.ctx.clock.now()
        for gh_eco, eco in ECOSYSTEMS.items():
            if not getattr(self.ctx.cfg.raw.upstreams, eco).enabled:
                continue
            changed += await self._sync_ecosystem(gh_eco)
        total = self.ctx.db.readers.one("SELECT count(*) FROM blocklist WHERE source = 'github' AND withdrawn IS NULL")
        n = int(total[0]) if total else 0
        await self.ctx.db.writer.run(
            lambda c: save_state(
                c, self.name, last_attempt=now, last_success=self.ctx.clock.now(), last_error=None, entries=n
            )
        )
        return changed

    async def _sync_ecosystem(self, gh_eco: str) -> int:
        key = f"github:{gh_eco}"
        state = load_state(self.ctx.db.readers.get(), key)
        mark: str | None = state.get("watermark")
        api = self.ctx.cfg.raw.feeds.github_api_url.rstrip("/")
        changed = 0
        newest = mark
        for withdrawn in (False, True):
            url = f"{api}/advisories?type=malware&ecosystem={gh_eco}&per_page={PER_PAGE}&sort=updated&direction=asc"
            if mark:
                url += "&updated=" + quote(f">={mark}")
            if withdrawn:
                url += "&is_withdrawn=true"
            pages = 0
            while url and pages < MAX_PAGES:
                pages += 1
                res = await self.ctx.upstream.fetch(url, headers=self._headers(), max_bytes=32 << 20, kind="feed")
                if res.status in (401, 403):
                    raise UpstreamError(
                        url, f"GitHub rejected the token ({res.status}); check GITHUB_TOKEN", res.status
                    )
                if res.status != 200:
                    raise UpstreamError(url, f"upstream returned {res.status}", res.status)
                items = _decoder.decode(res.body)
                advisories = [to_advisory(a) for a in items]
                for a in items:
                    if a.updated_at and (newest is None or a.updated_at > newest):
                        newest = a.updated_at
                if advisories:
                    now = self.ctx.clock.now()
                    changed += await self.ctx.db.writer.run(
                        lambda c, batch=advisories, t=now: apply_advisories(c, batch, t)
                    )
                m = _NEXT.search(res.headers.get("link", ""))
                url = m.group(1) if m else ""
        if newest and newest != mark:
            await self.ctx.db.writer.run(
                lambda c: save_state(c, key, watermark=newest, last_success=self.ctx.clock.now())
            )
        return changed
