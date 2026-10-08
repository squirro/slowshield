"""NuGet (at /nuget/): nuget.org through SlowShield. See docs/design/nuget.md."""

from __future__ import annotations

from typing import Any

from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from slowshield.config import NugetUpstream
from slowshield.context import AppContext
from slowshield.web import TEXT, route_path, text_error


class NugetService:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx

    @property
    def settings(self) -> NugetUpstream:
        return self.ctx.cfg.raw.upstreams.nuget

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":  # pragma: no cover - lifespan is handled by the outer app
            return
        request = Request(scope, receive)
        response = await self.dispatch(request)
        await response(scope, receive, send)

    async def dispatch(self, request: Request) -> Any:
        if request.method not in ("GET", "HEAD"):
            return text_error(405, "method not allowed", headers={"Allow": "GET, HEAD"})
        if route_path(request.scope).lstrip("/") == "":
            return Response(
                b"SlowShield NuGet feed: use <this URL>v3/index.json as the package source.\n", media_type=TEXT
            )
        return text_error(404, "not found")
