"""Shared fixtures: a real fake registry (subprocess), app factory with a frozen clock, ASGI helpers."""

from __future__ import annotations

import os
import tomllib
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import msgspec
import pytest
from fakeupstream import FakeUpstream

from slowshield import config as config_mod
from slowshield.app import SlowShield, create_app
from slowshield.clock import FrozenClock

NOW = 1_790_000_000.0  # 2026-09-21T13:33:20Z — the fake registry's reference time
DAY = 86400.0

_ENV_PREFIXES = ("SLOWSHIELD_", "OTEL_", "GITHUB_TOKEN", "DATABASE_URL")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith(_ENV_PREFIXES):
            monkeypatch.delenv(key, raising=False)


@pytest.fixture(scope="session")
def fake() -> Iterator[FakeUpstream]:
    with FakeUpstream(now=NOW) as f:
        yield f


@pytest.fixture
def upstream(fake: FakeUpstream) -> Iterator[FakeUpstream]:
    """The fake registry, reset to its pristine catalog before and after the test."""
    fake.reset()
    yield fake
    fake.reset()


def base_config(data_dir: Path, fake_url: str) -> dict[str, Any]:
    return {
        "bind_address": "127.0.0.1:8080",
        "public_url": "https://slowshield.test",
        "data_dir": str(data_dir),
        "default_delay_days": 7,
        "metadata_cache_ttl_hours": 6,
        "upstreams": {
            "pypi": {"mirrors": [f"{fake_url}/pypi"], "files_url": f"{fake_url}/files"},
            "npm": {"mirrors": [f"{fake_url}/npm"]},
            "go": {"mirrors": [f"{fake_url}/go"], "sumdb_url": f"{fake_url}/sumdb"},
        },
        "feeds": {"osv_base_url": f"{fake_url}/osv", "github_api_url": f"{fake_url}/github"},
    }


def deep_merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in extra.items():
        out[k] = deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


@pytest.fixture
def make_config(tmp_path: Path, upstream: FakeUpstream) -> Callable[..., config_mod.LoadedConfig]:
    """Config pointing at the fake registry; `extra` is TOML deep-merged over the defaults."""

    def build(extra: str = "", *, data_dir: Path | None = None) -> config_mod.LoadedConfig:
        data = deep_merge(base_config(data_dir or tmp_path / "data", upstream.url), tomllib.loads(extra))
        cfg = msgspec.convert(data, config_mod.Config)
        return config_mod.build(cfg, path=None, warnings=[])

    return build


@dataclass
class Running:
    app: SlowShield
    client: httpx.AsyncClient
    clock: FrozenClock
    fake: FakeUpstream
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def ctx(self) -> Any:
        assert self.app.ctx is not None
        return self.app.ctx

    async def drain(self) -> None:
        """Flush in-memory stats and wait until every queued DB write has committed."""
        self.ctx.recorder.flush()
        await self.ctx.db.writer.run(lambda _c: None)

    def rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[Any]:
        return [tuple(r) for r in self.ctx.db.readers.query(sql, params)]


@pytest.fixture
async def start_app(
    make_config: Callable[..., config_mod.LoadedConfig], upstream: FakeUpstream
) -> AsyncIterator[Callable[..., Any]]:
    started: list[Running] = []

    async def start(extra: str = "", *, clock: FrozenClock | None = None, host: str = "slowshield.test") -> Running:
        cfg = make_config(extra)
        clk = clock or FrozenClock(NOW)
        app = create_app(cfg, clock=clk, background=False)
        await app.startup()
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=f"http://{host}")
        run = Running(app, client, clk, upstream)
        started.append(run)
        return run

    yield start
    for run in started:
        await stop(run)


@pytest.fixture
async def running(start_app: Callable[..., Any]) -> Running:
    return await start_app()


async def stop(run: Running) -> None:
    await run.client.aclose()
    await run.app.shutdown()


@dataclass
class AsgiResult:
    status: int | None
    headers: dict[str, str]
    body: bytes
    error: BaseException | None


async def asgi_get(app: Any, path: str, *, method: str = "GET", headers: dict[str, str] | None = None) -> AsgiResult:
    """Call the ASGI app directly and record exactly what was sent, even if it aborts mid-stream."""
    raw_path = path.split("?", 1)[0]
    query = path.split("?", 1)[1] if "?" in path else ""
    from urllib.parse import unquote

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": unquote(raw_path),
        "raw_path": raw_path.encode(),
        "query_string": query.encode(),
        "root_path": "",
        "headers": [(b"host", b"slowshield.test")]
        + [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": ("10.1.2.3", 1234),
        "server": ("slowshield.test", 80),
        "extensions": {},
    }
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    err: BaseException | None = None
    try:
        await app(scope, receive, send)
    except Exception as exc:
        err = exc
    status = None
    hdrs: dict[str, str] = {}
    body = b""
    for m in sent:
        if m["type"] == "http.response.start":
            status = m["status"]
            hdrs = {k.decode(): v.decode() for k, v in m.get("headers", [])}
        elif m["type"] == "http.response.body":
            body += m.get("body", b"")
    return AsgiResult(status, hdrs, body, err)
