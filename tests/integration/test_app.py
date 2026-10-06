"""Application wiring: lifespan, readiness, routing labels, leader election, background loops, telemetry."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from slowshield import app as app_mod
from slowshield import telemetry
from slowshield.app import Leader, SlowShield, _host, _route_label, create_app
from slowshield.telemetry import process
from tests.conftest import Running


async def _lifespan(app: Any, *messages: str) -> list[dict[str, Any]]:
    queue = [{"type": m} for m in messages]
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return queue.pop(0)

    async def send(msg: dict[str, Any]) -> None:
        sent.append(msg)

    await app({"type": "lifespan"}, receive, send)
    return sent


async def test_lifespan_protocol(make_config) -> None:
    app = create_app(make_config(), background=False)
    sent = await _lifespan(app, "lifespan.startup", "lifespan.shutdown")
    assert [m["type"] for m in sent] == ["lifespan.startup.complete", "lifespan.shutdown.complete"]
    await app({"type": "websocket"}, None, None)  # ignored


async def test_lifespan_startup_failure(make_config, tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    app = create_app(make_config(data_dir=blocker / "sub"), background=False)
    sent = await _lifespan(app, "lifespan.startup")
    assert sent[0]["type"] == "lifespan.startup.failed"


async def test_not_ready_before_startup(make_config) -> None:
    import httpx

    app = SlowShield(make_config(), background=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/")).status_code == 503
    r = await app.readyz(None)  # type: ignore[arg-type]
    assert r.status_code == 503


async def test_readyz_reports_db_failure(running: Running, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*_a: Any) -> None:
        raise RuntimeError("db gone")

    monkeypatch.setattr(running.ctx.db.readers, "one", broken)
    r = await running.client.get("/readyz")
    assert r.status_code == 503


def test_create_app_from_path(tmp_path: Path) -> None:
    p = tmp_path / "c.toml"
    p.write_text("default_delay_days = 3\n")
    assert create_app(str(p)).cfg.raw.default_delay_days == 3


def test_host_parsing() -> None:
    def scope(h: str | None) -> dict[str, Any]:
        return {"headers": [] if h is None else [(b"host", h.encode())]}

    assert _host(scope("PyPI.Example:443")) == "pypi.example"
    assert _host(scope("[::1]:8080")) == "[::1]"
    assert _host(scope("example")) == "example"
    assert _host(scope(None)) == ""
    assert _host(scope("::1")) == "::1"


@pytest.mark.parametrize(
    ("path", "label"),
    [
        ("/", "/"),
        ("/ui/", "/ui/"),
        ("/ui/static/app.css", "/ui/static/{asset}"),
        ("/healthz", "/healthz"),
        ("/pypi/simple/requests/", "/pypi/simple/{project}/"),
        ("/pypi/packages/aa/bb/x.whl", "/pypi/packages/{file}"),
        ("/simple/x/", "/simple/{project}/"),
        ("/packages/a", "/packages/{file}"),
        ("/npm/-/ping", "/npm/-/{endpoint}"),
        ("/npm/lodash", "/npm/{package}"),
        ("/npm/lodash/-/lodash-1.0.0.tgz", "/npm/{package}/-/{file}"),
        ("/static/app.css", "/static/{asset}"),
        ("/ui/packages/pypi/x", "/ui/packages"),
        ("/ui/random-attacker-path", "/ui/{page}"),
        ("/lodash", "/{package}"),
        ("/lodash/-/lodash-1.0.0.tgz", "/{package}/-/{file}"),
        ("/cargo/config.json", "/cargo/config.json"),
        ("/cargo/se/rd/serde", "/cargo/{index_file}"),
        ("/cargo/crates/serde/1.0.0/download", "/cargo/crates/{crate}/{version}/download"),
    ],
)
def test_route_labels_are_low_cardinality(path: str, label: str) -> None:
    assert _route_label(path) == label


def test_leader_lock(tmp_path: Path) -> None:
    a, b = Leader(tmp_path / "leader.lock"), Leader(tmp_path / "leader.lock")
    assert a.try_acquire() and a.try_acquire()
    assert not b.try_acquire()
    a.release()
    a.release()
    assert b.try_acquire()
    b.release()


async def test_background_loops(start_app, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    run = await start_app()
    app: SlowShield = run.app
    ctx = run.ctx
    real_sleep = asyncio.sleep

    async def one_shot_sleep(_s: float) -> None:
        await real_sleep(0)
        raise asyncio.CancelledError

    # maintenance: one full cycle (evict, purge, retention, scrub), then the sleep cancels it
    monkeypatch.setattr(app_mod.asyncio, "sleep", one_shot_sleep)
    with pytest.raises(asyncio.CancelledError):
        await app._maintenance(ctx)

    # a failing cycle is logged, not fatal
    async def broken_evict() -> int:
        raise RuntimeError("disk")

    monkeypatch.setattr(ctx.artifact_cache, "evict", broken_evict)
    with pytest.raises(asyncio.CancelledError):
        await app._maintenance(ctx)
    # config watcher picks up changes
    with pytest.raises(asyncio.CancelledError):
        await app._config_watcher(ctx)

    # leader loop: becomes leader, runs feeds + maintenance
    called: list[str] = []

    async def fake_forever() -> None:
        called.append("feeds")

    async def fake_maint(_ctx: Any) -> None:
        called.append("maintenance")

    monkeypatch.setattr(app._scheduler, "run_forever", fake_forever)
    monkeypatch.setattr(app, "_maintenance", fake_maint)
    await app._leader_loop(ctx)
    assert ctx.is_leader and called == ["feeds", "maintenance"]


async def test_background_tasks_start_and_stop(make_config) -> None:
    app = create_app(make_config(), background=True)
    await app.startup()
    assert len(app._tasks) == 4
    await asyncio.sleep(0.05)
    await app.shutdown()
    assert app._tasks == []


async def test_config_watcher_applies_reload(running: Running, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def fake_reload() -> bool:
        calls["n"] += 1
        return True

    monkeypatch.setattr(running.ctx.config, "maybe_reload", fake_reload)
    real_sleep = asyncio.sleep
    state = {"i": 0}

    async def sleeper(_s: float) -> None:
        state["i"] += 1
        if state["i"] > 1:
            raise asyncio.CancelledError
        await real_sleep(0)

    monkeypatch.setattr(app_mod.asyncio, "sleep", sleeper)
    with pytest.raises(asyncio.CancelledError):
        await running.app._config_watcher(running.ctx)
    assert calls["n"] == 1


def test_process_metrics() -> None:
    assert process.rss_bytes() > 1_000_000
    user, system = process.cpu_seconds()
    assert user >= 0 and system >= 0
    assert process.open_fds() >= 0
    process.register()


async def test_eventloop_lag_monitor() -> None:
    task = asyncio.create_task(process.eventloop_lag_monitor(0.01))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def test_telemetry_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    assert not telemetry.setup(version="t")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9")
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    assert not telemetry.setup(version="t")
    monkeypatch.delenv("OTEL_SDK_DISABLED")
    for sig in ("TRACES", "METRICS", "LOGS"):
        monkeypatch.setenv(f"OTEL_{sig}_EXPORTER", "none")
    assert not telemetry.setup(version="t")


def test_telemetry_setup_and_shutdown(monkeypatch: pytest.MonkeyPatch, fake) -> None:
    """Installs real SDK providers exporting to an endpoint that discards everything."""
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", f"{fake.url}/otlp")
    monkeypatch.setenv("OTEL_METRIC_EXPORT_INTERVAL", "600000")
    monkeypatch.setenv("OTEL_BSP_SCHEDULE_DELAY", "600000")
    assert telemetry.setup(version="t", worker=1)
    assert telemetry.is_active()
    assert telemetry.setup(version="t")  # second call is a no-op
    import logging

    from slowshield.telemetry import instruments

    with instruments.tracer.start_as_current_span("unit-test"):
        instruments.decisions.add(1, {"slowshield.ecosystem": "pypi"})
        try:
            raise ValueError("x")
        except ValueError:
            logging.getLogger("slowshield.test").exception("logged", extra={"api_key": "s", "n": 1, "o": object()})
    telemetry.shutdown()
    assert not telemetry.is_active()
