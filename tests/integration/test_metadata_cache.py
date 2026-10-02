"""Metadata caching: one SQLite store shared by all workers, a small in-memory layer per worker."""

from __future__ import annotations

from slowshield.clock import FrozenClock
from slowshield.ecosystems.npm.service import SMALL_BODY
from tests.conftest import NOW

ACCEPT_JSON = {"Accept": "application/vnd.pypi.simple.v1+json"}


async def test_second_worker_serves_from_the_shared_store(start_app) -> None:
    """A document one worker fetched is served by another without asking upstream again."""
    a = await start_app()
    npm_a = await a.client.get("/npm/left-pad-ng")
    pypi_a = await a.client.get("/pypi/simple/alpha/", headers=ACCEPT_JSON)
    assert npm_a.status_code == pypi_a.status_code == 200
    before = a.fake.hits("/")
    b = await start_app()  # same data directory, fresh process memory
    npm_b = await b.client.get("/npm/left-pad-ng")
    pypi_b = await b.client.get("/pypi/simple/alpha/", headers=ACCEPT_JSON)
    assert npm_b.content == npm_a.content and pypi_b.content == pypi_a.content
    assert b.fake.hits("/") == before


async def test_stale_document_from_the_shared_store_when_upstream_fails(start_app) -> None:
    a = await start_app()
    assert (await a.client.get("/npm/left-pad-ng")).status_code == 200
    a.fake.control("fail", prefix="/npm", status=503)
    b = await start_app(clock=FrozenClock(NOW + 7 * 3600))  # past the 6 h TTL
    r = await b.client.get("/npm/left-pad-ng")
    assert r.status_code == 200 and list(r.json()["versions"]) == ["1.0.0", "1.1.0"]


async def test_large_bodies_stay_out_of_process_memory(start_app) -> None:
    run = await start_app()
    for i in range(400):
        run.fake.control("publish", ecosystem="npm", name="big-pkg", version=f"1.0.{i}", age_days=30)
    r = await run.client.get("/npm/big-pkg")
    assert r.status_code == 200 and len(r.content) > SMALL_BODY
    in_memory = [k for k in run.ctx.metadata_cache._data if k[0] == "npm:body"]
    assert in_memory == []
    _, stored = run.ctx.metadata_store.usage()
    assert stored > 2 * len(r.content)  # the upstream document and the rendered body
    again = await run.client.get("/npm/big-pkg")
    assert again.content == r.content


async def test_memory_budget_is_shared_by_workers_and_never_exceeded(start_app) -> None:
    run = await start_app("workers = 4\n[cache]\nmetadata_memory_mb = 64\n")
    assert run.ctx.metadata_cache.max_bytes == 16 << 20
    tiny = await start_app("[cache]\nmetadata_memory_mb = 0.25\n")
    for i in range(200):
        tiny.fake.control("publish", ecosystem="npm", name="big-pkg", version=f"2.0.{i}", age_days=30)
    for path in ("/npm/big-pkg", "/npm/left-pad-ng", "/pypi/simple/alpha/", "/npm/big-pkg"):
        assert (await tiny.client.get(path)).status_code == 200
        assert tiny.ctx.metadata_cache.bytes <= tiny.ctx.metadata_cache.max_bytes


async def test_tarballs_never_hold_full_documents_in_memory(start_app) -> None:
    """A burst of tarball requests works from the compact index; no parsed packument stays in memory."""
    from slowshield.ecosystems.npm import packument as P

    run = await start_app()
    for i in range(50):
        run.fake.control("publish", ecosystem="npm", name="big-pkg", version=f"3.0.{i}", age_days=30)
    r = await run.client.get("/npm/big-pkg/-/big-pkg-3.0.7.tgz")
    assert r.status_code == 200
    values = [e.value for e in run.ctx.metadata_cache._data.values()]
    assert any(isinstance(v, P.Index) for v in values)
    assert not any(isinstance(v, P.Packument) for v in values)
    assert (await run.client.get("/npm/big-pkg/3.0.7")).json()["version"] == "3.0.7"  # manifest from the store
