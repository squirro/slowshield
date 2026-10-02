"""Verified streaming, tamper detection (TOFU), integrity mismatches, legacy checksums and the disk cache."""

from __future__ import annotations

import hashlib
import os
import time

import msgspec
import pytest

from slowshield.ecosystems.pypi.project import JSON_V1
from slowshield.legacy import LEGACY_DIGEST
from tests.conftest import Running, asgi_get

NO_CACHE = """
[cache]
artifacts_enabled = false
"""


def _wheel_path(run: Running, project: str = "alpha", version: str = "1.1.0") -> str:
    files = run.fake.info()["pypi"][project][version]
    return next(f["path"] for f in files if f["filename"].endswith(".whl"))


async def _sha(run: Running, project: str, filename_prefix: str) -> str:
    r = await run.client.get(f"/pypi/simple/{project}/", headers={"Accept": JSON_V1})
    return next(f["hashes"]["sha256"] for f in r.json()["files"] if f["filename"].startswith(filename_prefix))


async def test_tofu_tamper_aborts_stream_and_blocks(start_app) -> None:
    run = await start_app(NO_CACHE)
    path = _wheel_path(run)
    first = await run.client.get(f"/pypi{path}")
    assert first.status_code == 200
    await run.drain()
    run.fake.control("tamper", path=path)

    res = await asgi_get(run.app, f"/pypi{path}")
    # A single-chunk artifact is verified before anything is sent: explicit 451, no bytes leaked.
    assert res.status == 451 and res.error is None
    assert msgspec.json.decode(res.body)["error"] == "tamper_detected"

    await run.drain()
    row = run.rows("SELECT tampered, sha256 FROM artifacts WHERE path = ?", (path,))
    assert row == [(1, hashlib.sha256(first.content).hexdigest())]
    ev = run.rows("SELECT type, details FROM events WHERE type = 'tampered'")
    assert len(ev) == 1 and "observed_sha256" in ev[0][1]

    again = await run.client.get(f"/pypi{path}")
    assert again.status_code == 451
    assert again.json()["error"] == "tamper_detected"


async def test_first_fetch_integrity_mismatch_is_not_permanent(start_app) -> None:
    run = await start_app(NO_CACHE)
    path = _wheel_path(run, version="1.0.0")
    run.fake.control("tamper", path=path)
    res = await asgi_get(run.app, f"/pypi{path}")
    assert res.status == 502 and msgspec.json.decode(res.body)["error"] == "integrity_mismatch"
    await run.drain()
    assert run.rows("SELECT count(*) FROM artifacts WHERE path = ?", (path,)) == [(0,)]
    ev = run.rows("SELECT type FROM events")
    assert ("integrity_mismatch",) in ev
    run.fake.reset()
    ok = await run.client.get(f"/pypi{path}")
    assert ok.status_code == 200


async def test_legacy_checksum_is_corrected(start_app) -> None:
    run = await start_app(NO_CACHE)
    path = _wheel_path(run)
    await run.ctx.db.writer.run(
        lambda c: c.execute(
            "INSERT INTO artifacts (ecosystem, path, package, version, filename, sha256, upstream_digest, first_seen, "
            "last_seen) VALUES ('pypi', ?, 'alpha', '1.1.0', 'alpha-1.1.0-py3-none-any.whl', ?, ?, 0, 0)",
            (path, "f" * 64, LEGACY_DIGEST),
        )
    )
    r = await run.client.get(f"/pypi{path}")
    assert r.status_code == 200
    await run.drain()
    ((sha, digest),) = run.rows("SELECT sha256, upstream_digest FROM artifacts WHERE path = ?", (path,))
    assert sha == hashlib.sha256(r.content).hexdigest()
    assert digest != LEGACY_DIGEST
    assert run.rows("SELECT count(*) FROM events WHERE type = 'tampered'") == [(0,)]


async def test_upstream_error_is_never_hashed(start_app) -> None:
    run = await start_app(NO_CACHE)
    path = _wheel_path(run)
    run.fake.control("fail", prefix="/files", status=503)
    r = await run.client.get(f"/pypi{path}")
    assert r.status_code == 502
    run.fake.control("fail", prefix="/files", status=404)
    r = await run.client.get(f"/pypi{path}")
    assert r.status_code == 404
    await run.drain()
    assert run.rows("SELECT count(*) FROM artifacts") == [(0,)]


async def test_cache_hit_survives_upstream_outage(running: Running) -> None:
    path = _wheel_path(running)
    first = await running.client.get(f"/pypi{path}")
    await running.drain()
    running.fake.control("fail", prefix="/files", status=503)
    second = await running.client.get(f"/pypi{path}")
    assert second.status_code == 200
    assert second.content == first.content
    assert second.headers["x-slowshield-cache"] == "hit"


async def test_cache_eviction_scrub_and_cleanup(start_app) -> None:
    run = await start_app(f"[cache]\nartifacts_max_gb = {1500 / (1 << 30)}\n")  # one wheel fits
    cache = run.ctx.artifact_cache
    for version in ("1.0.0", "1.1.0"):
        r = await run.client.get(f"/pypi{_wheel_path(run, version=version)}")
        assert r.status_code == 200
    await run.drain()
    assert run.rows("SELECT count(*) FROM cache_entries") == [(2,)]
    evicted = await cache.evict()
    await run.drain()
    assert evicted >= 1
    assert list(cache.trash.iterdir())
    # corrupt one object and scrub
    ((sha,),) = run.rows("SELECT sha256 FROM cache_entries LIMIT 1")
    cache.object_path(sha).write_bytes(b"corrupted")
    bad = await cache.scrub()
    await run.drain()
    assert bad == [sha]
    assert run.rows("SELECT count(*) FROM cache_entries WHERE sha256 = ?", (sha,)) == [(0,)]
    # stale tmp files and trash are cleaned up
    stale = cache.tmp / "old.part"
    stale.write_bytes(b"x")
    old = time.time() - 7200
    os.utime(stale, (old, old))
    for p in cache.trash.iterdir():
        os.utime(p, (old, old))
    cache.cleanup()
    assert not stale.exists()
    assert not list(cache.trash.iterdir())


async def test_cache_cleanup_drops_rows_without_objects(running: Running) -> None:
    path = _wheel_path(running)
    await running.client.get(f"/pypi{path}")
    await running.drain()
    cache = running.ctx.artifact_cache
    ((sha,),) = running.rows("SELECT sha256 FROM cache_entries")
    cache.object_path(sha).unlink()
    cache.cleanup()
    await running.drain()
    assert running.rows("SELECT count(*) FROM cache_entries") == [(0,)]
    r = await running.client.get(f"/pypi{path}")
    assert r.status_code == 200 and r.headers["x-slowshield-cache"] == "miss"


async def test_concurrent_first_fetch_with_different_bytes(start_app) -> None:
    """If another request stored a different digest first, the stream is aborted as tampering."""
    run = await start_app(NO_CACHE)
    path = _wheel_path(run)
    server = run.ctx.artifacts
    original = server._remember

    async def racing(req, verifier):  # type: ignore[no-untyped-def]
        await run.ctx.db.writer.run(
            lambda c: c.execute(
                "INSERT INTO artifacts (ecosystem, path, package, filename, sha256, first_seen, last_seen) "
                "VALUES ('pypi', ?, 'alpha', 'x', ?, 0, 0)",
                (path, "e" * 64),
            )
        )
        return await original(req, verifier)

    server._remember = racing  # type: ignore[method-assign]
    res = await asgi_get(run.app, f"/pypi{path}")
    assert res.status == 451
    await run.drain()
    assert run.rows("SELECT tampered FROM artifacts WHERE path = ?", (path,)) == [(1,)]


def _scope(path: str) -> dict:
    return {
        "type": "http",
        "method": "GET",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"slowshield.test")],
        "client": ("127.0.0.1", 1),
    }


async def _receive():  # type: ignore[no-untyped-def]
    return {"type": "http.request", "body": b"", "more_body": False}


async def _failing_send(message):  # type: ignore[no-untyped-def]
    if message["type"] == "http.response.body":
        raise ConnectionResetError("client went away")


async def test_disconnect_after_verification_caches_but_does_not_count(start_app) -> None:
    run = await start_app()
    path = _wheel_path(run)
    with pytest.raises(ConnectionResetError):
        await run.app(_scope(f"/pypi{path}"), _receive, _failing_send)
    await run.drain()
    assert not list(run.ctx.artifact_cache.tmp.iterdir())
    assert run.rows("SELECT count(*) FROM cache_entries") == [(1,)]
    assert run.rows("SELECT count(*) FROM downloads_hourly") == [(0,)]


async def test_disconnect_mid_stream_discards_partial_download(start_app, monkeypatch) -> None:
    from slowshield import upstream as up

    orig = up.StreamResponse.chunks

    async def split_chunks(self):  # type: ignore[no-untyped-def]
        async for chunk in orig(self):
            data = bytes(chunk)
            yield data[: len(data) // 2]
            yield data[len(data) // 2 :]

    monkeypatch.setattr(up.StreamResponse, "chunks", split_chunks)
    run = await start_app()
    path = _wheel_path(run)
    with pytest.raises(ConnectionResetError):
        await run.app(_scope(f"/pypi{path}"), _receive, _failing_send)
    await run.drain()
    assert not list(run.ctx.artifact_cache.tmp.iterdir())
    assert run.rows("SELECT count(*) FROM cache_entries") == [(0,)]
    assert run.rows("SELECT count(*) FROM artifacts") == [(0,)]


async def test_mid_stream_tamper_aborts_and_withholds_last_chunk(start_app, monkeypatch) -> None:
    from slowshield import upstream as up

    orig = up.StreamResponse.chunks

    async def split_chunks(self):  # type: ignore[no-untyped-def]
        async for chunk in orig(self):
            data = bytes(chunk)
            for i in range(0, len(data), 100):
                yield data[i : i + 100]

    monkeypatch.setattr(up.StreamResponse, "chunks", split_chunks)
    run = await start_app(NO_CACHE)
    path = _wheel_path(run)
    first = await run.client.get(f"/pypi{path}")
    assert first.status_code == 200
    await run.drain()
    run.fake.control("tamper", path=path)
    res = await asgi_get(run.app, f"/pypi{path}")
    assert res.status == 200  # headers went out with the first chunk...
    assert res.error is not None  # ...then the response was aborted
    assert 0 < len(res.body) < len(first.content)  # the final chunk was withheld
    await run.drain()
    assert run.rows("SELECT tampered FROM artifacts WHERE path = ?", (path,)) == [(1,)]
