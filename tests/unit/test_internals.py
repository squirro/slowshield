"""Unit tests for the building blocks: web helpers, upstream client, DB writer, caches, integrity, feeds."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import logging
import sqlite3
from pathlib import Path

import msgspec
import pytest

from slowshield import web
from slowshield.blocklist import BlockEntry, PackageBlocks
from slowshield.cache.metadata import LRUCache, SingleFlight
from slowshield.clock import FrozenClock, SystemClock
from slowshield.db import Database, _split_sql, migrate
from slowshield.ecosystems.pypi import filenames
from slowshield.feeds import Advisory, BlockSpec, apply_advisories, load_state, save_state
from slowshield.feeds.github import GhAdvisory
from slowshield.feeds.github import to_advisory as gh_to_advisory
from slowshield.feeds.osv import OsvVuln, _ranges_to_specs
from slowshield.feeds.osv import to_advisory as osv_to_advisory
from slowshield.integrity import Expected, StreamVerifier, parse_sri
from slowshield.recorder import Recorder, retention
from slowshield.telemetry import logsetup
from slowshield.upstream import TooLargeError, Upstream, UpstreamError

# ---- web --------------------------------------------------------------------------------------

TRUSTED = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("127.0.0.0/8")]


def _scope(peer: str | None, xff: str | None = None, host: str = "x") -> dict:
    headers = [(b"host", host.encode())]
    if xff is not None:
        headers.append((b"x-forwarded-for", xff.encode()))
    return {"client": (peer, 1) if peer else None, "headers": headers, "path": "/a/b", "root_path": "/a"}


def test_client_ip() -> None:
    assert web.client_ip(_scope("203.0.113.1", "1.1.1.1"), TRUSTED) == "203.0.113.1"  # untrusted peer: ignore XFF
    assert web.client_ip(_scope("10.0.0.1"), TRUSTED) == "10.0.0.1"
    assert web.client_ip(_scope("10.0.0.1", "198.51.100.7, 10.1.1.1"), TRUSTED) == "198.51.100.7"
    assert web.client_ip(_scope("10.0.0.1", "10.2.2.2, 10.1.1.1"), TRUSTED) == "10.2.2.2"
    assert web.client_ip(_scope("10.0.0.1", "garbage"), TRUSTED) == "10.0.0.1"
    assert web.client_ip(_scope("10.0.0.1", " , "), TRUSTED) == "10.0.0.1"
    assert web.client_ip(_scope(None), TRUSTED) is None
    assert web.client_ip(_scope("not-an-ip", "1.2.3.4"), TRUSTED) == "not-an-ip"
    assert web.client_ip(_scope("10.0.0.1", "[2001:db8::1]"), TRUSTED) == "2001:db8::1"


def test_local_http_helpers() -> None:
    for host in (
        "localhost",
        "localhost:8080",
        "app.localhost",
        "127.0.0.1",
        "127.9.9.9:80",
        "[::1]",
        "[::1]:8080",
        "::1",
    ):
        assert web.is_loopback_host(host), host
    # Hosts are echoed into Setup page snippets and npm tarball links: malformed ones never qualify.
    crafted = (
        "localhost:$(id)",
        "127.0.0.1:80;id",
        "x$(id).localhost",
        "localhost:8080 x",
        "[::1]x",
        "localhost:99999x",
    )
    for host in ("slowshield.test", "10.0.0.1", "localhost.evil.test", "[2001:db8::1]", "", *crafted):
        assert not web.is_loopback_host(host), host

    def scope(peer: str, proto: str | None, host: str) -> dict:
        s = _scope(peer, host=host)
        if proto:
            s["headers"].append((b"x-forwarded-proto", proto.encode()))
        s["scheme"] = "https"
        return s

    assert web.request_scheme(scope("10.0.0.1", "http", "x"), TRUSTED) == "http"  # from the trusted proxy
    assert web.request_scheme(scope("203.0.113.1", "http", "x"), TRUSTED) == "https"  # untrusted: ignored
    assert web.request_scheme(scope("10.0.0.1", "gopher", "x"), TRUSTED) == "https"
    assert web.local_http_origin(scope("10.0.0.1", "http", "localhost:8080"), True, TRUSTED) == "http://localhost:8080"
    assert web.local_http_origin(scope("10.0.0.1", "http", "localhost"), False, TRUSTED) is None  # disabled
    assert web.local_http_origin(scope("10.0.0.1", "https", "localhost"), True, TRUSTED) is None  # came in over TLS
    assert (
        web.local_http_origin(scope("10.0.0.1", "http", "evil.test"), True, TRUSTED) is None
    )  # never echo other hosts


def test_route_path_and_header() -> None:
    assert web.route_path({"path": "/npm/x", "root_path": "/npm"}) == "/x"
    assert web.route_path({"path": "/npm", "root_path": "/npm"}) == ""
    assert web.route_path({"path": "/npmx", "root_path": "/npm"}) == "/npmx"
    assert web.route_path({"path": "/y", "root_path": ""}) == "/y"
    assert web.header(_scope("1.1.1.1"), b"host") == "x" and web.header(_scope("1.1.1.1"), b"nope") is None


@pytest.mark.parametrize(
    ("accept", "expected"),
    [
        (None, "text/html"),
        ("application/vnd.pypi.simple.v1+json", "application/vnd.pypi.simple.v1+json"),
        ("application/vnd.pypi.simple.v1+json;q=0.5, text/html", "text/html"),
        ("*/*", "text/html"),
        ("application/*", "application/vnd.pypi.simple.v1+html"),
        ("text/plain", "text/html"),
        ("application/vnd.pypi.simple.v1+json;q=0, */*;q=0.1", "text/html"),
        ("application/vnd.pypi.simple.v1+json;q=bad", "text/html"),
    ],
)
def test_accept(accept: str | None, expected: str) -> None:
    offered = ("text/html", "application/vnd.pypi.simple.v1+html", "application/vnd.pypi.simple.v1+json")
    assert web.accept_prefers(accept, offered, "text/html") == expected


def test_error_response_shape() -> None:
    r = web.error(451, "blocked", headers={"X-A": "1"}, reason=None, advisory_id="MAL-1")
    assert r.status_code == 451 and r.headers["x-a"] == "1" and r.headers["cache-control"] == "no-store"
    assert msgspec.json.decode(r.body) == {"error": "blocked", "advisory_id": "MAL-1"}


# ---- upstream ------------------------------------------------------------------------------------


@pytest.fixture
async def client(fake):
    up = Upstream(user_agent="test", allowed_hosts=["127.0.0.1"], connect_timeout=1, read_timeout=5)
    yield up
    await up.close()


async def test_fetch_ok_redirect_and_limits(client: Upstream, fake) -> None:
    res = await client.fetch(
        f"{fake.url}/pypi/simple/Alpha/", headers={"Accept": "application/vnd.pypi.simple.v1+json"}, max_bytes=1 << 20
    )
    assert res.status == 200 and res.url.endswith("/pypi/simple/alpha/") and res.etag
    with pytest.raises(TooLargeError):
        await client.fetch(f"{fake.url}/blob?n=5000", max_bytes=100)
    with pytest.raises(UpstreamError, match="not a configured upstream"):
        await client.fetch(f"{fake.url}/redirect?to=https://evil.example/x", max_bytes=1000)
    with pytest.raises(UpstreamError):
        await client.fetch("https://evil.example/x", max_bytes=10)


async def test_fetch_failover_between_mirrors(client: Upstream, fake) -> None:
    res = await client.fetch(
        ["http://127.0.0.1:9/nothing", f"{fake.url}/healthz"], max_bytes=100, attempts_per_mirror=1
    )
    assert res.status == 200 and res.body == b"ok"
    fake.control("fail", prefix="/healthz", status=503)
    try:
        with pytest.raises(UpstreamError, match="503"):
            await client.fetch(f"{fake.url}/healthz", max_bytes=100, attempts_per_mirror=2)
    finally:
        fake.reset()
    with pytest.raises(UpstreamError):
        await client.fetch([], max_bytes=1)


async def test_stream_and_post(client: Upstream, fake) -> None:
    async with client.stream(f"{fake.url}/redirect?to={fake.url}/blob%3Fn%3D3000") as resp:
        assert resp.status == 200 and resp.content_length == 3000
        body = b"".join([bytes(c) async for c in resp.chunks()])
    assert body == b"x" * 3000
    with pytest.raises(UpstreamError):
        async with client.stream(f"{fake.url}/redirect?to=https://evil.example/") as resp:
            pass
    with pytest.raises(UpstreamError):
        async with client.stream("http://127.0.0.1:9/x") as resp:
            pass
    res = await client.post(f"{fake.url}/npm/-/npm/v1/security/audits/quick", b"{}", max_bytes=1000)
    assert res.status == 200
    with pytest.raises(UpstreamError):
        await client.post("https://evil.example/", b"", max_bytes=1)
    with pytest.raises(UpstreamError):
        await client.post("http://127.0.0.1:9/x", b"", max_bytes=1)


# ---- database --------------------------------------------------------------------------------------


def test_split_sql() -> None:
    assert _split_sql("-- c\nCREATE TABLE a (x);\n\nINSERT INTO a VALUES (';');\nSELECT 1") == [
        "CREATE TABLE a (x);",
        "INSERT INTO a VALUES (';');",
        "SELECT 1",
    ]


async def test_writer_isolates_failures(tmp_path: Path) -> None:
    path = tmp_path / "w.db"
    migrate(path)
    assert migrate(path) == 5  # idempotent
    db = Database(path)
    db.open()
    try:
        ok = db.writer.submit(lambda c: c.execute("INSERT INTO meta (key, value) VALUES ('a', '1')").rowcount)
        bad = db.writer.submit(lambda c: c.execute("INSERT INTO nope VALUES (1)"))
        db.writer.execute("INSERT INTO meta (key, value) VALUES ('b', '2')")
        db.writer.executemany("INSERT INTO meta (key, value) VALUES (?, ?)", [("c", "3"), ("d", "4")])
        db.writer.executemany("INSERT INTO meta (key, value) VALUES (?, ?)", [])
        assert ok.result(5) == 1
        with pytest.raises(sqlite3.OperationalError):
            bad.result(5)
        await db.writer.run(lambda _c: None)
        assert db.meta("a") == "1" and db.meta("b") == "2" and db.meta("d") == "4" and db.meta("zz") is None
        assert db.writer.failures == 1 and db.writer.queue_depth == 0
        rows = await db.readers.aquery("SELECT count(*) FROM meta")
        assert rows[0][0] == 5
    finally:
        db.close()
    db.writer.stop()  # second stop is a no-op


def test_readers_are_read_only(tmp_path: Path) -> None:
    path = tmp_path / "r.db"
    migrate(path)
    db = Database(path)
    with pytest.raises(sqlite3.OperationalError):
        db.readers.get().execute("INSERT INTO meta VALUES ('x', 'y')")
    db.readers.close()


# ---- caches -------------------------------------------------------------------------------------------


def test_lru_cache() -> None:
    c: LRUCache[str] = LRUCache(100)
    c.put("a", "A", 40, expires=10)
    c.put("b", "B", 40, expires=10)
    assert c.get("a", now=5) == "A"  # refreshes recency
    c.put("c", "C", 40, expires=10)  # evicts b (least recent)
    assert c.get("b", now=5) is None and c.evictions == 1 and c.bytes == 80
    assert c.get("a", now=11) is None and c.get_stale("a") == "A"  # expired but stale-readable
    c.touch("a", expires=20)
    assert c.get("a", now=11) == "A"
    c.touch("missing", expires=1)
    c.put("huge", "H", 1000, expires=10)  # larger than the cache: ignored
    assert c.get_stale("huge") is None
    c.put("a", "A2", 10, expires=30)
    assert c.bytes == 50 and len(c) == 2
    c.invalidate("a")
    c.invalidate("a")
    assert len(c) == 1
    c.clear()
    assert len(c) == 0 and c.bytes == 0 and c.hits >= 2 and c.misses >= 2


async def test_single_flight() -> None:
    sf = SingleFlight()
    calls = 0
    gate = asyncio.Event()

    async def load() -> int:
        nonlocal calls
        calls += 1
        await gate.wait()
        return 42

    tasks = [asyncio.create_task(sf.run("k", load)) for _ in range(5)]
    await asyncio.sleep(0.01)
    gate.set()
    assert await asyncio.gather(*tasks) == [42] * 5 and calls == 1

    async def boom() -> int:
        await asyncio.sleep(0.01)
        raise ValueError("x")

    results = await asyncio.gather(sf.run("e", boom), sf.run("e", boom), return_exceptions=True)
    assert all(isinstance(r, ValueError) for r in results)

    # if the leader is cancelled, a waiter takes over
    slow = asyncio.Event()

    async def slow_load() -> str:
        await slow.wait()
        return "done"

    leader = asyncio.create_task(sf.run("c", slow_load))
    await asyncio.sleep(0)
    follower = asyncio.create_task(sf.run("c", slow_load))
    await asyncio.sleep(0)
    leader.cancel()
    await asyncio.sleep(0)
    slow.set()
    assert await follower == "done"


# ---- integrity ------------------------------------------------------------------------------------------


def test_integrity_verifier() -> None:
    data = b"hello world" * 100
    sri = base64.b64encode(hashlib.sha512(data).digest()).decode()
    assert parse_sri(f"sha512-{sri}") == hashlib.sha512(data).digest()
    assert parse_sri("sha1-abc sha512-!!!") is None and parse_sri(None) is None and parse_sri("sha256-x") is None
    good = Expected(
        sha256=hashlib.sha256(data).hexdigest(),
        tofu_sha256=hashlib.sha256(data).hexdigest(),
        blake2b_256=hashlib.blake2b(data, digest_size=32).hexdigest(),
        sha512=hashlib.sha512(data).digest(),
        size=len(data),
    )
    v = StreamVerifier(good)
    v.update(data[:10])
    v.update(data[10:])
    assert v.problems() == [] and not v.tofu_mismatch()
    bad = StreamVerifier(Expected(sha256="0" * 64, blake2b_256="1" * 64, sha512=b"x", size=1, tofu_sha256="2" * 64))
    bad.update(data)
    assert len(bad.problems()) == 4 and bad.tofu_mismatch()
    sha1 = StreamVerifier(Expected(sha1=hashlib.sha1(data, usedforsecurity=False).hexdigest()))
    sha1.update(data)
    assert sha1.problems() == []
    sha1_bad = StreamVerifier(Expected(sha1="0" * 40))
    sha1_bad.update(data)
    assert sha1_bad.problems() == ["sha1 does not match dist.shasum"]


# ---- filenames ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("markdown_it_py-3.0.0-py3-none-any.whl", ("markdown-it-py", "3.0.0")),
        ("foo-1.0-1-py3-none-any.whl", ("foo", "1.0")),
        ("bad-wheel.whl", (None, None)),
        ("foo-notaversion-py3-none-any.whl", (None, None)),
        ("python-dateutil-2.8.2.tar.gz", ("python-dateutil", "2.8.2")),
        ("pkg-1.0-beta.tar.gz", ("pkg-1-0", "beta")),
        ("pkg-1.0-py3.8.egg", ("pkg", "1.0")),
        ("pkg-1.0.0.tar.bz2", ("pkg", "1.0.0")),
        ("noversion.exe", (None, None)),
    ],
)
def test_filename_parsing(filename: str, expected: tuple[str | None, str | None]) -> None:
    assert filenames.parse(filename) == expected


def test_filename_guess_with_known_versions() -> None:
    assert filenames.parse("my-tool-2.0-beta-1.tar.bz2", known_versions=["2.0-beta-1", "2.0"], project="my_tool") == (
        "my-tool",
        "2.0-beta-1",
    )


# ---- feeds parsing -----------------------------------------------------------------------------------------


def test_osv_ranges_and_advisories() -> None:
    from slowshield.feeds.osv import _Event, _Range

    assert _ranges_to_specs([_Range("SEMVER", [_Event(introduced="0")])]) == [None]
    assert _ranges_to_specs([_Range("SEMVER", [_Event(introduced="1.0.0"), _Event(fixed="1.2.0")])]) == [
        ">= 1.0.0, < 1.2.0"
    ]
    assert _ranges_to_specs([_Range("ECOSYSTEM", [_Event(introduced="0"), _Event(last_affected="2.0")])]) == ["<= 2.0"]
    assert _ranges_to_specs([_Range("ECOSYSTEM", [_Event(introduced="3.0")])]) == [">= 3.0"]
    assert _ranges_to_specs([_Range("GIT", [_Event(introduced="abc")])]) == []
    doc = msgspec.json.decode(
        b'{"id": "MAL-1", "summary": "s", "affected": ['
        b'{"package": {"ecosystem": "PyPI", "name": "Evil_Pkg"}},'
        b'{"package": {"ecosystem": "npm", "name": "x"}, "versions": ["1.0.0", "1.0.0"]},'
        b'{"package": {"ecosystem": "crates.io", "name": "y"}},'
        b'{"package": {"ecosystem": "npm", "name": ""}},'
        b'{"package": {"ecosystem": "npm", "name": "r"},'
        b' "ranges": [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}]}]}]}',
        type=OsvVuln,
    )
    adv = osv_to_advisory(doc)
    assert adv is not None and not adv.withdrawn
    assert adv.specs == [
        BlockSpec("pypi", "evil-pkg"),
        BlockSpec("npm", "x", version="1.0.0"),
        BlockSpec("cargo", "y"),
        BlockSpec("npm", "r", version_range=">= 2.0.0"),
    ]
    assert osv_to_advisory(OsvVuln(id="GHSA-1")) is None
    empty = osv_to_advisory(OsvVuln(id="MAL-2", details="d" * 400))
    assert empty is not None and empty.withdrawn and len(empty.reason or "") == 300


def test_github_advisory_mapping() -> None:
    a = msgspec.json.decode(
        b'{"ghsa_id": "GHSA-1", "summary": "s", "vulnerabilities": ['
        b'{"package": {"ecosystem": "pip", "name": "Foo_Bar"}, "vulnerable_version_range": "= 1.2.3"},'
        b'{"package": {"ecosystem": "npm", "name": "n"}, "vulnerable_version_range": ">= 0"},'
        b'{"package": {"ecosystem": "npm", "name": "m"}, "vulnerable_version_range": "< 2.0.0"},'
        b'{"package": {"ecosystem": "rubygems", "name": "r"}},'
        b'{"package": null}]}',
        type=GhAdvisory,
    )
    adv = gh_to_advisory(a)
    assert adv.url == "https://github.com/advisories/GHSA-1"
    assert adv.specs == [
        BlockSpec("pypi", "foo-bar", version="1.2.3"),
        BlockSpec("npm", "n"),
        BlockSpec("npm", "m", version_range="< 2.0.0"),
    ]
    assert gh_to_advisory(GhAdvisory(ghsa_id="GHSA-2", withdrawn_at="2026-01-01T00:00:00Z")).withdrawn


async def test_apply_advisories_replace_and_withdraw(tmp_path: Path) -> None:
    path = tmp_path / "f.db"
    migrate(path)
    db = Database(path)
    db.open()
    try:
        adv = Advisory("osv", "MAL-1", [BlockSpec("npm", "a"), BlockSpec("npm", "b", version="1.0.0")], "r1", "u")
        assert await db.writer.run(lambda c: apply_advisories(c, [adv], 1.0)) == 2
        adv2 = Advisory("osv", "MAL-1", [BlockSpec("npm", "a")], "r2", "u")
        assert await db.writer.run(lambda c: apply_advisories(c, [adv2], 2.0)) == 1
        rows = db.readers.query("SELECT name, version, reason, first_seen, updated FROM blocklist")
        assert [tuple(r) for r in rows] == [("a", None, "r2", 1.0, 2.0)]
        gone = Advisory("osv", "MAL-1", [], None, None, withdrawn=True)
        assert await db.writer.run(lambda c: apply_advisories(c, [gone], 3.0)) == 1
        assert db.readers.one("SELECT withdrawn FROM blocklist")[0] == 3.0
        assert await db.writer.run(lambda c: apply_advisories(c, [adv2], 4.0)) == 0  # revived in place
        assert db.readers.one("SELECT withdrawn FROM blocklist")[0] is None
        assert db.meta("blocklist_generation") == "3"
        await db.writer.run(lambda c: save_state(c, "s", watermark="w", entries=3))
        await db.writer.run(lambda c: save_state(c, "s", last_error="e"))
        state = load_state(db.readers.get(), "s")
        assert state["watermark"] == "w" and state["entries"] == 3 and state["last_error"] == "e"
        assert load_state(db.readers.get(), "missing") == {}
    finally:
        db.close()


def test_package_blocks_matching() -> None:
    entries = [
        BlockEntry("npm", "x", "1.0.0", None, "osv", "A", None, None),
        BlockEntry("npm", "x", None, ">= 2.0.0, < 3.0.0", "github", "B", None, None),
    ]
    pb = PackageBlocks("npm", entries)
    assert pb and pb.package_block is None
    assert pb.match("npm", "v1.0.0") is entries[0]
    assert pb.match("npm", "2.5.0") is entries[1]
    assert pb.match("npm", "3.0.0") is None and pb.match("npm", None) is None
    whole = BlockEntry("pypi", "y", None, ">= 0", "osv", "C", "r", "https://u")
    assert whole.package_level and whole.matches(None) and whole.as_json()["url"] == "https://u"
    assert PackageBlocks("pypi", [whole]).match("pypi", "1") is whole
    assert not entries[0].matches(None) and entries[1].matches("2.0.0")
    assert not PackageBlocks("npm", [])


# ---- recorder ------------------------------------------------------------------------------------------------


async def test_recorder_aggregates_and_collapses(tmp_path: Path) -> None:
    path = tmp_path / "r.db"
    migrate(path)
    db = Database(path)
    db.open()
    clock = FrozenClock(1_800_000_000)
    rec = Recorder(db, clock, record_client_ip=False)
    try:
        rec.flush()  # nothing to do
        for _ in range(3):
            rec.download("pypi", "a", "1.0", 100, cache_hit=True)
            rec.event("blocked", "pypi", "a", "1.0", client_ip="1.2.3.4", details={"x": 1})
        rec.download("pypi", "a", None, 50, cache_hit=False)
        rec.decision("pypi", "artifact", "served", 4)
        rec.lookup("pypi", cached=True)
        rec.lookup("pypi", cached=True)
        rec.lookup("pypi", cached=False)
        clock.advance(300)  # next 5-minute bucket, same hour
        rec.download("pypi", "a", "1.0", 10, cache_hit=True)
        rec.lookup("pypi", cached=True)
        rec.catalog("pypi", "a", [("1.0", 1.0, False), ("2.0", None, True)])
        rec.catalog("pypi", "a")  # within an hour: skipped
        clock.advance(4000)
        rec.catalog("pypi", "a")
        rec.flush()
        await db.writer.run(lambda _c: None)
        q = db.readers.query
        assert tuple(q("SELECT serves, cache_hits, bytes FROM packages WHERE name='a'")[0]) == (5, 4, 360)
        assert tuple(q("SELECT count, client_ip FROM events")[0]) == (3, None)
        assert q("SELECT sum(count) FROM decisions_hourly")[0][0] == 4
        assert q("SELECT sum(count) FROM decisions_5min")[0][0] == 4
        assert q("SELECT count(*) FROM package_versions")[0][0] == 3  # 1.0, 2.0 and "" (unknown)
        assert q("SELECT count(*) FROM downloads_daily")[0][0] == 2
        # 5-minute rows roll up into one hourly row per version; cache bytes are tracked separately
        assert q("SELECT count(*) FROM downloads_5min WHERE version = '1.0'")[0][0] == 2
        hourly = q("SELECT serves, cache_hits, bytes, cache_bytes FROM downloads_hourly WHERE version = '1.0'")
        assert tuple(hourly[0]) == (4, 4, 310, 310)
        assert tuple(q("SELECT bytes, cache_bytes FROM downloads_daily WHERE version = ''")[0]) == (50, 0)
        assert dict(q("SELECT source, sum(count) FROM lookups_hourly GROUP BY source")) == {"cache": 3, "upstream": 1}
        assert q("SELECT count(*) FROM lookups_5min")[0][0] == 3
        clock.advance(400 * 86400)
        await db.writer.run(lambda c: retention(c, clock.now(), event_days=30, stats_days=30, ip_days=1))
        assert q("SELECT count(*) FROM events")[0][0] == 0
        assert q("SELECT count(*) FROM downloads_daily")[0][0] == 0
        assert q("SELECT count(*) FROM downloads_5min")[0][0] == 0
        assert q("SELECT count(*) FROM lookups_hourly")[0][0] == 0
    finally:
        db.close()


# ---- logging & clock ---------------------------------------------------------------------------------------------


def test_json_and_text_log_formatters(capsys: pytest.CaptureFixture[str]) -> None:
    logsetup.configure("debug", "json")
    logsetup.configure("debug", "json")  # idempotent: one handler
    log = logging.getLogger("slowshield.test")
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        log.exception("failed", extra={"github_token": "secret", "items": [1, object()], "obj": object(), "n": 3})
    line = capsys.readouterr().out.strip().splitlines()[-1]
    rec = msgspec.json.decode(line)
    assert rec["msg"] == "failed" and rec["github_token"] == "[redacted]" and rec["n"] == 3
    assert "RuntimeError" in rec["exception"] and isinstance(rec["items"][1], str)
    logsetup.configure("info", "text")
    log.info("hello", extra={"a": 1})
    assert "hello {'a': 1}" in capsys.readouterr().out
    logsetup.configure("warning", None)
    log.warning("plain")
    assert "plain" in capsys.readouterr().out


def test_clocks() -> None:
    assert SystemClock().now() > 1_700_000_000
    c = FrozenClock(5)
    c.advance(1)
    assert c.now() == 6
    c.set(1)
    assert c.now() == 1


async def test_writer_survives_cancelled_waiters(tmp_path: Path) -> None:
    """Regression: a cancelled `writer.run()` used to crash the writer thread (InvalidStateError)."""
    import threading

    path = tmp_path / "c.db"
    migrate(path)
    db = Database(path)
    db.open()
    gate = threading.Event()
    try:
        blocker = db.writer.submit(lambda _c: gate.wait(5))
        waiter = asyncio.create_task(db.writer.run(lambda c: c.execute("INSERT INTO meta VALUES ('k', 'v')")))
        await asyncio.sleep(0.01)
        waiter.cancel()
        gate.set()
        blocker.result(5)
        assert await db.writer.run(lambda c: c.execute("SELECT value FROM meta WHERE key = 'k'").fetchone()[0]) == "v"
    finally:
        db.close()
    with pytest.raises(RuntimeError, match="stopped"):
        db.writer.submit(lambda _c: None).result(1)
    db.writer.enqueue(lambda _c: None)  # dropped quietly


async def test_streamed_artifact_skips_empty_chunks() -> None:
    """HTTP/2 upstreams end with an empty DATA frame; it must not become a body message of its own."""
    from slowshield.ecosystems.artifacts import StreamedArtifact

    async def body():  # type: ignore[no-untyped-def]
        yield b"tarball"
        yield b""

    sent: list[dict] = []
    closed: list[bool] = []

    async def send(message):  # type: ignore[no-untyped-def]
        sent.append(message)

    async def on_close() -> None:
        closed.append(True)

    response = StreamedArtifact(200, {"Content-Length": "7"}, body(), on_close)
    await response({"type": "http"}, None, send)  # type: ignore[arg-type]
    assert [(m["type"], m.get("body"), m.get("more_body")) for m in sent] == [
        ("http.response.start", None, None),
        ("http.response.body", b"tarball", True),
        ("http.response.body", b"", False),
    ]
    assert closed == [True]


def test_ui_window_rejects_unknown_granularity() -> None:
    from slowshield.ui.queries import Window, window

    w = window("24h", 1_790_000_000)
    assert (w.table, w.decisions_table, w.lookups_table) == ("downloads_hourly", "decisions_hourly", "lookups_hourly")
    assert window("1h", 1_790_000_000).decisions_table == "decisions_5min"
    assert window("30d", 1_790_000_000).table == "downloads_daily"
    with pytest.raises(ValueError, match="unknown granularity"):
        Window("x", 60, "daily; DROP TABLE events", 0, 60)


def test_healthcheck_only_accepts_http_urls(capsys: pytest.CaptureFixture[str]) -> None:
    import argparse

    from slowshield.cli import cmd_healthcheck

    assert cmd_healthcheck(argparse.Namespace(url="file:///etc/passwd", timeout=1)) == 2
    assert "must be http(s)" in capsys.readouterr().err


async def test_config_blocks_sync_to_the_blocklist(tmp_path: Path) -> None:
    from slowshield.blocklist import sync_config_blocks

    path = tmp_path / "b.db"
    migrate(path)
    db = Database(path)
    db.open()
    try:

        def rows() -> list[tuple]:
            return [tuple(r) for r in db.readers.query(
                "SELECT ecosystem, name, version, reason FROM blocklist WHERE source = 'config' ORDER BY name"
            )]  # fmt: skip

        blocks = [("oci", "docker.io/library/evil", None, "miner", None), ("npm", "left-pad-ng", "2.0.0", None, None)]
        assert await db.writer.run(lambda c: sync_config_blocks(c, blocks, 1.0)) == 2
        assert await db.writer.run(lambda c: sync_config_blocks(c, blocks, 2.0)) == 0  # unchanged: nothing written
        gen = db.meta("blocklist_generation")
        changed = [("oci", "docker.io/library/evil", None, "miner, confirmed", None)]
        assert await db.writer.run(lambda c: sync_config_blocks(c, changed, 3.0)) == 2  # one updated, one removed
        assert rows() == [("oci", "docker.io/library/evil", None, "miner, confirmed")]
        assert db.meta("blocklist_generation") != gen
    finally:
        db.close()
