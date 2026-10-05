"""Go module proxy: version lists, publish times from the mirror's Last-Modified, gating, verified downloads,
fail-open, case encoding, the checksum database pass-through and the upstream requests it all costs."""

from __future__ import annotations

import hashlib

from slowshield.feeds import FeedScheduler
from slowshield.feeds.github import GithubFeed
from slowshield.feeds.osv import OsvFeed
from tests.conftest import DAY, NOW, Running, asgi_get

TEXT = "text/plain; charset=utf-8"
HELLO = "/go/example.com/hello/@v"


def _hits(run: Running, prefix: str) -> dict[str, int]:
    return run.fake.hits(prefix)


async def test_list_hides_versions_the_mirror_stored_recently(running: Running) -> None:
    r = await running.client.get(f"{HELLO}/list")
    assert r.status_code == 200
    assert r.headers["content-type"] == TEXT
    # v1.2.0 was stored 2 days ago (its commit is from 2021), v1.3.0-rc.1 yesterday.
    assert r.text.splitlines() == ["v1.0.0", "v1.1.0"]
    assert r.headers["x-slowshield-held-versions"] == "2"
    # Looked up (cache-only) from the newest release down to the first old enough one, plus the prerelease above
    # it; v1.0.0, below the chosen v1.1.0, costs nothing.
    hits = _hits(running, "/go/example.com/hello/@v/")
    assert {p.rsplit("/", 1)[-1]: n for p, n in hits.items()} == {
        "list": 1,
        "v1.2.0.mod": 1,
        "v1.1.0.mod": 1,
        "v1.3.0-rc.1.mod": 1,
    }
    await running.drain()
    rows = running.rows("SELECT version, published FROM package_versions WHERE ecosystem = 'go' ORDER BY version")
    assert [v for v, _ in rows] == ["v1.1.0", "v1.2.0", "v1.3.0-rc.1"]
    assert dict(rows)["v1.2.0"] == NOW - 2 * DAY


async def test_too_new_is_refused_with_text_the_go_command_prints(running: Running) -> None:
    r = await running.client.get(f"{HELLO}/v1.2.0.info")
    assert r.status_code == 403
    assert r.headers["content-type"] == TEXT
    assert "example.com/hello@v1.2.0 is too new" in r.text
    assert "requires 7 days" in r.text and len(r.text.splitlines()) <= 8
    assert int(r.headers["retry-after"]) == int(5 * DAY)
    for ext in ("mod", "zip"):
        assert (await running.client.get(f"{HELLO}/v1.2.0.{ext}")).status_code == 403
    running.clock.advance(5 * DAY + 1)
    r = await running.client.get(f"{HELLO}/v1.2.0.info")
    assert r.status_code == 200
    assert r.json()["Version"] == "v1.2.0"
    assert "v1.2.0" in (await running.client.get(f"{HELLO}/list")).text.splitlines()


async def test_downloads_are_verified_against_the_checksum_database(running: Running) -> None:
    mod = await running.client.get(f"{HELLO}/v1.0.0.mod")
    assert mod.status_code == 200 and mod.text.startswith("module example.com/hello")
    z = await running.client.get(f"{HELLO}/v1.0.0.zip")
    assert z.status_code == 200 and z.headers["content-type"] == "application/zip"
    assert z.headers["x-slowshield-cache"] == "miss"
    await running.drain()
    hit = await running.client.get(f"{HELLO}/v1.0.0.zip")
    assert hit.headers["x-slowshield-cache"] == "hit" and hit.content == z.content
    want = running.fake.info()["go"]["example.com/hello"]["v1.0.0"]["zip_h1"]
    rows = running.rows("SELECT path, upstream_digest, sha256 FROM artifacts WHERE ecosystem = 'go' ORDER BY path")
    assert rows[1] == ("/example.com/hello/@v/v1.0.0.zip", want, hashlib.sha256(z.content).hexdigest())


async def test_zips_redirected_to_storage_are_followed_and_verified(running: Running) -> None:
    r = await running.client.get("/go/example.com/redirected/@v/v1.0.0.zip")
    assert r.status_code == 200 and r.content[:2] == b"PK"
    await running.drain()
    want = running.fake.info()["go"]["example.com/redirected"]["v1.0.0"]["zip_h1"]
    assert running.rows("SELECT upstream_digest FROM artifacts WHERE package = 'example.com/redirected'") == [(want,)]
    assert _hits(running, "/storage/") == {"/storage/example.com/redirected/@v/v1.0.0.zip": 1}


async def test_a_zip_that_fails_its_h1_is_aborted(running: Running) -> None:
    running.fake.control("tamper", path="/go/example.com/hello/@v/v1.1.0.zip")
    res = await asgi_get(running.app, f"{HELLO}/v1.1.0.zip")
    assert res.status == 502 or res.error is not None  # aborted before the last chunk
    await running.drain()
    events = running.rows("SELECT type, package, version FROM events WHERE ecosystem = 'go'")
    assert ("integrity_mismatch", "example.com/hello", "v1.1.0") in events


async def test_bytes_that_change_after_the_first_download_are_tampering(running: Running) -> None:
    assert (await running.client.get(f"{HELLO}/v1.0.0.mod")).status_code == 200
    await running.drain()
    running.ctx.artifact_cache.enabled = False  # force the next request upstream
    running.fake.control("tamper", path="/go/example.com/hello/@v/v1.0.0.mod")
    res = await asgi_get(running.app, f"{HELLO}/v1.0.0.mod")
    assert res.status == 451
    assert res.headers["content-type"] == TEXT and b"changed upstream" in res.body
    again = await running.client.get(f"{HELLO}/v1.0.0.mod")
    assert again.status_code == 451


async def test_a_version_new_to_the_mirror_starts_its_clock_now(running: Running) -> None:
    # Tagged 400 days ago, but nobody fetched it: the mirror stores it now, so it is new (and v0.9.0, stored
    # 200 days ago, keeps the module from failing open).
    r = await running.client.get("/go/example.com/unstored/@v/v1.0.0.info")
    assert r.status_code == 403
    hits = _hits(running, "/go/example.com/unstored/")
    assert hits["/go/example.com/unstored/@v/v1.0.0.mod"] == 2  # cache-only HEAD, then the fetch
    assert running.fake.control("info")["go"]["example.com/unstored"]["v1.0.0"]["stored"] == NOW
    running.clock.advance(7 * DAY + 1)
    assert (await running.client.get("/go/example.com/unstored/@v/v1.0.0.info")).status_code == 200


async def test_without_last_modified_the_clock_starts_at_first_sight(running: Running) -> None:
    # The mirror has it (stored 300 days ago) but sends no Last-Modified: its age counts from now.
    assert (await running.client.get("/go/example.com/nolm/@v/v1.0.0.info")).status_code == 200  # fail-open
    await running.drain()
    assert running.rows("SELECT published FROM package_versions WHERE name = 'example.com/nolm'") == [(NOW,)]
    running.clock.advance(7 * DAY + 1)
    r = await running.client.get("/go/example.com/nolm/@v/v1.0.0.zip")
    assert r.status_code == 200


async def test_a_version_cannot_be_aged_before_it_exists(running: Running) -> None:
    r = await running.client.get(f"{HELLO}/v9.9.9.info")
    assert r.status_code == 404
    await running.drain()
    assert not running.rows("SELECT 1 FROM package_versions WHERE ecosystem = 'go' AND version = 'v9.9.9'")
    # Published a week later: its age counts from then, not from the first request.
    running.fake.control("publish", ecosystem="go", name="example.com/hello", version="v9.9.9", age_days="none")
    running.fake.control("clock", offset=str(8 * DAY))
    running.clock.advance(8 * DAY)
    assert (await running.client.get(f"{HELLO}/v9.9.9.info")).status_code == 403
    running.fake.control("clock", offset="0")


async def test_case_encoded_module_paths(running: Running) -> None:
    r = await running.client.get("/go/github.com/!acme/!widget/@v/list")
    assert r.status_code == 200 and r.text.splitlines() == ["v0.1.0", "v0.2.0"]
    assert (await running.client.get("/go/github.com/!acme/!widget/@v/v0.2.0.zip")).status_code == 200
    assert (await running.client.get("/go/github.com/Acme/Widget/@v/list")).status_code == 404  # not escaped
    await running.drain()
    assert running.rows("SELECT name FROM packages WHERE ecosystem = 'go' AND name LIKE 'github.com/%'") == [
        ("github.com/Acme/Widget",)
    ]


async def test_brand_new_module_fails_open(running: Running) -> None:
    r = await running.client.get("/go/example.com/brandnew/@v/list")
    assert r.text == "v0.1.0\n" and r.headers["x-slowshield-fail-open"] == "1"
    assert (await running.client.get("/go/example.com/brandnew/@v/v0.1.0.zip")).status_code == 200
    await running.drain()
    assert running.rows("SELECT type FROM events WHERE package = 'example.com/brandnew'")[0] == ("fail_open",)


async def test_strict_mode_does_not_fail_open(start_app) -> None:
    run = await start_app("fail_open = false\n")
    assert (await run.client.get("/go/example.com/brandnew/@v/list")).text == ""
    assert (await run.client.get("/go/example.com/brandnew/@v/v0.1.0.zip")).status_code == 403


async def test_untagged_module_latest_and_queries(running: Running) -> None:
    head = "v0.0.0-20260920120000-abcdef123456"
    # Nothing known about this module yet: the newest commit is served (fail-open), like a brand-new package.
    r = await running.client.get("/go/example.com/untagged/@latest")
    assert r.status_code == 200 and r.json()["Version"] == head
    r = await running.client.get("/go/example.com/untagged/@v/main.info")
    assert r.status_code == 200 and r.json()["Version"] == head
    # Once an old commit is known, the module has a version old enough: the one-day-old head is held.
    old = await running.client.get("/go/example.com/untagged/@v/v0.0.0-20250101000000-0123456789ab.info")
    assert old.status_code == 200
    assert (await running.client.get("/go/example.com/untagged/@latest")).status_code == 403
    assert (await running.client.get("/go/example.com/untagged/@v/main.info")).status_code == 403
    assert (await running.client.get(f"/go/example.com/untagged/@v/{head}.zip")).status_code == 403


async def test_incompatible_versions(running: Running) -> None:
    r = await running.client.get("/go/example.com/incompat/@v/list")
    assert r.text == "v2.0.0+incompatible\n"
    assert (await running.client.get("/go/example.com/incompat/@v/v2.0.0+incompatible.zip")).status_code == 200


async def test_malware_is_refused(start_app, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    run = await start_app()
    await FeedScheduler(run.ctx, [OsvFeed(run.ctx), GithubFeed(run.ctx)]).run_once()
    for path in ("/go/example.com/malware/@v/list", "/go/example.com/malware/@v/v1.0.0.zip"):
        r = await run.client.get(path)
        assert r.status_code == 451 and r.headers["content-type"] == TEXT
        assert "MAL-2026-2001" in r.text and "blocked as known malware" in r.text
    # GitHub: only v1.1.0 of example.com/partly (`= 1.1.0`, without the `v`).
    r = await run.client.get("/go/example.com/partly/@v/list")
    assert r.text.splitlines() == ["v1.0.0"]
    r = await run.client.get("/go/example.com/partly/@v/v1.1.0.mod")
    assert r.status_code == 451 and "GHSA-aaaa-0005-0005" in r.text


async def test_exceptions(start_app) -> None:
    run = await start_app(
        '[[exceptions]]\necosystem = "go"\npackage = "example.com/hello"\nversion = "1.2.0"\ndelay_days = 0\n'
    )
    assert (await run.client.get(f"{HELLO}/v1.2.0.info")).status_code == 200
    assert "v1.2.0" in (await run.client.get(f"{HELLO}/list")).text.splitlines()


async def test_checksum_database_pass_through(running: Running) -> None:
    base = "/go/sumdb/sum.golang.org"
    r = await running.client.get(f"{base}/supported")
    assert r.status_code == 200
    lookup = await running.client.get(f"{base}/lookup/example.com/hello@v1.0.0")
    assert lookup.status_code == 200 and "example.com/hello v1.0.0/go.mod h1:" in lookup.text
    assert (await running.client.get(f"{base}/lookup/example.com/hello@v1.0.0")).text == lookup.text
    assert _hits(running, "/sumdb/lookup/")["/sumdb/lookup/example.com/hello@v1.0.0"] == 1
    tile = await running.client.get(f"{base}/tile/8/0/x001/234.p/5")
    assert tile.status_code == 200 and len(tile.content) == 256
    assert (await running.client.get(f"{base}/latest")).text.startswith("go.sum database tree")
    for bad in ("/go/sumdb/sum.example.org/latest", f"{base}/lookup/../../etc", f"{base}/tile/../x", f"{base}/x"):
        assert (await running.client.get(bad)).status_code == 404, bad


async def test_outside_the_protocol_is_not_found(running: Running) -> None:
    for path in (
        "/go/example.com/hello/@v/v1.0.0.tar",
        "/go/example.com/hello/@v/latest.mod",  # only .info resolves queries
        "/go/hello/@v/list",  # no dot in the first element
        "/go/example.com/hello/@v/x/y.info",
        "/go/example.com/../hello/@v/list",
        "/go/example.com/hello/v1/@v/list",
    ):
        r = await running.client.get(path)
        assert r.status_code == 404, path
    assert (await running.client.post(f"{HELLO}/list")).status_code == 405


async def test_mirror_down_fails_closed_for_unknown_versions(running: Running) -> None:
    assert (await running.client.get(f"{HELLO}/v1.0.0.mod")).status_code == 200  # learned before the outage
    await running.drain()
    running.fake.control("fail", prefix="/go/", status="503")
    r = await running.client.get(f"{HELLO}/v1.1.0.info")
    assert r.status_code == 503 and r.headers["retry-after"] == "60"
    assert "cannot establish when" in r.text
    assert (await running.client.get(f"{HELLO}/v1.0.0.mod")).status_code == 200  # cached and verified
    running.fake.control("fail", prefix="/go/", status="0")


async def test_upstream_requests_per_new_version(running: Running) -> None:
    """What the go command does for one new dependency, and what it costs upstream: one HEAD on top of the
    client's own requests, and the client's checksum lookup comes from SlowShield's cache."""
    for path in (
        f"{HELLO}/list",
        f"{HELLO}/v1.1.0.info",
        f"{HELLO}/v1.1.0.mod",
        "/go/sumdb/sum.golang.org/lookup/example.com/hello@v1.1.0",
        f"{HELLO}/v1.1.0.zip",
    ):
        assert (await running.client.get(path)).status_code == 200, path
    hits = {p: n for p, n in _hits(running, "/").items() if "/v1.1.0" in p or p.endswith(("/list", "@v1.1.0"))}
    assert hits == {
        "/go/example.com/hello/@v/list": 1,
        "/go/example.com/hello/@v/v1.1.0.info": 1,
        "/go/example.com/hello/@v/v1.1.0.mod": 2,  # the HEAD for its publish time, then the download
        "/go/example.com/hello/@v/v1.1.0.zip": 1,
        "/sumdb/lookup/example.com/hello@v1.1.0": 1,
    }
