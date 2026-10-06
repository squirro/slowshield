"""Cargo sparse registry: index files with held versions marked as yanked, publish times from `pubtime` (never
earlier than first seen), 403/451 refusals as text, verified .crate downloads, RustSec malware, upstream failures."""

from __future__ import annotations

import hashlib
import json

import httpx

from slowshield.feeds import FeedScheduler
from slowshield.feeds.github import GithubFeed
from slowshield.feeds.osv import OsvFeed
from tests.conftest import DAY, NOW, Running, asgi_get

TEXT = "text/plain; charset=utf-8"
HELLO = "/cargo/fa/ke/fake_hello"


def _lines(body: str) -> dict[str, dict]:
    return {d["vers"]: d for d in (json.loads(line) for line in body.splitlines())}


def _yanked(body: str) -> dict[str, bool]:
    return {v: d["yanked"] for v, d in _lines(body).items()}


def _hits(run: Running, prefix: str) -> dict[str, int]:
    return run.fake.hits(prefix)


async def test_config_json_points_downloads_at_slowshield(running: Running) -> None:
    r = await running.client.get("/cargo/config.json")
    assert r.status_code == 200 and r.json() == {"dl": "https://slowshield.test/cargo/crates"}
    root = await running.client.get("/cargo/")
    assert root.status_code == 200 and "sparse+" in root.text


async def test_index_marks_too_new_versions_as_yanked_and_passes_the_rest_unchanged(running: Running) -> None:
    r = await running.client.get(HELLO)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert _yanked(r.text) == {"1.0.0": False, "1.0.1": True, "1.1.0": False, "1.2.0": True}  # 1.0.1 upstream
    assert r.headers["x-slowshield-held-versions"] == "1"
    assert int(r.headers["cache-control"].removeprefix("max-age=")) == 300
    again = await running.client.get(HELLO, headers={"If-None-Match": r.headers["etag"]})
    assert again.status_code == 304 and again.headers["etag"] == r.headers["etag"]
    assert _hits(running, "/cargo-index/") == {"/cargo-index/fa/ke/fake_hello": 1}  # the rest came from memory
    running.clock.advance(5 * DAY + 1)  # 1.2.0 is 7 days old now
    later = await running.client.get(HELLO, headers={"If-None-Match": r.headers["etag"]})
    assert later.status_code == 200 and _yanked(later.text)["1.2.0"] is False
    # Byte for byte what crates.io sent, but for the one token.
    async with httpx.AsyncClient() as client:
        upstream = (await client.get(f"{running.fake.url}/cargo-index/fa/ke/fake_hello")).content
    assert later.content == upstream
    held = upstream.split(b"\n")
    held[3] = held[3].replace(b'"yanked":false', b'"yanked":true')
    assert r.content == b"\n".join(held)


async def test_index_paths_are_the_lower_case_canonical_ones(running: Running) -> None:
    assert (await running.client.get("/cargo/fa/nc/fancy-name")).status_code == 200
    for path in ("/cargo/fa/nc/Fancy-Name", "/cargo/xx/yy/fancy-name", "/cargo/fancy-name", "/cargo/2/fancy-name"):
        assert (await running.client.get(path)).status_code == 404, path
    unknown = "/cargo/no/-s/no-such-crate"
    assert (await running.client.get(unknown)).status_code == 404
    assert (await running.client.get(unknown)).status_code == 404
    assert _hits(running, "/cargo-index/no/") == {"/cargo-index/no/-s/no-such-crate": 1}  # the 404 is remembered
    assert (await running.client.post(HELLO)).status_code == 405


async def test_downloads_are_verified_against_the_index_and_cached(running: Running) -> None:
    r = await running.client.get("/cargo/crates/fake_hello/1.1.0/download")
    assert r.status_code == 200 and r.headers["x-slowshield-cache"] == "miss"
    cksum = running.fake.control("info")["cargo"]["fake_hello"]["1.1.0"]["cksum"]
    assert hashlib.sha256(r.content).hexdigest() == cksum
    await running.drain()
    hit = await running.client.get("/cargo/crates/fake_hello/1.1.0/download")
    assert hit.headers["x-slowshield-cache"] == "hit" and hit.content == r.content
    rows = running.rows("SELECT package, version, filename, upstream_digest, published FROM artifacts")
    assert rows == [("fake_hello", "1.1.0", "fake_hello-1.1.0.crate", cksum, NOW - 30 * DAY)]
    head = await running.client.head("/cargo/crates/fake_hello/1.1.0/download")
    assert head.status_code == 200 and int(head.headers["content-length"]) == len(r.content)
    # Yanked upstream still downloads: cargo only skips yanked versions when it resolves, not for a lockfile.
    assert (await running.client.get("/cargo/crates/fake_hello/1.0.1/download")).status_code == 200


async def test_too_new_downloads_get_403_with_the_version_to_use(running: Running) -> None:
    r = await running.client.get("/cargo/crates/fake_hello/1.2.0/download")
    assert r.status_code == 403 and r.headers["content-type"] == TEXT
    assert r.text.startswith("slowshield: fake_hello@1.2.0 is too new.\nIt was published 2026-09-19T14:13:20Z")
    assert "cargo update -p fake_hello@1.2.0 --precise 1.1.0" in r.text
    assert int(r.headers["retry-after"]) == int(5 * DAY)
    assert _hits(running, "/cargo-static/") == {}  # refused without asking upstream
    await running.drain()
    assert ("age_gate", "fake_hello", "1.2.0") in running.rows("SELECT type, package, version FROM events")
    running.clock.advance(5 * DAY + 1)
    assert (await running.client.get("/cargo/crates/fake_hello/1.2.0/download")).status_code == 200


async def test_downloads_use_the_index_spelling_of_the_name(running: Running) -> None:
    for name in ("Fancy-Name", "fancy-name"):  # cargo sends the index spelling; only the index path is lower case
        r = await running.client.get(f"/cargo/crates/{name}/1.0.0/download")
        assert r.status_code == 200, name
        await running.drain()
    assert _hits(running, "/cargo-static/") == {"/cargo-static/crates/Fancy-Name/1.0.0/download": 1}
    await running.drain()
    assert running.rows("SELECT name FROM packages WHERE ecosystem = 'cargo'") == [("fancy_name",)]


async def test_versions_not_in_the_index_are_404(running: Running) -> None:
    for path in (
        "/cargo/crates/fake_hello/9.9.9/download",
        "/cargo/crates/fake_hello/not-a-version/download",
        "/cargo/crates/no-such-crate/1.0.0/download",
        "/cargo/crates/fake_hello/1.0.0/download/extra",
    ):
        assert (await running.client.get(path)).status_code == 404, path


async def test_brand_new_crates_are_held_unless_fail_open_is_on(start_app) -> None:
    strict = await start_app()
    path = "/cargo/br/an/brand-new-crate"
    assert _yanked((await strict.client.get(path)).text) == {"0.1.0": True}
    assert (await strict.client.get("/cargo/crates/brand-new-crate/0.1.0/download")).status_code == 403
    lenient = await start_app("[upstreams.cargo]\nfail_open = true\n")
    r = await lenient.client.get(path)
    assert _yanked(r.text) == {"0.1.0": False} and r.headers["x-slowshield-fail-open"] == "1"
    assert (await lenient.client.get("/cargo/crates/brand-new-crate/0.1.0/download")).status_code == 200


async def test_a_line_without_pubtime_is_timed_from_when_it_was_first_listed(running: Running) -> None:
    assert _yanked((await running.client.get("/cargo/un/ti/untimed")).text) == {"1.0.0": True}
    await running.drain()
    assert running.rows("SELECT published, first_listed FROM package_versions WHERE name = 'untimed'") == [(None, NOW)]
    running.clock.advance(7 * DAY)
    assert (await running.client.get("/cargo/crates/untimed/1.0.0/download")).status_code == 200


async def test_a_publish_time_never_moves_earlier(running: Running) -> None:
    assert _yanked((await running.client.get(HELLO)).text)["1.2.0"] is True
    await running.drain()
    # The index now claims 1.2.0 is 30 days old (same bytes, so the same checksum).
    running.fake.control("publish", ecosystem="cargo", name="fake_hello", version="1.2.0", age_days="30")
    running.clock.advance(7 * 3600)  # past the metadata TTL: the index is fetched again
    r = await running.client.get(HELLO)
    assert '"pubtime":"2026-08-22' in r.text and _yanked(r.text)["1.2.0"] is True
    assert (await running.client.get("/cargo/crates/fake_hello/1.2.0/download")).status_code == 403
    await running.drain()
    rows = running.rows("SELECT published FROM package_versions WHERE name = 'fake_hello' AND version = '1.2.0'")
    assert rows == [(NOW - 2 * DAY,)]


async def test_malware_is_refused(start_app, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    run = await start_app()
    await FeedScheduler(run.ctx, [OsvFeed(run.ctx), GithubFeed(run.ctx)]).run_once()
    for path in ("/cargo/ev/il/evil-crate", "/cargo/crates/evil-crate/1.0.0/download"):
        r = await run.client.get(path)
        assert r.status_code == 451 and r.headers["content-type"] == TEXT, path
        assert r.text.startswith("slowshield: evil_crate is blocked as known malware.\nAdvisory: MAL-2026-4001")
    # RustSec's own malware advisories count too, unless a MAL- advisory covers them already.
    r = await run.client.get("/cargo/ru/st/rustsec-evil")
    assert r.status_code == 451 and "RUSTSEC-2026-0001" in r.text
    # Removed from crates.io since: still refused, and recorded.
    assert (await run.client.get("/cargo/crates/rustsec-evil/0.0.1/download")).status_code == 451
    partly = await run.client.get("/cargo/pa/rt/partly-crate")
    assert _yanked(partly.text) == {"1.0.0": False, "1.1.0": True}
    r = await run.client.get("/cargo/crates/partly-crate/1.1.0/download")
    assert r.status_code == 451 and "GHSA-aaaa-0007-0007" in r.text
    # An ordinary vulnerability and an open-ended "malicious from 2.0.0 on" are not blocks.
    assert (await run.client.get("/cargo/crates/fake_hello/1.0.0/download")).status_code == 200
    assert (await run.client.get("/cargo/crates/hijacked/2.0.0/download")).status_code == 200
    blocks = run.rows("SELECT name, version, advisory_id FROM blocklist WHERE ecosystem = 'cargo' ORDER BY name")
    assert blocks == [
        ("evil_crate", None, "MAL-2026-4001"),
        ("partly_crate", "1.1.0", "GHSA-aaaa-0007-0007"),
        ("rustsec_evil", None, "RUSTSEC-2026-0001"),
    ]
    await run.drain()
    events = run.rows("SELECT package, version FROM events WHERE type = 'blocked' AND ecosystem = 'cargo'")
    assert ("rustsec_evil", "0.0.1") in events


async def test_bytes_that_do_not_match_the_index_are_refused(running: Running) -> None:
    running.fake.control("tamper", path="/cargo-static/crates/fake_hello/1.1.0/download")
    res = await asgi_get(running.app, "/cargo/crates/fake_hello/1.1.0/download")
    assert res.status == 503 or res.error is not None  # never a whole tampered file
    await running.drain()
    events = running.rows("SELECT type, package, version FROM events WHERE ecosystem = 'cargo'")
    assert ("integrity_mismatch", "fake_hello", "1.1.0") in events


async def test_bytes_that_change_after_the_first_download_are_tampering(running: Running) -> None:
    assert (await running.client.get("/cargo/crates/fake_hello/1.0.0/download")).status_code == 200
    await running.drain()
    running.ctx.artifact_cache.enabled = False  # force the next request upstream
    running.fake.control("tamper", path="/cargo-static/crates/fake_hello/1.0.0/download")
    res = await asgi_get(running.app, "/cargo/crates/fake_hello/1.0.0/download")
    assert res.status == 451 and b"changed upstream" in res.body
    assert (await running.client.get("/cargo/crates/fake_hello/1.0.0/download")).status_code == 451


async def test_upstream_failures_are_503_and_a_stale_index_is_served(running: Running) -> None:
    running.fake.control("fail", prefix="/cargo-index/", status="503")
    r = await running.client.get("/cargo/fa/nc/fancy-name")
    assert r.status_code == 503 and r.headers["retry-after"] == "10"
    running.fake.control("fail", prefix="/cargo-index/", status="0")
    assert (await running.client.get(HELLO)).status_code == 200
    running.clock.advance(7 * 3600)  # past the metadata TTL
    running.fake.control("fail", prefix="/cargo-index/", status="503")
    assert (await running.client.get(HELLO)).status_code == 200  # stale, rather than nothing
    running.fake.control("fail", prefix="/cargo-index/", status="0")
    running.fake.control("fail", prefix="/cargo-static/", status="500")
    r = await running.client.get("/cargo/crates/fake_hello/1.1.0/download")
    assert r.status_code == 503 and r.headers["retry-after"] == "10"  # cargo retries a 503
    running.fake.control("fail", prefix="/cargo-static/", status="0")


async def test_exceptions_match_any_spelling_of_the_name(start_app) -> None:
    run = await start_app(
        '[[exceptions]]\necosystem = "cargo"\npackage = "Fake-Hello"\nversion = "1.2.0"\ndelay_days = 0\n'
    )
    assert _yanked((await run.client.get(HELLO)).text)["1.2.0"] is False
    assert (await run.client.get("/cargo/crates/fake_hello/1.2.0/download")).status_code == 200


async def test_setup_page_shows_the_cargo_config(running: Running) -> None:
    page = (await running.client.get("/ui/setup")).text
    assert "sparse+https://slowshield.test/cargo/" in page
    assert "[source.crates-io]" in page and "replace-with = &#34;slowshield&#34;" in page


async def test_an_index_file_without_a_usable_line_is_an_upstream_failure(running: Running) -> None:
    running.fake.control("fail", prefix="/cargo-index/fa/nc/", status="200")  # 200 "injected failure 200"
    r = await running.client.get("/cargo/fa/nc/fancy-name")
    assert r.status_code == 503 and "without a usable line" in r.text  # not cached as a crate without versions
    running.fake.control("fail", prefix="/cargo-index/fa/nc/", status="0")
    assert _yanked((await running.client.get("/cargo/fa/nc/fancy-name")).text) == {"1.0.0": False}
    # Once a good copy is stored, a broken answer serves that copy instead.
    running.clock.advance(7 * 3600)
    running.fake.control("fail", prefix="/cargo-index/fa/nc/", status="200")
    assert _yanked((await running.client.get("/cargo/fa/nc/fancy-name")).text) == {"1.0.0": False}
    running.fake.control("fail", prefix="/cargo-index/fa/nc/", status="0")


async def test_operator_blocks_from_the_config(start_app) -> None:
    run = await start_app('[[blocks]]\necosystem = "cargo"\npackage = "Fancy-Name"\nreason = "internal policy"\n')
    r = await run.client.get("/cargo/crates/Fancy-Name/1.0.0/download")
    assert r.status_code == 451
    assert r.text == "slowshield: fancy_name is blocked by the administrator of this proxy.\ninternal policy\n"
