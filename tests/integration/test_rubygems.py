"""RubyGems compact index: info files without held lines (ETag = MD5, Repr-Digest), /versions with zeroed checksums
kept up to date by Range requests, publish times from `created_at` per version and platform, 425/451 refusals,
verified .gem downloads, gem specifications, the full Marshal index refused, malware, upstream failures."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from pathlib import Path

import httpx

from slowshield.ecosystems.rubygems.versions_file import zero_checksums
from slowshield.feeds import FeedScheduler
from slowshield.feeds.github import GithubFeed
from slowshield.feeds.osv import OsvFeed
from tests.conftest import DAY, NOW, Running, asgi_get

TEXT = "text/plain; charset=utf-8"
HELLO = "/rubygems/info/fake_hello"


def _keys(body: str) -> list[str]:
    lines = body.splitlines()
    assert lines[0] == "---", body
    return [line.split(" ", 1)[0] for line in lines[1:]]


def _md5(body: bytes) -> str:
    return '"' + hashlib.md5(body, usedforsecurity=False).hexdigest() + '"'


def _sha(body: bytes) -> str:
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


async def _upstream(run: Running, path: str) -> bytes:
    async with httpx.AsyncClient() as client:
        return (await client.get(f"{run.fake.url}{path}")).content


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


async def test_root_explains_the_setup(running: Running) -> None:
    r = await running.client.get("/rubygems/")
    assert r.status_code == 200 and "mirror.https://rubygems.org" in r.text
    assert (await running.client.post(HELLO)).status_code == 405


async def test_info_leaves_out_too_new_versions_and_passes_the_rest_unchanged(running: Running) -> None:
    r = await running.client.get(HELLO)
    assert r.status_code == 200 and r.headers["content-type"] == TEXT
    assert _keys(r.text) == ["1.0.0", "1.1.0"] and r.headers["x-slowshield-held-versions"] == "1"
    # The compact index's own headers: Bundler 2.4 and older check the ETag against the MD5 of the body, newer ones
    # the Repr-Digest; no-transform keeps proxies from compressing (and re-tagging) it.
    assert r.headers["etag"] == _md5(r.content) and r.headers["repr-digest"] == _sha(r.content)
    assert r.headers["cache-control"] == "max-age=60, no-transform"
    again = await running.client.get(HELLO, headers={"If-None-Match": r.headers["etag"]})
    assert again.status_code == 304 and again.headers["etag"] == r.headers["etag"]
    assert running.fake.hits("/rubygems-index/") == {"/rubygems-index/info/fake_hello": 1}
    upstream = await _upstream(running, "/rubygems-index/info/fake_hello")
    assert r.content == b"".join(line + b"\n" for line in upstream.split(b"\n")[:3])  # header, 1.0.0, 1.1.0
    running.clock.advance(5 * DAY + 1)  # 1.2.0 is 7 days old now
    later = await running.client.get(HELLO, headers={"If-None-Match": r.headers["etag"]})
    assert later.status_code == 200 and later.content == upstream  # byte for byte what rubygems.org sent


async def test_platform_gems_are_judged_by_their_own_push_time(running: Running) -> None:
    r = await running.client.get("/rubygems/info/fake_native")
    # 2.1.0's platform gems were pushed a day ago for a version that is 60 days old: held like a new version.
    assert _keys(r.text) == ["2.0.0", "2.0.0-x86_64-linux", "2.0.0-aarch64-linux", "2.1.0"]
    assert r.headers["x-slowshield-held-versions"] == "2"
    held = await running.client.get("/rubygems/gems/fake_native-2.1.0-x86_64-linux.gem")
    assert held.status_code == 425 and "fake_native-2.1.0-x86_64-linux is too new" in held.text
    ok = await running.client.get("/rubygems/gems/fake_native-2.0.0-aarch64-linux.gem")
    assert ok.status_code == 200
    await running.drain()
    rows = running.rows(
        "SELECT version, published FROM package_versions WHERE name = 'fake_native' AND version LIKE '2.1.0%'"
    )
    assert sorted(rows) == [
        ("2.1.0", NOW - 60 * DAY),
        ("2.1.0-aarch64-linux", NOW - DAY),
        ("2.1.0-x86_64-linux", NOW - DAY),
    ]


async def test_versions_has_every_checksum_zeroed_and_the_same_length(running: Running) -> None:
    upstream = await _upstream(running, "/rubygems-index/versions")
    r = await running.client.get("/rubygems/versions")
    assert r.status_code == 200 and r.content == zero_checksums(upstream) and len(r.content) == len(upstream)
    assert b"fake_hello 1.0.0,1.1.0,1.2.0 " + b"0" * 32 + b"\n" in r.content  # held versions stay listed
    assert r.headers["etag"] == _md5(r.content) and r.headers["repr-digest"] == _sha(r.content)
    assert r.headers["accept-ranges"] == "bytes" and "no-transform" in r.headers["cache-control"]
    assert (
        await running.client.get("/rubygems/versions", headers={"If-None-Match": r.headers["etag"]})
    ).status_code == 304
    head = await running.client.head("/rubygems/versions")
    assert head.status_code == 200 and int(head.headers["content-length"]) == len(r.content) and not head.content
    # Bundler appends: one byte before the end of its copy, then whatever is new.
    tail = await running.client.get("/rubygems/versions", headers={"Range": f"bytes={len(r.content) - 1}-"})
    assert tail.status_code == 206 and tail.content == b"\n"
    assert tail.headers["content-range"] == f"bytes {len(r.content) - 1}-{len(r.content) - 1}/{len(r.content)}"
    assert tail.headers["repr-digest"] == r.headers["repr-digest"]  # of the whole file, as Bundler checks it
    # A start past the end (a copy from rubygems.org or another instance): the whole file.
    past = await running.client.get("/rubygems/versions", headers={"Range": f"bytes={len(r.content) + 50}-"})
    assert past.status_code == 200 and past.content == r.content
    # One request from SlowShield (a minute's copy), one from this test.
    assert running.fake.hits("/rubygems-index/versions") == {"/rubygems-index/versions": 2}


async def test_versions_is_updated_by_appending_and_rebuilt_when_upstream_is(running: Running) -> None:
    first = (await running.client.get("/rubygems/versions")).content
    running.fake.control("publish", ecosystem="rubygems", name="fake_hello", version="1.3.0", age_days="0")
    assert (await running.client.get("/rubygems/versions")).content == first  # checked at most once a minute
    running.clock.advance(61)
    r = await running.client.get("/rubygems/versions")
    assert r.content.startswith(first) and r.content.endswith(b"fake_hello 1.3.0 " + b"0" * 32 + b"\n")
    sent = running.fake.headers("/rubygems-index/versions")
    assert sent["range"] == f"bytes={len(first) - 1}-" and sent["if-none-match"].startswith('"')
    tail = await running.client.get("/rubygems/versions", headers={"Range": f"bytes={len(first) - 1}-"})
    assert tail.status_code == 206 and tail.content == b"\n" + r.content[len(first) :]
    upstream = await _upstream(running, "/rubygems-index/versions")
    assert r.content == zero_checksums(upstream)
    # The monthly rebuild: the old copy is no longer a prefix, so the whole file is fetched again.
    running.fake.control("rubygems-rebuild")
    running.clock.advance(61)
    rebuilt = await running.client.get("/rubygems/versions")
    upstream = await _upstream(running, "/rubygems-index/versions")
    assert rebuilt.content == zero_checksums(upstream) and rebuilt.content != r.content
    assert b"fake_hello 1.0.0,1.1.0,1.2.0,1.3.0 " in rebuilt.content
    assert sorted(p.name for p in (Path(running.ctx.cfg.raw.data_dir) / "rubygems").iterdir()) == [
        "lock",
        "served.2",
        "state.json",
        "upstream.2",
    ]


async def test_versions_outlives_upstream_failures(running: Running) -> None:
    running.fake.control("fail", prefix="/rubygems-index/versions", status="503")
    r = await running.client.get("/rubygems/versions")
    assert r.status_code == 503 and r.headers["retry-after"] == "10"
    running.fake.control("fail", prefix="/rubygems-index/versions", status="0")
    good = await running.client.get("/rubygems/versions")
    assert good.status_code == 200
    running.clock.advance(61)
    running.fake.control("fail", prefix="/rubygems-index/versions", status="503")
    stale = await running.client.get("/rubygems/versions")
    assert stale.status_code == 200 and stale.content == good.content
    running.fake.control("fail", prefix="/rubygems-index/versions", status="0")


async def test_downloads_are_verified_against_the_index_and_cached(running: Running) -> None:
    r = await running.client.get("/rubygems/gems/fake_hello-1.1.0.gem")
    assert r.status_code == 200 and r.headers["x-slowshield-cache"] == "miss"
    sha = running.fake.info()["rubygems"]["fake_hello"]["1.1.0"]["sha256"]
    assert hashlib.sha256(r.content).hexdigest() == sha
    await running.drain()
    hit = await running.client.get("/rubygems/gems/fake_hello-1.1.0.gem")
    assert hit.headers["x-slowshield-cache"] == "hit" and hit.content == r.content
    rows = running.rows("SELECT package, version, filename, upstream_digest, published FROM artifacts")
    assert rows == [("fake_hello", "1.1.0", "fake_hello-1.1.0.gem", sha, NOW - 30 * DAY)]
    head = await running.client.head("/rubygems/gems/fake_hello-1.1.0.gem")
    assert head.status_code == 200 and int(head.headers["content-length"]) == len(r.content)


async def test_too_new_downloads_get_425_with_the_reason(running: Running) -> None:
    r = await running.client.get("/rubygems/gems/fake_hello-1.2.0.gem")
    assert r.status_code == 425 and r.headers["content-type"] == TEXT
    assert r.text.startswith(
        f"slowshield: fake_hello-1.2.0 is too new.\nIt was published {_iso(NOW - 2 * DAY)} (2.0 days ago)"
    )
    assert int(r.headers["retry-after"]) == int(5 * DAY)
    assert running.fake.hits("/rubygems-dl/") == {}  # refused without asking upstream
    spec = await running.client.get("/rubygems/quick/Marshal.4.8/fake_hello-1.2.0.gemspec.rz")
    assert spec.status_code == 425
    await running.drain()
    assert ("age_gate", "fake_hello", "1.2.0") in running.rows("SELECT type, package, version FROM events")
    running.clock.advance(5 * DAY + 1)
    assert (await running.client.get("/rubygems/gems/fake_hello-1.2.0.gem")).status_code == 200


async def test_gem_specifications_are_served_once_fetched(running: Running) -> None:
    path = "/rubygems/quick/Marshal.4.8/fake_deps-0.1.0.gemspec.rz"
    r = await running.client.get(path)
    assert r.status_code == 200 and r.content == await _upstream(
        running, "/rubygems-dl/quick/Marshal.4.8/fake_deps-0.1.0.gemspec.rz"
    )
    assert (await running.client.get(path)).content == r.content
    # One request from SlowShield, one from this test.
    assert running.fake.hits("/rubygems-dl/quick/") == {"/rubygems-dl/quick/Marshal.4.8/fake_deps-0.1.0.gemspec.rz": 2}
    assert (await running.client.get("/rubygems/quick/Marshal.4.8/fake_deps-9.9.gemspec.rz")).status_code == 404


async def test_file_names_are_read_against_the_index(running: Running) -> None:
    # `fake-2fa-1.0.0`: the gem `fake` doesn't exist, `fake-2fa` 1.0.0 does.
    assert (await running.client.get("/rubygems/gems/fake-2fa-1.0.0.gem")).status_code == 200
    # Names are case-sensitive, as on rubygems.org.
    assert (await running.client.get("/rubygems/info/Fake_Case")).status_code == 200
    assert (await running.client.get("/rubygems/info/fake_case")).status_code == 404
    assert (await running.client.get("/rubygems/gems/Fake_Case-1.0.0.gem")).status_code == 200
    for path in (
        "/rubygems/gems/fake_hello-9.9.9.gem",
        "/rubygems/gems/no_such_gem-1.0.0.gem",
        "/rubygems/gems/fake_hello.gem",
        "/rubygems/gems/fake_hello-1.0.0.tgz",
        "/rubygems/info/a/b",
        "/rubygems/elsewhere",
    ):
        assert (await running.client.get(path)).status_code == 404, path


async def test_the_full_marshal_index_and_the_api_are_not_served(running: Running) -> None:
    for path in ("/rubygems/specs.4.8.gz", "/rubygems/latest_specs.4.8.gz", "/rubygems/api/v1/dependencies"):
        r = await running.client.get(path)
        assert r.status_code == 404 and "can't be filtered by release age" in r.text, path
    assert running.fake.hits("/rubygems") == {}


async def test_brand_new_gems_are_held_unless_fail_open_is_on(start_app) -> None:
    strict = await start_app()
    r = await strict.client.get("/rubygems/info/brand_new_gem")
    assert r.status_code == 200 and r.text == "---\n"  # nothing to install: "could not find" in both clients
    assert (await strict.client.get("/rubygems/gems/brand_new_gem-0.1.0.gem")).status_code == 425
    lenient = await start_app("[upstreams.rubygems]\nfail_open = true\n")
    r = await lenient.client.get("/rubygems/info/brand_new_gem")
    assert _keys(r.text) == ["0.1.0"] and r.headers["x-slowshield-fail-open"] == "1"
    assert (await lenient.client.get("/rubygems/gems/brand_new_gem-0.1.0.gem")).status_code == 200


async def test_lines_without_a_plausible_created_at_are_timed_from_when_they_were_first_listed(
    running: Running,
) -> None:
    for name in ("untimed_gem", "future_gem"):
        assert _keys((await running.client.get(f"/rubygems/info/{name}")).text) == [], name
    await running.drain()
    rows = running.rows(
        "SELECT name, published, first_listed FROM package_versions WHERE name IN ('untimed_gem', 'future_gem') "
        "ORDER BY name"
    )
    assert rows == [("future_gem", None, NOW), ("untimed_gem", None, NOW)]
    running.clock.advance(7 * DAY)
    assert (await running.client.get("/rubygems/gems/untimed_gem-1.0.0.gem")).status_code == 200


async def test_a_publish_time_never_moves_earlier(running: Running) -> None:
    assert _keys((await running.client.get(HELLO)).text) == ["1.0.0", "1.1.0"]
    await running.drain()
    # The index now claims 1.2.0 is 30 days old (same bytes, so the same checksum).
    running.fake.control("publish", ecosystem="rubygems", name="fake_hello", version="1.2.0", age_days="30")
    running.clock.advance(7 * 3600)  # past the metadata TTL: the info file is fetched again
    r = await running.client.get(HELLO)
    assert "1.2.0" not in _keys(r.text)
    assert (await running.client.get("/rubygems/gems/fake_hello-1.2.0.gem")).status_code == 425
    await running.drain()
    rows = running.rows("SELECT published FROM package_versions WHERE name = 'fake_hello' AND version = '1.2.0'")
    assert rows == [(NOW - 2 * DAY,)]


async def test_yanked_lines_are_recorded(running: Running) -> None:
    assert _keys((await running.client.get("/rubygems/info/partly_gem")).text) == ["1.0.0", "1.1.0"]
    await running.drain()
    running.fake.control("rubygems-yank", name="partly_gem", key="1.1.0")
    running.clock.advance(7 * 3600)
    assert _keys((await running.client.get("/rubygems/info/partly_gem")).text) == ["1.0.0"]
    assert (await running.client.get("/rubygems/gems/partly_gem-1.1.0.gem")).status_code == 404
    await running.drain()
    rows = running.rows("SELECT version, yanked FROM package_versions WHERE name = 'partly_gem' ORDER BY version")
    assert rows == [("1.0.0", 0), ("1.1.0", 1)]


async def test_malware_is_refused(start_app, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    run = await start_app()
    await FeedScheduler(run.ctx, [OsvFeed(run.ctx), GithubFeed(run.ctx)]).run_once()
    r = await run.client.get("/rubygems/info/evil_gem")
    assert r.status_code == 200 and r.text == "---\n"
    r = await run.client.get("/rubygems/gems/evil_gem-1.0.0.gem")
    assert r.status_code == 451 and r.headers["content-type"] == TEXT
    assert r.text.startswith("slowshield: evil_gem is blocked as known malware.\nAdvisory: MAL-2026-7001")
    partly = await run.client.get("/rubygems/info/partly_gem")
    assert _keys(partly.text) == ["1.0.0"]
    r = await run.client.get("/rubygems/gems/partly_gem-1.1.0.gem")
    assert r.status_code == 451 and "GHSA-aaaa-0010-0010" in r.text
    # Yanked from rubygems.org since: still refused, and recorded.
    run.fake.control("rubygems-yank", name="evil_gem", key="1.0.0")
    run.clock.advance(7 * 3600)
    assert (await run.client.get("/rubygems/gems/evil_gem-1.0.0.gem")).status_code == 451
    blocks = run.rows("SELECT name, version, advisory_id FROM blocklist WHERE ecosystem = 'rubygems' ORDER BY name")
    assert blocks == [("evil_gem", None, "MAL-2026-7001"), ("partly_gem", "1.1.0", "GHSA-aaaa-0010-0010")]
    await run.drain()
    events = run.rows("SELECT package, version FROM events WHERE type = 'blocked' AND ecosystem = 'rubygems'")
    assert ("evil_gem", None) in events and ("evil_gem", "1.0.0") in events


async def test_bytes_that_do_not_match_the_index_are_refused(running: Running) -> None:
    running.fake.control("tamper", path="/rubygems-dl/gems/fake_hello-1.1.0.gem")
    res = await asgi_get(running.app, "/rubygems/gems/fake_hello-1.1.0.gem")
    assert res.status == 503 or res.error is not None  # never a whole tampered file
    await running.drain()
    events = running.rows("SELECT type, package, version FROM events WHERE ecosystem = 'rubygems'")
    assert ("integrity_mismatch", "fake_hello", "1.1.0") in events


async def test_bytes_that_change_after_the_first_download_are_tampering(running: Running) -> None:
    assert (await running.client.get("/rubygems/gems/fake_hello-1.0.0.gem")).status_code == 200
    await running.drain()
    running.ctx.artifact_cache.enabled = False  # force the next request upstream
    running.fake.control("tamper", path="/rubygems-dl/gems/fake_hello-1.0.0.gem")
    res = await asgi_get(running.app, "/rubygems/gems/fake_hello-1.0.0.gem")
    assert res.status == 451 and b"changed upstream" in res.body


async def test_upstream_failures_are_503_and_a_stale_info_file_is_served(running: Running) -> None:
    running.fake.control("fail", prefix="/rubygems-index/info/", status="503")
    r = await running.client.get("/rubygems/info/fake_deps")
    assert r.status_code == 503 and r.headers["retry-after"] == "10"
    running.fake.control("fail", prefix="/rubygems-index/info/", status="0")
    assert (await running.client.get(HELLO)).status_code == 200
    running.clock.advance(7 * 3600)  # past the metadata TTL
    running.fake.control("fail", prefix="/rubygems-index/info/", status="503")
    assert _keys((await running.client.get(HELLO)).text) == ["1.0.0", "1.1.0"]  # stale, rather than nothing
    running.fake.control("fail", prefix="/rubygems-index/info/", status="0")
    running.fake.control("fail", prefix="/rubygems-dl/", status="500")
    r = await running.client.get("/rubygems/gems/fake_hello-1.1.0.gem")
    assert r.status_code == 503 and r.headers["retry-after"] == "10"
    running.fake.control("fail", prefix="/rubygems-dl/", status="0")


async def test_an_info_file_without_a_usable_line_is_an_upstream_failure(running: Running) -> None:
    running.fake.control("fail", prefix="/rubygems-index/info/fake_deps", status="200")  # 200 "injected failure 200"
    r = await running.client.get("/rubygems/info/fake_deps")
    assert r.status_code == 503 and "without a usable line" in r.text
    running.fake.control("fail", prefix="/rubygems-index/info/fake_deps", status="0")
    assert _keys((await running.client.get("/rubygems/info/fake_deps")).text) == ["0.1.0"]


async def test_exceptions_and_operator_blocks(start_app) -> None:
    run = await start_app(
        '[[exceptions]]\necosystem = "rubygems"\npackage = "fake_hello"\nversion = "1.2.0"\ndelay_days = 0\n'
        '[[blocks]]\necosystem = "rubygems"\npackage = "fake_deps"\nreason = "internal policy"\n'
    )
    assert _keys((await run.client.get(HELLO)).text) == ["1.0.0", "1.1.0", "1.2.0"]
    assert (await run.client.get("/rubygems/gems/fake_hello-1.2.0.gem")).status_code == 200
    r = await run.client.get("/rubygems/gems/fake_deps-0.1.0.gem")
    assert r.status_code == 451
    assert r.text == "slowshield: fake_deps is blocked by the administrator of this proxy.\ninternal policy\n"
    assert (await run.client.get("/rubygems/info/fake_deps")).text == "---\n"


async def test_names_are_passed_on(running: Running) -> None:
    r = await running.client.get("/rubygems/names")
    assert r.status_code == 200 and r.content == await _upstream(running, "/rubygems-index/names")
    assert r.headers["etag"] == _md5(r.content)


async def test_setup_page_shows_the_bundler_mirror_and_gems_source(running: Running) -> None:
    page = (await running.client.get("/ui/setup")).text
    assert "bundle config set --global mirror.https://rubygems.org https://slowshield.test/rubygems" in page
    assert ":sources:\n- https://slowshield.test/rubygems/" in page
    assert "bundle config set --global cooldown 3" in page
    assert "set <code>fallback_timeout</code> on the mirror" in page and "<code>gem search</code>" in page  # notes
