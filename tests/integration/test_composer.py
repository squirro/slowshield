"""Composer at /composer/: the generated packages.json, p2 files without held versions and with dists at SlowShield,
publish times from `published-time` (never the author's `time`, never earlier than first seen), Last-Modified that
follows the filtered file, 425/451 refusals as JSON warnings, verified dists (the same files archived again are not
tampering), malware, upstream failures, and the shield wall's first-listed times."""

from __future__ import annotations

import email.utils
import hashlib
from typing import Any

from slowshield.ecosystems.composer import metadata as M
from slowshield.feeds import FeedScheduler
from slowshield.feeds.github import GithubFeed
from slowshield.feeds.osv import OsvFeed
from tests.conftest import DAY, NOW, Running, asgi_get
from tests.integration.test_shieldwall import Pair, _join, pair, start  # noqa: F401 (fixtures)

BASE = "https://slowshield.test/composer"
HELLO = "/composer/p2/fake/hello.json"


def _versions(doc: dict[str, Any], name: str) -> dict[str, dict[str, Any]]:
    return {e["version"]: e for e in M.expand(doc["packages"][name])}


async def _p2(run: Running, name: str, dev: bool = False) -> dict[str, dict[str, Any]]:
    r = await run.client.get(f"/composer/{M.file_of(name, dev)}")
    assert r.status_code == 200, r.text
    return _versions(r.json(), name)


def _ref(run: Running, name: str, version: str) -> str:
    return run.fake.info()["composer"][name][version]["reference"]


def _dist(run: Running, name: str, version: str) -> str:
    return f"/composer/dists/{name}/{_ref(run, name, version)}.zip"


async def _run_feeds(run: Running) -> None:
    await FeedScheduler(run.ctx, [OsvFeed(run.ctx), GithubFeed(run.ctx)]).run_once()
    run.ctx.blocklist.refresh_generation(force=True)  # it looks again only once a second


# ---- the repository ----------------------------------------------------------------------------------------------


async def test_packages_json_points_metadata_and_the_malware_list_at_slowshield(running: Running) -> None:
    r = await running.client.get("/composer/packages.json")
    assert r.status_code == 200 and r.headers["content-type"] == "application/json"
    assert r.json() == {
        "packages": [],
        "metadata-url": f"{BASE}/p2/%package%.json",
        "security-advisories": {"metadata": True, "api-url": f"{BASE}/api/security-advisories/"},
        "filter": {
            "metadata": True,
            "lists": {"malware": {"enabled": True}},
            "summary-url": f"{BASE}/lists/all/summary.json",
        },
    }
    assert running.fake.hits("/packagist") == {}  # written by SlowShield
    root = await running.client.get("/composer/")
    assert root.status_code == 200 and "composer config -g repos.slowshield composer" in root.text
    assert (await running.client.post("/composer/packages.json")).status_code == 405


async def test_composer_audit_asks_packagist_through_slowshield(running: Running) -> None:
    # As Composer sends it (PHP's http_build_query), with a name that isn't one and another field.
    form = "packages%5B0%5D=fake%2Fhello&packages%5B1%5D=..%2Fx&packages%5B2%5D=fake%2Fdeps&other=1"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = await running.client.post("/composer/api/security-advisories/", content=form, headers=headers)
    assert r.status_code == 200 and r.headers["content-type"] == "application/json"
    assert r.json()["advisories"]["fake/hello"][0]["advisoryId"] == "PKSA-fake-0001"
    # Only the valid package names went upstream, in a form of their own.
    assert running.fake.control("composer-advisories")["asked"] == ["fake/deps", "fake/hello"]
    empty = await running.client.post("/composer/api/security-advisories/", content="x=1", headers=headers)
    assert empty.json() == {"advisories": {}}
    running.fake.control("fail", prefix="/packagist-api/", status="503")
    r = await running.client.post("/composer/api/security-advisories/", content=form, headers=headers)
    assert r.status_code == 503 and "unusable (HTTP 503)" in r.json()["warning"]
    running.fake.control("fail", prefix="/packagist-api/", status="0")
    assert (await running.client.post("/composer/p2/fake/hello.json")).status_code == 405


async def test_the_malware_list_is_passed_on(running: Running) -> None:
    r = await running.client.get("/composer/lists/all/summary.json")
    assert r.status_code == 200 and r.json()["filter"]["malware"]["fake/evil"] == "*"
    again = await running.client.get(
        "/composer/lists/all/summary.json", headers={"If-Modified-Since": r.headers["last-modified"]}
    )
    assert again.status_code == 304
    assert running.fake.hits("/packagist/lists/") == {"/packagist/lists/all/summary.json": 1}


# ---- held versions -----------------------------------------------------------------------------------------------


async def test_p2_files_leave_out_too_new_versions_and_point_dists_at_slowshield(running: Running) -> None:
    r = await running.client.get(HELLO)
    assert r.status_code == 200 and r.headers["content-type"] == "application/json"
    doc = r.json()
    assert doc["minified"] == "composer/2.0" and doc["security-advisories"][0]["advisoryId"] == "PKSA-fake-0001"
    versions = _versions(doc, "fake/hello")
    # 1.2.0 was published two days ago; its author's `time` says 400 days, which doesn't count.
    assert list(versions) == ["v1.1.0", "1.0.0"]
    assert r.headers["x-slowshield-held-versions"] == "1"
    v110 = versions["v1.1.0"]
    ref = _ref(running, "fake/hello", "v1.1.0")
    assert v110["dist"] == {"url": f"{BASE}/dists/fake/hello/{ref}.zip", "type": "zip", "shasum": "", "reference": ref}
    assert v110["source"]["url"] == "https://github.com/fake/hello.git"  # passed on
    assert v110["published-time"] == "2026-08-22T14:13:20+00:00"
    # Apart from the dists, every entry is what Packagist sent.
    raw = await (await running.client.get("/composer/p2/fake/deps.json")).aread()
    assert b'"require":{"fake/hello":"^1.0"}' in raw and b'"autoload":{"psr-4":{"Fake\\\\":"src/"}}' in raw
    assert running.fake.hits("/packagist/p2/fake/hello") == {"/packagist/p2/fake/hello.json": 1}


async def test_branches_are_held_from_their_last_update(running: Running) -> None:
    assert list(await _p2(running, "fake/hello", dev=True)) == ["dev-legacy"]  # dev-main changed yesterday
    assert (await running.client.get(_dist(running, "fake/hello", "dev-legacy"))).status_code == 200
    r = await running.client.get(_dist(running, "fake/hello", "dev-main"))
    assert r.status_code == 425 and "fake/hello dev-main is too new" in r.json()["warning"]


async def test_last_modified_follows_the_filtered_file(running: Running) -> None:
    r = await running.client.get(HELLO)
    assert r.headers["last-modified"] == email.utils.formatdate(NOW, usegmt=True)
    for headers in ({"If-Modified-Since": r.headers["last-modified"]}, {"If-None-Match": r.headers["etag"]}):
        again = await running.client.get(HELLO, headers=headers)
        assert again.status_code == 304 and again.headers["etag"] == r.headers["etag"]
    # Upstream didn't change, but 1.2.0 comes of age: the file is new, and so is its date.
    running.clock.advance(5 * DAY + 1)
    later = await running.client.get(HELLO, headers={"If-Modified-Since": r.headers["last-modified"]})
    assert later.status_code == 200 and "1.2.0" in _versions(later.json(), "fake/hello")
    assert later.headers["last-modified"] == email.utils.formatdate(NOW + 5 * DAY + 1, usegmt=True)
    assert (
        await running.client.get(HELLO, headers={"If-Modified-Since": later.headers["last-modified"]})
    ).status_code == 304


async def test_brand_new_packages_are_held_unless_fail_open_is_on(start_app) -> None:
    strict = await start_app()
    r = await strict.client.get("/composer/p2/fake/brand-new.json")
    assert r.status_code == 200 and r.json()["packages"]["fake/brand-new"] == []
    assert r.json()["warning"].startswith("slowshield: every version of fake/brand-new is newer than 7 days")
    assert (await strict.client.get(_dist(strict, "fake/brand-new", "0.1.0"))).status_code == 425
    lenient = await start_app("[upstreams.composer]\nfail_open = true\n")
    r = await lenient.client.get("/composer/p2/fake/brand-new.json")
    assert list(_versions(r.json(), "fake/brand-new")) == ["0.1.0"] and r.headers["x-slowshield-fail-open"] == "1"
    assert "warning" not in r.json()
    assert (await lenient.client.get(_dist(lenient, "fake/brand-new", "0.1.0"))).status_code == 200


# ---- downloads ---------------------------------------------------------------------------------------------------


async def test_dists_are_verified_and_cached(running: Running) -> None:
    path = _dist(running, "fake/hello", "v1.1.0")
    r = await running.client.get(path)
    assert r.status_code == 200 and r.headers["x-slowshield-cache"] == "miss"
    assert r.headers["content-type"] == "application/zip"
    assert hashlib.sha256(r.content).hexdigest() == running.fake.info()["composer"]["fake/hello"]["v1.1.0"]["sha256"]
    await running.drain()
    hit = await running.client.get(path)
    assert hit.headers["x-slowshield-cache"] == "hit" and hit.content == r.content
    ref = _ref(running, "fake/hello", "v1.1.0")
    rows = running.rows("SELECT path, package, version, filename, upstream_digest, published FROM artifacts")
    assert len(rows) == 1
    key, package, version, filename, digest, published = rows[0]
    assert (key, package, version, filename) == (
        f"/fake/hello/{ref}.zip",
        "fake/hello",
        "v1.1.0",
        f"fake-hello-{ref}.zip",
    )
    assert digest.startswith("h1:") and published == NOW - 30 * DAY  # the files in the zip, and published-time
    head = await running.client.head(path)
    assert head.status_code == 200 and int(head.headers["content-length"]) == len(r.content)
    assert running.fake.hits("/codeload/") == {f"/codeload/fake/hello/legacy.zip/{ref}": 1}


async def test_too_new_dists_get_425_with_the_version_to_use(running: Running) -> None:
    r = await running.client.get(_dist(running, "fake/hello", "1.2.0"))
    assert r.status_code == 425 and r.headers["content-type"] == "application/json"
    text = r.json()["warning"]
    assert text.startswith("slowshield: fake/hello 1.2.0 is too new. It was published 2026-09-19T14:13:20Z")
    assert "composer update fake/hello --with fake/hello:v1.1.0" in text
    assert int(r.headers["retry-after"]) == int(5 * DAY)
    assert running.fake.hits("/codeload/") == {}  # refused without asking upstream
    await running.drain()
    assert ("age_gate", "fake/hello", "1.2.0") in running.rows("SELECT type, package, version FROM events")
    running.clock.advance(5 * DAY + 1)
    assert (await running.client.get(_dist(running, "fake/hello", "1.2.0"))).status_code == 200


async def test_unknown_names_references_and_spellings_are_404(running: Running) -> None:
    ref = _ref(running, "fake/hello", "1.0.0")
    for path in (
        "/composer/p2/fake/no-such-package.json",
        "/composer/p2/Fake/Hello.json",
        "/composer/p2/fake/hello",
        "/composer/p2/fake.json",
        f"/composer/dists/fake/hello/{'0' * 40}.zip",
        f"/composer/dists/fake/hello/{ref}.tar",
        f"/composer/dists/fake/hello/{ref}",
        f"/composer/dists/fake/hello/1.0.0/{ref}.zip",
        "/composer/p2/fake/hello.json/extra",
    ):
        assert (await running.client.get(path)).status_code == 404, path
    assert (await running.client.get("/composer/p2/fake/no-such-package.json")).status_code == 404
    assert running.fake.hits("/packagist/p2/fake/no-") == {"/packagist/p2/fake/no-such-package.json": 1}  # remembered
    # A trailing newline isn't part of a name: refused without asking Packagist (it would miss the blocklist).
    for path in ("/composer/p2/fake/hello%0A.json", f"/composer/dists/fake/hello/{ref}%0A.zip"):
        assert (await running.client.get(path)).status_code == 404, path
    assert not [p for p in running.fake.hits("/packagist/") if "\n" in p or "%0A" in p.upper()]


async def test_a_dist_on_a_host_that_is_not_allowed_is_refused(running: Running) -> None:
    assert "1.0.0" in await _p2(running, "fake/elsewhere")
    r = await running.client.get(_dist(running, "fake/elsewhere", "1.0.0"))
    assert r.status_code == 502 and "downloads.example.org" in r.json()["warning"]
    assert "upstreams.composer.download_hosts" in r.json()["warning"]


# ---- publish times -----------------------------------------------------------------------------------------------


async def test_a_version_without_published_time_is_timed_from_when_it_was_first_listed(running: Running) -> None:
    assert await _p2(running, "fake/untimed") == {}  # its `time` says 300 days; it doesn't count
    await running.drain()
    assert running.rows("SELECT published, first_listed FROM package_versions WHERE name = 'fake/untimed'") == [
        (None, NOW)
    ]
    running.clock.advance(7 * DAY)
    assert (await running.client.get(_dist(running, "fake/untimed", "1.0.0"))).status_code == 200


async def test_a_publish_time_never_moves_earlier(running: Running) -> None:
    assert "1.2.0" not in await _p2(running, "fake/hello")
    await running.drain()
    running.fake.control("publish", ecosystem="composer", name="fake/hello", version="1.2.0", age_days="30")
    running.clock.advance(7 * 3600)  # past the metadata TTL: the file is fetched again
    r = await running.client.get(HELLO)
    assert "1.2.0" not in _versions(r.json(), "fake/hello")
    assert (await running.client.get(_dist(running, "fake/hello", "1.2.0"))).status_code == 425
    rows = running.rows("SELECT published FROM package_versions WHERE name = 'fake/hello' AND version = '1.2.0'")
    assert rows == [(NOW - 2 * DAY,)]


async def test_a_published_time_in_the_future_counts_as_now(running: Running) -> None:
    assert "v1.1.0" in await _p2(running, "fake/hello")
    await running.drain()
    # The same commit, but the file now says it was published in a month: held, not timed from the stored time.
    running.fake.control("publish", ecosystem="composer", name="fake/hello", version="v1.1.0", age_days="-30")
    running.clock.advance(7 * 3600)
    assert "v1.1.0" not in await _p2(running, "fake/hello")
    assert (await running.client.get(_dist(running, "fake/hello", "v1.1.0"))).status_code == 425
    await running.drain()
    row = "SELECT published, first_listed FROM package_versions WHERE name = 'fake/hello' AND version = 'v1.1.0'"
    assert running.rows(row) == [(NOW - 30 * DAY, None)]  # kept for the commit; the future time isn't stored


async def test_a_new_commit_under_a_known_name_is_timed_afresh(running: Running) -> None:
    """A repository without `published-time` (a mirror, Satis): a branch's new commit, or a moved tag, is timed from
    when SlowShield first sees it, not from the first commit's time."""
    old = _ref(running, "fake/hello", "dev-legacy")
    assert "dev-legacy" in await _p2(running, "fake/hello", dev=True)  # 60 days old
    await running.drain()
    new = running.fake.control("composer-push", name="fake/hello", version="dev-legacy")["reference"]
    running.clock.advance(7 * 3600)  # past the metadata TTL
    assert "dev-legacy" not in await _p2(running, "fake/hello", dev=True)
    r = await running.client.get(f"/composer/dists/fake/hello/{new}.zip")
    assert r.status_code == 425 and "fake/hello dev-legacy is too new" in r.json()["warning"]
    assert (await running.client.get(f"/composer/dists/fake/hello/{old}.zip")).status_code == 404
    await running.drain()
    row = "SELECT published, first_listed, reference FROM package_versions WHERE name = 'fake/hello' AND version = ?"
    assert running.rows(row, ("dev-legacy",)) == [(None, NOW + 7 * 3600, new)]
    # Pushed again, with a `published-time` 10 days ahead: held from now, not from when the last commit was seen.
    newer = running.fake.control("composer-push", name="fake/hello", version="dev-legacy", age_days="-10")
    path = f"/composer/dists/fake/hello/{newer['reference']}.zip"
    running.clock.advance(6 * DAY)
    assert (await running.client.get(path)).status_code == 425
    await running.drain()
    assert running.rows(row, ("dev-legacy",)) == [(None, NOW + 6 * DAY + 7 * 3600, newer["reference"])]
    # A week later the `published-time` has passed: it counts, and is 3 days old.
    running.clock.advance(7 * DAY)
    assert (await running.client.get(path)).status_code == 425
    running.clock.advance(4 * DAY)
    assert (await running.client.get(path)).status_code == 200


# ---- malware and blocks ------------------------------------------------------------------------------------------


async def test_malware_is_refused(start_app, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    run = await start_app()
    await _run_feeds(run)
    for path in ("/composer/p2/fake/evil.json", _dist(run, "fake/evil", "1.0.0")):
        r = await run.client.get(path)
        assert r.status_code == 451 and r.headers["content-type"] == "application/json", path
        assert r.json()["warning"].startswith(
            "slowshield: fake/evil is blocked as known malware. Advisory: MAL-2026-6001"
        )
    # Removed from Packagist since: still refused, and recorded.
    assert (await run.client.get(f"/composer/dists/fake/evil/{'1' * 40}.zip")).status_code == 451
    # GitHub's "= v1.1" names v1.1.0 (Composer's normalized form).
    assert list(await _p2(run, "fake/partly")) == ["1.0.0"]
    r = await run.client.get(_dist(run, "fake/partly", "v1.1.0"))
    assert r.status_code == 451 and "GHSA-aaaa-0009-0009" in r.json()["warning"]
    assert (await run.client.get(_dist(run, "fake/partly", "1.0.0"))).status_code == 200
    blocks = run.rows("SELECT name, version, version_range, advisory_id FROM blocklist WHERE ecosystem = 'composer'")
    assert sorted(blocks) == [
        ("fake/evil", None, None, "MAL-2026-6001"),
        ("fake/partly", "v1.1", None, "GHSA-aaaa-0009-0009"),
    ]
    await run.drain()
    events = run.rows("SELECT package, version FROM events WHERE type = 'blocked' AND ecosystem = 'composer'")
    assert ("fake/partly", "v1.1.0") in events


async def test_operator_blocks_and_exceptions_use_any_spelling(start_app) -> None:
    run = await start_app(
        '[[blocks]]\necosystem = "composer"\npackage = "Fake/Deps"\nreason = "internal policy"\n\n'
        '[[exceptions]]\necosystem = "composer"\npackage = "fake/hello"\nversion = "v1.2"\ndelay_days = 0\n'
    )
    r = await run.client.get(_dist(run, "fake/deps", "1.0.0"))
    assert r.status_code == 451
    assert r.json() == {
        "warning": "slowshield: fake/deps is blocked by the administrator of this proxy. internal policy"
    }
    assert "1.2.0" in await _p2(run, "fake/hello")
    assert (await run.client.get(_dist(run, "fake/hello", "1.2.0"))).status_code == 200


# ---- integrity ---------------------------------------------------------------------------------------------------


async def test_a_shasum_is_checked(running: Running) -> None:
    running.fake.control("tamper", path="/codeload/fake/checked/legacy.zip/" + _ref(running, "fake/checked", "1.0.0"))
    res = await asgi_get(running.app, _dist(running, "fake/checked", "1.0.0"))
    assert res.status == 503 or res.error is not None  # never a whole tampered file
    await running.drain()
    events = running.rows("SELECT type, package, details FROM events WHERE ecosystem = 'composer'")
    assert any(t == "integrity_mismatch" and "sha1" in d for t, _, d in events), events


async def test_a_dist_that_cannot_be_read_is_an_integrity_failure(running: Running, monkeypatch) -> None:
    def unreadable(_path: object) -> str:
        raise RuntimeError("File is encrypted, password required for extraction")

    # The hook raising (not only returning None) is recorded like a digest mismatch, not a broken stream.
    monkeypatch.setattr("slowshield.ecosystems.composer.service.zip_content", unreadable)
    res = await asgi_get(running.app, _dist(running, "fake/hello", "1.0.0"))
    assert res.status == 503 and b"can't be read as an archive" in res.body
    await running.drain()
    events = running.rows("SELECT type, package, version FROM events WHERE ecosystem = 'composer'")
    assert ("integrity_mismatch", "fake/hello", "1.0.0") in events
    assert running.rows("SELECT count(*) FROM artifacts") == [(0,)]


async def test_other_files_after_the_first_download_are_tampering(running: Running) -> None:
    path = _dist(running, "fake/hello", "1.0.0")
    assert (await running.client.get(path)).status_code == 200
    await running.drain()
    running.ctx.artifact_cache.enabled = False  # force the next request upstream
    running.fake.control("tamper", path="/codeload/fake/hello/legacy.zip/" + _ref(running, "fake/hello", "1.0.0"))
    res = await asgi_get(running.app, path)
    assert res.status == 451 and b"changed upstream" in res.body
    assert (await running.client.get(path)).status_code == 451


async def test_the_same_files_archived_again_are_not_tampering(running: Running) -> None:
    path = _dist(running, "fake/hello", "1.0.0")
    first = await running.client.get(path)
    assert first.status_code == 200
    await running.drain()
    before = running.rows("SELECT sha256, upstream_digest FROM artifacts")
    running.ctx.artifact_cache.enabled = False
    running.fake.control("composer-rearchive", name="fake/hello", version="1.0.0")
    running.ctx.artifact_cache.enabled = True  # the content check needs the spooled file
    for store in running.ctx.artifacts.stores.values():
        store.lookup = lambda _sha: None  # type: ignore[method-assign]  # a cache miss, as after an eviction
    again = await running.client.get(path)
    assert again.status_code == 200 and again.content != first.content
    await running.drain()
    after = running.rows("SELECT sha256, upstream_digest, tampered FROM artifacts")
    assert after == [(hashlib.sha256(again.content).hexdigest(), before[0][1], 0)]
    assert running.rows("SELECT count(*) FROM events WHERE type = 'tampered'") == [(0,)]


# ---- upstream failures -------------------------------------------------------------------------------------------


async def test_upstream_failures_are_503_and_a_stale_file_is_served(running: Running) -> None:
    running.fake.control("fail", prefix="/packagist/p2/fake/deps", status="503")
    r = await running.client.get("/composer/p2/fake/deps.json")
    assert (
        r.status_code == 503 and r.headers["retry-after"] == "10" and "Packagist is unavailable" in r.json()["warning"]
    )
    running.fake.control("fail", prefix="/packagist/p2/fake/deps", status="0")
    assert (await running.client.get(HELLO)).status_code == 200
    running.clock.advance(7 * 3600)  # past the metadata TTL
    running.fake.control("fail", prefix="/packagist/p2/", status="503")
    assert (await running.client.get(HELLO)).status_code == 200  # stale, rather than nothing
    running.fake.control("fail", prefix="/packagist/p2/", status="0")
    running.fake.control("fail", prefix="/codeload/", status="500")
    r = await running.client.get(_dist(running, "fake/hello", "v1.1.0"))
    assert r.status_code == 503 and r.headers["retry-after"] == "10"  # Composer retries a 503
    running.fake.control("fail", prefix="/codeload/", status="0")


async def test_a_p2_file_that_is_not_one_is_an_upstream_failure(running: Running) -> None:
    running.fake.control("fail", prefix="/packagist/p2/fake/deps", status="200")  # 200 "injected failure 200"
    r = await running.client.get("/composer/p2/fake/deps.json")
    assert r.status_code == 503 and "isn't one" in r.json()["warning"]
    running.fake.control("fail", prefix="/packagist/p2/fake/deps", status="0")
    assert list(await _p2(running, "fake/deps")) == ["1.0.0"]
    running.clock.advance(7 * 3600)
    running.fake.control("fail", prefix="/packagist/p2/fake/deps", status="200")
    assert list(await _p2(running, "fake/deps")) == ["1.0.0"]  # the stored copy
    running.fake.control("fail", prefix="/packagist/p2/fake/deps", status="0")


async def test_setup_page_shows_the_composer_config(running: Running) -> None:
    page = (await running.client.get("/ui/setup")).text
    command = "composer config -g repo.packagist false &amp;&amp; composer config -g repos.slowshield composer"
    assert f"{command} https://slowshield.test/composer/" in page


# ---- the shield wall ---------------------------------------------------------------------------------------------


async def test_a_follower_learns_when_the_leader_first_listed_a_version(pair: Pair) -> None:  # noqa: F811
    p = pair
    await _join(p)
    assert await _p2(p.leader, "fake/untimed") == {}  # no published-time: timed from now, on the leader
    await p.leader.drain()
    await p.sync()
    row = "SELECT first_listed FROM package_versions WHERE ecosystem = 'composer' AND name = 'fake/untimed'"
    assert p.follower.rows(row) == [(NOW,)]
    assert p.follower.ctx.cfg.fail_open_for("composer") is False
