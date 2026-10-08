"""NuGet at /nuget/: the generated service index, held versions left out of the flat container, the registration
(inlined and linked pages) and search, 425/451 refusals as text, verified downloads, tampering and re-signing,
canonical spellings, upstream failures, the publish-time rule, and the shield wall's first-listed times."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from slowshield.feeds import FeedScheduler
from slowshield.feeds.github import GithubFeed
from slowshield.feeds.osv import OsvFeed
from tests.conftest import DAY, NOW, Running, asgi_get
from tests.integration.test_shieldwall import Pair, _join, pair, start  # noqa: F401 (fixtures)

TEXT = "text/plain; charset=utf-8"
BASE = "https://slowshield.test/nuget/v3/"
FLAT = "/nuget/v3/flatcontainer/"
REG = "/nuget/v3/registration/"


def _nupkg(pid: str, version: str) -> str:
    return f"{FLAT}{pid}/{version}/{pid}.{version}.nupkg"


async def _versions(run: Running, pid: str) -> list[str]:
    r = await run.client.get(f"{FLAT}{pid}/index.json")
    assert r.status_code == 200, r.text
    return r.json()["versions"]


def _leaves(doc: dict[str, Any]) -> list[str]:
    return [leaf["catalogEntry"]["version"] for leaf in doc["items"]]


async def _with_feeds(start_app: Any, monkeypatch: Any) -> Running:
    """An instance whose OSV and GitHub feeds have run (the token must be there when it starts)."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    run = await start_app()
    await _run_feeds(run)
    return run


async def _run_feeds(run: Running) -> None:
    await FeedScheduler(run.ctx, [OsvFeed(run.ctx), GithubFeed(run.ctx)]).run_once()
    run.ctx.blocklist.refresh_generation(force=True)  # it looks again only once a second


# ---- the service index -------------------------------------------------------------------------------------------


async def test_the_service_index_lists_only_what_slowshield_serves(running: Running) -> None:
    r = await running.client.get("/nuget/v3/index.json")
    assert r.status_code == 200 and r.headers["content-type"] == "application/json"
    doc = r.json()
    assert doc["version"] == "3.0.0"
    resources = {(x["@type"], x["@id"]) for x in doc["resources"]}
    assert resources == {
        ("PackageBaseAddress/3.0.0", f"{BASE}flatcontainer/"),
        ("RegistrationsBaseUrl/3.6.0", f"{BASE}registration/"),
        ("VulnerabilityInfo/6.7.0", f"{BASE}vulnerabilities/index.json"),
        ("SearchQueryService", f"{BASE}query"),
        ("SearchQueryService/3.0.0-beta", f"{BASE}query"),
        ("SearchQueryService/3.0.0-rc", f"{BASE}query"),
        ("SearchQueryService/3.5.0", f"{BASE}query"),
    }
    assert running.fake.hits("/nuget") == {}  # written by SlowShield, nothing asked upstream
    root = await running.client.get("/nuget/")
    assert root.status_code == 200 and "v3/index.json" in root.text
    assert (await running.client.post("/nuget/v3/index.json")).status_code == 405


# ---- held versions -------------------------------------------------------------------------------------------


async def test_held_versions_are_left_out_of_the_flat_container(running: Running) -> None:
    r = await running.client.get(f"{FLAT}fake.hello/index.json")
    # 1.0.1 is unlisted (published 1900-01-01: timed from now), 1.2.0 is two days old.
    assert r.json() == {"versions": ["1.0.0", "1.1.0", "2.0.0-beta.1"]}
    assert r.headers["x-slowshield-held-versions"] == "2"
    again = await running.client.get(f"{FLAT}fake.hello/index.json", headers={"If-None-Match": r.headers["etag"]})
    assert again.status_code == 304
    assert running.fake.hits("/nuget-reg/fake.hello/") == {"/nuget-reg/fake.hello/index.json": 1}
    assert running.fake.hits("/nuget-flat/") == {}  # the list comes from the registration snapshot
    running.clock.advance(5 * DAY + 1)  # 1.2.0 is 7 days old now
    assert "1.2.0" in await _versions(running, "fake.hello")


async def test_held_versions_are_left_out_of_inlined_registration_pages(running: Running) -> None:
    r = await running.client.get(f"{REG}fake.hello/index.json")
    assert r.status_code == 200 and r.headers["x-slowshield-held-versions"] == "2"
    doc = r.json()
    assert doc["@id"] == f"{BASE}registration/fake.hello/index.json" and doc["count"] == 2
    first, second = doc["items"]
    assert (first["lower"], first["upper"], first["count"]) == ("1.0.0", "1.1.0", 2)
    assert _leaves(first) == ["1.0.0", "1.1.0"]
    assert first["@id"] == f"{BASE}registration/fake.hello/index.json#page/1.0.0/1.1.0"
    assert (second["lower"], second["upper"], second["count"]) == ("2.0.0-beta.1", "2.0.0-beta.1", 1)
    assert _leaves(second) == ["2.0.0-Beta.1"]
    leaf = first["items"][1]
    assert (
        leaf["packageContent"]
        == leaf["catalogEntry"]["packageContent"]
        == f"{BASE}flatcontainer/fake.hello/1.1.0/fake.hello.1.1.0.nupkg"
    )
    assert leaf["@id"] == f"{BASE}registration/fake.hello/1.1.0.json"
    assert leaf["catalogEntry"]["@id"].startswith(running.fake.url + "/nuget-catalog/")  # not served: unchanged
    single = await running.client.get(f"{REG}fake.hello/1.1.0.json")
    assert single.status_code == 200 and single.json()["packageContent"].startswith(BASE)
    assert (await running.client.get(f"{REG}fake.hello/1.2.0.json")).status_code == 404


async def test_held_versions_are_left_out_of_linked_registration_pages(running: Running) -> None:
    # Fake.Paged: pages [1.0-1.2] [1.3-1.5] [1.6-1.7]; 1.5.0, 1.6.0 and 1.7.0 are days old.
    doc = (await running.client.get(f"{REG}fake.paged/index.json")).json()
    assert [(p["lower"], p["upper"], p["count"], "items" in p) for p in doc["items"]] == [
        ("1.0.0", "1.2.0", 3, False),
        ("1.3.0", "1.4.0", 2, False),  # recomputed; the third page, left empty, is gone
    ]
    assert doc["count"] == 2
    assert len(running.fake.hits("/nuget-reg/fake.paged/page/")) == 3  # every page is part of the snapshot
    page = await running.client.get(doc["items"][1]["@id"].removeprefix("https://slowshield.test"))
    assert page.status_code == 200
    body = page.json()
    assert _leaves(body) == ["1.3.0", "1.4.0"] and body["parent"] == f"{BASE}registration/fake.paged/index.json"
    # nuget.org's own bounds (a client that read an older index): the served versions within them.
    old = (await running.client.get(f"{REG}fake.paged/page/1.3.0/1.5.0.json")).json()
    assert _leaves(old) == ["1.3.0", "1.4.0"]
    assert await _versions(running, "fake.paged") == ["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"]
    running.clock.advance(7 * DAY)
    doc = (await running.client.get(f"{REG}fake.paged/index.json")).json()
    assert [(p["lower"], p["upper"]) for p in doc["items"]] == [
        ("1.0.0", "1.2.0"),
        ("1.3.0", "1.5.0"),
        ("1.6.0", "1.7.0"),
    ]


# ---- downloads -------------------------------------------------------------------------------------------------


async def test_downloads_are_verified_against_the_catalog_and_cached(running: Running) -> None:
    r = await running.client.get(_nupkg("fake.hello", "1.1.0"))
    assert r.status_code == 200 and r.headers["x-slowshield-cache"] == "miss"
    info = running.fake.info()["nuget"]["fake.hello"]["1.1.0"]
    sha512 = base64.b64decode(info["sha512"])
    assert hashlib.sha512(r.content).digest() == sha512
    await running.drain()
    hit = await running.client.get(_nupkg("fake.hello", "1.1.0"))
    assert hit.headers["x-slowshield-cache"] == "hit" and hit.content == r.content
    rows = running.rows("SELECT path, package, version, filename, upstream_digest, published FROM artifacts")
    assert rows == [
        ("/fake.hello/1.1.0/fake.hello.1.1.0.nupkg", "fake.hello", "1.1.0", "fake.hello.1.1.0.nupkg", sha512.hex(),
         NOW - 30 * DAY)
    ]  # fmt: skip
    head = await running.client.head(_nupkg("fake.hello", "1.1.0"))
    assert head.status_code == 200 and int(head.headers["content-length"]) == len(r.content)
    # A prerelease, in nuget.org's lower-case spelling.
    assert (await running.client.get(_nupkg("fake.hello", "2.0.0-beta.1"))).status_code == 200


async def test_too_new_downloads_get_425_with_retry_after(running: Running) -> None:
    r = await running.client.get(_nupkg("fake.hello", "1.2.0"))
    assert r.status_code == 425 and r.headers["content-type"] == TEXT
    assert r.text.startswith("slowshield: fake.hello 1.2.0 is too new.\nIt was published 2026-09-19T14:13:20Z")
    assert "Use an older version (1.1.0)" in r.text
    assert int(r.headers["retry-after"]) == int(5 * DAY)
    assert running.fake.hits("/nuget-flat/") == {} and running.fake.hits("/nuget-catalog/") == {}
    await running.drain()
    assert ("age_gate", "fake.hello", "1.2.0") in running.rows("SELECT type, package, version FROM events")
    running.clock.advance(5 * DAY + 1)
    assert (await running.client.get(_nupkg("fake.hello", "1.2.0"))).status_code == 200


async def test_brand_new_packages_are_held_unless_fail_open_is_on(start_app) -> None:
    strict = await start_app()
    assert await _versions(strict, "fake.new") == []
    assert (await strict.client.get(_nupkg("fake.new", "0.1.0"))).status_code == 425
    lenient = await start_app("[upstreams.nuget]\nfail_open = true\n")
    r = await lenient.client.get(f"{FLAT}fake.new/index.json")
    assert r.json()["versions"] == ["0.1.0"] and r.headers["x-slowshield-fail-open"] == "1"
    assert (await lenient.client.get(_nupkg("fake.new", "0.1.0"))).status_code == 200


async def test_malware_is_refused_with_451(start_app, monkeypatch) -> None:
    run = await _with_feeds(start_app, monkeypatch)
    for path in (f"{FLAT}fake.evil/index.json", f"{REG}fake.evil/index.json", _nupkg("fake.evil", "1.0.0")):
        r = await run.client.get(path)
        assert r.status_code == 451 and r.headers["content-type"] == TEXT, path
        assert r.text.startswith("slowshield: fake.evil is blocked as known malware.\nAdvisory: MAL-2026-5001")
    assert run.fake.hits("/nuget-reg/fake.evil/") == {}  # refused before anything is fetched
    # GitHub's advisory names "1.1": the same version as 1.1.0.
    assert await _versions(run, "fake.partly") == ["1.0.0"]
    r = await run.client.get(_nupkg("fake.partly", "1.1.0"))
    assert r.status_code == 451 and "GHSA-aaaa-0008-0008" in r.text
    assert r.text.startswith("slowshield: fake.partly 1.1.0 is blocked as known malware.")
    assert (await run.client.get(_nupkg("fake.partly", "1.0.0"))).status_code == 200
    blocks = run.rows("SELECT name, version, advisory_id FROM blocklist WHERE ecosystem = 'nuget' ORDER BY name")
    assert blocks == [("fake.evil", None, "MAL-2026-5001"), ("fake.partly", "1.1.0", "GHSA-aaaa-0008-0008")]
    await run.drain()
    events = run.rows("SELECT package, version FROM events WHERE type = 'blocked' AND ecosystem = 'nuget'")
    assert ("fake.evil", "1.0.0") in events and ("fake.partly", "1.1.0") in events


async def test_operator_blocks_and_exceptions_use_any_spelling(start_app) -> None:
    run = await start_app(
        '[[blocks]]\necosystem = "nuget"\npackage = "Fake.Deps"\nversion = "1.0"\nreason = "internal policy"\n'
        '[[exceptions]]\necosystem = "nuget"\npackage = "FAKE.HELLO"\nversion = "1.2"\ndelay_days = 0\n'
    )
    r = await run.client.get(_nupkg("fake.deps", "1.0.0"))
    assert r.status_code == 451
    assert r.text == "slowshield: fake.deps 1.0.0 is blocked by the administrator of this proxy.\ninternal policy\n"
    assert run.rows("SELECT version FROM blocklist WHERE ecosystem = 'nuget'") == [("1.0.0",)]
    assert "1.2.0" in await _versions(run, "fake.hello")
    assert (await run.client.get(_nupkg("fake.hello", "1.2.0"))).status_code == 200


# ---- integrity -------------------------------------------------------------------------------------------------


async def test_bytes_that_do_not_match_the_package_hash_are_refused(running: Running) -> None:
    running.fake.control("tamper", path="/nuget-flat/fake.hello/1.1.0/fake.hello.1.1.0.nupkg")
    res = await asgi_get(running.app, _nupkg("fake.hello", "1.1.0"))
    assert res.status == 503 or res.error is not None  # never a whole tampered file
    await running.drain()
    events = running.rows("SELECT type, package, version, details FROM events WHERE ecosystem = 'nuget'")
    assert [(t, p, v) for t, p, v, _ in events] == [("integrity_mismatch", "fake.hello", "1.1.0")]
    assert "sha512 does not match the registry digest" in events[0][3]


async def test_a_resigned_package_is_tampering_even_when_the_catalog_hash_matches(running: Running) -> None:
    first = await running.client.get(_nupkg("fake.hello", "1.0.0"))
    assert first.status_code == 200
    await running.drain()
    running.ctx.artifact_cache.enabled = False  # force the next request upstream
    running.fake.control("nuget-resign", id="Fake.Hello", version="1.0.0")
    running.clock.advance(7 * 3600)  # past the metadata TTL: the registration names the new catalog leaf
    res = await asgi_get(running.app, _nupkg("fake.hello", "1.0.0"))
    assert res.status == 451 and b"changed upstream" in res.body
    assert (await running.client.get(_nupkg("fake.hello", "1.0.0"))).status_code == 451
    await running.drain()
    rows = running.rows("SELECT type, details FROM events WHERE ecosystem = 'nuget' AND type = 'tampered'")
    assert len(rows) == 1 and '"problems":[]' in rows[0][1].replace(" ", "")  # the new hash matched the new bytes
    assert running.rows("SELECT tampered FROM artifacts WHERE package = 'fake.hello'") == [(1,)]


# ---- spellings -------------------------------------------------------------------------------------------------


async def test_only_nuget_orgs_spellings_are_served(running: Running) -> None:
    assert (await running.client.get(_nupkg("fake.hello", "1.1.0"))).status_code == 200
    for path in (
        f"{FLAT}Fake.Hello/index.json",
        f"{REG}Fake.Hello/index.json",
        f"{FLAT}fake.hello/1.1/fake.hello.1.1.nupkg",
        f"{FLAT}fake.hello/1.1.0.0/fake.hello.1.1.0.0.nupkg",
        f"{FLAT}fake.hello/01.1.0/fake.hello.01.1.0.nupkg",
        f"{FLAT}fake.hello/2.0.0-Beta.1/fake.hello.2.0.0-Beta.1.nupkg",
        f"{FLAT}fake.hello/1.1.0/Fake.Hello.1.1.0.nupkg",
        f"{FLAT}fake.hello/1.1.0/fake.hello.1.1.0.nuspec",
        f"{FLAT}fake.hello/1.1.0+meta/fake.hello.1.1.0+meta.nupkg",
        f"{FLAT}fake.hello/9.9.9/fake.hello.9.9.9.nupkg",
        f"{REG}fake.hello/page/1.0/1.1.0.json",
        f"{REG}fake.hello/1.1.json",
        "/nuget/flatcontainer/fake.hello/index.json",
        "/nuget/v3/catalog0/index.json",
    ):
        assert (await running.client.get(path)).status_code == 404, path
    # As sent, without a client normalizing the path first.
    res = await asgi_get(running.app, "/nuget/v3/flatcontainer/../registration/fake.hello/index.json")
    assert res.status == 404
    for _ in range(2):
        assert (await running.client.get(f"{FLAT}no.such.package/index.json")).status_code == 404
    assert running.fake.hits("/nuget-reg/no.such.package/") == {"/nuget-reg/no.such.package/index.json": 1}


# ---- upstream failures -----------------------------------------------------------------------------------------


async def test_upstream_failures_are_503_and_a_stale_snapshot_is_served(running: Running) -> None:
    running.fake.control("fail", prefix="/nuget-reg/", status="503")
    r = await running.client.get(f"{FLAT}fake.deps/index.json")
    assert r.status_code == 503 and r.headers["retry-after"] == "10" and r.headers["content-type"] == TEXT
    running.fake.control("fail", prefix="/nuget-reg/", status="0")
    assert await _versions(running, "fake.paged") == ["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"]
    running.clock.advance(7 * 3600)  # past the metadata TTL
    running.fake.control("fail", prefix="/nuget-reg/fake.paged/page/", status="503")  # a page, not the index
    assert await _versions(running, "fake.paged") == ["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"]  # stale
    running.fake.control("fail", prefix="/nuget-reg/fake.paged/page/", status="0")
    running.fake.control("fail", prefix="/nuget-catalog/", status="503")
    r = await running.client.get(_nupkg("fake.paged", "1.0.0"))
    assert r.status_code == 503 and r.headers["retry-after"] == "10"  # no packageHash, nothing served
    running.fake.control("fail", prefix="/nuget-catalog/", status="0")
    running.fake.control("fail", prefix="/nuget-flat/", status="500")
    r = await running.client.get(_nupkg("fake.paged", "1.0.0"))
    assert r.status_code == 503 and r.headers["retry-after"] == "10"
    running.fake.control("fail", prefix="/nuget-flat/", status="0")
    assert (await running.client.get(_nupkg("fake.paged", "1.0.0"))).status_code == 200


async def test_a_registration_without_a_usable_version_is_an_upstream_failure(running: Running) -> None:
    running.fake.control("fail", prefix="/nuget-reg/fake.deps/", status="200")  # 200 "injected failure 200"
    r = await running.client.get(f"{FLAT}fake.deps/index.json")
    assert r.status_code == 503 and "unusable registration" in r.text
    running.fake.control("fail", prefix="/nuget-reg/fake.deps/", status="0")
    assert await _versions(running, "fake.deps") == ["1.0.0"]


# ---- publish time ----------------------------------------------------------------------------------------------


async def test_an_unlisted_version_is_timed_from_when_it_was_first_listed_even_after_relisting(
    running: Running,
) -> None:
    assert "1.0.1" not in await _versions(running, "fake.hello")
    await running.drain()
    row = "SELECT published, first_listed, yanked FROM package_versions WHERE name = 'fake.hello' AND version = '1.0.1'"
    assert running.rows(row) == [(None, NOW, 1)]
    assert (await running.client.get(_nupkg("fake.hello", "1.0.1"))).status_code == 425
    # Listed again, with its original date (90 days ago): still timed from when SlowShield first listed it.
    running.fake.control("nuget-list", id="Fake.Hello", version="1.0.1", listed="true")
    running.clock.advance(7 * 3600)
    assert "1.0.1" not in await _versions(running, "fake.hello")
    await running.drain()
    assert running.rows(row) == [(NOW - 90 * DAY, NOW, 0)]
    assert (await running.client.get(_nupkg("fake.hello", "1.0.1"))).status_code == 425
    running.clock.advance(7 * DAY)
    assert "1.0.1" in await _versions(running, "fake.hello")
    assert (await running.client.get(_nupkg("fake.hello", "1.0.1"))).status_code == 200


async def test_a_listed_version_unlisted_later_keeps_its_time(running: Running) -> None:
    assert "1.1.0" in await _versions(running, "fake.hello")
    await running.drain()
    running.fake.control("nuget-list", id="Fake.Hello", version="1.1.0", listed="false")
    running.clock.advance(7 * 3600)
    assert "1.1.0" in await _versions(running, "fake.hello")  # still 30 days old, now 1900 upstream


async def test_a_publish_time_never_moves_earlier(running: Running) -> None:
    assert "1.2.0" not in await _versions(running, "fake.hello")
    await running.drain()
    running.fake.control("publish", ecosystem="nuget", name="Fake.Hello", version="1.2.0", age_days="30")
    running.clock.advance(7 * 3600)  # the registration now says 30 days
    assert "1.2.0" not in await _versions(running, "fake.hello")
    assert (await running.client.get(_nupkg("fake.hello", "1.2.0"))).status_code == 425
    await running.drain()
    row = "SELECT published FROM package_versions WHERE name = 'fake.hello' AND version = '1.2.0'"
    assert running.rows(row) == [(NOW - 2 * DAY,)]


async def test_a_publish_time_in_the_future_is_not_one(running: Running) -> None:
    assert await _versions(running, "fake.future") == []
    await running.drain()
    row = "SELECT published, first_listed FROM package_versions WHERE name = 'fake.future'"
    assert running.rows(row) == [(None, NOW)]
    running.clock.advance(7 * DAY)
    assert (await running.client.get(_nupkg("fake.future", "1.0.0"))).status_code == 200


# ---- search ----------------------------------------------------------------------------------------------------


async def test_search_leaves_out_held_versions_and_packages_with_nothing_left(start_app, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    run = await start_app()
    r = await run.client.get("/nuget/v3/query?q=fake&take=50")
    assert r.status_code == 200
    doc = r.json()
    found = {d["id"]: (d["version"], [v["version"] for v in d["versions"]]) for d in doc["data"]}
    assert found == {
        "Fake.Deps": ("1.0.0", ["1.0.0"]),
        "Fake.Evil": ("1.0.0", ["1.0.0"]),
        "Fake.Hello": ("1.1.0", ["1.0.0", "1.1.0"]),  # not 1.2.0 (too new); 1.0.1 is unlisted
        "Fake.Paged": ("1.4.0", ["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"]),
        "Fake.Partly": ("1.1.0", ["1.0.0", "1.1.0"]),
    }  # Fake.New and Fake.Future have nothing old enough
    assert doc["totalHits"] == 5
    hello = next(d for d in doc["data"] if d["id"] == "Fake.Hello")
    assert hello["@id"] == hello["registration"] == f"{BASE}registration/fake.hello/index.json"
    assert hello["versions"][0]["@id"] == f"{BASE}registration/fake.hello/1.0.0.json"
    assert doc["@context"]["@base"] == f"{BASE}registration/"
    pre = (await run.client.get("/nuget/v3/query?q=fake.hello&prerelease=true")).json()
    assert pre["data"][0]["version"] == "2.0.0-Beta.1"
    await _run_feeds(run)
    found = {d["id"]: d["version"] for d in (await run.client.get("/nuget/v3/query?q=fake")).json()["data"]}
    assert "Fake.Evil" not in found and found["Fake.Partly"] == "1.0.0"


async def test_search_fails_closed(running: Running) -> None:
    running.fake.control("fail", prefix="/nuget-reg/fake.hello/", status="503")
    found = [d["id"] for d in (await running.client.get("/nuget/v3/query?q=fake.")).json()["data"]]
    assert "Fake.Hello" not in found and "Fake.Deps" in found
    running.fake.control("fail", prefix="/nuget-reg/fake.hello/", status="0")
    running.fake.control("fail", prefix="/nuget-search/", status="503")
    r = await running.client.get("/nuget/v3/query?q=fake")
    assert r.status_code == 503 and r.headers["retry-after"] == "10"
    running.fake.control("fail", prefix="/nuget-search/", status="0")


# ---- vulnerability data ----------------------------------------------------------------------------------------


async def test_vulnerability_data_comes_through_slowshield(running: Running) -> None:
    r = await running.client.get("/nuget/v3/vulnerabilities/index.json")
    assert r.status_code == 200
    ids = [x["@id"] for x in r.json()]
    assert ids == [
        f"{BASE}vulnerabilities/nuget-vuln-data/2026.09.20/vulnerability.base.json",
        f"{BASE}vulnerabilities/nuget-vuln-data/2026.09.20/2026.09.21/vulnerability.update.json",
    ]  # the entry on another host is left out
    base = await running.client.get(ids[0].removeprefix("https://slowshield.test"))
    assert base.status_code == 200 and "fake.hello" in base.json()
    for path in ("nuget-vuln-data/other.json", "nuget-vuln/index.json", "not-the-vulnerability-host.json"):
        assert (await running.client.get(f"/nuget/v3/vulnerabilities/{path}")).status_code == 404, path


# ---- the shield wall ---------------------------------------------------------------------------------------------


async def test_a_follower_learns_when_the_leader_first_listed_a_version(pair: Pair) -> None:  # noqa: F811
    p = pair
    await _join(p)
    assert "1.0.1" not in await _versions(p.leader, "fake.hello")  # unlisted: timed from now, on the leader
    await p.leader.drain()
    await p.sync()
    row = "SELECT first_listed FROM package_versions WHERE ecosystem = 'nuget' AND name = 'fake.hello' AND version = ?"
    assert p.follower.rows(row, ("1.0.1",)) == [(NOW,)]
    # The leader's policy reaches the follower for NuGet too.
    assert p.follower.ctx.cfg.fail_open_for("nuget") is False
