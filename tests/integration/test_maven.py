"""Maven repositories: filtered metadata, publish times from Last-Modified (per file, plus the first-listed clock),
425 refusals, checksums from headers / checksum files / the Plugin Portal's path, /maven/all/ routing, feeds."""

from __future__ import annotations

import hashlib
import re

from slowshield.feeds import FeedScheduler
from slowshield.feeds.github import GithubFeed
from slowshield.feeds.osv import OsvFeed
from tests.conftest import DAY, NOW, Running, asgi_get

TEXT = "text/plain; charset=utf-8"
HELLO = "/maven/central/org/example/hello"


def _versions(body: str) -> list[str]:
    return re.findall(r"<version>([^<]+)</version>", body)


def _hits(run: Running, prefix: str) -> dict[str, int]:
    return run.fake.hits(prefix)


async def test_metadata_hides_too_new_versions(running: Running) -> None:
    r = await running.client.get(f"{HELLO}/maven-metadata.xml")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/xml")
    assert _versions(r.text) == ["1.0.0", "1.1.0"]  # 1.2.0 is 2 days old; snapshots never on Central
    assert "<latest>1.1.0</latest>" in r.text and "<release>1.1.0</release>" in r.text
    assert "<lastUpdated>20260920000000</lastUpdated>" in r.text  # everything else unchanged
    assert r.headers["x-slowshield-held-versions"] == "1"
    assert r.headers["x-checksum-sha1"] == hashlib.sha1(r.content, usedforsecurity=False).hexdigest()
    for algo in ("sha1", "md5", "sha256", "sha512"):
        sidecar = await running.client.get(f"{HELLO}/maven-metadata.xml.{algo}")
        assert sidecar.text == hashlib.new(algo, r.content, usedforsecurity=False).hexdigest(), algo
    # Newest first until one is old enough: a HEAD of the 1.2.0 and 1.1.0 poms, nothing for 1.0.0.
    hits = {p.rsplit("/", 1)[-1]: n for p, n in _hits(running, f"{HELLO}/").items()}
    assert hits == {"maven-metadata.xml": 1, "hello-1.2.0.pom": 1, "hello-1.1.0.pom": 1}


async def test_files_of_a_too_new_version_get_425(running: Running) -> None:
    await running.client.get(f"{HELLO}/maven-metadata.xml")  # learns 1.2.0's publish time
    for name in ("hello-1.2.0.pom", "hello-1.2.0.jar", "hello-1.2.0.jar.sha1"):
        r = await running.client.get(f"{HELLO}/1.2.0/{name}")
        assert r.status_code == 425, name
        assert r.headers["content-type"] == TEXT and "org.example:hello:1.2.0 is too new" in r.text
        assert int(r.headers["retry-after"]) == int(5 * DAY)
    assert f"{HELLO}/1.2.0/hello-1.2.0.jar" not in _hits(running, f"{HELLO}/1.2.0/")  # refused without asking
    head = await running.client.head(f"{HELLO}/1.2.0/hello-1.2.0.jar")
    assert head.status_code == 425
    running.clock.advance(5 * DAY + 1)
    assert (await running.client.get(f"{HELLO}/1.2.0/hello-1.2.0.jar")).status_code == 200


async def test_a_file_is_judged_by_its_own_last_modified(running: Running) -> None:
    # Never seen before: the file's own Last-Modified decides, from the download SlowShield makes anyway.
    r = await running.client.get(f"{HELLO}/1.2.0/hello-1.2.0.jar")
    assert r.status_code == 425
    # A classifier added to a 100-day-old version yesterday is held on its own.
    base = "/maven/central/org/example/late-classifier/1.0.0"
    assert (await running.client.get(f"{base}/late-classifier-1.0.0.jar")).status_code == 200
    assert (await running.client.get(f"{base}/late-classifier-1.0.0-extra.jar")).status_code == 425


async def test_downloads_are_verified_and_carry_checksum_headers(running: Running) -> None:
    r = await running.client.get(f"{HELLO}/1.0.0/hello-1.0.0.jar")
    assert r.status_code == 200 and r.headers["x-slowshield-cache"] == "miss"
    sha1 = hashlib.sha1(r.content, usedforsecurity=False).hexdigest()
    assert r.headers["x-checksum-sha1"] == sha1  # Maven then skips the .sha1 request
    await running.drain()
    hit = await running.client.get(f"{HELLO}/1.0.0/hello-1.0.0.jar")
    assert hit.headers["x-slowshield-cache"] == "hit" and hit.headers["x-checksum-sha1"] == sha1
    assert (await running.client.get(f"{HELLO}/1.0.0/hello-1.0.0.jar.sha1")).text == sha1  # from the record
    assert running.rows("SELECT upstream_digest FROM artifacts WHERE ecosystem = 'maven'") == [(sha1,)]
    assert f"{HELLO}/1.0.0/hello-1.0.0.jar.sha1" not in _hits(running, HELLO)  # Central sent it as a header


async def test_bytes_that_do_not_match_the_checksum_are_refused(running: Running) -> None:
    running.fake.control("tamper", path=f"{HELLO}/1.1.0/hello-1.1.0.jar")
    res = await asgi_get(running.app, f"{HELLO}/1.1.0/hello-1.1.0.jar")
    assert res.status == 503 or res.error is not None  # 503, not 502 or 404: Maven caches a 404
    await running.drain()
    assert ("integrity_mismatch", "org.example:hello") in running.rows(
        "SELECT type, package FROM events WHERE ecosystem = 'maven'"
    )


async def test_a_bulk_rewrite_does_not_hold_old_versions_forever(running: Running) -> None:
    # org.example:migrated's files get a new Last-Modified on every request, like a repository migrating its storage.
    base = "/maven/central/org/example/migrated"
    for v in ("1.0.0", "0.9.0"):  # the .pom lookups fail: only the first-listed clock is recorded
        running.fake.control("fail", prefix=f"{base}/{v}/", status="503")
    r = await running.client.get(f"{base}/maven-metadata.xml")
    assert r.status_code == 200
    for v in ("1.0.0", "0.9.0"):
        running.fake.control("fail", prefix=f"{base}/{v}/", status="0")
    await running.drain()
    assert running.rows("SELECT published, first_listed FROM package_versions WHERE name = 'org.example:migrated'") == [
        (None, NOW),
        (None, NOW),
    ]
    running.clock.advance(8 * DAY)
    running.fake.control("clock", offset=str(8 * DAY))
    # Its files' Last-Modified is still "now", but SlowShield first saw 1.0.0 listed 8 days ago.
    assert (await running.client.get(f"{base}/1.0.0/migrated-1.0.0.jar")).status_code == 200
    running.fake.control("clock", offset="0")


async def test_brand_new_artifacts_are_held_unless_fail_open_is_on(start_app) -> None:
    strict = await start_app()
    base = "/maven/central/org/example/brandnew"
    assert _versions((await strict.client.get(f"{base}/maven-metadata.xml")).text) == []
    assert (await strict.client.get(f"{base}/0.1.0/brandnew-0.1.0.jar")).status_code == 425
    lenient = await start_app("[upstreams.maven]\nfail_open = true\n")
    r = await lenient.client.get(f"{base}/maven-metadata.xml")
    assert _versions(r.text) == ["0.1.0"] and r.headers["x-slowshield-fail-open"] == "1"
    assert (await lenient.client.get(f"{base}/0.1.0/brandnew-0.1.0.jar")).status_code == 200


async def test_google_maven_checksums_come_from_its_checksum_files(running: Running) -> None:
    base = "/maven/google/androidx/test/core"
    assert _versions((await running.client.get(f"{base}/maven-metadata.xml")).text) == ["1.5.0"]
    r = await running.client.get(f"{base}/1.5.0/core-1.5.0.jar")
    assert r.status_code == 200
    assert r.headers["x-checksum-sha1"] == hashlib.sha1(r.content, usedforsecurity=False).hexdigest()
    assert _hits(running, f"{base}/1.5.0/").get(f"{base}/1.5.0/core-1.5.0.jar.sha1") == 1  # no header: fetched


async def test_all_routes_googles_groups_to_google_and_the_rest_to_central(running: Running) -> None:
    google = await running.client.get("/maven/all/androidx/test/core/1.5.0/core-1.5.0.pom")
    central = await running.client.get("/maven/all/org/example/hello/1.0.0/hello-1.0.0.pom")
    assert google.status_code == 200 and central.status_code == 200
    assert "/maven/google/androidx/test/core/1.5.0/core-1.5.0.pom" in _hits(running, "/maven/google/")
    assert "/maven/central/org/example/hello/1.0.0/hello-1.0.0.pom" in _hits(running, "/maven/central/")
    # Same file, same fingerprint record, whichever path served it.
    assert (await running.client.get(f"{HELLO}/1.0.0/hello-1.0.0.pom")).content == central.content
    await running.drain()
    assert running.rows("SELECT path FROM artifacts WHERE package = 'org.example:hello'") == [
        ("/central/org/example/hello/1.0.0/hello-1.0.0.pom",)
    ]


async def test_plugin_portal_files_are_verified_by_the_sha256_in_their_path(running: Running) -> None:
    marker = "/maven/gradle-plugins/com/example/plugin/com.example.plugin.gradle.plugin/1.0"
    r = await running.client.get(f"{marker}/com.example.plugin.gradle.plugin-1.0.pom")
    assert r.status_code == 200
    await running.drain()
    digest = hashlib.sha256(r.content).hexdigest()
    rows = running.rows("SELECT upstream_digest FROM artifacts WHERE package LIKE 'com.example.plugin:%'")
    assert rows == [(digest,)]
    # The Portal also serves Central: same artifact, same clock, same refusal.
    via_portal = await running.client.get("/maven/gradle-plugins/org/example/hello/1.2.0/hello-1.2.0.jar")
    assert via_portal.status_code == 425


async def test_malware_is_refused(start_app, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    run = await start_app()
    await FeedScheduler(run.ctx, [OsvFeed(run.ctx), GithubFeed(run.ctx)]).run_once()
    for path in (
        "/maven/central/io/github/evil/typosquat/maven-metadata.xml",
        "/maven/all/io/github/evil/typosquat/1.0.0/typosquat-1.0.0.jar",
    ):
        r = await run.client.get(path)
        assert r.status_code == 451 and "MAL-2026-3001" in r.text, path
    base = "/maven/central/org/example/partly"
    assert _versions((await run.client.get(f"{base}/maven-metadata.xml")).text) == ["1.0.0"]
    r = await run.client.get(f"{base}/1.1.0/partly-1.1.0.pom")
    assert r.status_code == 451 and "GHSA-aaaa-0006-0006" in r.text


async def test_exceptions(start_app) -> None:
    run = await start_app(
        '[[exceptions]]\necosystem = "maven"\npackage = "org.example:hello"\nversion = "1.2.0"\ndelay_days = 0\n'
    )
    assert "1.2.0" in _versions((await run.client.get(f"{HELLO}/maven-metadata.xml")).text)
    assert (await run.client.get(f"{HELLO}/1.2.0/hello-1.2.0.jar")).status_code == 200


async def test_head_answers_what_a_get_would(running: Running) -> None:
    base = "/maven/central/org/example/bom/1.0.0"
    assert (await running.client.head(f"{base}/bom-1.0.0.pom")).status_code == 200
    assert (await running.client.head(f"{base}/bom-1.0.0.jar")).status_code == 404  # Gradle asks: pom-only module
    ok = await running.client.head(f"{HELLO}/1.0.0/hello-1.0.0.jar")
    assert ok.status_code == 200 and int(ok.headers["content-length"]) > 0 and "x-checksum-sha1" in ok.headers


async def test_upstream_failures_are_503_never_404(running: Running) -> None:
    running.fake.control("fail", prefix="/maven/central/", status="503")
    for path in (f"{HELLO}/maven-metadata.xml", f"{HELLO}/1.1.0/hello-1.1.0.jar"):
        assert (await running.client.get(path)).status_code == 503, path
    running.fake.control("fail", prefix="/maven/central/", status="0")


async def test_paths_outside_the_layout_are_404(running: Running) -> None:
    for path in (
        "/maven/central/.index/nexus-maven-repository-index.gz",
        "/maven/central/org/example/hello/",
        "/maven/central/org/example/hello/1.3.0-SNAPSHOT/hello-1.3.0-SNAPSHOT.jar",  # no snapshots on Central
        "/maven/central/org/example/hello/1.0.0/unrelated.jar",
        "/maven/nope/org/example/hello/maven-metadata.xml",
        "/maven/central/org/example/missing/1.0/missing-1.0.jar",
    ):
        assert (await running.client.get(path)).status_code == 404, path
    assert (await running.client.post(f"{HELLO}/maven-metadata.xml")).status_code == 405


async def test_group_metadata_and_operator_snapshots_pass_through(running: Running) -> None:
    plugins = await running.client.get("/maven/central/org/apache/maven/plugins/maven-metadata.xml")
    assert plugins.status_code == 200 and "<prefix>fake</prefix>" in plugins.text
    snap = await running.client.get("/maven/snapshots/org/example/nightly/2.0-SNAPSHOT/nightly-2.0-SNAPSHOT.jar")
    assert snap.status_code == 200 and snap.content[:2] == b"PK"


async def test_upstream_requests_per_new_version(running: Running) -> None:
    """A Maven build resolving one dependency: metadata, pom, jar. SlowShield adds the metadata walk's HEADs and
    nothing else; Maven skips checksum files because the responses carry X-Checksum-Sha1."""
    for path in (f"{HELLO}/maven-metadata.xml", f"{HELLO}/1.1.0/hello-1.1.0.pom", f"{HELLO}/1.1.0/hello-1.1.0.jar"):
        assert (await running.client.get(path)).status_code == 200, path
    hits = {p.removeprefix(f"{HELLO}/"): n for p, n in _hits(running, f"{HELLO}/").items()}
    assert hits == {
        "maven-metadata.xml": 1,
        "1.2.0/hello-1.2.0.pom": 1,  # the walk's HEAD
        "1.1.0/hello-1.1.0.pom": 2,  # the walk's HEAD, then the download (its date is already known)
        "1.1.0/hello-1.1.0.jar": 1,
    }
    await running.drain()
    rows = running.rows("SELECT version, published FROM package_versions WHERE name = 'org.example:hello' ORDER BY 1")
    assert dict(rows)["1.1.0"] == NOW - 30 * DAY
