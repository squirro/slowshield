"""npm registry proxy: packument filtering, abbreviated output, dist-tags, tarballs, pass-through."""

from __future__ import annotations

import base64
import hashlib

from tests.conftest import DAY, Running, asgi_get

CORGI = "application/vnd.npm.install-v1+json"


async def test_full_packument_filters_and_rewrites(running: Running) -> None:
    r = await running.client.get("/npm/left-pad-ng")
    assert r.status_code == 200
    doc = r.json()
    assert list(doc["versions"]) == ["1.0.0", "1.1.0"]
    assert "2.0.0" not in doc["time"]
    assert {"created", "modified", "1.0.0", "1.1.0"} <= set(doc["time"])
    assert doc["dist-tags"] == {"latest": "1.1.0"}
    tarball = doc["versions"]["1.0.0"]["dist"]["tarball"]
    assert tarball == "https://slowshield.test/npm/left-pad-ng/-/left-pad-ng-1.0.0.tgz"
    # fields we do not understand are preserved byte-for-byte
    assert doc["versions"]["1.0.0"]["dist"]["signatures"][0]["keyid"] == "SHA256:fake"
    assert doc["readme"] and doc["maintainers"] and doc["_rev"] == "1-fake"
    assert r.headers["x-slowshield-held-versions"] == "1"
    etag = r.headers["etag"]
    assert (await running.client.get("/npm/left-pad-ng", headers={"If-None-Match": etag})).status_code == 304


async def test_abbreviated_packument(running: Running) -> None:
    running.clock.advance(5 * DAY)  # left-pad-ng 2.0.0 (with a postinstall script) becomes available
    r = await running.client.get("/npm/left-pad-ng", headers={"Accept": f"{CORGI}; q=1.0, application/json; q=0.8"})
    assert r.headers["content-type"] == CORGI
    doc = r.json()
    assert set(doc) == {"name", "dist-tags", "versions", "modified"}
    v2 = doc["versions"]["2.0.0"]
    assert v2["hasInstallScript"] is True
    assert "scripts" not in v2 and "description" not in v2 and "_npmUser" not in v2
    assert v2["dist"]["tarball"].startswith("https://slowshield.test/npm/")
    assert doc["versions"]["1.1.0"]["deprecated"] == "use 1.0.0"


async def test_scoped_packages_both_encodings(running: Running) -> None:
    for path in ("/npm/@acme/widget", "/npm/@acme%2fwidget", "/npm/@acme%2Fwidget"):
        res = await asgi_get(running.app, path)
        assert res.status == 200, path
    r = await running.client.get("/npm/@acme/widget")
    doc = r.json()
    assert list(doc["versions"]) == ["0.1.0", "0.2.0"]
    assert doc["dist-tags"] == {"latest": "0.2.0"}  # `next` pointed at a too-new prerelease: dropped
    t = await running.client.get("/npm/@acme/widget/-/widget-0.1.0.tgz")
    assert t.status_code == 200
    assert t.content[:2] == b"\x1f\x8b"


async def test_dist_tags_only_point_at_served_versions(running: Running) -> None:
    doc = (await running.client.get("/npm/tagged")).json()
    served = set(doc["versions"])
    assert doc["dist-tags"]["latest"] == "1.5.0"
    assert doc["dist-tags"]["beta"] == "1.6.0-beta.1"
    assert "next" not in doc["dist-tags"]
    assert set(doc["dist-tags"].values()) <= served


async def test_version_manifest_endpoint(running: Running) -> None:
    r = await running.client.get("/npm/tagged/latest")
    assert r.status_code == 200 and r.json()["version"] == "1.5.0"
    assert (await running.client.get("/npm/tagged/1.0.0")).json()["version"] == "1.0.0"
    assert (await running.client.get("/npm/tagged/2.0.0")).status_code == 404


async def test_tarball_verified_and_cached(running: Running) -> None:
    r = await running.client.get("/npm/left-pad-ng/-/left-pad-ng-1.0.0.tgz")
    assert r.status_code == 200
    doc = (await running.client.get("/npm/left-pad-ng")).json()
    integrity = doc["versions"]["1.0.0"]["dist"]["integrity"]
    assert integrity == "sha512-" + base64.b64encode(hashlib.sha512(r.content).digest()).decode()
    await running.drain()
    hit = await running.client.get("/npm/left-pad-ng/-/left-pad-ng-1.0.0.tgz")
    assert hit.headers["x-slowshield-cache"] == "hit"


async def test_too_new_tarball_403(running: Running) -> None:
    r = await running.client.get("/npm/left-pad-ng/-/left-pad-ng-2.0.0.tgz")
    assert r.status_code == 403
    assert r.json()["error"] == "age_too_new"
    assert int(r.headers["retry-after"]) > 4 * DAY


async def test_tarball_name_validation(running: Running) -> None:
    assert (await running.client.get("/npm/left-pad-ng/-/other-1.0.0.tgz")).status_code == 404
    assert (await running.client.get("/npm/left-pad-ng/-/left-pad-ng-notaversion.tgz")).status_code == 404
    assert (await running.client.get("/npm/left-pad-ng/-/left-pad-ng-9.9.9.tgz")).status_code == 404
    assert (await running.client.get("/npm/_private")).status_code == 404
    assert (await running.client.get("/npm/a/b/c/d")).status_code == 404
    assert (await running.client.get("/npm/@scope")).status_code == 404
    assert (await running.client.get("/npm/nope-not-here")).status_code == 404


async def test_sha1_only_legacy_version(running: Running) -> None:
    r = await running.client.get("/npm/old-sha1/-/old-sha1-0.1.0.tgz")
    assert r.status_code == 200


async def test_tarball_integrity_mismatch_aborts(start_app) -> None:
    run = await start_app("[cache]\nartifacts_enabled = false\n")
    run.fake.control("tamper", path="/npm/left-pad-ng/-/left-pad-ng-1.0.0.tgz")
    res = await asgi_get(run.app, "/npm/left-pad-ng/-/left-pad-ng-1.0.0.tgz")
    assert res.status == 502 and b"sha512 does not match" in res.body
    await run.drain()
    assert run.rows("SELECT type FROM events") == [("integrity_mismatch",)]


async def test_fail_open_npm(running: Running) -> None:
    running.fake.control("publish", ecosystem="npm", name="fresh-pkg", version="0.0.1")
    r = await running.client.get("/npm/fresh-pkg")
    assert r.headers["x-slowshield-fail-open"] == "1"
    assert list(r.json()["versions"]) == ["0.0.1"]


async def test_ping_root_and_passthrough(running: Running) -> None:
    assert (await running.client.get("/npm/-/ping")).json() == {}
    assert (await running.client.get("/npm/")).json()["slowshield"] is True
    keys = await running.client.get("/npm/-/npm/v1/keys")
    assert keys.status_code == 200 and keys.json()["keys"][0]["keyid"] == "SHA256:fake"
    audit = await running.client.post("/npm/-/npm/v1/security/advisories/bulk", json={"left-pad-ng": ["1.0.0"]})
    assert audit.status_code == 200
    assert (await running.client.get("/npm/-/whoami")).status_code == 404
    assert (await running.client.post("/npm/left-pad-ng")).status_code == 405


async def test_audit_passthrough_disabled_and_body_limit(start_app, monkeypatch) -> None:
    run = await start_app("[upstreams.npm]\naudit_passthrough = false\n")
    assert (await run.client.post("/npm/-/npm/v1/security/advisories/bulk", json={})).status_code == 404
    from slowshield.ecosystems.npm import service

    monkeypatch.setattr(service, "MAX_AUDIT_BODY", 10)
    run2 = await start_app()
    r = await run2.client.post("/npm/-/npm/v1/security/audits/quick", content=b"x" * 100)
    assert r.status_code == 413


async def test_npm_host_routing_and_public_url(start_app) -> None:
    run = await start_app(
        """
[upstreams.npm]
hostnames = ["npm.internal"]
""",
        host="npm.internal",
    )
    doc = (await run.client.get("/left-pad-ng")).json()
    assert doc["versions"]["1.0.0"]["dist"]["tarball"] == "https://npm.internal/left-pad-ng/-/left-pad-ng-1.0.0.tgz"
    assert (await run.client.get("/left-pad-ng/-/left-pad-ng-1.0.0.tgz")).status_code == 200
    assert (await run.client.get("/healthz")).status_code == 200


async def test_explicit_npm_public_url(start_app) -> None:
    run = await start_app('[upstreams.npm]\npublic_url = "https://registry.example.com/"\n')
    doc = (await run.client.get("/npm/left-pad-ng")).json()
    assert doc["versions"]["1.0.0"]["dist"]["tarball"].startswith("https://registry.example.com/left-pad-ng/-/")


async def test_npm_upstream_errors(running: Running) -> None:
    running.fake.control("fail", prefix="/npm", status=503)
    r = await running.client.get("/npm/left-pad-ng")
    assert r.status_code == 502
    r = await running.client.get("/npm/left-pad-ng/-/left-pad-ng-1.0.0.tgz")
    assert r.status_code == 502
    r = await running.client.get("/npm/-/npm/v1/keys")
    assert r.status_code == 502
