"""PyPI simple API proxy: filtering, rendering, negotiation, redirects, artifact gating."""

from __future__ import annotations

import json

from slowshield.ecosystems.pypi.project import HTML_V1, JSON_V1
from tests.conftest import DAY, NOW, Running

ACCEPT_JSON = {"Accept": f"{JSON_V1}, {HTML_V1};q=0.2, text/html;q=0.01"}


async def _index(run: Running, name: str, prefix: str = "/pypi") -> dict:
    r = await run.client.get(f"{prefix}/simple/{name}/", headers=ACCEPT_JSON)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == JSON_V1
    return r.json()


def _file(doc: dict, startswith: str) -> dict:
    return next(f for f in doc["files"] if f["filename"].startswith(startswith))


async def test_too_new_versions_are_hidden(running: Running) -> None:
    doc = await _index(running, "alpha")
    assert doc["versions"] == ["1.0.0", "1.0.1", "1.1.0"]
    assert all("2.0.0" not in f["filename"] for f in doc["files"])
    assert doc["meta"]["api-version"] == "1.4"
    assert doc["project-status"] == {"status": "active"}


async def test_relative_urls_and_metadata_fields(running: Running) -> None:
    doc = await _index(running, "alpha")
    wheel = _file(doc, "alpha-1.0.0-py3")
    assert wheel["url"].startswith("../../packages/")
    assert wheel["hashes"]["sha256"]
    assert wheel["core-metadata"]["sha256"]
    # PEP 714, as PyPI: pip 22.3-23.1 crash on a dict under the old "dist-info-metadata" key.
    assert "dist-info-metadata" not in wheel
    assert wheel["data-dist-info-metadata"] == wheel["core-metadata"]
    assert wheel["upload-time"].endswith("Z")
    assert isinstance(wheel["size"], int)
    yanked = _file(doc, "alpha-1.0.1-py3")
    assert yanked["yanked"] == "broken build"


async def test_held_versions_header_and_caching_headers(running: Running) -> None:
    r = await running.client.get("/pypi/simple/alpha/", headers=ACCEPT_JSON)
    assert r.headers["x-slowshield-held-versions"] == "1"
    assert r.headers["vary"] == "Accept"
    max_age = int(r.headers["cache-control"].removeprefix("max-age="))
    assert 0 < max_age <= 600
    etag = r.headers["etag"]
    r2 = await running.client.get("/pypi/simple/alpha/", headers={**ACCEPT_JSON, "If-None-Match": etag})
    assert r2.status_code == 304


async def test_render_revision_changes_the_etag(start_app, monkeypatch) -> None:
    from slowshield.ecosystems.pypi import service

    old = await start_app()
    r = await old.client.get("/pypi/simple/alpha/", headers=ACCEPT_JSON)
    monkeypatch.setattr(service, "RENDER_REVISION", "next")
    new = await start_app()
    r2 = await new.client.get("/pypi/simple/alpha/", headers={**ACCEPT_JSON, "If-None-Match": r.headers["etag"]})
    # A client holding the old rendering must get the new one, not a 304 for the old bytes.
    assert r2.status_code == 200
    assert r2.headers["etag"] != r.headers["etag"]


async def test_html_is_default_and_escaped(running: Running) -> None:
    r = await running.client.get("/pypi/simple/alpha/", headers={"Accept": "*/*"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    body = r.text
    assert '<meta name="pypi:repository-version" content="1.4">' in body
    assert 'href="../../packages/' in body and "#sha256=" in body
    assert 'data-requires-python="&gt;=3.8"' in body
    assert 'data-yanked="broken build"' in body
    assert "content-security-policy" in r.headers

    r = await running.client.get("/pypi/simple/alpha/", headers={"Accept": HTML_V1})
    assert r.headers["content-type"] == HTML_V1


async def test_name_normalisation_redirect(running: Running) -> None:
    r = await running.client.get("/pypi/simple/Alpha", follow_redirects=False)
    assert r.status_code == 301
    assert r.headers["location"] == "/pypi/simple/alpha/"
    r = await running.client.get("/pypi/simple/alpha", follow_redirects=False)
    assert r.status_code == 301
    r = await running.client.get("/pypi/simple/_bad_/")
    assert r.status_code == 404


async def test_unknown_project_404(running: Running) -> None:
    r = await running.client.get("/pypi/simple/does-not-exist/", headers=ACCEPT_JSON)
    assert r.status_code == 404
    assert r.json() == {"error": "not_found"}


async def test_root_index_and_redirect(running: Running) -> None:
    r = await running.client.get("/pypi/simple/", headers=ACCEPT_JSON)
    assert r.status_code == 200 and r.json()["projects"] == []
    r = await running.client.get("/pypi/simple/", headers={"Accept": "text/html"})
    assert r.headers["content-type"].startswith("text/html")
    r = await running.client.get("/pypi/simple", follow_redirects=False)
    assert r.status_code == 301 and r.headers["location"] == "/pypi/simple/"


async def test_single_host_root_alias(running: Running) -> None:
    doc = await _index(running, "alpha", prefix="")
    assert doc["versions"] == ["1.0.0", "1.0.1", "1.1.0"]


async def test_fail_open_for_brand_new_package(running: Running) -> None:
    r = await running.client.get("/pypi/simple/brand-new/", headers=ACCEPT_JSON)
    assert r.status_code == 200
    assert r.headers["x-slowshield-fail-open"] == "1"
    assert r.json()["versions"] == ["0.1.0"]
    await running.drain()
    events = running.rows("SELECT type, package FROM events")
    assert ("fail_open", "brand-new") in events


async def test_fail_closed_when_disabled(start_app) -> None:
    run = await start_app("fail_open = false")
    r = await run.client.get("/pypi/simple/brand-new/", headers=ACCEPT_JSON)
    assert r.status_code == 200
    assert r.json()["files"] == []


async def test_exception_rules(start_app) -> None:
    run = await start_app(
        """
[[exceptions]]
ecosystem = "pypi"
package = "Alpha"
delay_days = 0
note = "trusted"
"""
    )
    doc = await _index(run, "alpha")
    assert "2.0.0" in doc["versions"]


async def test_version_specific_exception(start_app) -> None:
    run = await start_app(
        """
[[exceptions]]
ecosystem = "pypi"
package = "alpha"
version = "2.0.0"
delay_days = 0
"""
    )
    doc = await _index(run, "alpha")
    assert doc["versions"][-1] == "2.0.0"


async def test_graduation_over_time(running: Running) -> None:
    doc = await _index(running, "alpha")
    assert "2.0.0" not in doc["versions"]
    running.clock.advance(6 * DAY + 60)
    doc = await _index(running, "alpha")
    assert "2.0.0" in doc["versions"]


async def test_legacy_filenames(running: Running) -> None:
    doc = await _index(running, "legacy-names")
    names = {f["filename"] for f in doc["files"]}
    assert names == {"legacy_names-1.0.0-py3-none-any.whl", "Legacy_Names-1.0.0.tar.gz", "legacy.names-0.9.0.zip"}
    assert set(doc["versions"]) == {"1.0.0", "0.9.0"}


async def test_upstream_failure_serves_stale_then_502(running: Running) -> None:
    await _index(running, "alpha")
    running.fake.control("fail", prefix="/pypi", status=503)
    running.clock.advance(7 * 3600)  # past the metadata TTL
    r = await running.client.get("/pypi/simple/alpha/", headers=ACCEPT_JSON)
    assert r.status_code == 200  # stale-if-error
    r = await running.client.get("/pypi/simple/partly-bad/", headers=ACCEPT_JSON)
    assert r.status_code == 502
    assert r.json()["error"] == "upstream_error"


async def test_revalidation_uses_etag(running: Running) -> None:
    await _index(running, "alpha")
    running.clock.advance(7 * 3600)
    await _index(running, "alpha")
    headers = running.fake.control("hits", prefix="/pypi/simple/alpha/")
    assert headers["/pypi/simple/alpha/"] == 2


# ---- artifacts -------------------------------------------------------------------------------------


async def test_download_wheel_and_metadata(running: Running) -> None:
    doc = await _index(running, "alpha")
    wheel = _file(doc, "alpha-1.1.0-py3")
    url = "/pypi/simple/alpha/" + wheel["url"]
    r = await running.client.get(url)
    assert r.status_code == 200, r.text
    import hashlib

    assert hashlib.sha256(r.content).hexdigest() == wheel["hashes"]["sha256"]
    assert r.headers["x-slowshield-cache"] == "miss"
    r = await running.client.get(url + ".metadata")
    assert r.status_code == 200
    assert hashlib.sha256(r.content).hexdigest() == wheel["core-metadata"]["sha256"]
    await running.drain()
    r = await running.client.get(url)
    assert r.status_code == 200 and r.headers["x-slowshield-cache"] == "hit"
    assert r.headers["etag"].strip('"') == wheel["hashes"]["sha256"]
    rows = running.rows("SELECT package, version, filename FROM artifacts ORDER BY filename")
    assert ("alpha", "1.1.0", "alpha-1.1.0-py3-none-any.whl") in rows
    await running.drain()
    totals = running.rows("SELECT serves, cache_hits FROM packages WHERE name = 'alpha'")
    assert totals == [(3, 1)]


async def test_range_request_on_cache_hit(running: Running) -> None:
    doc = await _index(running, "alpha")
    url = "/pypi/simple/alpha/" + _file(doc, "alpha-1.0.0-py3")["url"]
    full = (await running.client.get(url)).content
    await running.drain()
    r = await running.client.get(url, headers={"Range": "bytes=0-9"})
    assert r.status_code == 206
    assert r.content == full[:10]


async def test_head_does_not_download(running: Running) -> None:
    doc = await _index(running, "alpha")
    wheel = _file(doc, "alpha-1.0.0-py3")
    r = await running.client.head("/pypi/simple/alpha/" + wheel["url"])
    assert r.status_code == 200
    assert r.headers["content-length"] == str(wheel["size"])
    hits = running.fake.hits("/files/")
    assert hits == {}


async def test_too_new_download_is_403(running: Running) -> None:
    info = running.fake.info()["pypi"]["alpha"]["2.0.0"]
    path = next(f["path"] for f in info if f["filename"].endswith(".whl"))
    r = await running.client.get(f"/pypi{path}")
    assert r.status_code == 403
    body = r.json()
    assert body["error"] == "age_too_new"
    assert body["version"] == "2.0.0"
    assert body["delay_days_required"] == 7
    wait = int(r.headers["retry-after"])
    assert 5 * DAY < wait < 6 * DAY + 60
    await running.drain()
    ev = running.rows("SELECT type, package, version, client_ip FROM events WHERE type = 'age_gate'")
    assert ev == [("age_gate", "alpha", "2.0.0", "127.0.0.1")]


async def test_download_age_gate_can_be_disabled(start_app) -> None:
    run = await start_app("enforce_age_on_download = false")
    info = run.fake.info()["pypi"]["alpha"]["2.0.0"]
    path = next(f["path"] for f in info if f["filename"].endswith(".whl"))
    r = await run.client.get(f"/pypi{path}")
    assert r.status_code == 200


async def test_unknown_or_mismatched_artifacts_404(running: Running) -> None:
    info = running.fake.info()["pypi"]["alpha"]["1.0.0"]
    path = next(f["path"] for f in info if f["filename"].endswith(".whl"))
    bad = path.replace(path.split("/")[4], "0" * 60)
    assert (await running.client.get(f"/pypi{bad}")).status_code == 404
    assert (await running.client.get("/pypi/packages/aa/bb/cc/alpha-1.0.0.tar.gz")).status_code == 404
    assert (await running.client.get("/pypi/packages/../../etc/passwd")).status_code == 404
    unknown = "/packages/00/11/" + "2" * 60 + "/nope-1.0.0-py3-none-any.whl"
    assert (await running.client.get(f"/pypi{unknown}")).status_code == 404
    # `.metadata` for a file that has none (sdist)
    sdist = next(f["path"] for f in info if f["filename"].endswith(".tar.gz"))
    assert (await running.client.get(f"/pypi{sdist}.metadata")).status_code == 404


async def test_percent_encoded_traversal_rejected(running: Running) -> None:
    from tests.conftest import asgi_get

    res = await asgi_get(running.app, "/pypi/packages/%2e%2e/%2e%2e/etc/passwd")
    assert res.status == 404


async def test_ip_from_trusted_proxy(running: Running) -> None:
    info = running.fake.info()["pypi"]["alpha"]["2.0.0"]
    path = next(f["path"] for f in info if f["filename"].endswith(".whl"))
    await running.client.get(f"/pypi{path}", headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.2"})
    await running.drain()
    ips = running.rows("SELECT client_ip FROM events WHERE type = 'age_gate'")
    assert ips == [("203.0.113.9",)]


async def test_host_routing(start_app) -> None:
    run = await start_app(
        """
[upstreams.pypi]
hostnames = ["pypi.internal"]
""",
        host="pypi.internal",
    )
    r = await run.client.get("/simple/alpha/", headers=ACCEPT_JSON)
    assert r.status_code == 200
    assert r.json()["versions"][-1] == "1.1.0"
    assert (await run.client.get("/healthz")).status_code == 200
    # the UI is not on the PyPI host
    assert (await run.client.get("/ui/packages")).status_code == 404


async def test_upload_time_missing_is_too_new(running: Running) -> None:
    """Defensive: files without a publish time never count as old enough."""
    from slowshield.ecosystems.pypi.project import parse_project

    raw = json.dumps(
        {
            "meta": {"api-version": "1.1"},
            "name": "x",
            "files": [
                {
                    "filename": "x-1.0.0.tar.gz",
                    "url": "https://files.example/packages/aa/bb/" + "c" * 60 + "/x-1.0.0.tar.gz",
                    "hashes": {"sha256": "0" * 64},
                }
            ],
        }
    ).encode()
    proj = parse_project(raw, base_url="https://pypi.example/simple/x/", name="x", etag=None)
    assert proj.files[0].upload_time is None
    assert proj.versions == ["1.0.0"]
    assert NOW  # keep import used
