"""OCI images at /v2/: tags that lag behind (time travel), digest refusals, verified blobs, takedowns, the layer store.

The fake registries: docker.io (Docker Hub API: a tag's current digest only), quay.io (complete tag history),
registry.k8s.io (gcr-style upload times in tags/list, no token), ghcr.io (no times). Blobs redirect to a CDN on
another host, which refuses any request that still carries the registry token.
"""

from __future__ import annotations

import hashlib
import json

from fakeupstream.catalog import make_oci_image

from tests.conftest import DAY, Running, asgi_get

ACCEPT = {"Accept": "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json"}
STRICT = "[upstreams.oci]\nfail_open = false\n"


def index_digest(path: str, version: str) -> str:
    return make_oci_image(path, version)[0]


async def get(run: Running, path: str, method: str = "GET") -> object:
    return await run.client.request(method, path, headers=ACCEPT)


def errors(r: object) -> str:
    return r.json()["errors"][0]["message"]  # type: ignore[attr-defined]


async def test_the_api_root_answers_without_a_challenge(running: Running) -> None:
    r = await running.client.get("/v2/")
    assert r.status_code == 200 and r.headers["docker-distribution-api-version"] == "registry/2.0"
    assert "www-authenticate" not in r.headers


async def test_a_tag_resolves_to_the_newest_old_enough_digest_from_the_registry_history(running: Running) -> None:
    # Quay keeps every digest a tag pointed to: 1.8.2 (2 days) is held, 1.8.1 (10 days) is served.
    r = await get(running, "/v2/quay.io/prometheus/node-exporter/manifests/latest")
    assert r.status_code == 200
    want = index_digest("prometheus/node-exporter", "1.8.1")
    assert r.headers["docker-content-digest"] == want == "sha256:" + hashlib.sha256(r.content).hexdigest()
    assert r.headers["x-slowshield-held-versions"] == "1" and "x-slowshield-fail-open" not in r.headers
    head = await get(running, "/v2/quay.io/prometheus/node-exporter/manifests/latest", "HEAD")
    assert head.headers["docker-content-digest"] == want and int(head.headers["content-length"]) == len(r.content)


async def test_with_only_the_current_digest_a_new_instance_fails_open_and_a_strict_one_refuses(start_app) -> None:
    lenient = await start_app()
    r = await get(lenient, "/v2/library/nginx/manifests/latest")  # Docker Hub's API knows only the current digest
    assert r.status_code == 200 and r.headers["x-slowshield-fail-open"] == "1"
    assert r.headers["docker-content-digest"] == index_digest("library/nginx", "1.27.2")
    strict = await start_app(STRICT)
    r = await get(strict, "/v2/library/nginx/manifests/latest")
    assert r.status_code == 403 and r.headers["x-slowshield-reason"] == "too_new"
    assert r.json()["errors"][0]["code"] == "DENIED"
    assert errors(r).startswith("slowshield: docker.io/library/nginx:latest (sha256:")
    assert "It was pushed 2026-09-19T14:13:20Z (2.0 days ago); this proxy requires 7 days." in errors(r)
    assert int(r.headers["retry-after"]) == int(5 * DAY)
    head = await get(strict, "/v2/library/nginx/manifests/latest", "HEAD")
    assert head.status_code == 403  # containerd resolves with HEAD, then repeats a 403 as GET to show the body


async def test_slowshields_own_history_lets_a_tag_lag_behind(start_app) -> None:
    run = await start_app(STRICT)
    first = index_digest("library/brandnew", "0.1")
    assert (await get(run, "/v2/library/brandnew/manifests/latest")).status_code == 403  # an hour old
    run.clock.advance(8 * DAY)
    r = await get(run, "/v2/library/brandnew/manifests/latest")
    assert r.status_code == 200 and r.headers["docker-content-digest"] == first
    # The tag moves upstream (pushed "now" in SlowShield's time): the tag keeps serving 0.1 for a week.
    run.fake.control("publish", ecosystem="oci", name="docker.io/library/brandnew:latest", version="0.2", age_days="-8")
    run.clock.advance(301)  # the tag's upstream digest is asked for again
    r = await get(run, "/v2/library/brandnew/manifests/latest")
    assert r.status_code == 200 and r.headers["docker-content-digest"] == first
    assert r.headers["x-slowshield-held-versions"] == "1"
    run.clock.advance(7 * DAY)
    r = await get(run, "/v2/library/brandnew/manifests/latest")
    assert r.headers["docker-content-digest"] == index_digest("library/brandnew", "0.2")


async def test_digest_pins_are_judged_and_platform_manifests_follow_their_index(start_app) -> None:
    run = await start_app(STRICT)
    old = index_digest("library/nginx", "1.27.0")  # 40 days
    r = await get(run, f"/v2/library/nginx/manifests/{old}")
    assert r.status_code == 200 and r.headers["cache-control"] == "max-age=31536000, immutable"
    child = json.loads(r.content)["manifests"][1]["digest"]
    r = await get(run, f"/v2/library/nginx/manifests/{child}")
    assert r.status_code == 200 and r.headers["content-type"] == "application/vnd.oci.image.manifest.v1+json"
    new = index_digest("library/nginx", "1.27.2")  # 2 days: Docker Hub's tag list says when it was pushed
    r = await get(run, f"/v2/library/nginx/manifests/{new}")
    assert r.status_code == 403 and errors(r).startswith("slowshield: docker.io/library/nginx@sha256:")
    assert "2.0 days ago" in errors(r)


async def test_upload_times_from_tags_list(start_app) -> None:
    run = await start_app(STRICT)
    assert (await get(run, "/v2/registry.k8s.io/pause/manifests/3.10")).status_code == 200
    r = await get(run, "/v2/registry.k8s.io/pause/manifests/3.11")
    assert r.status_code == 403 and "1.0 days ago" in errors(r)


async def test_containerd_names_the_registry_with_ns(start_app) -> None:
    lenient = await start_app()
    r = await get(lenient, "/v2/squirro/slowshield/manifests/0.0.6?ns=ghcr.io")
    assert r.status_code == 200 and r.headers["x-slowshield-fail-open"] == "1"  # GHCR has no times: first sight
    strict = await start_app(STRICT)
    r = await get(strict, "/v2/squirro/slowshield/manifests/0.0.6?ns=ghcr.io")
    assert r.status_code == 403 and "0.0 hours ago" in errors(r)
    strict.clock.advance(7 * DAY)
    assert (await get(strict, "/v2/squirro/slowshield/manifests/0.0.6?ns=ghcr.io")).status_code == 200


async def test_unconfigured_registries_and_other_paths(running: Running) -> None:
    r = await get(running, "/v2/evil.example.com/x/manifests/latest")
    assert r.status_code == 403 and r.headers["x-slowshield-reason"] == "registry_not_configured"
    r = await get(running, "/v2/mcr.microsoft.com/dotnet/runtime/manifests/9.0")  # switched off in the tests
    assert r.status_code == 403
    assert (await get(running, "/v2/library/nginx/manifests/no-such-tag")).status_code == 404
    assert (await get(running, "/v2/library/nginx/blobs/latest")).status_code == 404
    r = await running.client.put("/v2/library/nginx/manifests/latest", content=b"{}")
    assert r.status_code == 405 and r.json()["errors"][0]["code"] == "UNSUPPORTED"


async def test_blobs_are_verified_without_sending_the_token_to_the_cdn(running: Running) -> None:
    _, manifests, blobs = make_oci_image("library/nginx", "1.27.0")
    digest, body = next((d, b) for d, (mt, b) in manifests.items() if "manifest.v1" in mt)
    image = json.loads(body)
    config, layer = image["config"]["digest"], image["layers"][0]["digest"]
    assert (await get(running, f"/v2/library/nginx/manifests/{digest}")).status_code == 200  # as a client would
    for digest in (config, layer):
        r = await running.client.get(f"/v2/library/nginx/blobs/{digest}")
        assert r.status_code == 200 and r.content == blobs[digest]  # the CDN refuses requests with a token
        assert r.headers["docker-content-digest"] == digest
    await running.drain()
    # The config is kept in the main cache; the layer isn't stored (no layer store configured).
    assert (await running.client.get(f"/v2/library/nginx/blobs/{config}")).headers["x-slowshield-cache"] == "hit"
    assert (await running.client.get(f"/v2/library/nginx/blobs/{layer}")).headers["x-slowshield-cache"] == "miss"


async def test_the_layer_store_keeps_layers_when_it_has_a_budget(start_app) -> None:
    run = await start_app("[upstreams.oci]\nlayer_cache_gb = 1\n")
    _, manifests, _ = make_oci_image("library/nginx", "1.27.0")
    image = next(json.loads(body) for mt, body in manifests.values() if "manifest.v1" in mt)
    layer = image["layers"][0]["digest"]
    assert (await run.client.get(f"/v2/library/nginx/blobs/{layer}")).headers["x-slowshield-cache"] == "miss"
    await run.drain()
    assert (await run.client.get(f"/v2/library/nginx/blobs/{layer}")).headers["x-slowshield-cache"] == "hit"
    assert run.rows("SELECT count(*) FROM oci_layer_entries") == [(1,)]
    assert run.rows("SELECT count(*) FROM cache_entries") == [(0,)]


async def test_tampered_blobs_are_never_delivered_whole(running: Running) -> None:
    _, manifests, _ = make_oci_image("library/nginx", "1.27.0")
    image = next(json.loads(body) for mt, body in manifests.values() if "manifest.v1" in mt)
    layer = image["layers"][0]["digest"]
    running.fake.control("tamper", path=f"/oci-cdn/docker.io/library/nginx/{layer}")
    res = await asgi_get(running.app, f"/v2/library/nginx/blobs/{layer}")
    assert res.status == 503 or res.error is not None
    await running.drain()
    assert ("integrity_mismatch", "docker.io/library/nginx") in running.rows(
        "SELECT type, package FROM events WHERE ecosystem = 'oci'"
    )


async def test_a_registry_takedown_propagates(running: Running) -> None:
    old = index_digest("library/nginx", "1.27.0")
    assert (await get(running, "/v2/library/nginx/manifests/1.27.0")).status_code == 200
    assert (await get(running, f"/v2/library/nginx/manifests/{old}")).status_code == 200
    running.fake.control("oci-remove", image="docker.io/library/nginx", digest=old)
    assert (await get(running, f"/v2/library/nginx/manifests/{old}")).status_code == 200  # checked again in 5 min
    running.clock.advance(301)
    r = await get(running, f"/v2/library/nginx/manifests/{old}")
    assert r.status_code == 403 and r.headers["x-slowshield-reason"] == "taken_down"
    r = await get(running, "/v2/library/nginx/manifests/1.27.0")  # the tag's only digest is gone
    assert r.status_code == 403 and r.headers["x-slowshield-reason"] == "taken_down"
    assert (await get(running, "/v2/library/nginx/manifests/never-seen-tag")).status_code == 404


async def test_operator_blocks(start_app) -> None:
    held_back = index_digest("prometheus/node-exporter", "1.8.1")
    run = await start_app(
        '[[blocks]]\necosystem = "oci"\npackage = "evil"\nreason = "cryptominer in the entrypoint"\n'
        '[[blocks]]\necosystem = "oci"\npackage = "quay.io/prometheus/node-exporter"\n'
        f'version = "{held_back}"\n'
        '[[blocks]]\necosystem = "oci"\npackage = "nginx"\nversion = "1.27.0"\n'
    )
    r = await get(run, "/v2/library/evil/manifests/latest")
    assert r.status_code == 403 and r.headers["x-slowshield-reason"] == "blocked"
    assert errors(r) == (
        "slowshield: docker.io/library/evil is blocked by the administrator of this proxy. "
        "cryptominer in the entrypoint"
    )
    # A blocked digest is skipped: the tag goes back to the next old-enough one.
    r = await get(run, "/v2/quay.io/prometheus/node-exporter/manifests/latest")
    assert r.headers["docker-content-digest"] == index_digest("prometheus/node-exporter", "1.8.0")
    r = await get(run, "/v2/library/nginx/manifests/1.27.0")  # a blocked tag
    assert r.status_code == 403 and "docker.io/library/nginx:1.27.0 is blocked" in errors(r)
    rows = run.rows("SELECT ecosystem, name, version, source FROM blocklist ORDER BY name")
    assert ("oci", "docker.io/library/evil", None, "config") in rows


async def test_exceptions_for_a_repository_or_digest(start_app) -> None:
    run = await start_app(STRICT + '[[exceptions]]\necosystem = "oci"\npackage = "nginx"\ndelay_days = 0\n')
    r = await get(run, "/v2/library/nginx/manifests/latest")
    assert r.status_code == 200 and r.headers["docker-content-digest"] == index_digest("library/nginx", "1.27.2")


async def test_tags_list_is_passed_through(running: Running) -> None:
    r = await running.client.get("/v2/quay.io/prometheus/node-exporter/tags/list")
    assert r.status_code == 200 and r.json()["tags"] == ["latest"]


async def test_a_registry_outage_serves_from_history(start_app) -> None:
    run = await start_app()
    want = index_digest("prometheus/node-exporter", "1.8.1")
    assert (await get(run, "/v2/quay.io/prometheus/node-exporter/manifests/latest")).status_code == 200
    run.fake.control("fail", prefix="/oci/quay.io/", status="503")
    run.clock.advance(301)
    r = await get(run, "/v2/quay.io/prometheus/node-exporter/manifests/latest")
    assert r.status_code == 200 and r.headers["docker-content-digest"] == want  # history and stored manifest
    r = await get(run, "/v2/quay.io/prometheus/other/manifests/latest")
    assert r.status_code == 503 and r.headers["retry-after"] == "10"
    run.fake.control("fail", prefix="/oci/quay.io/", status="0")


async def test_the_package_page_shows_what_each_tag_pointed_to(running: Running) -> None:
    assert (await get(running, "/v2/quay.io/prometheus/node-exporter/manifests/latest")).status_code == 200
    page = (await running.client.get("/ui/packages/oci/quay.io/prometheus/node-exporter")).text
    assert "<h2>Tags</h2>" in page and "<h2>Versions</h2>" not in page
    trs = page.split('<tr class="row-')
    digests = {v: index_digest("prometheus/node-exporter", v)[:19] for v in ("1.8.0", "1.8.1", "1.8.2")}
    rows = {v: next(r for r in trs if d in r) for v, d in digests.items()}
    assert rows["1.8.2"].startswith("held") and "(registry)" in rows["1.8.2"]
    assert rows["1.8.1"].startswith("available") and "served for this tag" in rows["1.8.1"]
    assert rows["1.8.0"].startswith("available") and "served for this tag" not in rows["1.8.0"]


async def test_a_new_instance_fails_open_for_tags_not_for_digests_dated_too_new(start_app) -> None:
    run = await start_app()  # lenient: a new instance in its first delay days
    fresh = index_digest("library/brandnew", "0.1")  # an hour old, and Docker Hub says so
    r = await get(run, f"/v2/library/brandnew/manifests/{fresh}")
    assert r.status_code == 403 and r.headers["x-slowshield-reason"] == "too_new"  # a pin is never let through
    r = await get(run, "/v2/library/brandnew/manifests/latest")  # the tag has no history yet: served, recorded
    assert r.status_code == 200 and r.headers["x-slowshield-fail-open"] == "1"
    child = json.loads(r.content)["manifests"][0]["digest"]
    r = await get(run, f"/v2/library/brandnew/manifests/{child}")  # its platform manifests follow the index
    assert r.status_code == 200 and r.headers["x-slowshield-fail-open"] == "1"
    # GHCR has no times: a pin it can't date is served on a new instance, and its platform manifests follow.
    pinned = index_digest("squirro/slowshield", "0.0.7")
    r = await get(run, f"/v2/ghcr.io/squirro/slowshield/manifests/{pinned}")
    assert r.status_code == 200 and r.headers["x-slowshield-fail-open"] == "1"
    child = json.loads(r.content)["manifests"][1]["digest"]
    assert (await get(run, f"/v2/ghcr.io/squirro/slowshield/manifests/{child}")).status_code == 200


async def test_an_alias_is_the_same_repository(start_app) -> None:
    run = await start_app(
        '[upstreams.oci.registries."quay.io"]\naliases = ["quay.example"]\n'
        '[[blocks]]\necosystem = "oci"\npackage = "quay.io/prometheus/node-exporter"\n'
    )
    r = await get(run, "/v2/quay.example/prometheus/node-exporter/manifests/latest")
    assert r.status_code == 403 and "quay.io/prometheus/node-exporter is blocked" in errors(r)
    run = await start_app(
        '[upstreams.oci.registries."quay.io"]\naliases = ["quay.example"]\n'
        '[[blocks]]\necosystem = "oci"\npackage = "quay.example/prometheus/node-exporter"\n'  # named by the alias
    )
    assert (await get(run, "/v2/quay.io/prometheus/node-exporter/manifests/latest")).status_code == 403


async def test_blobs_of_a_blocked_repository_are_refused(start_app) -> None:
    _, manifests, _ = make_oci_image("library/evil", "6.6.6")
    image = next(json.loads(body) for mt, body in manifests.values() if "manifest.v1" in mt)
    layer = image["layers"][0]["digest"]
    run = await start_app('[[blocks]]\necosystem = "oci"\npackage = "evil"\n')
    r = await run.client.get(f"/v2/library/evil/blobs/{layer}")
    assert r.status_code == 403 and r.headers["x-slowshield-reason"] == "blocked"
    run = await start_app(f'[[blocks]]\necosystem = "oci"\npackage = "evil"\nversion = "{layer}"\n')  # one layer
    assert (await run.client.get(f"/v2/library/evil/blobs/{layer}")).status_code == 403
    assert (await run.client.get(f"/v2/library/evil/blobs/{image['config']['digest']}")).status_code == 200


async def test_a_pull_resolves_with_head_then_follows_the_index(start_app) -> None:
    # What containerd and Podman do: HEAD the tag, GET the index by digest, then a platform manifest by digest.
    run = await start_app(STRICT)
    repo = "/v2/quay.io/prometheus/node-exporter"
    head = await get(run, f"{repo}/manifests/latest", "HEAD")
    index = head.headers["docker-content-digest"]
    r = await get(run, f"{repo}/manifests/{index}")
    assert r.status_code == 200
    for entry in json.loads(r.content)["manifests"]:
        assert (await get(run, f"{repo}/manifests/{entry['digest']}")).status_code == 200
