"""OCI: reference paths, image names, auth challenges, registry times, safe redirects, manifests, config."""

from __future__ import annotations

import json

import pytest

from slowshield import config as C
from slowshield import names
from slowshield.ecosystems import ECOSYSTEMS
from slowshield.ecosystems.oci.reference import parse
from slowshield.ecosystems.oci.registry import Manifest, RegistryClient, bearer
from slowshield.ecosystems.oci.service import blob_error
from slowshield.ecosystems.oci.times import _ts
from slowshield.upstream import Upstream, redirected

D = "sha256:" + "a" * 64


@pytest.mark.parametrize(
    ("path", "ns", "want"),
    [
        ("/library/nginx/manifests/latest", None, ("docker.io", "library/nginx", "manifests", "latest")),
        ("/nginx/manifests/1.29", None, ("docker.io", "library/nginx", "manifests", "1.29")),
        ("/docker.io/nginx/manifests/1.29", None, ("docker.io", "library/nginx", "manifests", "1.29")),
        ("/index.docker.io/bitnami/redis/manifests/7", None, ("docker.io", "bitnami/redis", "manifests", "7")),
        ("/ghcr.io/squirro/slowshield/manifests/0.0.7", None, ("ghcr.io", "squirro/slowshield", "manifests", "0.0.7")),
        ("/squirro/slowshield/blobs/" + D, "ghcr.io", ("ghcr.io", "squirro/slowshield", "blobs", D)),
        ("/library/nginx/manifests/latest", "docker.io", ("docker.io", "library/nginx", "manifests", "latest")),
        ("/localhost:5000/x/manifests/v1", None, ("localhost:5000", "x", "manifests", "v1")),
        ("/quay.io/prometheus/node-exporter/tags/list", None, ("quay.io", "prometheus/node-exporter", "tags", "")),
        ("/a/manifests/b/manifests/c", None, ("docker.io", "a/manifests/b", "manifests", "c")),
        ("/x/referrers/" + D, None, ("docker.io", "library/x", "referrers", D)),
    ],
)
def test_reference_paths(path: str, ns: str | None, want: tuple[str, str, str, str]) -> None:
    req = parse(path, ns)
    assert req is not None and (req.registry, req.path, req.kind, req.reference) == want
    assert req.repository == f"{want[0]}/{want[1]}"


@pytest.mark.parametrize(
    ("path", "ns"),
    [
        ("/", None),
        ("/x/manifests/bad tag", None),
        ("/x/manifests/-dash", None),
        ("/x/blobs/latest", None),
        ("/x/referrers/latest", None),
        ("/Upper/manifests/latest", None),
        ("/a//b/manifests/latest", None),
        ("/x/manifests/latest", "not a host"),
        ("/x/uploads/abc", None),
    ],
)
def test_other_paths_name_nothing(path: str, ns: str | None) -> None:
    assert parse(path, ns) is None


def test_image_names() -> None:
    assert (
        names.normalize_oci("nginx")
        == names.normalize_oci("index.docker.io/library/nginx")
        == "docker.io/library/nginx"
    )
    assert names.normalize_oci("Quay.io/Prometheus/Node-Exporter") == "quay.io/prometheus/node-exporter"
    assert names.is_valid_oci("ghcr.io/squirro/slowshield") and not names.is_valid_oci("a//b")
    page = ECOSYSTEMS["oci"].page_url
    assert page("docker.io/library/nginx") == "https://hub.docker.com/_/nginx"
    assert page("docker.io/bitnami/redis") == "https://hub.docker.com/r/bitnami/redis"
    assert page("quay.io/prometheus/node-exporter") == "https://quay.io/repository/prometheus/node-exporter"
    assert page("ghcr.io/squirro/slowshield") == "https://ghcr.io/squirro/slowshield"


def test_bearer_challenges() -> None:
    assert bearer('Bearer realm="https://auth.docker.io/token",service="registry.docker.io"') == (
        "https://auth.docker.io/token",
        "registry.docker.io",
    )
    assert bearer('Bearer realm="https://quay.io/v2/auth"') == ("https://quay.io/v2/auth", None)
    assert bearer('Basic realm="x"') is None and bearer("") is None


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("2026-10-06T04:53:45.43102Z", 1791262425.43102),  # Docker Hub
        ("2026-10-02T20:25:48.0000000+00:00", 1790972748.0),  # MCR: 7 fractional digits
        (1784031990, 1784031990.0),  # Quay start_ts
        ("2026-10-06T04:53:45", None),  # no time zone: not a usable time
        ("garbage", None),
        (None, None),
    ],
)
def test_registry_times(raw: object, want: float | None) -> None:
    assert _ts(raw) == want


def test_redirects_never_carry_credentials_to_another_host() -> None:
    headers = {"Authorization": "Bearer t", "Cookie": "c", "Accept": "x"}
    url, kept = redirected("https://registry-1.docker.io/v2/x/blobs/d", "/v2/y", headers)
    assert url == "https://registry-1.docker.io/v2/y" and kept == headers
    url, kept = redirected("https://registry-1.docker.io/v2/x", "https://production.cloudfront.docker.com/b", headers)
    assert url == "https://production.cloudfront.docker.com/b" and kept == {"Accept": "x"}


async def test_allowed_hosts_take_patterns() -> None:
    up = Upstream(user_agent="t", allowed_hosts=["ghcr.io", "*.data.mcr.microsoft.com", "*-docker.pkg.dev"])
    try:
        assert up._allowed("https://ghcr.io/v2/")
        assert up._allowed("https://westeurope.data.mcr.microsoft.com/x")
        assert up._allowed("https://europe-west8-docker.pkg.dev/v2/x")
        assert not up._allowed("https://data.mcr.microsoft.com.evil.example/x")
        assert not up._allowed("https://evil.example/ghcr.io")
    finally:
        await up.close()


def test_manifest_children_and_config() -> None:
    index = json.dumps({"manifests": [{"digest": D}, {"digest": "nope"}]}).encode()
    m = Manifest(D, "application/vnd.oci.image.index.v1+json", index, len(index))
    assert m.is_index and m.children() == [D] and m.config() == ""
    image = json.dumps({"config": {"digest": D}, "layers": []}).encode()
    m = Manifest(D, "application/vnd.oci.image.manifest.v1+json", image, len(image))
    assert not m.is_index and m.children() == [] and m.config() == D


def test_blob_errors_follow_the_distribution_spec() -> None:
    r = blob_error(451, "tamper_detected", artifact="/blobs/x")
    assert r.status_code == 403 and json.loads(r.body)["errors"][0]["code"] == "DENIED"
    assert r.headers["x-slowshield-reason"] == "tampered"
    r = blob_error(502, "upstream_error", detail="boom")
    assert r.status_code == 503 and r.headers["retry-after"] == "10"
    assert blob_error(404, "not_found").status_code == 404


def test_registry_config() -> None:
    oci = C.parse("").raw.upstreams.oci
    assert sorted(oci.all_registries()) == [
        "docker.io", "gcr.io", "ghcr.io", "mcr.microsoft.com", "public.ecr.aws", "quay.io", "registry.k8s.io",
    ]  # fmt: skip
    assert oci.layer_cache_gb == 0 and oci.fail_open is None
    extra = C.parse('[upstreams.oci.registries."registry.example.com"]\nurl = "https://registry.example.com"\n')
    assert "registry.example.com" in extra.raw.upstreams.oci.all_registries()
    off = C.parse('[upstreams.oci.registries."gcr.io"]\nurl = "https://gcr.io"\nenabled = false\n')
    assert "gcr.io" not in off.raw.upstreams.oci.all_registries()


@pytest.mark.parametrize(
    "toml",
    [
        '[upstreams.oci.registries."not a host"]\nurl = "https://x.example"',
        '[upstreams.oci.registries."x.example"]\nurl = "ftp://x.example"',
        '[upstreams.oci.registries."x.example"]\nurl = "https://x.example"\ndownload_hosts = ["a/b"]',
        '[upstreams.oci.registries."x.example"]\nurl = "https://x.example"\ntimes = "hub"',
        '[upstreams.oci.registries."x.example"]\nurl = "https://x.example"\nusername = "u"',
        "[upstreams.oci]\nlayer_cache_gb = -1",
    ],
)
def test_invalid_registry_config(toml: str) -> None:
    with pytest.raises(C.ConfigError):
        C.parse(toml)


def test_ratelimit_gauge_reads_the_count() -> None:
    client = RegistryClient.__new__(RegistryClient)
    client.ratelimit = {"docker.io": "87;w=21600", "odd.example": "n/a"}
    assert client.remaining() == [(87.0, {"registry": "docker.io"})]
