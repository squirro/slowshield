"""End-to-end behaviour of the shipped images: real clients through Caddy against the fake registry."""

# ruff: noqa: S603, S607 - the e2e suite drives docker/curl/uv/npm on purpose

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from tests.e2e.conftest import Stack

pytestmark = pytest.mark.e2e

JSON_V1 = "application/vnd.pypi.simple.v1+json"


def _files(stack: Stack, name: str, version: str) -> list[dict[str, str]]:
    return stack.fake_info()["pypi"][name][version]


# ---- container hardening -----------------------------------------------------------------------


@pytest.mark.parametrize("service", ["slowshield", "caddy"])
def test_containers_are_hardened(stack: Stack, service: str) -> None:
    cid = stack.container_id(service)
    info = json.loads(subprocess.run(["docker", "inspect", cid], capture_output=True, text=True, check=True).stdout)[0]
    assert info["Config"]["User"] == "65532:65532"
    assert info["HostConfig"]["ReadonlyRootfs"] is True
    assert {c.upper().removeprefix("CAP_") for c in info["HostConfig"]["CapDrop"]} >= {"ALL"}
    assert any("no-new-privileges" in o for o in info["HostConfig"]["SecurityOpt"])
    # No shell in the image.
    r = subprocess.run(["docker", "exec", cid, "/bin/sh", "-c", "true"], capture_output=True, text=True, check=False)
    assert r.returncode != 0


def test_only_caddy_publishes_ports(stack: Stack) -> None:
    def bindings(service: str) -> dict:
        out = subprocess.run(
            ["docker", "inspect", "--format", "{{json .HostConfig.PortBindings}}", stack.container_id(service)],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(out.stdout) or {}

    assert bindings("slowshield") == {}
    assert set(bindings("caddy")) == {"8080/tcp", "8443/tcp", "8443/udp"}


# ---- TLS edge ------------------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl not installed")
def test_http2_and_modern_tls(stack: Stack) -> None:
    common = ["curl", "-sS", "--cacert", str(stack.ca_file), "-o", "/dev/null"]
    h2 = subprocess.run(
        [*common, "--http2", "-w", "%{http_version}", f"{stack.base}/"], capture_output=True, text=True, check=True
    )
    assert h2.stdout.strip() == "2"
    legacy = subprocess.run(
        [*common, "--tls-max", "1.2", f"{stack.base}/"], capture_output=True, text=True, check=False
    )
    assert legacy.returncode != 0, "TLS 1.2 must be refused by default"


def test_security_headers(stack: Stack) -> None:
    status, headers, _ = stack.get("/")
    assert status == 200
    assert headers["strict-transport-security"].startswith("max-age=63072000")
    assert "default-src 'none'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"
    assert "server" not in headers
    assert headers["alt-svc"] == f'h3=":{stack.https_port}"; ma=86400'


def test_plain_http_redirects_and_health(stack: Stack) -> None:
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", stack.http_port, timeout=10)
    conn.request("GET", "/pypi/simple/alpha/", headers={"Host": "localhost"})
    r = conn.getresponse()
    r.read()
    assert r.status == 308
    assert r.getheader("Location") == f"https://localhost:{stack.https_port}/pypi/simple/alpha/"
    conn.request("GET", "/healthz", headers={"Host": "localhost"})
    health = conn.getresponse()
    health.read()
    assert health.status == 200


def test_unsafe_methods_rejected(stack: Stack) -> None:
    import urllib.error
    import urllib.request

    req = urllib.request.Request(f"{stack.base}/pypi/simple/alpha/", method="DELETE")
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, context=stack.ssl_context(), timeout=10)
    assert exc.value.code == 405


# ---- PyPI ---------------------------------------------------------------------------------------


def test_too_new_versions_hidden_and_downloads_refused(stack: Stack) -> None:
    status, headers, body = stack.get("/pypi/simple/alpha/", headers={"Accept": JSON_V1})
    assert status == 200
    doc = json.loads(body)
    assert "2.0.0" not in doc["versions"] and "1.1.0" in doc["versions"]
    assert headers["x-slowshield-held-versions"] == "1"
    too_new = _files(stack, "alpha", "2.0.0")[0]["path"]
    status, headers, body = stack.get("/pypi" + too_new)
    assert status == 403
    assert json.loads(body)["error"] == "age_too_new"
    assert int(headers["retry-after"]) > 0


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv not installed")
def test_uv_installs_through_the_proxy(stack: Stack, tmp_path: Path) -> None:
    venv = tmp_path / "venv"
    subprocess.run(["uv", "venv", "-q", "--python", sys.executable, str(venv)], check=True)
    env = {
        **os.environ,
        "SSL_CERT_FILE": str(stack.ca_file),
        "UV_INDEX_URL": "",
        "UV_DEFAULT_INDEX": f"{stack.base}/pypi/simple/",
        "UV_NO_CACHE": "1",
    }
    subprocess.run(
        ["uv", "pip", "install", "-q", "--python", str(venv / "bin" / "python"), "alpha"], env=env, check=True
    )
    freeze = subprocess.run(
        ["uv", "pip", "freeze", "--python", str(venv / "bin" / "python")],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "alpha==1.1.0" in freeze.stdout  # 2.0.0 is one day old


def test_artifact_cache_hit_on_second_download(stack: Stack) -> None:
    import time

    path = "/pypi" + _files(stack, "alpha", "1.0.0")[0]["path"]
    first = stack.get(path)
    assert first[0] == 200
    # The verified copy is committed to the cache right after the first response completes.
    deadline = time.monotonic() + 15
    while True:
        again = stack.get(path)
        assert again[0] == 200 and again[2] == first[2]
        if again[1].get("x-slowshield-cache") == "hit" or time.monotonic() > deadline:
            break
        time.sleep(0.5)
    assert again[1].get("x-slowshield-cache") == "hit"


def test_tampered_artifact_is_never_delivered_complete(stack: Stack) -> None:
    import http.client
    import ssl

    f = next(x for x in _files(stack, "partly-bad", "1.0.0") if x["filename"].endswith(".tar.gz"))
    stack.control("tamper", path="/files" + f["path"])
    conn = http.client.HTTPSConnection("localhost", stack.https_port, context=stack.ssl_context(), timeout=30)
    conn.request("GET", "/pypi" + f["path"])
    resp = conn.getresponse()
    if resp.status != 200:
        # Small artifacts: the mismatch is found before any byte (or header) leaves the server.
        assert resp.status >= 500
        assert resp.getheader("x-slowshield-cache") is None
        return
    # Large artifacts: headers are out, the final chunk is withheld and the stream aborted.
    with pytest.raises((http.client.IncompleteRead, ssl.SSLError, ConnectionError, http.client.HTTPException)):
        resp.read()


def test_malware_is_blocked_with_451(feeds_synced: Stack) -> None:
    status, _, body = feeds_synced.get("/pypi/simple/malware-pkg/")
    assert status == 451
    assert json.loads(body)["advisory_id"] == "MAL-2026-0001"
    status, _, _ = feeds_synced.get("/npm/malicious-npm")
    assert status == 451


def test_version_level_block_keeps_other_versions(feeds_synced: Stack) -> None:
    status, _, body = feeds_synced.get("/pypi/simple/partly-bad/", headers={"Accept": JSON_V1})
    assert status == 200
    versions = json.loads(body)["versions"]
    assert "1.2.0" not in versions and "1.0.0" in versions


# ---- npm ----------------------------------------------------------------------------------------


def test_npm_packument_is_filtered(stack: Stack) -> None:
    status, _, body = stack.get("/npm/left-pad-ng", headers={"Accept": "application/json"})
    assert status == 200
    doc = json.loads(body)
    assert "2.0.0" not in doc["versions"]
    assert doc["dist-tags"]["latest"] == "1.1.0"
    tarball = doc["versions"]["1.1.0"]["dist"]["tarball"]
    assert tarball.startswith(f"https://localhost:{stack.https_port}/npm/")


@pytest.mark.skipif(shutil.which("npm") is None, reason="npm not installed")
def test_npm_installs_through_the_proxy(stack: Stack, tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "e2e", "version": "1.0.0", "private": true}')
    env = {**os.environ, "NODE_EXTRA_CA_CERTS": str(stack.ca_file), "npm_config_cache": str(tmp_path / ".npm")}
    subprocess.run(
        [
            "npm",
            "install",
            "--no-audit",
            "--no-fund",
            "--registry",
            f"{stack.base}/npm/",
            "left-pad-ng",
            "@acme/widget",
        ],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
    )
    lock = json.loads((tmp_path / "package-lock.json").read_text())
    # `latest` is held back (2.0.0 is two days old) and falls to 1.1.0, which is deprecated, so npm
    # prefers the newest non-deprecated version: 1.0.0.
    assert lock["packages"]["node_modules/left-pad-ng"]["version"] == "1.0.0"
    # 0.2.0 is ten days old (latest); 0.3.0-beta.1 (`next`) is held back.
    assert lock["packages"]["node_modules/@acme/widget"]["version"] == "0.2.0"
