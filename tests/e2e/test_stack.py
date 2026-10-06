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

from slowshield.ui import snippets

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
    status, headers, _ = stack.get("/ui/")
    assert status == 200
    assert headers["strict-transport-security"].startswith("max-age=63072000")
    assert "default-src 'none'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"
    assert "server" not in headers
    assert headers["alt-svc"] == f'h3=":{stack.https_port}"; ma=86400'


def test_plain_http_redirects_and_health(stack: Stack) -> None:
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", stack.http_port, timeout=10)
    conn.request("GET", "/pypi/simple/alpha/", headers={"Host": "slowshield.example.com"})
    r = conn.getresponse()
    r.read()
    assert r.status == 308
    assert r.getheader("Location") == f"https://slowshield.example.com:{stack.https_port}/pypi/simple/alpha/"
    conn.request("GET", "/healthz", headers={"Host": "slowshield.example.com"})
    health = conn.getresponse()
    health.read()
    assert health.status == 200


def test_local_plain_http(stack: Stack) -> None:
    """SLOWSHIELD_LOCAL_HTTP=on (the Compose default): localhost is served over HTTP, tarballs follow."""
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", stack.http_port, timeout=10)
    conn.request(
        "GET", "/pypi/simple/alpha/", headers={"Host": "localhost", "Accept": "application/vnd.pypi.simple.v1+json"}
    )
    r = conn.getresponse()
    body = r.read()
    assert r.status == 200 and b"alpha" in body
    assert r.getheader("Strict-Transport-Security") is None
    conn.request("GET", "/npm/left-pad-ng", headers={"Host": f"localhost:{stack.http_port}"})
    r = conn.getresponse()
    doc = json.loads(r.read())
    assert r.status == 200
    tarballs = [v["dist"]["tarball"] for v in doc["versions"].values()]
    assert tarballs and all(t.startswith(f"http://localhost:{stack.http_port}/npm/") for t in tarballs)


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


@pytest.mark.skipif(shutil.which("go") is None, reason="go not installed")
def test_go_downloads_through_the_proxy(stack: Stack, tmp_path: Path) -> None:
    env = {
        **os.environ,
        "SSL_CERT_FILE": str(stack.ca_file),
        "GOPROXY": f"{stack.base}/go",
        "GOSUMDB": "off",  # the fake checksum database is not signed by sum.golang.org's key
        "GOPATH": str(tmp_path / "gopath"),
        "GOMODCACHE": str(tmp_path / "modcache"),
        "GOFLAGS": "-modcacherw",
        "GOTOOLCHAIN": "local",
        "GOENV": "off",
    }
    ok = subprocess.run(
        ["go", "mod", "download", "-json", "example.com/hello@latest"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout)["Version"] == "v1.1.0"  # v1.2.0 was stored by the mirror two days ago
    held = subprocess.run(
        ["go", "mod", "download", "example.com/hello@v1.2.0"], env=env, capture_output=True, text=True, check=False
    )
    assert held.returncode != 0
    assert "403 Forbidden" in held.stderr and "is too new" in held.stderr  # our text/plain body, printed by go


MAVEN_IMAGE = "maven:3.9-eclipse-temurin-21@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320"
MAVEN_SETTINGS = """<settings><mirrors><mirror>
  <!-- replaces Maven's built-in blocker of http:// repositories: the test talks plain HTTP inside the stack -->
  <id>maven-default-http-blocker</id><mirrorOf>*</mirrorOf>
  <url>http://localhost:8080/maven/all/</url><blocked>false</blocked>
</mirror></mirrors></settings>
"""


def _parent_pom(version: str) -> str:
    return (
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>'
        f"<parent><groupId>org.example</groupId><artifactId>bom</artifactId><version>{version}</version>"
        "<relativePath/></parent><artifactId>child</artifactId><packaging>pom</packaging></project>"
    )


def test_maven_resolves_through_the_proxy(stack: Stack, tmp_path: Path) -> None:
    """Real Maven against the stack: a parent POM is resolved while the model is built, with no plugins needed (the
    fake registry has none). 1.0.0 is 100 days old; 1.1.0 two days, so Maven reports a 425."""
    (tmp_path / "settings.xml").write_text(MAVEN_SETTINGS)
    (tmp_path / "ok.xml").write_text(_parent_pom("1.0.0"))
    (tmp_path / "new.xml").write_text(_parent_pom("1.1.0"))

    def mvn(pom: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["docker", "run", "--rm", "--network", f"container:{stack.container_id('slowshield')}",
             "-v", f"{tmp_path}:/w:ro", MAVEN_IMAGE, "mvn", "-B", "-s", "/w/settings.xml",
             "-Dmaven.repo.local=/tmp/m2", "-f", f"/w/{pom}", "validate"],
            capture_output=True, text=True, timeout=600, check=False,
        )  # fmt: skip

    ok = mvn("ok.xml")
    assert ok.returncode == 0, ok.stdout[-3000:]
    held = mvn("new.xml")
    assert held.returncode != 0
    assert "status code: 425, reason phrase: Too Early (425)" in held.stdout, held.stdout[-3000:]


GRADLE_IMAGE = "gradle:9.8.0-jdk21@sha256:4debe478645a3ad9208f3403ac021859fdf4d1a819d59970d75309b098f28f76"


def _gradle_project(root: Path, version: str) -> None:
    root.mkdir()
    (root / "settings.gradle").write_text(f"rootProject.name = 'try-{version}'\n")
    (root / "build.gradle").write_text(
        "plugins { id 'java' }\nrepositories { mavenCentral() }\n"
        f"dependencies {{ implementation 'org.example:hello:{version}' }}\n"
        "tasks.register('resolve') { doLast { configurations.compileClasspath.files.each { println it.name } } }\n"
    )


def test_gradle_resolves_through_the_proxy(stack: Stack, tmp_path: Path) -> None:
    """Real Gradle with the Setup page's init script, which points mavenCentral() at SlowShield. 1.0.0 of
    org.example:hello is 100 days old; 1.2.0 two days, so Gradle reports a 425."""
    (tmp_path / "init.gradle").write_text(snippets.gradle_init("http://localhost:8080/maven"))
    for version in ("1.0.0", "1.2.0"):
        _gradle_project(tmp_path / version, version)

    def gradle(version: str) -> subprocess.CompletedProcess[str]:
        # Gradle writes into the project (build/reports), so it works on a copy inside the container.
        script = (
            f"cp -r /w/{version} /tmp/project && gradle --no-daemon --no-configuration-cache -q -g /tmp/gradle-home "
            "-I /w/init.gradle -p /tmp/project resolve"
        )
        return subprocess.run(
            ["docker", "run", "--rm", "--network", f"container:{stack.container_id('slowshield')}",
             "-v", f"{tmp_path}:/w:ro", "--entrypoint", "sh", GRADLE_IMAGE, "-c", script],
            capture_output=True, text=True, timeout=600, check=False,
        )  # fmt: skip

    ok = gradle("1.0.0")
    assert ok.returncode == 0 and "hello-1.0.0.jar" in ok.stdout, (ok.stdout + ok.stderr)[-3000:]
    held = gradle("1.2.0")
    assert held.returncode != 0
    assert "Received status code 425 from server" in held.stderr, held.stderr[-3000:]


CARGO_IMAGE = "rust:1.99-slim@sha256:24e632c09342c20abf8312cf4f61430a911c01ed3a5e4c02b87292b1c39c5273"
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


def test_cargo_resolves_through_the_proxy(stack: Stack, tmp_path: Path) -> None:
    """Real cargo with the Setup page's command (official images set CARGO_HOME). fake-deps needs fake_hello ^1:
    1.2.0 is two days old, so it is marked yanked and cargo picks 1.1.0. A Cargo.lock that pins 1.2.0 gets the
    403 text."""
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "Cargo.toml").write_text(
        '[package]\nname = "try-cargo"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nfake-deps = "0.1"\n'
    )
    (project / "src" / "lib.rs").write_text("pub use fake_deps::VERSION;\n")
    pinned = tmp_path / "pinned"
    (pinned / "src").mkdir(parents=True)
    (pinned / "Cargo.toml").write_text(
        '[package]\nname = "pinned"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nfake_hello = "1"\n'
    )
    (pinned / "src" / "lib.rs").write_text("")
    cksum = stack.fake_info()["cargo"]["fake_hello"]["1.2.0"]["cksum"]
    (pinned / "Cargo.lock").write_text(
        f'version = 4\n\n[[package]]\nname = "fake_hello"\nversion = "1.2.0"\nsource = "{CRATES_IO}"\n'
        f'checksum = "{cksum}"\n\n[[package]]\nname = "pinned"\nversion = "0.1.0"\ndependencies = ["fake_hello"]\n'
    )
    setup = snippets.cargo_command("http://localhost:8080/cargo/")

    def cargo(script: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["docker", "run", "--rm", "--network", f"container:{stack.container_id('slowshield')}",
             "-v", f"{tmp_path}:/w:ro", "--entrypoint", "sh", CARGO_IMAGE, "-c", f"{setup} && {script}"],
            capture_output=True, text=True, timeout=600, check=False,
        )  # fmt: skip

    ok = cargo("cp -r /w/project /tmp/p && cd /tmp/p && cargo build -q && cat Cargo.lock")
    assert ok.returncode == 0, ok.stderr[-3000:]
    assert f'name = "fake_hello"\nversion = "1.1.0"\nsource = "{CRATES_IO}"' in ok.stdout  # crates.io, unchanged
    assert 'name = "fake-deps"\nversion = "0.1.0"' in ok.stdout
    held = cargo("cp -r /w/pinned /tmp/p && cd /tmp/p && cargo fetch --locked")
    assert held.returncode != 0
    assert "got 403" in held.stderr and "fake_hello@1.2.0 is too new" in held.stderr, held.stderr[-3000:]
    assert "--precise 1.1.0" in held.stderr
