"""The real server (Granian, subprocess): zero-copy cache hits and tamper aborts over a real socket."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from fakeupstream import FakeUpstream
from fakeupstream.testing import free_port

from tests.conftest import NOW


@pytest.fixture
def server(tmp_path: Path, upstream: FakeUpstream) -> Iterator[str]:
    port = free_port()
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        f"""
bind_address = "127.0.0.1:{port}"
public_url = "http://127.0.0.1:{port}"
data_dir = "{tmp_path / "data"}"
default_delay_days = 0
[upstreams.pypi]
mirrors = ["{upstream.url}/pypi"]
files_url = "{upstream.url}/files"
[upstreams.npm]
mirrors = ["{upstream.url}/npm"]
[feeds.osv]
enabled = false
[feeds.github_advisory]
enabled = false
"""
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SLOWSHIELD_", "OTEL_"))}
    env.update({"SLOWSHIELD_LOG_FORMAT": "json", "SLOWSHIELD_LOG_LEVEL": "warning"})
    proc = subprocess.Popen(  # noqa: S603 - fixed argv
        [sys.executable, "-m", "slowshield.cli", "serve", "--config", str(cfg)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 30
    try:
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(proc.stderr.read().decode() if proc.stderr else "server exited")
            try:
                if httpx.get(base + "/readyz", timeout=1).status_code == 200:
                    break
            except httpx.TransportError:
                time.sleep(0.1)
        else:
            raise RuntimeError("server did not become ready")
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(15)
        except subprocess.TimeoutExpired:
            proc.kill()


def _wheel_url(upstream: FakeUpstream, project: str, version: str) -> str:
    files = upstream.info()["pypi"][project][version]
    return next(f["path"] for f in files if f["filename"].endswith(".whl"))


def test_serves_and_caches_over_real_http(server: str, upstream: FakeUpstream) -> None:
    assert NOW
    with httpx.Client(base_url=server, timeout=10) as c:
        idx = c.get("/pypi/simple/alpha/", headers={"Accept": "application/vnd.pypi.simple.v1+json"})
        assert idx.status_code == 200
        path = _wheel_url(upstream, "alpha", "1.1.0")
        first = c.get(f"/pypi{path}")
        assert first.status_code == 200 and first.headers["x-slowshield-cache"] == "miss"
        expected = next(f["hashes"]["sha256"] for f in idx.json()["files"] if path.endswith(f["filename"]))
        assert hashlib.sha256(first.content).hexdigest() == expected
        time.sleep(0.3)  # let the cache commit land
        hit = c.get(f"/pypi{path}")
        assert hit.status_code == 200 and hit.headers["x-slowshield-cache"] == "hit"
        assert hit.content == first.content
        part = c.get(f"/pypi{path}", headers={"Range": "bytes=5-14"})
        assert part.status_code == 206 and part.content == first.content[5:15]
        ui = c.get("/")
        assert ui.status_code == 200 and "content-security-policy" in ui.headers


def test_tampered_small_download_gets_explicit_error(server: str, upstream: FakeUpstream) -> None:
    path = _wheel_url(upstream, "alpha", "1.0.0")
    upstream.control("tamper", path=path)
    with httpx.Client(base_url=server, timeout=10) as c:
        r = c.get(f"/pypi{path}")
    assert r.status_code == 502
    assert r.json()["error"] == "integrity_mismatch"
