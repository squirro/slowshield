"""End-to-end stack: real images (SlowShield, Caddy, fakeupstream) brought up with Docker Compose.

Runs only with E2E=1. Image references come from SLOWSHIELD_IMAGE, SLOWSHIELD_CADDY_IMAGE and
FAKEUPSTREAM_IMAGE (CI builds them as slowshield:ci, slowshield-caddy:ci, slowshield-fakeupstream:ci).
Every session uses its own compose project and random host ports and removes everything afterwards.
"""

# ruff: noqa: S603 - the e2e suite drives docker/curl/uv/npm on purpose

from __future__ import annotations

import json
import os
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = ROOT / "deploy" / "docker"
HERE = Path(__file__).resolve().parent


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class Stack:
    project: str
    env: dict[str, str]
    https_port: int
    http_port: int
    fake_port: int
    ca_file: Path

    @property
    def base(self) -> str:
        return f"https://localhost:{self.https_port}"

    @property
    def fake(self) -> str:
        return f"http://127.0.0.1:{self.fake_port}"

    def compose(self, *args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
        cmd = [
            "docker", "compose",
            "-f", str(COMPOSE_DIR / "compose.yaml"),
            "-f", str(COMPOSE_DIR / "compose.e2e.yaml"),
            "-p", self.project, *args,
        ]  # fmt: skip
        return subprocess.run(cmd, cwd=COMPOSE_DIR, env=self.env, check=check, capture_output=capture, text=True)

    def container_id(self, service: str) -> str:
        return self.compose("ps", "-q", service).stdout.strip()

    def ssl_context(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=str(self.ca_file))

    def get(
        self, path: str, *, headers: dict[str, str] | None = None, timeout: float = 30
    ) -> tuple[int, dict[str, str], bytes]:
        req = urllib.request.Request(self.base + path, headers=headers or {})
        try:
            with urllib.request.urlopen(req, context=self.ssl_context(), timeout=timeout) as r:
                return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
        except urllib.error.HTTPError as e:
            return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()

    def control(self, endpoint: str, **params: str) -> dict:
        qs = urllib.parse.urlencode(params)
        req = urllib.request.Request(f"{self.fake}/_control/{endpoint}?{qs}", method="POST", data=b"")
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())

    def fake_info(self) -> dict:
        with urllib.request.urlopen(f"{self.fake}/_control/info", timeout=10) as r:
            return json.loads(r.read())


def _wait(predicate, timeout: float, what: str) -> None:  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception as exc:
            last = exc
        time.sleep(1)
    raise TimeoutError(f"timed out waiting for {what}: {last}")


@pytest.fixture(scope="session")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    if os.environ.get("E2E") != "1":
        pytest.skip("end-to-end tests run only with E2E=1 (they need Docker and the built images)")
    if shutil.which("docker") is None:
        pytest.skip("docker is not available")
    work = tmp_path_factory.mktemp("e2e")
    env = {
        **os.environ,
        "SLOWSHIELD_IMAGE": os.environ.get("SLOWSHIELD_IMAGE", "slowshield:ci"),
        "SLOWSHIELD_CADDY_IMAGE": os.environ.get("SLOWSHIELD_CADDY_IMAGE", "slowshield-caddy:ci"),
        "FAKEUPSTREAM_IMAGE": os.environ.get("FAKEUPSTREAM_IMAGE", "slowshield-fakeupstream:ci"),
        "HTTP_PORT": str(_free_port()),
        "HTTPS_PORT": str(_free_port()),
        "FAKEUPSTREAM_PORT": str(_free_port()),
        "SLOWSHIELD_CONFIG_FILE": str(HERE / "config.e2e.toml"),
        "GITHUB_TOKEN_SECRET_FILE": str(HERE / "github_token"),
    }
    st = Stack(
        project=f"ss-e2e-{uuid.uuid4().hex[:8]}",
        env=env,
        https_port=int(env["HTTPS_PORT"]),
        http_port=int(env["HTTP_PORT"]),
        fake_port=int(env["FAKEUPSTREAM_PORT"]),
        ca_file=work / "root.crt",
    )
    try:
        st.compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "180")
        _wait(
            lambda: (
                st.compose(
                    "cp", "caddy:/data/caddy/pki/authorities/local/root.crt", str(st.ca_file), check=False
                ).returncode
                == 0
                and st.ca_file.stat().st_size > 0
            ),
            60,
            "Caddy's internal CA",
        )
        _wait(lambda: st.get("/readyz")[0] == 200, 60, "SlowShield behind Caddy")
        yield st
    finally:
        logs = st.compose("logs", "--no-color", "--tail", "200", check=False).stdout
        (work / "compose.log").write_text(logs or "")
        st.compose("down", "-v", "--remove-orphans", check=False)


@pytest.fixture(scope="session")
def feeds_synced(stack: Stack) -> Stack:
    """Wait until the first OSV/GitHub sync has blocked the fake registry's malware."""
    _wait(lambda: stack.get("/pypi/simple/malware-pkg/")[0] == 451, 120, "the blocklist to sync")
    return stack
