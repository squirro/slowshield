# ruff: noqa: S603 - the e2e suite drives docker on purpose
"""Real container clients against the e2e stack, configured with the Setup page's snippets.

Each client runs in its own container on the stack's backend network and reaches SlowShield as
http://slowshield:8080. Checked for each: an old-enough image arrives (the fake images carry their version in a
label and a file), a tag whose every digest is too new is refused with SlowShield's message where the client
prints one, and nothing goes around SlowShield. Fallbacks to the real registries (BuildKit, Docker's classic store)
need the internet and are not tested here.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from slowshield.ui import snippets as S

if TYPE_CHECKING:
    from tests.e2e.conftest import Stack

pytestmark = pytest.mark.e2e

BASE = "http://slowshield:8080"
REGISTRIES = ("docker.io", "ghcr.io", "quay.io", "registry.k8s.io")
CRANE = (
    "gcr.io/go-containerregistry/crane:debug@sha256:e78770b31258a3846f878036d9c1f63fbe4c871f9f56990bf77fd95c013e3c1b"
)
SKOPEO = "quay.io/skopeo/stable:v1.22.3@sha256:966b7d73acc4478906280e4967cafd93f4a85273e9a97b41b2ea8f9bd55292a5"
PODMAN = "quay.io/podman/stable:v5.8.7@sha256:fb16645f30c295c7e45864f4de8bbe87513d4f31fea146ed782f876508ee6bb9"
DOCKER = "docker:29.8.2-dind@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1"
BUILDKIT = "moby/buildkit:v0.33.1@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea"
AL2023 = (
    "public.ecr.aws/amazonlinux/amazonlinux:2023"
    "@sha256:12052e9b5d3fd85769abbdd863dd038e1890c9ace31d5fdbe1afa78eda97d061"
)
REFUSED = "slowshield: docker.io/library/brandnew:latest ("  # an hour old, nothing older: refused, not time-travelled


def snippet(tool: str, label: str) -> str:
    """The Setup page's snippet for `tool` whose label starts with `label`."""
    for t in S.oci_tools(BASE, REGISTRIES):
        if t.name == tool:
            return next(code for lbl, code in t.snippets if lbl.startswith(label)) + "\n"
    raise KeyError(tool)


def run(stack: Stack, image: str, files: dict[str, str], script: str, tmp_path: Path, *, privileged: bool = False,
        entrypoint: str = "/bin/sh") -> str:  # fmt: skip
    """`script` in `image` on the stack's backend network, with `files` under /c; stdout and stderr together."""
    # A new directory each time: Docker Desktop's file sharing can serve a rewritten file at its old size.
    work = Path(tempfile.mkdtemp(dir=tmp_path))
    for name, text in {**files, "run.sh": script}.items():
        (work / name).write_text(text)
    cmd = ["docker", "run", "--rm", "--network", f"{stack.project}_backend", "-v", f"{work}:/c:ro",
           "--entrypoint", entrypoint]  # fmt: skip
    if privileged:
        cmd.append("--privileged")
    out = subprocess.run([*cmd, image, "/c/run.sh"], capture_output=True, text=True, timeout=600, check=False)
    return out.stdout + out.stderr


@pytest.fixture(scope="module")
def versions(stack: Stack) -> dict[str, str]:
    """Index digests of the images the tests expect: node-exporter:latest travels back to 1.8.1 (10 days old)."""
    oci = stack.fake_info()["oci"]
    return {"node-exporter": oci["quay.io/prometheus/node-exporter"]["latest"][1][0]}


def test_crane_and_skopeo_take_slowshield_in_the_image_name(stack: Stack, tmp_path: Path, versions: dict) -> None:
    out = run(stack, CRANE, {}, """
crane digest --insecure slowshield:8080/quay.io/prometheus/node-exporter:latest
crane digest --insecure slowshield:8080/docker.io/library/brandnew:latest
""", tmp_path, entrypoint="/busybox/sh")  # fmt: skip
    assert versions["node-exporter"] in out
    assert "DENIED: " + REFUSED in out and "is too new" in out
    out = run(stack, SKOPEO, {}, """
skopeo inspect --tls-verify=false --format 'version={{.Labels.version}}' docker://slowshield:8080/registry.k8s.io/pause:3.10
skopeo inspect --tls-verify=false docker://slowshield:8080/registry.k8s.io/pause:3.11
""", tmp_path)  # fmt: skip
    assert "version=3.10" in out
    assert "denied: slowshield: registry.k8s.io/pause:3.11 (" in out


def test_containerd_asks_only_slowshield(stack: Stack, tmp_path: Path) -> None:
    out = run(stack, AL2023, {"default.toml": snippet("containerd", "/etc/containerd/certs.d/_default/")}, """
dnf install -y -q containerd >/dev/null 2>&1 || { echo "dnf failed"; exit 1; }
mkdir -p /etc/containerd/certs.d/_default && cp /c/default.toml /etc/containerd/certs.d/_default/hosts.toml
(containerd >/tmp/containerd.log 2>&1 &)
for i in $(seq 30); do ctr version >/dev/null 2>&1 && break; sleep 1; done
ctr images pull --hosts-dir /etc/containerd/certs.d quay.io/prometheus/node-exporter:latest >/dev/null && echo pulled
ctr images ls -q
ctr content fetch --hosts-dir /etc/containerd/certs.d docker.io/library/brandnew:latest 2>&1 | tail -1
ctr images tag quay.io/prometheus/node-exporter:latest docker.io/x/y:1 >/dev/null
ctr images push --hosts-dir /etc/containerd/certs.d docker.io/x/y:1 2>&1 | tail -1
""", tmp_path, privileged=True)  # fmt: skip
    assert "pulled" in out and "quay.io/prometheus/node-exporter:latest" in out
    # containerd 2.2 shows the status line only; it must not have tried registry-1.docker.io next.
    assert "slowshield:8080/v2/library/brandnew/manifests/latest?ns=docker.io: 403 Forbidden" in out
    assert "registry-1.docker.io" not in out
    assert "no push hosts" in out  # pull-only: a registry you push to needs its own hosts.toml


def test_docker_on_the_containerd_store(stack: Stack, tmp_path: Path) -> None:
    out = run(stack, DOCKER, {"default.toml": snippet("Docker", "/etc/docker/certs.d/_default/")}, """
mkdir -p /etc/docker/certs.d/_default /w && cp /c/default.toml /etc/docker/certs.d/_default/hosts.toml
(dockerd-entrypoint.sh dockerd >/tmp/dockerd.log 2>&1 &)
for i in $(seq 60); do docker info >/dev/null 2>&1 && break; sleep 1; done
docker info --format '{{.DriverStatus}}'
docker pull -q quay.io/prometheus/node-exporter:latest >/dev/null
echo "version=$(docker image inspect -f '{{index .Config.Labels "version"}}' quay.io/prometheus/node-exporter:latest)"
docker pull docker.io/library/brandnew:latest 2>&1 | tail -1
printf 'FROM docker.io/library/brandnew:latest\\n' > /w/Dockerfile
docker build -q /w 2>&1 | grep -i denied
""", tmp_path, privileged=True)  # fmt: skip
    assert "io.containerd.snapshotter.v1" in out
    assert "version=1.8.1" in out
    assert "Error response from daemon: error from registry: " + REFUSED in out
    assert "denied: " + REFUSED in out  # docker build: the same file covers BuildKit inside Docker


def test_podman_with_the_drop_in(stack: Stack, tmp_path: Path) -> None:
    out = run(stack, PODMAN, {"50-slowshield.conf": snippet("Podman", "/etc/containers/")}, """
cp /c/50-slowshield.conf /etc/containers/registries.conf.d/
podman pull -q nginx:1.27.0 >/dev/null
podman pull -q quay.io/prometheus/node-exporter:latest >/dev/null
podman image ls --format '{{.Repository}}:{{.Tag}} version={{.Labels.version}}'
podman pull docker.io/library/brandnew:latest 2>&1 | tail -1
""", tmp_path, privileged=True)  # fmt: skip
    assert "docker.io/library/nginx:1.27.0 version=1.27.0" in out  # short name, through docker.io's prefix
    assert "quay.io/prometheus/node-exporter:latest version=1.8.1" in out
    assert "denied: " + REFUSED in out


def test_buildkit_with_mirrors(stack: Stack, tmp_path: Path) -> None:
    out = run(stack, BUILDKIT, {"buildkitd.toml": snippet("BuildKit", "buildkitd.toml")}, """
mkdir -p /w
(buildkitd --config /c/buildkitd.toml >/tmp/buildkitd.log 2>&1 &)
for i in $(seq 30); do buildctl debug workers >/dev/null 2>&1 && break; sleep 1; done
build() {
  printf 'FROM %s\\n' "$1" > /w/Dockerfile
  buildctl build --frontend dockerfile.v0 --local context=/w --local dockerfile=/w --output type=local,dest=/w/out 2>&1
}
build quay.io/prometheus/node-exporter:latest >/dev/null && cat /w/out/etc/prometheus-node-exporter-release
build docker.io/library/brandnew:latest | grep -i denied
""", tmp_path, privileged=True)  # fmt: skip
    assert "1.8.1 " in out
    assert "denied: " + REFUSED in out
