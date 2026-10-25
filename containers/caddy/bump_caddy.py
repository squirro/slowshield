"""Compute (and optionally apply) the pinned Caddy and Go versions for containers/caddy.

    uv run python containers/caddy/bump_caddy.py                       # newest releases older than 7 days
    uv run python containers/caddy/bump_caddy.py 2.11.7 --go 1.26.10 --write

Caddy is built from source (containers/caddy/build) until a Caddy release carries Go's October 2026
HTTP/2 fixes (Go 1.26.9, golang.org/x/net v0.60.0); then the image goes back to the official,
cosign-signed release binary (see git history for the previous version of this script).

--write sets the Caddy module version in build/go.mod (`go get` + `go mod tidy`, run in the Dockerfile's
own AL2023 + Go stage, so modules are checked against Go's checksum database), and rewrites the
CADDY_VERSION, GO_VERSION and GO_SHA256_* ARG lines in the Dockerfile. The Go version defaults to the
newest patch release of the pinned minor line; the SHA-256 sums come from go.dev/dl.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO = "caddyserver/caddy"
MODULE = "github.com/caddyserver/caddy/v2"
HERE = Path(__file__).parent
ROOT = HERE.parents[1]
DOCKERFILE = HERE / "Dockerfile"
BUILD = HERE / "build"
ARCHES = ("amd64", "arm64")
GO_IMAGE = "slowshield-caddy-go:bump"


def _get(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL {url!r}")
    req = urllib.request.Request(  # noqa: S310 - https enforced above
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": "slowshield-bump"}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed https URLs
        return resp.read()


def pick_version(min_age_days: float) -> tuple[str, datetime]:
    releases = json.loads(_get(f"https://api.github.com/repos/{REPO}/releases?per_page=30"))
    cutoff = datetime.now(UTC) - timedelta(days=min_age_days)
    for rel in releases:
        if rel["prerelease"] or rel["draft"]:
            continue
        published = datetime.fromisoformat(rel["published_at"])
        if published <= cutoff:
            return rel["tag_name"].removeprefix("v"), published
    sys.exit(f"no stable release older than {min_age_days} days")


def _go_released(version: str) -> datetime:
    """When go.dev published a toolchain (its golang.org/toolchain module on the Go module proxy)."""
    info = json.loads(_get(f"https://proxy.golang.org/golang.org/toolchain/@v/v0.0.1-go{version}.linux-amd64.info"))
    return datetime.fromisoformat(info["Time"])


def pick_go(version: str | None, current: str, min_age_days: float) -> tuple[str, dict[str, str], datetime]:
    """The Go version (given, or the newest patch of `current`'s minor line past the age limit, at least `current`)."""
    releases = json.loads(_get("https://go.dev/dl/?mode=json&include=all"))
    if version is None:
        minor = ".".join(current.split(".")[:2])
        cutoff = datetime.now(UTC) - timedelta(days=min_age_days)
        for rel in releases:  # newest first
            v = rel["version"].removeprefix("go")
            # Never older than the pinned one, which may have been taken early as a security exception.
            if v == current or (
                rel["stable"] and (v == minor or v.startswith(f"{minor}.")) and _go_released(v) <= cutoff
            ):
                version = v
                break
        else:
            sys.exit(f"no Go {minor}.x release older than {min_age_days} days")
    rel = next((r for r in releases if r["version"] == f"go{version}"), None)
    if rel is None:
        sys.exit(f"go{version} is not listed on go.dev/dl")
    sums = {
        f["arch"]: f["sha256"]
        for f in rel["files"]
        if f["os"] == "linux" and f["kind"] == "archive" and f["filename"] == f"go{version}.linux-{f['arch']}.tar.gz"
    }
    if not set(ARCHES) <= set(sums):
        sys.exit(f"go{version}: linux archives for {ARCHES} not found on go.dev/dl")
    return version, {a: sums[a] for a in ARCHES}, _go_released(version)


def _arg(name: str) -> str:
    m = re.search(rf"^ARG {name}=(\S+)$", DOCKERFILE.read_text(), re.MULTILINE)
    if m is None:
        sys.exit(f"ARG {name} not found in {DOCKERFILE}")
    return m.group(1)


def write_dockerfile(caddy: str, go: str, go_sums: dict[str, str]) -> None:
    text = DOCKERFILE.read_text()
    text = re.sub(r"ARG CADDY_VERSION=\S+", f"ARG CADDY_VERSION={caddy}", text)
    text = re.sub(r"ARG GO_VERSION=\S+", f"ARG GO_VERSION={go}", text)
    for a in ARCHES:
        text = re.sub(rf"ARG GO_SHA256_{a.upper()}=\S+", f"ARG GO_SHA256_{a.upper()}={go_sums[a]}", text)
    DOCKERFILE.write_text(text)
    print(f"updated {DOCKERFILE}")


def write_go_mod(caddy: str, go: str) -> None:
    """`go get` the Caddy module and tidy, in the Dockerfile's `go` stage (AL2023 + the pinned toolchain). The `go`
    line follows the toolchain: scanners read it as the Go the binary is built with."""
    build = ["docker", "buildx", "build", "--load", "--quiet", "--target", "go", "-f", str(DOCKERFILE)]
    subprocess.run([*build, "-t", GO_IMAGE, str(ROOT)], check=True, stdout=subprocess.DEVNULL)  # noqa: S603
    tmp = "/tmp"  # noqa: S108 - inside a throwaway container
    # The image keeps GOPATH and GOMODCACHE under /go, which this user can't write (the checksum database cache is
    # under GOPATH).
    env = {"GOFLAGS": "-mod=mod", "GOPATH": f"{tmp}/go", "GOMODCACHE": f"{tmp}/go/pkg/mod"}
    env |= {"GOCACHE": f"{tmp}/go-build", "HOME": tmp}
    run = ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{BUILD}:/src", "-w", "/src"]
    run += [arg for k, v in env.items() for arg in ("-e", f"{k}={v}")]
    script = (
        f"go mod edit -go={go} && go get {MODULE}@v{caddy} && go mod tidy && go mod verify"
        f" && go list -m {MODULE} golang.org/x/net"
    )
    subprocess.run([*run, GO_IMAGE, "sh", "-euc", script], check=True)  # noqa: S603 - docker via PATH
    print(f"updated {BUILD / 'go.mod'} and go.sum")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("version", nargs="?", help="Caddy, e.g. 2.11.7 (default: newest release past --min-age-days)")
    ap.add_argument("--go", help="Go, e.g. 1.26.10 (default: newest patch of the pinned minor past --min-age-days)")
    ap.add_argument("--min-age-days", type=float, default=7.0)
    ap.add_argument("--write", action="store_true", help="rewrite the Dockerfile's ARG lines and build/go.mod")
    args = ap.parse_args()

    version = args.version
    if version is None:
        version, published = pick_version(args.min_age_days)
        print(f"selected Caddy v{version} (published {published:%Y-%m-%d})")
    go, go_sums, go_published = pick_go(args.go, _arg("GO_VERSION"), args.min_age_days)
    print(f"selected Go {go} (published {go_published:%Y-%m-%d})")

    lines = [f"ARG CADDY_VERSION={version}", f"ARG GO_VERSION={go}"]
    lines += [f"ARG GO_SHA256_{a.upper()}={go_sums[a]}" for a in ARCHES]
    print("\n".join(lines))
    if args.write:
        write_dockerfile(version, go, go_sums)
        write_go_mod(version, go)


if __name__ == "__main__":
    main()
