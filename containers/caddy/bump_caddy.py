"""Compute (and optionally apply) the pinned Caddy and Go versions for containers/caddy.

    uv run python containers/caddy/bump_caddy.py                       # newest releases older than 7 days
    uv run python containers/caddy/bump_caddy.py 2.11.7 --go 1.26.10 --write

Caddy is built from source (containers/caddy/build) until a Caddy release carries Go's October 2026
HTTP/2 fixes (Go 1.26.9, golang.org/x/net v0.60.0); then the image goes back to the official,
cosign-signed release binary (see git history for the previous version of this script).

--write first checks the Caddy source against Caddy's own signed release: the release's checksums file is
verified with cosign (keyless, the GitHub Actions identity of caddyserver/caddy's release workflow at the
tag), the release's source tarball (caddy_<v>_src.tar.gz) against that file, and every file of the
github.com/caddyserver/caddy/v2 module (as `go mod download` fetches it) byte for byte against the
tarball. Without the `cosign` binary it refuses to --write unless --no-verify is given explicitly.

It then sets the Caddy module version in build/go.mod (`go get` + `go mod tidy`, run in the Dockerfile's
own AL2023 + Go stage, so modules are checked against Go's checksum database), and rewrites the
CADDY_VERSION, GO_VERSION and GO_SHA256_* ARG lines in the Dockerfile. The Go version defaults to the
newest patch release of the pinned minor line; the SHA-256 sums come from go.dev/dl.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
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
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
# Who signs Caddy's releases: the release workflow of caddyserver/caddy, run by GitHub Actions for the tag.
SIGNER = f"https://github.com/{REPO}/.github/workflows/release.yml@refs/tags/v{{version}}"
ISSUER = "https://token.actions.githubusercontent.com"
TMP = "/tmp"  # noqa: S108 - inside a throwaway container


def _get(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL {url!r}")
    req = urllib.request.Request(  # noqa: S310 - https enforced above
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": "slowshield-bump"}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed https URLs
        return resp.read()


def _checked(version: str, what: str) -> str:
    """A plain x.y.z version, or exit: versions end up in URLs, the Dockerfile and the Go stage's commands."""
    if not VERSION.fullmatch(version):
        sys.exit(f"{what} version {version!r} is not of the form x.y.z")
    return version


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
            if VERSION.fullmatch(v) and (
                v == current or (rel["stable"] and v.startswith(f"{minor}.") and _go_released(v) <= cutoff)
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


def _go_image() -> str:
    """The Dockerfile's `go` stage (AL2023 + the pinned toolchain), built for the Go commands below."""
    build = ["docker", "buildx", "build", "--load", "--quiet", "--target", "go", "-f", str(DOCKERFILE)]
    subprocess.run([*build, "-t", GO_IMAGE, str(ROOT)], check=True, stdout=subprocess.DEVNULL)  # noqa: S603
    return GO_IMAGE


def _go_run(mounts: dict[Path, str], workdir: str, env: dict[str, str], script: str, *, capture: bool = False) -> str:
    """Run a fixed `sh -euc` script in the Go stage as the calling user; values come in as environment variables.
    The image keeps GOPATH and GOMODCACHE under /go, which this user can't write (the checksum database cache is
    under GOPATH)."""
    env = {"GOPATH": f"{TMP}/go", "GOMODCACHE": f"{TMP}/go/pkg/mod", "GOCACHE": f"{TMP}/go-build", "HOME": TMP} | env
    run = ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}", "-w", workdir]
    run += [arg for host, path in mounts.items() for arg in ("-v", f"{host}:{path}")]
    run += [arg for k, v in env.items() for arg in ("-e", f"{k}={v}")]
    stdout = subprocess.PIPE if capture else None
    done = subprocess.run([*run, _go_image(), "sh", "-euc", script], check=True, text=True, stdout=stdout)  # noqa: S603
    return done.stdout or ""


def _cosign_verify(cosign: str, version: str, t: Path, name: str) -> str:
    """Keyless cosign check of a release file, pinned to Caddy's release workflow at the tag; returns the identity."""
    identity = SIGNER.format(version=version)
    subprocess.run(  # noqa: S603 - fixed argv, cosign resolved via PATH on purpose
        [
            cosign,
            "verify-blob",
            "--certificate",
            str(t / f"{name}.pem"),
            "--signature",
            str(t / f"{name}.sig"),
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            ISSUER,
            str(t / name),
        ],
        check=True,
    )
    return identity


def _module_files(root: Path) -> dict[str, Path]:
    return {p.relative_to(root).as_posix(): p for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()}


def check_release_source(version: str, cosign: str | None) -> None:
    """The Caddy module that `go get` would take is the source Caddy signed for this release.

    Caddy's release ships `caddy_<v>_src.tar.gz` (the repository at the tag plus vendor/), listed with its SHA-512 in
    `caddy_<v>_checksums.txt`, which is signed keylessly by the release workflow. (The release's buildable-artifact
    tarball holds only cmd/caddy's main and the vendored packages it builds, no tests: not the whole module.) Every
    file of the module zip, as proxy.golang.org serves it and the checksum database vouches for it, must be in the
    source tarball at the same path with the same bytes. The tarball is extracted as data and nothing in it is run.
    """
    base = f"https://github.com/{REPO}/releases/download/v{version}"
    sums_name, src_name = f"caddy_{version}_checksums.txt", f"caddy_{version}_src.tar.gz"
    with tempfile.TemporaryDirectory(prefix="bump-caddy-") as tmp:
        release, src, gopath = (Path(tempfile.mkdtemp(prefix=p, dir=tmp)) for p in ("release-", "src-", "gopath-"))
        (release / sums_name).write_bytes(_get(f"{base}/{sums_name}"))
        if cosign is None:
            print(f"# signature of {sums_name} NOT verified (--no-verify)")
        else:
            (release / f"{sums_name}.sig").write_bytes(_get(f"{base}/{sums_name}.sig"))
            (release / f"{sums_name}.pem").write_bytes(_get(f"{base}/{sums_name}.pem"))
            identity = _cosign_verify(cosign, version, release, sums_name)
            print(f"# signature of {sums_name} verified with cosign: {identity} (issuer {ISSUER})")

        sums: dict[str, str] = {}
        for line in (release / sums_name).read_text().splitlines():
            digest, _, fname = line.partition("  ")
            sums[fname.strip()] = digest.strip()
        want = sums.get(src_name, "")
        if not re.fullmatch(r"[0-9a-f]{128}", want):
            sys.exit(f"no SHA-512 for {src_name} in {sums_name}")
        (release / src_name).write_bytes(_get(f"{base}/{src_name}"))
        got = hashlib.sha512((release / src_name).read_bytes()).hexdigest()
        if got != want:
            sys.exit(f"{src_name}: SHA-512 {got} does not match {sums_name} ({want})")
        print(f"# {src_name}: SHA-512 matches {sums_name}")
        with tarfile.open(release / src_name) as tar:
            tar.extractall(src, filter="data")

        out = _go_run(
            {gopath: f"{TMP}/go"},
            TMP,
            {"GOFLAGS": "-mod=mod", "CADDY_MODULE": f"{MODULE}@v{version}"},
            'go mod download -json "$CADDY_MODULE"',
            capture=True,
        )
        info = json.loads(out)
        module = gopath / Path(info["Dir"]).relative_to(f"{TMP}/go")
        files, released = _module_files(module), _module_files(src)
        missing = [rel for rel in files if rel not in released]
        differ = [rel for rel in files if rel in released and files[rel].read_bytes() != released[rel].read_bytes()]
        for rel in missing:
            print(f"  missing from {src_name}: {rel}", file=sys.stderr)
        for rel in differ:
            print(f"  differs from {src_name}: {rel}", file=sys.stderr)
        if missing or differ or not files:
            sys.exit(f"{MODULE}@v{version} is not the source Caddy signed for v{version}")
        # What the source tarball holds beyond the module, by top-level directory (vendor/ for one).
        extra = collections.Counter(re.sub(r"/.*", "/", rel) for rel in released.keys() - files.keys())
        kinds = ", ".join(f"{top} {n}" for top, n in extra.most_common())
        print(f"# {MODULE}@v{version} ({info['Sum']}): all {len(files)} files identical to {src_name}")
        print(f"# {src_name} has {extra.total()} more files, not in the module: {kinds or 'none'}")


def write_go_mod(caddy: str, go: str) -> None:
    """`go get` the Caddy module and tidy, in the Dockerfile's `go` stage (AL2023 + the pinned toolchain). The `go`
    line follows the toolchain: scanners read it as the Go the binary is built with."""
    script = (
        'go mod edit -go="$GO_VERSION" && go get "$CADDY_MODULE" && go mod tidy && go mod verify'
        ' && go list -m "${CADDY_MODULE%@*}" golang.org/x/net'
    )
    env = {"GOFLAGS": "-mod=mod", "GO_VERSION": go, "CADDY_MODULE": f"{MODULE}@v{caddy}"}
    _go_run({BUILD: "/src"}, "/src", env, script)
    print(f"updated {BUILD / 'go.mod'} and go.sum")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("version", nargs="?", help="Caddy, e.g. 2.11.7 (default: newest release past --min-age-days)")
    ap.add_argument("--go", help="Go, e.g. 1.26.10 (default: newest patch of the pinned minor past --min-age-days)")
    ap.add_argument("--min-age-days", type=float, default=7.0)
    ap.add_argument("--write", action="store_true", help="rewrite the Dockerfile's ARG lines and build/go.mod")
    ap.add_argument("--no-verify", action="store_true", help="skip cosign verification (not recommended)")
    args = ap.parse_args()

    version = args.version
    if version is None:
        version, published = pick_version(args.min_age_days)
        print(f"selected Caddy v{version} (published {published:%Y-%m-%d})")
    version = _checked(version, "Caddy")
    go_arg = None if args.go is None else _checked(args.go, "Go")
    go, go_sums, go_published = pick_go(go_arg, _arg("GO_VERSION"), args.min_age_days)
    go = _checked(go, "Go")
    print(f"selected Go {go} (published {go_published:%Y-%m-%d})")

    lines = [f"ARG CADDY_VERSION={version}", f"ARG GO_VERSION={go}"]
    lines += [f"ARG GO_SHA256_{a.upper()}={go_sums[a]}" for a in ARCHES]
    print("\n".join(lines))
    if args.write:
        cosign = None if args.no_verify else shutil.which("cosign")
        if cosign is None and not args.no_verify:
            sys.exit("cosign not found: install it (or pass --no-verify knowingly) before --write")
        check_release_source(version, cosign)
        write_dockerfile(version, go, go_sums)
        write_go_mod(version, go)


if __name__ == "__main__":
    main()
