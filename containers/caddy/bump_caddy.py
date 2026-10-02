"""Compute (and optionally apply) the pinned Caddy version + SHA-512 sums for containers/caddy/Dockerfile.

    uv run python containers/caddy/bump_caddy.py                # newest release older than 7 days
    uv run python containers/caddy/bump_caddy.py 2.11.6 --write # a specific version, rewriting the Dockerfile

The release's checksums file is verified with cosign (keyless, GitHub Actions identity of
caddyserver/caddy) when the `cosign` binary is available; without it the script refuses to --write
unless --no-verify is given explicitly.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO = "caddyserver/caddy"
DOCKERFILE = Path(__file__).with_name("Dockerfile")
ARCHES = ("amd64", "arm64")


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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("version", nargs="?", help="e.g. 2.11.6 (default: newest release past --min-age-days)")
    ap.add_argument("--min-age-days", type=float, default=7.0)
    ap.add_argument("--write", action="store_true", help="rewrite the ARG lines in the Dockerfile")
    ap.add_argument("--no-verify", action="store_true", help="skip cosign verification (not recommended)")
    args = ap.parse_args()

    version = args.version
    if version is None:
        version, published = pick_version(args.min_age_days)
        print(f"selected v{version} (published {published:%Y-%m-%d})")
    base = f"https://github.com/{REPO}/releases/download/v{version}"
    name = f"caddy_{version}_checksums.txt"
    checksums = _get(f"{base}/{name}")

    verified = False
    cosign = shutil.which("cosign")
    if cosign and not args.no_verify:
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            (t / name).write_bytes(checksums)
            (t / f"{name}.sig").write_bytes(_get(f"{base}/{name}.sig"))
            (t / f"{name}.pem").write_bytes(_get(f"{base}/{name}.pem"))
            subprocess.run(  # noqa: S603 - fixed argv, cosign resolved via PATH on purpose
                [
                    cosign,
                    "verify-blob",
                    "--certificate",
                    str(t / f"{name}.pem"),
                    "--signature",
                    str(t / f"{name}.sig"),
                    "--certificate-identity-regexp",
                    rf"^https://github\.com/{REPO}/\.github/workflows/release\.yml@refs/tags/v",
                    "--certificate-oidc-issuer",
                    "https://token.actions.githubusercontent.com",
                    str(t / name),
                ],
                check=True,
            )
            verified = True
    elif not args.no_verify and args.write:
        sys.exit("cosign not found: install it (or pass --no-verify knowingly) before --write")

    sums: dict[str, str] = {}
    for line in checksums.decode().splitlines():
        digest, _, fname = line.partition("  ")
        for arch in ARCHES:
            if fname.strip() == f"caddy_{version}_linux_{arch}.tar.gz":
                sums[arch] = digest.strip()
    if set(sums) != set(ARCHES):
        sys.exit(f"checksums for {ARCHES} not found in {name}")

    lines = [f"ARG CADDY_VERSION={version}"] + [f"ARG CADDY_SHA512_{a.upper()}={sums[a]}" for a in ARCHES]
    print("\n".join(lines))
    print(f"# signature {'verified with cosign' if verified else 'NOT verified'}")
    if args.write:
        text = DOCKERFILE.read_text()
        text = re.sub(r"ARG CADDY_VERSION=\S+", f"ARG CADDY_VERSION={version}", text)
        for a in ARCHES:
            text = re.sub(rf"ARG CADDY_SHA512_{a.upper()}=\S+", f"ARG CADDY_SHA512_{a.upper()}={sums[a]}", text)
        DOCKERFILE.write_text(text)
        print(f"updated {DOCKERFILE}")


if __name__ == "__main__":
    main()
