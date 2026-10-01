"""Vendor a pinned htmx build: fetch the npm tarball, verify its registry integrity, extract the min.js.

    uv run python scripts/vendor_htmx.py 4.0.0

Writes src/slowshield/ui/static/vendor/htmx.min.js and prints the SRI hash for base template.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import sys
import tarfile
import urllib.request
from pathlib import Path

REGISTRY = "https://registry.npmjs.org/htmx.org"
DEST = Path(__file__).resolve().parents[1] / "src/slowshield/ui/static/vendor"


def main(version: str) -> None:
    with urllib.request.urlopen(f"{REGISTRY}/{version}", timeout=30) as r:  # noqa: S310 - fixed https URL
        meta = json.load(r)
    tarball_url, integrity = meta["dist"]["tarball"], meta["dist"]["integrity"]
    algo, _, expected = integrity.partition("-")
    if algo != "sha512" or not tarball_url.startswith("https://registry.npmjs.org/"):
        sys.exit(f"unexpected dist metadata: {integrity} {tarball_url}")
    with urllib.request.urlopen(tarball_url, timeout=60) as r:  # noqa: S310
        data = r.read()
    got = base64.b64encode(hashlib.sha512(data).digest()).decode()
    if got != expected:
        sys.exit("tarball integrity mismatch - refusing to vendor")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        member = tf.getmember("package/dist/htmx.min.js")
        fh = tf.extractfile(member)
        assert fh is not None
        js = fh.read()
        try:
            lic = tf.extractfile(tf.getmember("package/LICENSE"))
            license_text = lic.read() if lic else b""
        except KeyError:
            license_text = b""
    DEST.mkdir(parents=True, exist_ok=True)
    (DEST / "htmx.min.js").write_bytes(js)
    if license_text:
        (DEST / "htmx.LICENSE").write_bytes(license_text)
    sri = "sha384-" + base64.b64encode(hashlib.sha384(js).digest()).decode()
    (DEST / "htmx.version").write_text(f"{version}\n{sri}\n")
    print(f"htmx {version} vendored ({len(js)} bytes) integrity={sri}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "4.0.0")
