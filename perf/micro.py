"""In-process micro benchmarks of the hot paths (no network, no containers).

Run on two checkouts on the same machine and pass the first result via `--compare` to get a
relative comparison; absolute numbers across machines are meaningless.
"""

from __future__ import annotations

import json
import statistics
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import msgspec

from slowshield import versions
from slowshield.blocklist import BlockEntry, PackageBlocks
from slowshield.ecosystems.npm import packument as P
from slowshield.ecosystems.pypi.project import parse_project
from slowshield.ecosystems.pypi.render import render_html, render_json
from slowshield.policy import Candidate, evaluate
from slowshield.web import accept_prefers

NOW = 1_790_000_000.0
DAY = 86400.0


def _npm_doc(n: int) -> bytes:
    vers, times = {}, {"created": "2015-01-01T00:00:00.000Z", "modified": "2026-09-01T00:00:00.000Z"}
    for i in range(n):
        v = f"{i // 100}.{(i // 10) % 10}.{i % 10}"
        vers[v] = {
            "name": "huge",
            "version": v,
            "description": "x" * 200,
            "dependencies": {f"dep{j}": "^1.0.0" for j in range(8)},
            "scripts": {"test": "node test.js"},
            "dist": {
                "tarball": f"https://registry.npmjs.org/huge/-/huge-{v}.tgz",
                "integrity": "sha512-" + "A" * 86 + "==",
                "shasum": "0" * 40,
                "signatures": [{"keyid": "SHA256:x", "sig": "y" * 96}],
            },
        }
        times[v] = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(NOW - (n - i) * DAY))
    return msgspec.json.encode(
        {
            "_id": "huge",
            "name": "huge",
            "dist-tags": {"latest": v},
            "versions": vers,
            "time": times,
            "readme": "r" * 50_000,
        }
    )


def _pypi_doc(n_versions: int, files_per: int = 5) -> bytes:
    files, vers = [], []
    for i in range(n_versions):
        v = f"{i // 50}.{i % 50}.0"
        vers.append(v)
        for j in range(files_per):
            fname = f"proj-{v}-cp3{10 + j}-cp3{10 + j}-manylinux_2_17_x86_64.whl"
            h = f"{(i * files_per + j):064x}"
            files.append(
                {
                    "filename": fname,
                    "url": f"https://files.pythonhosted.org/packages/{h[:2]}/{h[2:4]}/{h[4:]}/{fname}",
                    "hashes": {"sha256": h},
                    "requires-python": ">=3.10",
                    "size": 1234567,
                    "upload-time": time.strftime(
                        "%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime(NOW - (n_versions - i) * DAY)
                    ),
                    "yanked": False,
                    "core-metadata": {"sha256": h},
                }
            )
    return msgspec.json.encode({"meta": {"api-version": "1.4"}, "name": "proj", "versions": vers, "files": files})


def bench(fn: Callable[[], Any], *, repeat: int, min_time: float = 0.2) -> dict[str, float]:
    loops = 1
    while True:
        t = time.perf_counter()
        for _ in range(loops):
            fn()
        if time.perf_counter() - t >= min_time / 5 or loops > 1 << 20:
            break
        loops *= 2
    samples = []
    for _ in range(repeat):
        t = time.perf_counter()
        for _ in range(loops):
            fn()
        samples.append((time.perf_counter() - t) / loops)
    return {"min_us": min(samples) * 1e6, "median_us": statistics.median(samples) * 1e6, "loops": loops}


def suite() -> dict[str, Callable[[], Any]]:
    npm_raw = _npm_doc(5000)
    bases = ["https://registry.npmjs.org"]
    doc = P.parse(npm_raw, name="huge", etag=None, upstream_bases=bases)
    kept = list(doc.versions)[:-20]
    tags = P.recompute_tags(doc.dist_tags, kept)
    py_raw = _pypi_doc(500)
    project = parse_project(py_raw, base_url="https://pypi.org/simple/proj/", name="proj", etag=None)
    blocks = PackageBlocks(
        "npm",
        [BlockEntry("npm", "x", f"1.{i}.0", None, "osv", f"MAL-{i}", None, None) for i in range(50)]
        + [BlockEntry("npm", "x", None, ">= 2.0.0, < 2.5.0", "github", "GHSA-1", None, None)],
    )
    cands = [Candidate(f, f.version, f.upload_time) for f in project.files]

    return {
        "npm_parse_5k": lambda: P.parse(npm_raw, name="huge", etag=None, upstream_bases=bases),
        "npm_render_full_5k": lambda: P.render_full(
            doc, kept, tags, upstream_bases=bases, public_base="https://proxy/npm"
        ),
        "npm_render_corgi_5k": lambda: P.render_abbreviated(
            doc, kept, tags, upstream_bases=bases, public_base="https://proxy/npm"
        ),
        "npm_tags_5k": lambda: P.recompute_tags(doc.dist_tags, kept),
        "pypi_parse_2500_files": lambda: parse_project(
            py_raw, base_url="https://pypi.org/simple/proj/", name="proj", etag=None
        ),
        "pypi_policy_2500_files": lambda: evaluate(
            cands, now=NOW, delay_for=lambda _v: 7.0, is_blocked=lambda _v: False, fail_open=True
        ),
        "pypi_render_json": lambda: render_json(project, project.files, project.versions),
        "pypi_render_html": lambda: render_html(project, project.files),
        "blocklist_match": lambda: [blocks.match("npm", f"2.{i}.0") for i in range(10)],
        "semver_sort_1k": lambda: sorted(
            (f"{i % 7}.{i % 13}.{i}" for i in range(1000)), key=lambda v: versions.sort_key("npm", v)
        ),
        "accept_negotiation": lambda: accept_prefers(
            "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.2, text/html;q=0.01",
            ("text/html", "application/vnd.pypi.simple.v1+html", "application/vnd.pypi.simple.v1+json"),
            "text/html",
        ),
    }


def main(*, out: Path, compare: Path | None, repeat: int) -> int:
    results = {name: bench(fn, repeat=repeat) for name, fn in suite().items()}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    prev = json.loads(compare.read_text()) if compare and compare.exists() else {}
    print(f"{'benchmark':28} {'median µs':>12} {'min µs':>12} {'vs prev':>9}")
    for name, r in results.items():
        delta = ""
        if name in prev and prev[name]["min_us"]:
            delta = f"{(r['min_us'] - prev[name]['min_us']) / prev[name]['min_us'] * 100:+.1f}%"
        print(f"{name:28} {r['median_us']:12.1f} {r['min_us']:12.1f} {delta:>9}")
    return 0
