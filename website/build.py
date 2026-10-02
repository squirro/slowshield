"""Build the static site into an output directory and enforce the site's rules.

    python3 website/build.py --out dist/site

Stdlib only and Python 3.9-compatible (runs in the Amazon Linux 2023 builder with the system python3).
* copies website/src and the brand assets it needs,
* fingerprints CSS/JS (immutable caching) and rewrites references,
* fails on CSP violations (inline script/style, event-handler attributes, javascript: URLs),
  broken in-page anchors, missing local assets, external sub-resources, or an exceeded size budget.
Precompression (gzip/brotli/zstd) is done by the Dockerfile with the AL2023 CLIs.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "src"
BRAND = HERE.parent / "brand"
BRAND_FILES = {
    "mark.svg": "mark.svg",
    "mark-dark.svg": "mark-dark.svg",
    "favicon.svg": "favicon.svg",
    "png/favicon.ico": "favicon.ico",
    "png/icon-180.png": "apple-touch-icon.png",
    "png/social-preview.png": "social-preview.png",
}
FINGERPRINT = ("assets/site.css", "assets/site.js")
BUDGET_BYTES = 200_000  # html + css + js, uncompressed

_INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>", re.I)
_STYLE_TAG = re.compile(r"<style\b", re.I)
_STYLE_ATTR = re.compile(r"\sstyle\s*=", re.I)
_HANDLER_ATTR = re.compile(r"\son[a-z]+\s*=", re.I)
_JS_URL = re.compile(r"javascript:", re.I)
_ANCHOR = re.compile(r'href="#([^"]+)"')
_IDS = re.compile(r'\bid="([^"]+)"')
_LOCAL_REF = re.compile(r'(?:src|href)="(/[^"#?]*)"')
_EXTERNAL_SUBRESOURCE = re.compile(
    r'<(?:script|img|source|iframe|video|audio)\b[^>]*\bsrc="(?:https?:)?//'
    r'|<link\b(?=[^>]*\brel="(?:stylesheet|icon|preload|modulepreload|apple-touch-icon|manifest)")[^>]*\bhref="(?:https?:)?//',
    re.I,
)


def fail(errors: list[str]) -> None:
    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    sys.exit(1)


def build(out: Path) -> None:
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(SRC, out)
    assets = out / "assets"
    for src, dest in BRAND_FILES.items():
        path = BRAND / src
        if path.is_file():
            shutil.copyfile(path, assets / dest)

    renames: dict[str, str] = {}
    for rel in FINGERPRINT:
        path = out / rel
        digest = hashlib.sha256(path.read_bytes()).hexdigest()[:10]
        new = path.with_name(f"{path.stem}.{digest}{path.suffix}")
        path.rename(new)
        renames["/" + rel] = "/" + str(new.relative_to(out))

    errors: list[str] = []
    html_files = sorted(out.rglob("*.html"))
    for html_path in html_files:
        text = html_path.read_text(encoding="utf-8")
        for old, new in renames.items():
            text = text.replace(f'"{old}"', f'"{new}"')
        html_path.write_text(text, encoding="utf-8")
        name = html_path.relative_to(out)
        for pattern, what in (
            (_INLINE_SCRIPT, "inline <script>"),
            (_STYLE_TAG, "<style> element"),
            (_STYLE_ATTR, "style= attribute"),
            (_HANDLER_ATTR, "inline event handler"),
            (_JS_URL, "javascript: URL"),
        ):
            if pattern.search(text):
                errors.append(f"{name}: {what} violates the CSP")
        if _EXTERNAL_SUBRESOURCE.search(text):
            errors.append(f"{name}: external sub-resource (everything must be self-hosted)")
        ids = set(_IDS.findall(text))
        errors.extend(f"{name}: broken in-page link #{a}" for a in _ANCHOR.findall(text) if a not in ids)
        errors.extend(
            f"{name}: missing local file {ref}"
            for ref in _LOCAL_REF.findall(text)
            if ref not in ("/", "/404.html") and not ref.endswith("/") and not (out / ref.lstrip("/")).is_file()
        )

    css_files = list(assets.glob("site.*.css"))
    for css in css_files:
        refs = re.findall(r'url\("?(/[^")]+)"?\)', css.read_text(encoding="utf-8"))
        errors.extend(f"{css.name}: missing {ref}" for ref in refs if not (out / ref.lstrip("/")).is_file())

    total = sum(p.stat().st_size for p in [*html_files, *css_files, *assets.glob("site.*.js")])
    if total > BUDGET_BYTES:
        errors.append(f"size budget exceeded: {total} > {BUDGET_BYTES} bytes")
    if errors:
        fail(errors)
    print(f"built {out} ({total} bytes html+css+js, {len(html_files)} pages)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=HERE.parent / "dist" / "site")
    build(parser.parse_args().out)


if __name__ == "__main__":
    main()
