"""Build the static site into an output directory and enforce the site's rules.

    python3 website/build.py --out dist/site

Stdlib only, Python 3.9 or later.
* copies website/src and the brand assets it needs,
* fingerprints CSS/JS (immutable caching) and rewrites references,
* fails on CSP violations (inline script/style, event-handler attributes, javascript: URLs),
  broken in-page anchors, missing local assets, external sub-resources, or an exceeded size budget,
* adds website/_headers (the response headers on Cloudflare Workers static assets, which hosts the site)
  and fails if a required security header is missing, the CSP is weakened, a page has no Cache-Control
  rule, or a Cloudflare limit is exceeded. Cloudflare compresses at the edge, so nothing is precompressed.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import re
import shutil
import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "src"
BRAND = HERE.parent / "brand"
BRAND_FILES = {
    "favicon.svg": "favicon.svg",
    "png/favicon.ico": "favicon.ico",
    "png/icon-180.png": "apple-touch-icon.png",
    "png/social-preview.png": "social-preview.png",
    "fonts/SchibstedGrotesk-latin.woff2": "fonts/SchibstedGrotesk-latin.woff2",
}
# Everything the style guide offers for download, served under /assets/brand/.
BRAND_DOWNLOADS = (
    "mark.svg", "mark-dark.svg", "mark-mono.svg", "mark-white.svg", "favicon.svg", "favicon-32.svg", "app-icon.svg",
    "lockup-horizontal.svg", "lockup-horizontal-dark.svg", "lockup-stacked.svg", "lockup-stacked-dark.svg",
    "wordmark.svg", "wordmark-dark.svg", "social-preview.svg", "readme-banner.svg", "readme-banner-dark.svg",
    "tokens.css", "png/favicon.ico", "png/icon-32.png", "png/icon-180.png", "png/icon-192.png", "png/icon-512.png",
    "png/social-preview.png", "fonts/SchibstedGrotesk-VF.ttf", "fonts/OFL.txt",
)  # fmt: skip
TOKENS_MARKER = "/* @tokens */"
PALETTE_MARKER = "<!-- @palette -->"
SPRITE_MARKER = "<!-- @sprite -->"
# Client snippets come from the same file as the product's Setup page, filled in for the laptop quick start.
SNIPPETS = HERE.parent / "src" / "slowshield" / "ui" / "snippets.toml"
SNIPPET_MARKER = re.compile(r"<!-- @snippet ([a-z]+)\.([a-z-]+) -->")
SITE_URLS = {
    "pypi": "http://localhost:8080/pypi/simple/",
    "npm": "http://localhost:8080/npm/",
    "go": "http://localhost:8080/go",
    "py_pkg": "requests",
    "age_days": "3",  # the package managers' own release age (snippets.CLIENT_AGE_DAYS)
}
FINGERPRINT = ("assets/site.css", "assets/site.js")
BUDGET_BYTES = 200_000  # html + css + js, uncompressed
HEADERS = HERE / "_headers"
REQUIRED_HEADERS = (
    "content-security-policy", "strict-transport-security", "x-content-type-options", "referrer-policy",
    "permissions-policy", "cross-origin-opener-policy", "cross-origin-resource-policy", "x-frame-options",
)  # fmt: skip
CF_MAX_RULES, CF_MAX_LINE = 100, 2000  # _headers limits
CF_MAX_FILES, CF_MAX_FILE_BYTES = 20_000, 25 * 1024 * 1024  # per Worker version (Free plan), per file

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


def load_snippets() -> dict[str, str]:
    """`shell.<id>` and `try.<name>` from snippets.toml, with the laptop URLs filled in."""
    data = tomllib.loads(SNIPPETS.read_text(encoding="utf-8"))
    raw = {f"shell.{s['id']}": s["code"] for s in data["shell"]} | {f"try.{k}": v for k, v in data["try"].items()}
    out = {}
    for key, template in raw.items():
        code = template
        for name, value in SITE_URLS.items():
            code = code.replace("{" + name + "}", value)
        out[key] = code.strip("\n")
    return out


def snippet(snippets: dict[str, str], m: re.Match[str], page: str, errors: list[str]) -> str:
    key = f"{m.group(1)}.{m.group(2)}"
    if key not in snippets:
        errors.append(f"{page}: unknown snippet {key!r} (not in {SNIPPETS.name})")
        return m.group(0)
    return html.escape(snippets[key], quote=False)


def check_headers(out: Path, html_files: list[Path]) -> list[str]:
    """Copy website/_headers into the site and check it (the site's only source of response headers)."""
    errors: list[str] = []
    rules: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for n, line in enumerate(HEADERS.read_text(encoding="utf-8").splitlines(), 1):
        if len(line) > CF_MAX_LINE:
            errors.append(f"_headers:{n}: longer than {CF_MAX_LINE} characters")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            current = rules.setdefault(line.strip(), {})
        elif current is not None and ":" in line and not line.strip().startswith("!"):
            name, value = line.strip().split(":", 1)
            current[name.strip().lower()] = value.strip()
    if len(rules) > CF_MAX_RULES:
        errors.append(f"_headers: {len(rules)} rules > {CF_MAX_RULES}")
    site_wide = rules.get("/*", {})
    errors.extend(f"_headers: /* must set {name}" for name in REQUIRED_HEADERS if name not in site_wide)
    csp = site_wide.get("content-security-policy", "")
    if "'unsafe-" in csp or "script-src 'self'" not in csp or "default-src 'none'" not in csp:
        errors.append("_headers: the CSP must keep default-src 'none' and script-src 'self', without 'unsafe-*'")
    # Every page needs its own Cache-Control rule, or it silently falls back to max-age=0.
    for page in html_files:
        rel = page.relative_to(out).as_posix()
        url = "/" + rel[: -len("index.html")] if rel.endswith("index.html") else "/" + rel
        if rel != "404.html" and "cache-control" not in rules.get(url, {}):
            errors.append(f"_headers: no Cache-Control rule for page {url}")
    files = [p for p in out.rglob("*") if p.is_file()]
    if len(files) >= CF_MAX_FILES:
        errors.append(f"{len(files)} files, Cloudflare allows {CF_MAX_FILES} per version")
    errors.extend(f"{p.relative_to(out)}: larger than 25 MiB" for p in files if p.stat().st_size > CF_MAX_FILE_BYTES)
    shutil.copyfile(HEADERS, out / "_headers")
    return errors


def build(out: Path) -> None:
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(SRC, out)
    assets = out / "assets"
    for src, dest in [*BRAND_FILES.items(), *((f, f"brand/{Path(f).name}") for f in BRAND_DOWNLOADS)]:
        path = BRAND / src
        if path.is_file():
            (assets / dest).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, assets / dest)
    # Design tokens are inlined at the top of the stylesheet; the style guide includes the generated palette.
    css = assets / "site.css"
    css.write_text(
        css.read_text(encoding="utf-8").replace(TOKENS_MARKER, (BRAND / "tokens.css").read_text(encoding="utf-8"))
    )
    sprite = (BRAND / "sprite.html").read_text(encoding="utf-8")
    snippets = load_snippets()
    snippet_errors: list[str] = []
    for page in out.rglob("*.html"):
        text = page.read_text(encoding="utf-8")
        new = SNIPPET_MARKER.sub(lambda m, name=page.name: snippet(snippets, m, name, snippet_errors), text)
        new = new.replace(SPRITE_MARKER, sprite)
        if new != text:
            page.write_text(new, encoding="utf-8")
    if snippet_errors:
        fail(snippet_errors)
    guide = out / "brand" / "index.html"
    if guide.is_file():
        guide.write_text(
            guide.read_text(encoding="utf-8").replace(
                PALETTE_MARKER, (BRAND / "palette.html").read_text(encoding="utf-8")
            )
        )

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
    errors.extend(check_headers(out, html_files))
    if errors:
        fail(errors)
    print(f"built {out} ({total} bytes html+css+js, {len(html_files)} pages)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=HERE.parent / "dist" / "site")
    build(parser.parse_args().out)


if __name__ == "__main__":
    main()
