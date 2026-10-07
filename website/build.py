"""Build the static site into an output directory and enforce the site's rules.

    python3 website/build.py --out dist/site

Stdlib only, Python 3.9 or later.
* copies website/src and the brand assets it needs,
* renders the guide (website/docs) into /docs/, with each tool's settings from the product's own snippets, and the
  same pages as Markdown for agents: /docs/**/index.md, /llms.txt, /llms-full.txt and the Agent Skill's references
  (plugins/slowshield/skills/slowshield, served at /skills/; `--write-skill` updates the committed copy),
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
import importlib.util
import re
import shutil
import sys
import tomllib
import types
import zipfile
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
# The guide: website/docs/pages/<slug>.html into /docs/<slug>/, in the layout website/docs/layout.html. Tool settings
# come from src/slowshield/ui/snippets.py (stdlib only), the module the Setup page renders, with example URLs.
DOCS = HERE / "docs"
DOCS_NAV = (
    ("", "Overview"), ("python", "Python"), ("javascript", "JavaScript"), ("go", "Go"), ("java", "Java"),
    ("rust", "Rust"), ("containers", "Container images"), ("container-builds", "Building images"), ("agents", "Agents"),
)  # fmt: skip
EXAMPLE = "https://slowshield.example.com"
EXAMPLE_REGISTRIES = (
    "docker.io", "gcr.io", "ghcr.io", "mcr.microsoft.com", "public.ecr.aws", "quay.io", "registry.k8s.io",
)  # fmt: skip
DOCS_MARKER = re.compile(r"<!-- @(tools|example) ([a-z.-]+) -->")
# The Agent Skill: SKILL.md is written by hand, its references are the guide's pages as Markdown.
SKILL = HERE.parent / "plugins" / "slowshield" / "skills" / "slowshield"
SKILL_PAGES = ("python", "javascript", "go", "java", "rust", "containers", "container-builds", "agents")
# The release the site's commands run. CI passes the latest published GitHub Release (`--release`): the release
# workflow creates it only once the images are tagged, then redeploys the site (docs/releasing.md). Local builds
# default to pyproject.toml's version.
DEFAULT_RELEASE = tomllib.loads((HERE.parent / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
RELEASE_MARKER = "{{release}}"
_VERSION = re.compile(r"\d+\.\d+\.\d+")
FINGERPRINT = ("assets/site.css", "assets/site.js")
BUDGET_BYTES = 200_000  # per page: its html + css + js, uncompressed
HEADERS = HERE / "_headers"
REQUIRED_HEADERS = (
    "content-security-policy", "strict-transport-security", "x-content-type-options", "referrer-policy",
    "permissions-policy", "cross-origin-opener-policy", "cross-origin-resource-policy", "x-frame-options",
)  # fmt: skip
CF_MAX_RULES, CF_MAX_LINE = 100, 2000  # _headers limits
CF_MAX_FILES, CF_MAX_FILE_BYTES = 20_000, 25 * 1024 * 1024  # per Worker version (Free plan), per file

# Inline scripts violate the CSP; JSON-LD is data, which browsers don't run.
_INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)(?![^>]*\btype=\"application/ld\+json\")[^>]*>", re.I)
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


def load_module(path: Path, name: str) -> types.ModuleType:
    """A stdlib-only module by path: the product's snippets.py, and markdown.py next to this file."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        sys.exit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look the module up while the class is created
    spec.loader.exec_module(module)
    return module


def product_snippets() -> types.ModuleType:
    return load_module(SNIPPETS.with_name("snippets.py"), "slowshield_snippets")


def to_markdown(fragment: str) -> str:
    return load_module(HERE / "markdown.py", "slowshield_site_markdown").to_markdown(fragment)


def docs_parts() -> dict[str, str]:
    """Everything a guide page can include: `tools.<ecosystem>` and `example.<name>`, filled in for EXAMPLE."""
    snip = product_snippets()
    urls = {
        "pypi": f"{EXAMPLE}/pypi/simple/", "npm": f"{EXAMPLE}/npm/", "go": f"{EXAMPLE}/go",
        "maven": f"{EXAMPLE}/maven", "cargo": f"{EXAMPLE}/cargo/",
    }  # fmt: skip
    tools = snip.tools(*urls.values()) + snip.oci_tools(EXAMPLE, EXAMPLE_REGISTRIES)
    parts: dict[str, list[str]] = {}

    def code_block(code: str) -> str:
        return (
            f'<div class="code"><pre><code>{html.escape(code, quote=False)}</code></pre>'
            '<button class="copy" type="button" data-copy>Copy</button></div>'
        )

    for t in tools:
        out = [f'<section class="doc-tool" id="{snip.slug(t.name)}">', f"<h3>{html.escape(t.name)}</h3>"]
        if t.age and t.age != snip.NO_AGE_DEFAULT:  # pages say once that a tool without one has only SlowShield
            out.append(f'<p class="doc-age">Release age: {html.escape(t.age)}</p>')
        for label, code in t.snippets:
            out.append(f'<p class="doc-label">{html.escape(label)}</p>{code_block(code)}')
        out.append("</section>")
        parts.setdefault(f"tools.{snip.DOCS_PAGES[t.ecosystem]}", []).extend(out)
    flat = {k: "\n".join(v) for k, v in parts.items()}
    shells = snip.for_instance(urls["pypi"], urls["npm"], urls["go"])
    for sh in shells.shells:
        flat[f"example.shell.{sh.id}"] = code_block(sh.code)
    flat["example.ci"] = code_block(snip.ci_env(urls["pypi"], urls["npm"], urls["go"], age_days=snip.CLIENT_AGE_DAYS))
    flat["example.maven"] = code_block(snip.maven_settings(urls["maven"]))
    flat["example.gradle"] = code_block(snip.gradle_init(urls["maven"]))
    flat["example.cargo"] = code_block(snip.cargo_config(urls["cargo"]))
    flat["example.cargo-command"] = code_block(snip.cargo_command(urls["cargo"]))
    return flat


def render_docs(out: Path, errors: list[str], release: str) -> dict[str, tuple[str, str, str]]:
    """website/docs/pages/*.html, each starting with a `<!-- title: … | description: … -->` line, into /docs/ as
    HTML and Markdown. Returns slug -> (title, description, Markdown)."""
    docs_md: dict[str, tuple[str, str, str]] = {}
    layout = (DOCS / "layout.html").read_text(encoding="utf-8")
    parts = docs_parts()
    pages = {p.stem: p for p in (DOCS / "pages").glob("*.html")}
    for slug, _ in DOCS_NAV:
        if (slug or "index") not in pages:
            errors.append(f"docs: {slug or 'index'}.html is in DOCS_NAV but missing")
    for name, path in pages.items():
        slug = "" if name == "index" else name
        if slug not in {s for s, _ in DOCS_NAV}:
            errors.append(f"docs: {name}.html isn't in DOCS_NAV")
            continue
        text = path.read_text(encoding="utf-8")
        head = re.match(r"<!-- title: (.+?) \| description: (.+?) -->\n", text)
        if head is None:
            errors.append(f"docs/{name}.html: first line must be <!-- title: … | description: … -->")
            continue
        body = text[head.end() :]

        def include(m: re.Match[str], name: str = name) -> str:
            key = f"{m.group(1)}.{m.group(2)}"
            if key not in parts:
                errors.append(f"docs/{name}.html: unknown include {key!r}")
                return m.group(0)
            return parts[key]

        body = DOCS_MARKER.sub(include, body).replace(RELEASE_MARKER, release)
        nav = "\n".join(
            f'<a href="/docs/{s + "/" if s else ""}"{' aria-current="page"' if s == slug else ""}>{label}</a>'
            for s, label in DOCS_NAV
        )
        url = f"https://slowshield.org/docs/{slug + '/' if slug else ''}"
        md_path = f"/docs/{slug + '/' if slug else ''}index.md"
        page = (
            layout.replace("{{title}}", html.escape(head.group(1)))
            .replace("{{markdown}}", md_path)
            .replace("{{description}}", html.escape(head.group(2)))
            .replace("{{canonical}}", url)
            .replace("{{nav}}", nav)
            .replace("{{body}}", body)
        )
        dest = out / "docs" / slug / "index.html" if slug else out / "docs" / "index.html"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(page, encoding="utf-8")
        md = (
            to_markdown(body)
            + f"\n---\n\nThis page as HTML: {url}. All of the guide in one file: https://slowshield.org/llms-full.txt\n"
        )
        dest.with_name("index.md").write_text(md, encoding="utf-8")
        docs_md[slug] = (head.group(1), head.group(2), md)
    return docs_md


def write_agent_files(
    out: Path, docs_md: dict[str, tuple[str, str, str]], errors: list[str], *, write_skill: bool
) -> None:
    """/llms.txt, /llms-full.txt, the skill's references (checked against the committed copy, or written with
    `--write-skill`), and the skill itself under /skills/ (a folder and a zip)."""
    index = "\n".join(
        f"- [{title}](https://slowshield.org/docs/{slug + '/' if slug else ''}index.md): {description}"
        for slug, _ in DOCS_NAV
        for title, description, _ in [docs_md.get(slug, ("", "", ""))]
        if title
    )
    llms = (DOCS / "llms.txt").read_text(encoding="utf-8").replace("{{pages}}", index)
    (out / "llms.txt").write_text(llms, encoding="utf-8")
    full = "\n\n".join(
        md for _, (_, _, md) in sorted(docs_md.items(), key=lambda kv: [s for s, _ in DOCS_NAV].index(kv[0]))
    )
    (out / "llms-full.txt").write_text(llms + "\n\n" + full, encoding="utf-8")

    refs = SKILL / "references"
    wanted = {
        f"{page}.md": f"<!-- Generated by website/build.py from website/docs/pages/{page}.html; run it with "
        f"--write-skill after changing that page. -->\n\n{docs_md[page][2]}"
        for page in SKILL_PAGES
        if page in docs_md
    }
    if write_skill:
        refs.mkdir(parents=True, exist_ok=True)
        for stale in {p.name for p in refs.glob("*.md")} - set(wanted):
            (refs / stale).unlink()
        for name, text in wanted.items():
            (refs / name).write_text(text, encoding="utf-8")
    else:
        for name, text in wanted.items():
            path = refs / name
            if not path.is_file() or path.read_text(encoding="utf-8") != text:
                errors.append(f"{path.relative_to(HERE.parent)} is stale: run python3 website/build.py --write-skill")
    dest = out / "skills" / "slowshield"
    shutil.copytree(SKILL, dest)
    with zipfile.ZipFile(out / "skills" / "slowshield.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(p for p in dest.rglob("*") if p.is_file()):
            info = zipfile.ZipInfo(f"slowshield/{path.relative_to(dest).as_posix()}", date_time=(2026, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            zf.writestr(info, path.read_bytes(), zipfile.ZIP_DEFLATED)


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
    # Every page needs a Cache-Control rule of its own or from a `*` rule, or it silently falls back to max-age=0.
    splats = [
        re.compile(re.escape(r).replace(r"\*", ".*") + "$")
        for r, h in rules.items()
        if "*" in r and "cache-control" in h
    ]
    for page in html_files:
        rel = page.relative_to(out).as_posix()
        url = "/" + rel[: -len("index.html")] if rel.endswith("index.html") else "/" + rel
        has_rule = "cache-control" in rules.get(url, {}) or any(s.match(url) for s in splats if s.pattern != ".*$")
        if rel != "404.html" and not has_rule:
            errors.append(f"_headers: no Cache-Control rule for page {url}")
    files = [p for p in out.rglob("*") if p.is_file()]
    if len(files) >= CF_MAX_FILES:
        errors.append(f"{len(files)} files, Cloudflare allows {CF_MAX_FILES} per version")
    errors.extend(f"{p.relative_to(out)}: larger than 25 MiB" for p in files if p.stat().st_size > CF_MAX_FILE_BYTES)
    shutil.copyfile(HEADERS, out / "_headers")
    return errors


def build(out: Path, *, write_skill: bool = False, release: str = DEFAULT_RELEASE) -> None:
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
    docs_md = render_docs(out, snippet_errors, release)
    write_agent_files(out, docs_md, snippet_errors, write_skill=write_skill)
    for page in out.rglob("*.html"):
        text = page.read_text(encoding="utf-8")
        new = SNIPPET_MARKER.sub(lambda m, name=page.name: snippet(snippets, m, name, snippet_errors), text)
        new = new.replace(SPRITE_MARKER, sprite).replace(RELEASE_MARKER, release)
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

    shared = sum(p.stat().st_size for p in [*css_files, *assets.glob("site.*.js")])
    total = shared + sum(p.stat().st_size for p in html_files)
    errors.extend(
        f"{page.relative_to(out)}: size budget exceeded: {page.stat().st_size + shared} > {BUDGET_BYTES} bytes"
        for page in html_files
        if page.stat().st_size + shared > BUDGET_BYTES
    )
    errors.extend(check_headers(out, html_files))
    if errors:
        fail(errors)
    print(f"built {out} ({total} bytes html+css+js, {len(html_files)} pages)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=HERE.parent / "dist" / "site")
    parser.add_argument("--write-skill", action="store_true", help="update the skill's committed references")
    parser.add_argument("--release", default=DEFAULT_RELEASE, help="the published release the commands run (X.Y.Z)")
    args = parser.parse_args()
    release = args.release.removeprefix("v")
    if not _VERSION.fullmatch(release):
        fail([f"--release: expected X.Y.Z, got {args.release!r}"])
    build(args.out, write_skill=args.write_skill, release=release)


if __name__ == "__main__":
    main()
