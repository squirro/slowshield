"""Web UI: every page renders, hostile feed data is escaped, security headers, CSV export guard."""

from __future__ import annotations

import hashlib
import importlib
import inspect
import re

import pytest

from slowshield.app import STATIC_DIR
from slowshield.ecosystems import IDS
from slowshield.ecosystems.pypi.project import JSON_V1
from slowshield.feeds import FeedScheduler
from slowshield.feeds.github import GithubFeed
from slowshield.feeds.osv import OsvFeed
from slowshield.ui import expect as X
from slowshield.ui import snippets as S
from tests.conftest import Running

PAGES = [
    "/ui/",
    "/ui/?range=1h",
    "/ui/?range=24h",
    "/ui/?range=30d&eco=pypi",
    "/ui/?range=bogus&eco=bogus",
    "/ui/partials/dashboard?range=90d",
    "/ui/packages",
    "/ui/packages?q=al&sort=bytes&eco=pypi&page=1",
    "/ui/packages?sort=name&page=abc",
    "/ui/partials/packages?q=x%25_",
    "/ui/packages/pypi/alpha",
    "/ui/packages/pypi/Alpha",
    "/ui/packages/npm/@acme/widget",
    "/ui/packages/npm/left-pad-ng?range=7d",
    "/ui/packages/pypi/never-seen",
    "/ui/packages/cargo/serde",
    "/ui/leaderboards",
    "/ui/leaderboards?range=24h&eco=npm",
    "/ui/leaderboards?range=1h",
    "/ui/packages/pypi/alpha?range=1h",
    "/ui/security?range=1h",
    "/ui/security",
    "/ui/security?type=blocked&eco=npm&q=evil&ip=10.0.0.1&range=7d",
    "/ui/partials/security?page=2",
    "/ui/blocklist",
    "/ui/blocklist?q=evil&eco=npm&source=osv&scope=version",
    "/ui/blocklist?scope=package",
    "/ui/partials/blocklist?page=2",
    "/ui/feeds",
    "/ui/setup",
    "/ui/about",
]


async def _populate(run: Running) -> None:
    await FeedScheduler(run.ctx, [OsvFeed(run.ctx), GithubFeed(run.ctx)]).run_once()
    for project in ("alpha", "legacy-names", "brand-new"):
        doc = (await run.client.get(f"/pypi/simple/{project}/", headers={"Accept": JSON_V1})).json()
        for f in doc["files"][:2]:
            await run.client.get(f"/pypi/simple/{project}/" + f["url"])
    await run.client.get("/npm/@acme/widget")
    await run.client.get("/npm/@acme/widget/-/widget-0.1.0.tgz")
    await run.client.get("/npm/left-pad-ng/-/left-pad-ng-2.0.0.tgz")  # 403 -> age_gate event
    await run.client.get("/npm/malicious-npm")  # 451 -> blocked event
    await run.client.get("/npm/@evil/thing/-/thing-1.0.0.tgz")
    await run.drain()


async def test_pages_render(running: Running) -> None:
    await _populate(running)
    for path in PAGES:
        r = await running.client.get(path)
        assert r.status_code == 200, (path, r.text[:500])
        assert r.headers["content-type"].startswith("text/html")
        assert "<script>alert(1)</script>" not in r.text, path


async def test_empty_database_pages_render(running: Running) -> None:
    for path in PAGES:
        r = await running.client.get(path)
        assert r.status_code == 200, path


async def test_security_headers_and_csp(running: Running) -> None:
    r = await running.client.get("/ui/")
    h = r.headers
    csp = h["content-security-policy"]
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp
    assert "frame-ancestors 'none'" in csp
    assert h["x-content-type-options"] == "nosniff"
    assert h["referrer-policy"] == "no-referrer"
    assert h["x-frame-options"] == "DENY"
    assert h["cache-control"] == "no-store"
    assert "<script>" not in r.text.split("</head>")[1]  # no inline script in the body
    assert ' style="' not in r.text and "onclick" not in r.text
    assert 'name="htmx-config" content="includeIndicatorCSS:false' in r.text


async def test_hostile_feed_text_is_escaped(running: Running) -> None:
    await _populate(running)
    r = await running.client.get("/ui/blocklist?q=evil")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text
    r = await running.client.get("/ui/packages/npm/@evil/thing")
    assert "&lt;script&gt;" in r.text and "<script>alert" not in r.text


async def test_dashboard_reflects_activity(running: Running) -> None:
    await _populate(running)
    r = await running.client.get("/ui/?range=24h")
    assert "alpha" in r.text and "Top packages" in r.text
    assert "Malware blocked" in r.text
    for label in ("Upstream traffic saved", "Fetched from upstream", "Upstream requests saved"):
        assert label in r.text
    r = await running.client.get("/ui/?range=1h")
    assert "alpha" in r.text and 'aria-current="true">1h<' in r.text
    r = await running.client.get("/ui/packages/pypi/alpha")
    assert "Held back" in r.text and "2.0.0" in r.text and "countdown" in r.text
    r = await running.client.get("/ui/leaderboards")
    assert "left-pad-ng" in r.text  # most often too new
    r = await running.client.get("/ui/security?type=age_gate")
    assert "left-pad-ng" in r.text and "127.0.0.1" in r.text


async def test_csv_export_neutralises_formulas(running: Running) -> None:
    await running.ctx.db.writer.run(
        lambda c: c.execute(
            "INSERT INTO events (ts, type, ecosystem, package, version, details) VALUES (?, 'blocked', 'npm', ?, ?, ?)",
            (running.clock.now(), '=HYPERLINK("http://x")', "+1", '{"reason": "@SUM(1)"}'),
        )
    )
    r = await running.client.get("/ui/security.csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    line = r.text.splitlines()[1]
    assert "'=HYPERLINK" in line and ",'+1," in line


async def test_static_assets_and_favicon(running: Running) -> None:
    css = await running.client.get("/ui/static/app.css")
    assert css.status_code == 200 and "--primary" in css.text
    js = await running.client.get("/ui/static/vendor/htmx.min.js")
    assert js.status_code == 200 and len(js.content) > 10_000
    fav = await running.client.get("/favicon.ico", follow_redirects=False)
    assert fav.status_code == 301 and fav.headers["location"] == "/ui/static/brand/favicon.ico"
    for asset in ("favicon.ico", "favicon.svg", "mark.svg", "mark-dark.svg", "apple-touch-icon.png"):
        assert (await running.client.get(f"/ui/static/brand/{asset}")).status_code == 200, asset
    page = (await running.client.get("/ui/")).text
    assert '"/static/' not in page
    # Versioned by content, not release: a rebuilt asset is never served from a stale browser cache.
    for name in ("app.css", "app.js"):
        digest = hashlib.sha256((STATIC_DIR / name).read_bytes()).hexdigest()[:12]
        assert f'"/ui/static/{name}?v={digest}"' in page, name


async def test_health_endpoints(running: Running) -> None:
    assert (await running.client.get("/healthz")).text == "ok"
    assert (await running.client.get("/readyz")).text == "ready"


def test_formatters() -> None:
    from slowshield.ui import fmt_bytes, fmt_duration, fmt_num, fmt_pct, fmt_ts, safe_href, short_version

    assert fmt_bytes(0) == "0 B" and fmt_bytes(1536) == "1.5 KB" and fmt_bytes(5 * 1024**5) == "5120.0 TB"
    assert fmt_num(12) == "12" and fmt_num(12_345) == "12.3k" and fmt_num(2_500_000) == "2.5M"
    assert fmt_duration(30) == "30s" and fmt_duration(90) == "1m" and fmt_duration(3 * 86400 + 7200) == "3d 2h"
    assert fmt_pct(None) == "—" and fmt_pct(0.5) == "50.0%"
    assert fmt_ts(None) == "—" and fmt_ts(1).startswith("1970-01-01")
    assert safe_href("https://osv.dev/x") == "https://osv.dev/x"
    assert safe_href("javascript:alert(1)") == "#" and safe_href(None) == "#"
    digest = "sha256:3734a9c4892eb699ef61a1a3ad123a89d92eeee41b353c233509e2c4fdc87ef1"
    assert short_version(digest) == "sha256:3734a9c4892e…"
    assert short_version("1.43.109") == "1.43.109" and short_version("sha256:not-hex") == "sha256:not-hex"


async def test_digests_are_shortened_wherever_versions_show(running: Running) -> None:
    digest = "sha256:" + "3734a9c4892e" + "b" * 52
    running.app.ctx.recorder.event("fail_open", "oci", "docker.io/library/python", digest, client_ip="10.0.0.1")
    await running.drain()
    for path in ("/ui/", "/ui/security", "/ui/packages/oci/docker.io/library/python"):
        page = (await running.client.get(path)).text
        assert f'<code class="ver" title="{digest}">sha256:3734a9c4892e…</code>' in page, path


async def test_setup_offers_plain_http_on_localhost(start_app) -> None:
    run = await start_app('local_http = true\npublic_url = "https://localhost"\n', host="localhost:8080")
    r = await run.client.get("/ui/setup", headers={"X-Forwarded-Proto": "http"})
    assert "http://localhost:8080/pypi/simple/" in r.text and "http://localhost:8080/npm/" in r.text
    assert "unsafeHttpWhitelist" in r.text and "verify_ssl = false" in r.text
    assert "https://localhost/pypi/simple/" in r.text  # HTTPS stays documented as the alternative
    # Viewed over HTTPS, the page still offers plain HTTP for the loopback public URL (default port).
    r = await run.client.get("/ui/setup", headers={"X-Forwarded-Proto": "https"})
    assert "http://localhost/pypi/simple/" in r.text


async def test_setup_without_local_http(start_app) -> None:
    run = await start_app('public_url = "https://localhost"\n', host="localhost")
    r = await run.client.get("/ui/setup", headers={"X-Forwarded-Proto": "http"})
    assert "http://localhost/pypi/simple/" not in r.text and "https://localhost/pypi/simple/" in r.text
    assert "unsafeHttpWhitelist" not in r.text and "verify_ssl = true" in r.text
    # A non-loopback public URL never switches to plain HTTP, whatever Host the request carries.
    run = await start_app('local_http = true\npublic_url = "https://slowshield.example.com"\n', host="evil.test")
    r = await run.client.get("/ui/setup", headers={"X-Forwarded-Proto": "http"})
    assert "http://evil.test" not in r.text and "https://slowshield.example.com/pypi/simple/" in r.text


async def test_setup_teaches_setup_url_while_responses_keep_public_url(start_app) -> None:
    run = await start_app(
        'public_url = "https://slowshield.example.com"\nsetup_url = "https://slowshield.tailnet.ts.net"\n'
    )
    page = (await run.client.get("/ui/setup")).text
    assert "https://slowshield.tailnet.ts.net/pypi/simple/" in page and "https://slowshield.tailnet.ts.net/npm/" in page
    assert "https://slowshield.example.com/pypi/simple/" not in page
    assert "New clients use <code>https://slowshield.tailnet.ts.net</code>" in page
    # Package URLs in responses stay under public_url, so clients set up before keep working.
    doc = (await run.client.get("/npm/left-pad-ng")).json()
    tarballs = [v["dist"]["tarball"] for v in doc["versions"].values()]
    assert tarballs and all(t.startswith("https://slowshield.example.com/npm/") for t in tarballs)
    # Without setup_url, nothing changes and no notice shows.
    run = await start_app('public_url = "https://slowshield.example.com"\n')
    page = (await run.client.get("/ui/setup")).text
    assert "https://slowshield.example.com/pypi/simple/" in page and "New clients use" not in page


# ---- Setup: what to expect, and the hosts to block ---------------------------------------------------------------


def _expect_rows(page: str) -> dict[str, str]:
    """Each ecosystem's row of the What to expect table, by ecosystem id, in page order."""
    table = page[page.index('<table class="table expect-table">') :]
    table = table[: table.index("</table>")]
    row = r'<tr( class="withdrawn")?>\s*<th scope="row"><span class="eco eco-([a-z]+)">(.*?)</tr>'
    rows = re.findall(row, table, re.S)
    return {eco: withdrawn + body for withdrawn, eco, body in rows}


def _firewall(page: str) -> str:
    section = page[page.index("Block these at the firewall") :]
    return section[: section.index("</section>")]


@pytest.mark.parametrize("eco", IDS)
def test_expect_statuses_are_the_ones_the_service_answers_with(eco: str) -> None:
    """The table's codes come from the services' own refusals, not from prose."""
    module = importlib.import_module(f"slowshield.ecosystems.{eco}.service")
    service = next(c for c in vars(module).values() if inspect.isclass(c) and hasattr(c, "_too_new"))
    statuses = {"TOO_EARLY": 425}

    def codes(method: str) -> set[int]:
        src = inspect.getsource(getattr(service, method))
        found = re.findall(r"(?:error|warning)\(\s*(4\d\d|TOO_EARLY)\b", src)
        return {statuses.get(c) or int(c) for c in found}

    row = X.EXPECT[eco]
    assert codes("_too_new") == {row.pinned}
    assert codes("_blocked") == {row.blocked}


async def test_setup_what_to_expect_has_a_row_per_ecosystem(running: Running) -> None:
    page = (await running.client.get("/ui/setup")).text
    rows = _expect_rows(page)
    assert list(rows) == list(IDS)  # ECOSYSTEMS order, with their labels and colours
    pinned = {eco: int(re.findall(r'class="badge st-held">(\d+)<', body)[0]) for eco, body in rows.items()}
    assert pinned == {
        "pypi": 403, "npm": 403, "go": 403, "maven": 425, "cargo": 403, "nuget": 425, "composer": 425,
        "rubygems": 425, "oci": 403,
    }  # fmt: skip
    blocked = {eco: int(re.findall(r'class="badge st-blocked">(\d+)<', body)[0]) for eco, body in rows.items()}
    assert blocked == {eco: 403 if eco == "oci" else 451 for eco in IDS}
    assert "withdrawn" not in "".join(rows.values()) and ">disabled<" not in "".join(rows.values())
    # Brand-new packages follow the config: fail_open = true at the top, false for Maven and the others by default.
    served = {eco for eco, body in rows.items() if "ev-fail_open" in body}
    assert served == {"pypi", "npm", "go", "oci"}


async def test_setup_brand_new_follows_fail_open(start_app) -> None:
    run = await start_app("fail_open = false\n[upstreams.maven]\nfail_open = true\n")
    rows = _expect_rows((await run.client.get("/ui/setup")).text)
    assert {eco for eco, body in rows.items() if "ev-fail_open" in body} == {"maven"}
    assert all('class="badge st-held">held<' in body for eco, body in rows.items() if eco != "maven")


async def test_setup_marks_a_disabled_ecosystem(start_app) -> None:
    run = await start_app('[upstreams.composer]\nenabled = false\nrepo_url = "https://packagist.mirror.example"\n')
    page = (await run.client.get("/ui/setup")).text
    rows = _expect_rows(page)
    composer = rows["composer"]
    assert composer.startswith(' class="withdrawn"') and '<span class="badge">disabled</span>' in composer
    assert sum("withdrawn" in body for body in rows.values()) == 1
    # Its hosts aren't on the list to block: SlowShield doesn't serve it here.
    firewall = _firewall(page)
    assert "packagist.mirror.example" not in firewall and "api.github.com" not in firewall
    assert re.search(r"switched off here:\s*PHP\.", firewall)


async def test_setup_firewall_hosts_come_from_the_config(start_app) -> None:
    run = await start_app(
        '[upstreams.maven.repos.jitpack]\nurl = "https://jitpack.example.net/m2"\n'
        '[upstreams.pypi]\nmirrors = ["https://pypi.mirror.example/"]\n'
    )
    firewall = _firewall((await run.client.get("/ui/setup")).text)
    groups = dict(re.findall(r'<span class="eco eco-([a-z]+)">.*?<span class="hosts">(.*?)</span>', firewall, re.S))
    # Each host once, under the first ecosystem that names it (here, most upstreams are the same fake registry).
    assert list(groups) == [eco for eco in IDS if eco in groups] and {"pypi", "maven", "composer"} <= set(groups)
    assert '<code class="host">pypi.mirror.example</code>' in groups["pypi"]
    assert '<code class="host">jitpack.example.net</code>' in groups["maven"]
    # Hosts clients use that the config doesn't hold, once each.
    assert '<code class="host">repo.maven.apache.org</code>' in groups["maven"]
    # Composer's download hosts: a lock written against packagist.org downloads from them directly.
    composer = re.findall(r'<code class="host">(.*?)</code>', groups["composer"])
    assert composer[-4:] == ["codeload.github.com", "gitlab.com", "bitbucket.org", "api.github.com"]
    # The same hosts, one per line, to copy.
    listed = re.search(r"<pre><code>(.*?)</code></pre>", firewall, re.S)
    assert listed is not None
    lines = listed.group(1).split("\n")
    assert len(lines) == len(set(lines))
    assert {"pypi.mirror.example", "jitpack.example.net", "api.github.com"} <= set(lines)
    # Never where other ecosystems' downloads redirect to: CDNs and cloud storage serve far more than packages.
    assert "storage.googleapis.com" not in firewall and "localhost" not in lines
    assert {"codeload.github.com", "gitlab.com", "bitbucket.org"} <= set(lines)


async def test_setup_tool_notes_render_code(running: Running) -> None:
    page = (await running.client.get("/ui/setup")).text
    assert (
        '<p class="muted small tool-note">Leave <code>,direct</code> and <code>|</code> out of <code>GOPROXY</code>'
        in page
    )
    assert page.count('class="muted small tool-note"') == sum(1 for t in S.tools(*["https://x"] * 5, nuget="https://x",
        composer="https://x", rubygems="https://x") if t.note)  # fmt: skip
