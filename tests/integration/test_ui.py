"""Web UI: every page renders, hostile feed data is escaped, security headers, CSV export guard."""

from __future__ import annotations

from slowshield.ecosystems.pypi.project import JSON_V1
from slowshield.feeds import FeedScheduler
from slowshield.feeds.github import GithubFeed
from slowshield.feeds.osv import OsvFeed
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
    assert "/ui/static/app.css" in page and '"/static/' not in page


async def test_health_endpoints(running: Running) -> None:
    assert (await running.client.get("/healthz")).text == "ok"
    assert (await running.client.get("/readyz")).text == "ready"


def test_formatters() -> None:
    from slowshield.ui import fmt_bytes, fmt_duration, fmt_num, fmt_pct, fmt_ts, safe_href

    assert fmt_bytes(0) == "0 B" and fmt_bytes(1536) == "1.5 KB" and fmt_bytes(5 * 1024**5) == "5120.0 TB"
    assert fmt_num(12) == "12" and fmt_num(12_345) == "12.3k" and fmt_num(2_500_000) == "2.5M"
    assert fmt_duration(30) == "30s" and fmt_duration(90) == "1m" and fmt_duration(3 * 86400 + 7200) == "3d 2h"
    assert fmt_pct(None) == "—" and fmt_pct(0.5) == "50.0%"
    assert fmt_ts(None) == "—" and fmt_ts(1).startswith("1970-01-01")
    assert safe_href("https://osv.dev/x") == "https://osv.dev/x"
    assert safe_href("javascript:alert(1)") == "#" and safe_href(None) == "#"


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
