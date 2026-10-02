"""Threat feeds end-to-end against the fake OSV bucket and GitHub API, and their effect on serving."""

from __future__ import annotations

from slowshield.ecosystems.pypi.project import JSON_V1
from slowshield.feeds import FeedScheduler
from slowshield.feeds.github import GithubFeed
from slowshield.feeds.osv import OsvFeed
from tests.conftest import DAY, NOW, Running


def _scheduler(run: Running) -> FeedScheduler:
    return FeedScheduler(run.ctx, [OsvFeed(run.ctx), GithubFeed(run.ctx)])


def _blocks(run: Running, source: str) -> set[tuple]:
    return set(
        run.rows(
            "SELECT ecosystem, name, version, version_range FROM blocklist WHERE source = ? AND withdrawn IS NULL",
            (source,),
        )
    )


async def test_github_disabled_without_token(running: Running) -> None:
    sched = _scheduler(running)
    gh = running.ctx.feeds["github"]
    assert (gh.enabled, gh.reason) == (False, "missing_token")
    assert gh.fix and "GITHUB_TOKEN" in gh.fix
    await sched.run_once()
    assert running.ctx.feeds["osv"].reason == "ok"
    assert running.ctx.feeds["github"].reason == "missing_token"
    page = await running.client.get("/ui/feeds")
    assert "Needs a token" in page.text and "GITHUB_TOKEN_FILE" in page.text
    dash = await running.client.get("/")
    assert "no API token configured" in dash.text


async def test_osv_full_snapshot_and_serving_effects(running: Running) -> None:
    await _scheduler(running).run_once()
    osv = _blocks(running, "osv")
    assert ("pypi", "malware-pkg", None, None) in osv
    assert ("pypi", "typosquat-pkg", "0.1.0", None) in osv
    assert ("npm", "malicious-npm", None, None) in osv
    assert ("npm", "@evil/thing", "1.0.0", None) in osv
    assert not any(name in ("alpha", "withdrawn-pkg", "left-pad-ng") for _, name, _, _ in osv)  # non-MAL / withdrawn
    st = running.rows("SELECT source, watermark FROM feed_state WHERE source LIKE 'osv:%' ORDER BY source")
    assert [s for s, _ in st] == ["osv:PyPI", "osv:npm"] and all(w for _, w in st)
    assert running.ctx.feeds["osv"].entries == len(osv)

    r = await running.client.get("/pypi/simple/malware-pkg/", headers={"Accept": JSON_V1})
    assert r.status_code == 451
    body = r.json()
    assert body["error"] == "blocked" and body["advisory_id"] == "MAL-2026-0001"
    assert body["url"] == "https://osv.dev/vulnerability/MAL-2026-0001"
    info = running.fake.info()["pypi"]["malware-pkg"]["0.0.1"]
    r = await running.client.get(f"/pypi{info[0]['path']}")
    assert r.status_code == 451
    r = await running.client.get("/npm/malicious-npm")
    assert r.status_code == 451
    await running.drain()
    ev = running.rows("SELECT type, ecosystem, package FROM events WHERE type = 'blocked'")
    assert ("blocked", "pypi", "malware-pkg") in ev and ("blocked", "npm", "malicious-npm") in ev


async def test_osv_incremental_updates_and_withdrawals(running: Running) -> None:
    sched = _scheduler(running)
    await sched.run_once()
    running.fake.control(
        "advisory",
        {
            "source": "osv",
            "ecosystem": "npm",
            "id": "MAL-2026-1003",
            "package": "left-pad-ng",
            "versions": ["1.0.0"],
            "modified": NOW + 60,
        },
    )
    running.fake.control(
        "advisory",
        {
            "source": "osv",
            "ecosystem": "npm",
            "id": "MAL-2026-1001",
            "package": "malicious-npm",
            "ranges": [["0", None]],
            "withdrawn": True,
            "modified": NOW + 120,
        },
    )
    running.clock.advance(3600)
    await sched.run_once()
    osv = _blocks(running, "osv")
    assert ("npm", "left-pad-ng", "1.0.0", None) in osv
    assert ("npm", "malicious-npm", None, None) not in osv
    doc = (await running.client.get("/npm/left-pad-ng")).json()
    assert "1.0.0" not in doc["versions"] and "1.1.0" in doc["versions"]
    assert (await running.client.get("/npm/left-pad-ng/-/left-pad-ng-1.0.0.tgz")).status_code == 451
    # a range-based OSV entry
    running.fake.control(
        "advisory",
        {
            "source": "osv",
            "ecosystem": "npm",
            "id": "MAL-2026-1004",
            "package": "ranged-npm",
            "ranges": [["1.1.0", "1.2.0"]],
            "modified": NOW + 180,
        },
    )
    await sched.run_once()
    assert ("npm", "ranged-npm", None, ">= 1.1.0, < 1.2.0") in _blocks(running, "osv")


async def test_osv_full_resync_when_watermark_is_old(running: Running) -> None:
    sched = _scheduler(running)
    await sched.run_once()
    running.clock.advance(40 * DAY)
    hits_before = running.fake.hits("/osv/npm/all.zip").get("/osv/npm/all.zip", 0)
    await sched.run_once()
    assert running.fake.hits("/osv/npm/all.zip")["/osv/npm/all.zip"] == hits_before + 1


async def test_github_feed_with_token(start_app, monkeypatch) -> None:
    from slowshield.feeds import github

    monkeypatch.setattr(github, "PER_PAGE", 1)  # exercise Link-header pagination
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    run = await start_app()
    sched = _scheduler(run)
    assert run.ctx.feeds["github"].enabled
    await sched.run_once()
    gh = _blocks(run, "github")
    assert ("pypi", "partly-bad", "1.2.0", None) in gh
    assert ("npm", "ranged-npm", None, ">= 1.1.0, < 1.2.0") in gh
    assert ("npm", "malicious-npm", None, None) in gh
    assert not any(n == "withdrawn-npm" for _, n, _, _ in gh)
    assert run.fake.control("hits", prefix="/github/").get("/github/advisories", 0) > 3
    state = run.rows("SELECT source, watermark FROM feed_state WHERE source LIKE 'github:%'")
    assert len(state) == 2

    doc = (await run.client.get("/pypi/simple/partly-bad/", headers={"Accept": JSON_V1})).json()
    assert doc["versions"] == ["1.0.0", "1.3.0"]
    info = run.fake.info()["pypi"]["partly-bad"]["1.2.0"]
    r = await run.client.get(f"/pypi{info[0]['path']}")
    assert r.status_code == 451 and r.json()["advisory_id"] == "GHSA-aaaa-0001-0001"
    npm = (await run.client.get("/npm/ranged-npm")).json()
    assert list(npm["versions"]) == ["1.0.0", "1.2.0"]

    # withdrawing lifts the block on the next sync
    run.fake.control(
        "advisory",
        {
            "source": "github",
            "ecosystem": "pip",
            "id": "GHSA-aaaa-0001-0001",
            "package": "partly-bad",
            "gh_range": "= 1.2.0",
            "withdrawn": True,
            "modified": NOW + 60,
        },
    )
    await sched.run_once()
    assert ("pypi", "partly-bad", "1.2.0", None) not in _blocks(run, "github")


async def test_github_bad_token_reports_error(start_app, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "bad")
    run = await start_app("[feeds.osv]\nenabled = false\n")
    sched = _scheduler(run)
    await sched.run_once()
    st = run.ctx.feeds["github"]
    assert st.reason == "error"
    assert "token" in (st.last_error or "")
    assert run.ctx.feeds["osv"].reason == "disabled"
    page = await run.client.get("/ui/feeds")
    assert "Failing" in page.text


async def test_github_token_from_file(start_app, monkeypatch, tmp_path) -> None:
    secret = tmp_path / "token"
    secret.write_text("ghp_from_file\n")
    monkeypatch.setenv("GITHUB_TOKEN_FILE", str(secret))
    run = await start_app()
    assert run.ctx.cfg.github_token == "ghp_from_file"
    assert run.ctx.cfg.github_token_status.source == "file"


async def test_feed_metrics_callbacks(running: Running) -> None:
    sched = _scheduler(running)
    await sched.run_once()
    sched.refresh_counts()
    values = {name: list(cb()) for name, cb in sched.gauges.items()}
    enabled = values["slowshield.feed.enabled"]
    assert (0.0, {"feed": "github", "reason": "missing_token"}) in enabled
    assert (1.0, {"feed": "osv", "reason": "ok"}) in enabled
    assert values["slowshield.feed.last_success.timestamp"]
    assert values["slowshield.blocklist.entries"]


async def test_feed_sync_failure_is_recorded(running: Running) -> None:
    running.fake.control("fail", prefix="/osv", status=500)
    sched = _scheduler(running)
    await sched.run_once()
    st = running.ctx.feeds["osv"]
    assert st.reason == "error" and st.last_error
    await running.drain()
    sched.refresh_status()
    assert running.ctx.feeds["osv"].reason == "error"
