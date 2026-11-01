"""Fast-tracks: an Admin releases a held-back version with a reason; a User asks, a second person approves."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from slowshield.feeds import FeedScheduler
from slowshield.feeds.github import GithubFeed
from slowshield.feeds.osv import OsvFeed
from tests.conftest import Running
from tests.integration.test_auth import SAME_ORIGIN, audit, idp, sign_in

TARBALL = "/npm/left-pad-ng/-/left-pad-ng-2.0.0.tgz"  # published 2 days ago, delay 7: held back
FORM = {**SAME_ORIGIN, "Content-Type": "application/x-www-form-urlencoded"}
ADMIN = {"name": "Ada Admin", "slowshield_roles": ["SlowShield Admins"]}
USER = {"name": "Uli User", "slowshield_roles": ["SlowShield Users"]}
OTHER = {"name": "Otto Other", "slowshield_roles": ["SlowShield Users"]}
VIEWER = {"name": "Vera Viewer", "slowshield_roles": []}


@pytest.fixture
def people(start_auth: Callable[..., Any], tmp_path: Path) -> Callable[..., Any]:
    """Instances on one database, one browser each: as(claims) signs someone in."""

    async def person(sub: str, claims: dict[str, Any]) -> Running:
        run = await start_auth(data_dir=tmp_path / "data")
        idp(run, sub=sub, claims=claims)
        assert (await sign_in(run)).status_code == 303
        return run

    return person


async def _held(run: Running) -> None:
    assert (await run.client.get("/npm/left-pad-ng")).status_code == 200
    assert (await run.client.get(TARBALL)).status_code == 403
    await run.drain()


async def _ask(run: Running, message: str = "needed for the 2.0 migration", version: str = "2.0.0") -> Any:
    body = f"eco=npm&name=left-pad-ng&version={version}&message={message.replace(' ', '+')}"
    return await run.client.post("/ui/fasttrack", content=body, headers=FORM)


async def _decide(run: Running, track_id: int, action: str, message: str = "reviewed the diff") -> Any:
    body = "message=" + message.replace(" ", "+")
    return await run.client.post(f"/ui/fasttrack/{track_id}/{action}", content=body, headers=FORM)


async def test_an_admin_fast_tracks_and_revokes(people: Callable[..., Any]) -> None:
    admin = await people("ada", ADMIN)
    await _held(admin)
    page = await admin.client.get("/ui/packages/npm/left-pad-ng")
    assert ">Fast-track</a>" in page.text
    form = await admin.client.get("/ui/fasttrack/new?eco=npm&name=left-pad-ng&version=2.0.0")
    assert form.status_code == 200 and "Fast-track now" in form.text
    assert (await _ask(admin, message="")).status_code == 400  # a reason is required
    r = await _ask(admin)
    assert r.status_code == 303 and r.headers["location"] == "/ui/packages/npm/left-pad-ng"
    assert (await admin.client.get(TARBALL)).status_code == 200
    assert "fast-tracked" in (await admin.client.get("/ui/packages/npm/left-pad-ng")).text
    assert (await _ask(admin)).status_code == 400  # once
    track = admin.rows("SELECT id, state, requester, request_message, decider FROM fast_tracks")
    assert track == [(1, "active", "Ada Admin", "needed for the 2.0 migration", "Ada Admin")]
    r = await _decide(admin, 1, "revoke", "the fix landed in 2.0.1")
    assert r.status_code == 303
    assert (await admin.client.get(TARBALL)).status_code == 403
    assert [a[0] for a in audit(admin)][-2:] == ["fasttrack_granted", "fasttrack_revoked"]
    activity = (await admin.client.get("/ui/activity")).text
    assert "Fast-tracked" in activity and "the fix landed in 2.0.1" in activity


async def test_a_user_asks_and_a_second_person_approves(people: Callable[..., Any]) -> None:
    uli = await people("uli", USER)
    await _held(uli)
    page = await uli.client.get("/ui/packages/npm/left-pad-ng")
    assert ">Request fast-track</a>" in page.text
    assert (await _ask(uli)).status_code == 303
    assert (await uli.client.get(TARBALL)).status_code == 403  # not before someone else approves
    assert "fast-track requested" in (await uli.client.get("/ui/packages/npm/left-pad-ng")).text
    assert (await _decide(uli, 1, "approve")).status_code == 400  # not one's own
    assert (await _decide(uli, 1, "approve", "")).status_code == 400
    vera = await people("vera", VIEWER)
    assert (await _decide(vera, 1, "approve")).status_code == 400  # Viewers can't
    assert (await _decide(uli, 1, "revoke")).status_code == 400  # Users can't revoke
    otto = await people("otto", OTHER)
    listing = await otto.client.get("/ui/fasttrack")
    assert "needed for the 2.0 migration" in listing.text and 'action="/ui/fasttrack/1/approve"' in listing.text
    assert (await _decide(otto, 1, "approve", "agreed, it fixes CVE-x")).status_code == 303
    await uli.ctx.fast_tracks.refresh()  # another worker picks it up (the config watcher does this every 5 s)
    assert (await uli.client.get(TARBALL)).status_code == 200
    assert otto.rows("SELECT state, requester, decider, decision_message FROM fast_tracks") == [
        ("active", "Uli User", "Otto Other", "agreed, it fixes CVE-x")
    ]
    assert (await _decide(otto, 1, "approve")).status_code == 400  # decided already
    assert [a[0] for a in audit(otto) if a[0].startswith("fasttrack")] == ["fasttrack_requested", "fasttrack_approved"]


async def test_a_request_can_be_rejected(people: Callable[..., Any]) -> None:
    uli = await people("uli", USER)
    await _held(uli)
    await _ask(uli)
    ada = await people("ada", ADMIN)
    assert (await _decide(ada, 1, "reject", "wait for the delay")).status_code == 303
    assert (await uli.client.get(TARBALL)).status_code == 403
    assert "wait for the delay" in (await uli.client.get("/ui/fasttrack")).text
    assert (await _ask(uli)).status_code == 303  # a new request is possible again


async def test_only_held_clean_versions(people: Callable[..., Any]) -> None:
    ada = await people("ada", ADMIN)
    await _held(ada)
    r = await _ask(ada, version="1.0.0")
    assert r.status_code == 400 and "isn&#39;t held back" in r.text
    assert (await _ask(ada, version="9.9.9")).status_code == 400  # never seen
    await ada.ctx.db.writer.run(
        lambda c: c.execute(
            "INSERT INTO artifacts (ecosystem, path, package, version, filename, first_seen, last_seen, tampered) "
            "VALUES ('npm', '/left-pad-ng/-/left-pad-ng-2.0.0.tgz', 'left-pad-ng', '2.0.0', 'x.tgz', 0, 0, 1)"
        )
    )
    r = await _ask(ada)
    assert r.status_code == 400 and "tampered" in r.text
    # Blocked by an advisory: refused, whether it is held back or not.
    await FeedScheduler(ada.ctx, [OsvFeed(ada.ctx), GithubFeed(ada.ctx)]).run_once()
    body = "eco=npm&name=malicious-npm&version=1.0.0&message=please"
    r = await ada.client.post("/ui/fasttrack", content=body, headers=FORM)
    assert r.status_code == 400 and "advisory" in r.text
    assert ada.rows("SELECT count(*) FROM fast_tracks") == [(0,)]


async def test_an_advisory_after_the_request_stops_the_approval(people: Callable[..., Any]) -> None:
    uli = await people("uli", USER)
    await _held(uli)
    await _ask(uli)
    uli.fake.control("advisory", {"ecosystem": "npm", "id": "MAL-2026-1", "package": "left-pad-ng",
                                  "versions": ["2.0.0"], "categories": ["malware"]})  # fmt: skip
    await FeedScheduler(uli.ctx, [OsvFeed(uli.ctx)]).run_once()
    otto = await people("otto", OTHER)
    r = await _decide(otto, 1, "approve")
    assert r.status_code == 400 and "advisory" in r.text
    assert otto.rows("SELECT state FROM fast_tracks") == [("pending",)]


async def test_fast_tracks_need_sign_in(running: Running, start_auth: Callable[..., Any]) -> None:
    assert "Fast-track" not in (await running.client.get("/ui/packages/npm/left-pad-ng")).text
    plain = {"Sec-Fetch-Site": "same-origin", "Content-Type": "application/x-www-form-urlencoded"}  # served over http
    r = await running.client.post("/ui/fasttrack", content="eco=npm", headers=plain)
    assert r.status_code == 400 and "UI sign-in" in r.text
    anon = await start_auth()
    await _held(anon)
    assert "Fast-track" not in (await anon.client.get("/ui/packages/npm/left-pad-ng")).text
    assert (await _ask(anon)).status_code == 400
    cross = {**FORM, "Sec-Fetch-Site": "cross-site"}
    assert (await anon.client.post("/ui/fasttrack", content="eco=npm", headers=cross)).status_code == 403


async def test_the_list_is_for_users_and_admins(people: Callable[..., Any], start_auth: Callable[..., Any]) -> None:
    anon = await start_auth()
    r = await anon.client.get("/ui/fasttrack")
    assert r.status_code == 403 and "Sign in" in r.text
    vera = await people("vera", VIEWER)
    assert (await vera.client.get("/ui/fasttrack")).status_code == 403
    uli = await people("uli", USER)
    assert (await uli.client.get("/ui/fasttrack")).status_code == 200


async def test_an_integrity_failure_stops_a_fast_track(people: Callable[..., Any]) -> None:
    """How a container image digest that didn't match is remembered: an event, not an artifact row."""
    ada = await people("ada", ADMIN)
    await _held(ada)
    await ada.ctx.db.writer.run(
        lambda c: c.execute(
            "INSERT INTO events (ts, type, ecosystem, package, version, count) "
            "VALUES (?, 'integrity_mismatch', 'npm', 'left-pad-ng', '2.0.0', 1)",
            (ada.clock.now(),),
        )
    )
    r = await _ask(ada)
    assert r.status_code == 400 and "tampered" in r.text


async def test_a_blocklist_change_in_between_means_checking_again(people: Callable[..., Any]) -> None:
    from functools import partial

    from slowshield import fasttrack as F
    from slowshield.auth import Principal

    ada = await people("ada", ADMIN)
    await _held(ada)
    me = Principal(role="admin", user_id=1, name="Ada Admin")
    stale = partial(F.create, eco="npm", name="left-pad-ng", version="2.0.0", who=me, text="now", now=0.0,
                    client_ip=None, blocklist_generation="stale")  # fmt: skip
    with pytest.raises(F.FastTrackError, match="blocklist changed"):
        await ada.ctx.db.writer.run(stale)
    assert ada.rows("SELECT count(*) FROM fast_tracks") == [(0,)]
