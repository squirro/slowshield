"""A leader and a follower in one process: pairing, reports up, policy and blocks down, files via the leader, and
the follower on its own when the leader is gone."""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest

from slowshield import config as config_mod
from slowshield.app import create_app, sync_blocks
from slowshield.clock import FrozenClock
from slowshield.shieldwall import follower as follower_mod
from slowshield.shieldwall import runtime
from slowshield.shieldwall.follower import FollowerService
from slowshield.shieldwall.identity import key_hash
from slowshield.shieldwall.join import JoinString, new_token
from slowshield.shieldwall.transport import Reply, TransportError
from tests.conftest import NOW, Running, stop

LEADER_URL = "https://leader.test"
DAY = 86400.0


class AsgiTransport:
    """The follower's HTTP to its leader, straight into the leader app. `down` makes the leader unreachable."""

    def __init__(self, app: Any) -> None:
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=LEADER_URL)
        self.down = False
        self.calls: list[str] = []

    async def send(self, method: str, url: str, headers: dict[str, str], body: bytes, limit: float) -> Reply:
        if self.down:
            raise TransportError(f"{url}: ConnectError")
        self.calls.append(url)
        r = await self.client.request(method, url, headers=headers, content=body)
        return Reply(r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.content)

    @asynccontextmanager
    async def stream(self, url: str, headers: dict[str, str]) -> AsyncIterator[tuple[int, dict[str, str], Any]]:
        if self.down:
            raise TransportError(f"{url}: ConnectError")
        self.calls.append(url)
        async with self.client.stream("GET", url, headers=headers) as r:
            yield r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.aiter_raw()

    async def close(self) -> None:
        await self.client.aclose()


class Pair:
    def __init__(self, leader: Running, follower: Running, service: FollowerService, net: AsgiTransport) -> None:
        self.leader, self.follower, self.service, self.net = leader, follower, service, net

    async def sync(self) -> None:
        await self.follower.drain()
        await self.service.step()  # applies what it took on this worker at once (no refresh here)
        await self.leader.drain()


@pytest.fixture
def start(make_config: Callable[..., config_mod.LoadedConfig], upstream: Any, tmp_path: Path) -> Any:
    """Starts an instance with its own data directory (`pair` stops them)."""

    async def go(name: str, extra: str, clock: FrozenClock) -> Running:
        cfg = make_config(extra, data_dir=tmp_path / name)
        app = create_app(cfg, clock=clock, background=False)
        await app.startup()
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://slowshield.test")
        return Running(app, client, clock, upstream)

    return go


@pytest.fixture
async def pair(start: Any, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Pair]:
    monkeypatch.setattr(follower_mod, "SYNC_WAIT", 0)
    clock = FrozenClock(NOW)
    leader = await start("leader", LEADER_CONFIG, clock)
    identity = leader.app._identity
    assert identity is not None
    token, secret = new_token()
    await leader.ctx.db.writer.run(
        lambda c: c.execute(
            "INSERT INTO shieldwall_tokens (id, secret, created, expires, name, location) VALUES (?, ?, ?, ?, ?, ?)",
            (token, secret, NOW, NOW + 600, "zurich-1", "zurich"),
        )
    )
    join = JoinString(LEADER_URL, key_hash(identity.public_key), token, secret)
    follower = await start("follower", f'[shieldwall]\njoin = "{join}"\n' + FOLLOWER_CONFIG, clock)
    net = AsgiTransport(leader.app)
    via = follower.ctx.artifacts.via
    assert via is not None
    await via.transport.close()
    via.transport = net
    assert follower.app._identity is not None
    service = FollowerService(follower.ctx, follower.app._identity, send=net.send)
    yield Pair(leader, follower, service, net)
    await net.close()
    for run in (follower, leader):
        await stop(run)


LEADER_CONFIG = """
default_delay_days = 3
[shieldwall]
role = "leader"
name = "hq"
location = "hq"
[[blocks]]
ecosystem = "npm"
package = "evil-pkg"
reason = "operator block on the leader"
"""

FOLLOWER_CONFIG = """
name = "zurich-1"
location = "zurich"
labels = { env = "prod" }
[cache]
artifacts_enabled = false
"""


async def _join(p: Pair) -> None:
    assert await p.service.step() == 2.0  # discovered, waiting for the operator
    leader_id = p.follower.rows("SELECT leader_id FROM shieldwall_leader")[0][0]
    page = await p.follower.client.get("/ui/shieldwall")
    assert "Join hq?" in page.text and p.leader.app._identity.fingerprint in page.text  # type: ignore[union-attr]
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    cross = {**form, "Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"}
    r = await p.follower.client.post("/ui/shieldwall/join", content=f"leader={leader_id}", headers=cross)
    assert r.status_code == 403
    other_scheme = {**form, "Origin": "https://slowshield.test"}  # this UI is served over http here
    r = await p.follower.client.post("/ui/shieldwall/join", content=f"leader={leader_id}", headers=other_scheme)
    assert r.status_code == 403
    same = {**form, "Origin": "http://slowshield.test", "Sec-Fetch-Site": "same-origin"}
    r = await p.follower.client.post("/ui/shieldwall/join", content=f"leader={leader_id}", headers=same)
    assert r.status_code == 303
    await p.service.step()  # join
    assert p.follower.rows("SELECT state, confirmed_by FROM shieldwall_leader") == [("active", "ui")]
    await p.sync()


def _wheel(run: Running, project: str = "alpha", version: str = "1.0.0") -> str:
    files = run.fake.info()["pypi"][project][version]
    return next(f["path"] for f in files if f["filename"].endswith(".whl"))


async def test_pairing_reports_and_policy(pair: Pair) -> None:
    p = pair
    # The follower served something before it joined: its history goes up with the join.
    path = _wheel(p.follower)
    assert (await p.follower.client.get(f"/pypi{path}")).status_code == 200
    await _join(p)
    member = p.follower.app._identity.id  # type: ignore[union-attr]
    assert p.leader.rows("SELECT name, location, labels, state FROM shieldwall_members") == [
        ("zurich-1", "zurich", '{"env": "prod"}', "active")
    ]
    assert p.leader.rows("SELECT sum(serves) FROM downloads_5min WHERE instance = ?", (member,)) == [(1,)]
    assert p.leader.rows("SELECT name FROM packages WHERE ecosystem = 'pypi'") == [("alpha",)]
    # Later reports arrive exactly once, and the follower's outbox empties.
    assert (await p.follower.client.get(f"/pypi{_wheel(p.follower, version='1.1.0')}")).status_code == 200
    await p.sync()
    await p.sync()
    assert p.leader.rows("SELECT sum(serves) FROM downloads_5min WHERE instance = ?", (member,)) == [(2,)]
    assert p.follower.rows("SELECT count(*) FROM shieldwall_outbox") == [(0,)]
    # The leader's policy applies: 3 days (the follower doesn't set its own delay).
    assert p.follower.ctx.cfg.raw.default_delay_days == 3
    # The leader's overview narrows to the follower, its location or its label.
    for scope in (member, "loc:zurich", "label:env=prod"):
        r = await p.leader.client.get(f"/ui/?in={scope}")
        assert r.status_code == 200
    r = await p.leader.client.get("/ui/shieldwall")
    assert "zurich-1" in r.text
    # The security CSV keeps the scope it was narrowed to.
    await p.leader.ctx.db.writer.run(
        lambda c: c.executemany(
            "INSERT INTO events (ts, type, ecosystem, package, count, instance) VALUES (?, 'blocked', 'npm', ?, 1, ?)",
            [(NOW, "seen-here", ""), (NOW, "seen-there", member)],
        )
    )
    page = await p.leader.client.get(f"/ui/security?in={member}")
    assert f"/ui/security.csv?range=30d&amp;in={member}" in page.text
    csv = (await p.leader.client.get(f"/ui/security.csv?in={member}")).text
    assert "seen-there" in csv and "seen-here" not in csv


async def test_loosening_waits_and_tightening_does_not(pair: Pair) -> None:
    p = pair
    await _join(p)
    leader_cfg = p.leader.ctx.cfg
    assert p.follower.ctx.cfg.raw.default_delay_days == 3

    def leader_policy(**changes: Any) -> None:
        import msgspec

        raw = msgspec.structs.replace(leader_cfg.raw, **changes)
        p.leader.ctx.config.local = p.leader.ctx.config.current = config_mod.build(
            raw, path=None, warnings=[], generation=leader_cfg.generation + 1
        )

    leader_policy(default_delay_days=10)
    await p.sync()
    assert p.follower.ctx.cfg.raw.default_delay_days == 10  # tighter: at once

    leader_policy(default_delay_days=2)
    await p.sync()
    assert p.follower.ctx.cfg.raw.default_delay_days == 10  # looser: waits
    assert p.follower.rows("SELECT kind FROM shieldwall_pending") == [("policy",)]
    page = await p.follower.client.get("/ui/shieldwall")
    assert "Looser policy" in page.text
    p.follower.clock.advance(3601)
    await runtime.housekeeping(p.follower.ctx)
    await runtime.refresh(p.follower.ctx)
    assert p.follower.ctx.cfg.raw.default_delay_days == 2

    leader_policy(default_delay_days=0)
    await p.sync()
    p.follower.clock.advance(3601)
    await runtime.housekeeping(p.follower.ctx)
    await runtime.refresh(p.follower.ctx)
    assert p.follower.ctx.cfg.raw.default_delay_days == 1  # never below the floor


async def test_blocks_come_down_and_lifting_waits(pair: Pair) -> None:
    p = pair
    await _join(p)
    rows = p.follower.rows("SELECT ecosystem, name, source, reason FROM blocklist WHERE withdrawn IS NULL")
    assert ("npm", "evil-pkg", "leader", "operator block on the leader") in rows
    assert p.follower.ctx.blocklist.for_package("npm", "evil-pkg").package_block is not None
    # The leader lifts it: the follower keeps it for a day.
    import msgspec

    raw = msgspec.structs.replace(p.leader.ctx.cfg.raw, blocks=[])
    p.leader.ctx.config.local = p.leader.ctx.config.current = config_mod.build(raw, path=None, warnings=[])
    await sync_blocks(p.leader.ctx)
    await p.sync()
    assert p.follower.rows("SELECT count(*) FROM blocklist WHERE source = 'leader' AND withdrawn IS NULL") == [(1,)]
    p.follower.clock.advance(DAY + 1)
    await runtime.housekeeping(p.follower.ctx)
    assert p.follower.rows("SELECT count(*) FROM blocklist WHERE source = 'leader' AND withdrawn IS NULL") == [(0,)]


async def test_files_come_through_the_leader_and_its_cache(pair: Pair) -> None:
    p = pair
    await _join(p)
    path = _wheel(p.follower, version="1.1.0")
    r = await p.follower.client.get(f"/pypi{path}")
    assert r.status_code == 200
    await p.follower.drain()
    await p.leader.drain()
    sha = hashlib.sha256(r.content).hexdigest()
    assert any("/_shieldwall/v1/blob" in c for c in p.net.calls)
    assert p.leader.rows("SELECT count(*) FROM cache_entries WHERE sha256 = ?", (sha,)) == [(1,)]
    assert p.follower.rows("SELECT sum(leader_bytes) FROM downloads_5min") == [(len(r.content),)]
    fetched = sum(p.leader.fake.hits(prefix="/files").values())
    # Again (this follower keeps no cache): the leader's cache answers, the registry isn't asked.
    again = await p.follower.client.get(f"/pypi{path}")
    assert again.status_code == 200 and again.content == r.content
    assert sum(p.leader.fake.hits(prefix="/files").values()) == fetched
    # The leader is gone: the follower goes to the registry itself and keeps serving.
    p.net.down = True
    r = await p.follower.client.get(f"/pypi{path}")
    assert r.status_code == 200
    assert sum(p.leader.fake.hits(prefix="/files").values()) == fetched + 1


async def test_follower_runs_on_its_own_and_catches_up(pair: Pair) -> None:
    p = pair
    await _join(p)
    p.net.down = True
    with pytest.raises(TransportError):
        await p.service.step()
    assert (await p.follower.client.get(f"/pypi{_wheel(p.follower)}")).status_code == 200
    await p.follower.drain()
    assert p.follower.rows("SELECT kind FROM shieldwall_outbox ORDER BY seq") == [("fingerprints",), ("stats",)]
    assert p.follower.ctx.cfg.raw.default_delay_days == 3  # the leader's last policy still applies
    p.net.down = False
    await p.sync()
    member = p.follower.app._identity.id  # type: ignore[union-attr]
    assert p.leader.rows("SELECT sum(serves) FROM downloads_5min WHERE instance = ?", (member,)) == [(1,)]


async def test_removed_follower_goes_its_own_way(pair: Pair) -> None:
    p = pair
    await _join(p)
    await p.leader.ctx.db.writer.run(lambda c: c.execute("UPDATE shieldwall_members SET state = 'removed'"))
    await p.sync()
    assert p.follower.rows("SELECT state FROM shieldwall_leader") == [("removed",)]
    await runtime.refresh(p.follower.ctx)
    assert p.follower.ctx.cfg.raw.default_delay_days == 7  # back to its own config


async def test_leader_refuses_bad_joins(pair: Pair) -> None:
    p = pair
    await _join(p)
    # The invitation is used up: a second instance can't join with it.
    body = json.dumps({"pubkey": "AAAA", "token": "x"}).encode()
    r = await p.net.client.post("/_shieldwall/v1/join", content=body)
    assert r.status_code == 400
    # An unknown key can't sync.
    r = await p.net.client.post("/_shieldwall/v1/sync", content=b"{}")
    assert r.status_code == 403
    # Nothing but a signed member gets files.
    r = await p.net.client.get("/_shieldwall/v1/blob", params={"sha256": "0" * 64, "url": "https://example.com/x"})
    assert r.status_code == 403


async def test_a_follower_that_saw_other_bytes_refuses_the_file(pair: Pair) -> None:
    from slowshield.shieldwall.leader import change_rows

    p = pair
    await _join(p)
    path = _wheel(p.follower)
    assert (await p.leader.client.get(f"/pypi{path}")).status_code == 200
    await p.leader.drain()
    # The leader saw other bytes for this file than the follower is about to.
    await p.leader.ctx.db.writer.run(
        lambda c: c.execute("UPDATE artifacts SET sha256 = ? WHERE path = ?", ("f" * 64, path))
    )
    p.net.down = True  # straight from the registry
    assert (await p.follower.client.get(f"/pypi{path}")).status_code == 200
    p.net.down = False
    await p.sync()  # the fingerprint goes up, the leader flags the file for this follower
    await p.sync()  # the flag comes down
    assert p.follower.rows("SELECT tampered FROM artifacts WHERE path = ?", (path,)) == [(1,)]
    assert (await p.follower.client.get(f"/pypi{path}")).status_code == 451
    # A follower's word refuses the file on that follower only: not on the leader, and no other follower hears of it.
    assert p.leader.rows("SELECT tampered FROM artifacts WHERE path = ?", (path,)) == [(0,)]
    member = p.follower.app._identity.id  # type: ignore[union-attr]
    assert p.leader.rows("SELECT type, instance FROM events WHERE type = 'tampered'") == [("tampered", member)]
    others, _ = change_rows(p.leader.ctx.db.readers.get(), 0, 1000, "sother")
    assert not [c for c in others if c["dataset"] == "flag"]


async def test_cli_invite_members_and_remove(
    pair: Pair, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    from slowshield import cli

    p = pair
    await _join(p)
    raw = p.leader.ctx.cfg.raw
    conf = tmp_path / "leader.toml"
    conf.write_text(f'data_dir = "{raw.data_dir}"\npublic_url = "{LEADER_URL}"\n[shieldwall]\nrole = "leader"\n')
    assert cli.main(["wall", "invite", "--config", str(conf), "-q"]) == 0
    join = JoinString.parse(capsys.readouterr().out.strip())
    assert join.url == LEADER_URL and join.key_hash == key_hash(p.leader.app._identity.public_key)  # type: ignore[union-attr]
    assert cli.main(["wall", "members", "--config", str(conf)]) == 0
    assert "zurich-1" in capsys.readouterr().out
    assert cli.main(["wall", "remove", "zurich-1", "--config", str(conf)]) == 0
    assert p.leader.rows("SELECT state FROM shieldwall_members") == [("removed",)]
    standalone = tmp_path / "standalone.toml"
    standalone.write_text(f'data_dir = "{tmp_path / "solo"}"\npublic_url = "{LEADER_URL}"\n')
    assert cli.main(["wall", "invite", "--config", str(standalone)]) == 2


async def test_followers_that_disagree_are_reported_not_flagged(pair: Pair) -> None:
    p = pair
    await _join(p)
    path = _wheel(p.follower, version="1.1.0")
    # Another follower reported other bytes for this file earlier; the leader never served it, so it can't tell
    # which of them is right.
    await p.leader.ctx.db.writer.run(
        lambda c: c.execute(
            "INSERT INTO shieldwall_fingerprints (ecosystem, path, instance, sha256, first_seen, package, version) "
            "VALUES ('pypi', ?, 'sother', ?, 0, 'alpha', '1.1.0')",
            (path, "e" * 64),
        )
    )
    p.net.down = True
    assert (await p.follower.client.get(f"/pypi{path}")).status_code == 200
    p.net.down = False
    await p.sync()
    await p.sync()
    assert p.leader.rows("SELECT count(*) FROM artifacts WHERE path = ?", (path,)) == [(0,)]
    assert p.leader.rows("SELECT type, package FROM events WHERE ecosystem = 'pypi'") == [
        ("integrity_mismatch", "alpha")
    ]
    assert (await p.follower.client.get(f"/pypi{path}")).status_code == 200


async def test_only_the_leader_can_remove_a_follower(pair: Pair) -> None:
    p = pair
    await _join(p)
    real = p.service.send

    async def forged(method: str, url: str, headers: dict[str, str], body: bytes, limit: float) -> Reply:
        if "/sync" in url:
            return Reply(403, {"content-type": "application/json"}, b'{"error":"removed"}')
        return await real(method, url, headers, body, limit)

    p.service.send = forged
    with pytest.raises(TransportError):
        await p.service.step()
    assert p.follower.rows("SELECT state FROM shieldwall_leader") == [("active",)]
    await runtime.refresh(p.follower.ctx)
    assert p.follower.ctx.cfg.raw.default_delay_days == 3  # still the leader's policy


async def test_files_served_before_pairing_are_compared_too(pair: Pair) -> None:
    p = pair
    path = _wheel(p.follower)
    assert (await p.leader.client.get(f"/pypi{path}")).status_code == 200
    await p.leader.drain()
    await p.leader.ctx.db.writer.run(
        lambda c: c.execute("UPDATE artifacts SET sha256 = ? WHERE path = ?", ("f" * 64, path))
    )
    assert (await p.follower.client.get(f"/pypi{path}")).status_code == 200  # before joining
    await p.follower.drain()
    await _join(p)  # the history at pairing carries the fingerprint
    await p.sync()
    assert p.follower.rows("SELECT tampered FROM artifacts WHERE path = ?", (path,)) == [(1,)]
