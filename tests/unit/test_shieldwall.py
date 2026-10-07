"""Shield wall building blocks without a server: identities, signed messages, join strings, the policy merge and the
late-news rule."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import msgspec
import pytest

from slowshield import config as config_mod
from slowshield.db import migrate
from slowshield.shieldwall import signing
from slowshield.shieldwall.apply import GRACE, MAX_OUTAGE_CREDIT, credited
from slowshield.shieldwall.identity import Identity, instance_id, key_hash
from slowshield.shieldwall.join import JoinString, JoinStringError, new_token, proof, proof_ok
from slowshield.shieldwall.policy import Bundle, BundleError, effective, loosens, tightest

NOW = 1_790_000_000.0


def _cfg(extra: dict | None = None, *, explicit: frozenset[str] = frozenset()) -> config_mod.LoadedConfig:
    cfg = msgspec.convert({"data_dir": "/tmp/unused", **(extra or {})}, config_mod.Config)
    return config_mod.build(cfg, path=None, warnings=[], explicit=explicit)


def _bundle(**kw: object) -> Bundle:
    base: dict[str, object] = {"version": 1, "default_delay_days": 7, "fail_open": True,
                               "enforce_age_on_download": True}  # fmt: skip
    return Bundle.parse({**base, **kw})


# ---- identity and signatures ----------------------------------------------------------------------------


def test_identity_is_created_once(tmp_path: Path) -> None:
    a = Identity.load_or_create(tmp_path)
    b = Identity.load_or_create(tmp_path)
    assert a.public_key == b.public_key
    assert a.id == instance_id(a.public_key)
    assert (tmp_path / "shieldwall" / "identity.key").stat().st_mode & 0o777 == 0o600
    assert len(a.fingerprint.replace("-", "")) == len(key_hash(a.public_key))


def test_request_signature_covers_method_path_query_and_body(tmp_path: Path) -> None:
    me = Identity.load_or_create(tmp_path)
    h = {
        k.lower(): v
        for k, v in signing.sign_request(me, "POST", "/_shieldwall/v1/sync", "wait=0", b"{}", now=NOW).items()
    }
    signed = signing.verify_request(
        h, "POST", "/_shieldwall/v1/sync", "wait=0", b"{}", public_key=me.public_key, now=NOW
    )
    assert signed.keyid == me.id
    for method, path, query, body in (
        ("POST", "/_shieldwall/v1/sync", "wait=0", b'{"x":1}'),
        ("POST", "/_shieldwall/v1/join", "wait=0", b"{}"),
        ("POST", "/_shieldwall/v1/sync", "wait=25", b"{}"),
        ("GET", "/_shieldwall/v1/sync", "wait=0", b"{}"),
    ):
        with pytest.raises(signing.SignatureError):
            signing.verify_request(h, method, path, query, body, public_key=me.public_key, now=NOW)
    other = Identity.load_or_create(tmp_path / "other")
    with pytest.raises(signing.SignatureError):
        signing.verify_request(h, "POST", "/_shieldwall/v1/sync", "wait=0", b"{}", public_key=other.public_key, now=NOW)
    with pytest.raises(signing.SignatureError, match="too old"):
        signing.verify_request(h, "POST", "/_shieldwall/v1/sync", "wait=0", b"{}", public_key=me.public_key,
                               now=NOW + signing.MAX_SKEW + 1)  # fmt: skip


def test_response_is_bound_to_its_request(tmp_path: Path) -> None:
    leader = Identity.load_or_create(tmp_path)
    resp = {k.lower(): v for k, v in signing.sign_response(leader, 200, b"ok", request_signature="ss=:a:",
                                                            now=NOW).items()}  # fmt: skip
    signing.verify_response(resp, 200, b"ok", request_signature="ss=:a:", public_key=leader.public_key, now=NOW)
    with pytest.raises(signing.SignatureError):  # replayed as the answer to another request
        signing.verify_response(resp, 200, b"ok", request_signature="ss=:b:", public_key=leader.public_key, now=NOW)
    with pytest.raises(signing.SignatureError):
        signing.verify_response(resp, 403, b"ok", request_signature="ss=:a:", public_key=leader.public_key, now=NOW)


# ---- join strings --------------------------------------------------------------------------------------------


def test_join_string_round_trip_and_proof() -> None:
    token, secret = new_token()
    j = JoinString("https://hq.example.com", "a" * 26, token, secret)
    assert JoinString.parse(str(j)) == j
    p = proof(secret, b"k" * 32, "sleader", 123)
    assert proof_ok(secret, b"k" * 32, "sleader", 123, p)
    assert not proof_ok(secret, b"x" * 32, "sleader", 123, p)  # bound to the follower's key
    assert not proof_ok(secret, b"k" * 32, "sother", 123, p)  # and to the leader
    for bad in ("", "ssj1:ftp://x#" + "a" * 26 + "." + token + "." + secret, str(j).replace("ssj1", "ssj2")):
        with pytest.raises(JoinStringError):
            JoinString.parse(bad)


def test_config_takes_the_join_string_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    token, secret = new_token()
    monkeypatch.setenv("SLOWSHIELD_JOIN", str(JoinString("https://hq.test", "b" * 26, token, secret)))
    monkeypatch.setenv("SLOWSHIELD_INSTANCE_LABELS", "env=prod,team=ml")
    cfg = _cfg()
    assert cfg.raw.shieldwall.role == "follower"
    assert cfg.raw.shieldwall.labels == {"env": "prod", "team": "ml"}
    monkeypatch.setenv("SLOWSHIELD_SHIELDWALL_ROLE", "leader")
    with pytest.raises(config_mod.ConfigError, match="can't also join"):
        _cfg()


# ---- policy ------------------------------------------------------------------------------------------------


def test_bundle_rejects_nonsense() -> None:
    for bad in (
        {"default_delay_days": float("nan")},
        {"default_delay_days": -1},
        {"fail_open_by_ecosystem": {"cobol": True}},
        {"exceptions": [{"ecosystem": "npm", "package": "x", "delay_days": 1e9}]},
        {"version": 0},
        {"fail_open": "yes"},
    ):
        with pytest.raises(BundleError):
            _bundle(**bad)


def test_leader_policy_is_floored_and_stricter_wins() -> None:
    local = _cfg({"default_delay_days": 10}, explicit=frozenset({"default_delay_days"}))
    eff = effective(local, _bundle(default_delay_days=3))
    assert eff.raw.default_delay_days == 10  # the instance's own explicit setting is stricter
    eff = effective(_cfg(), _bundle(default_delay_days=0))
    assert eff.raw.default_delay_days == 1  # the floor
    eff = effective(_cfg(), _bundle(default_delay_days=14))
    assert eff.raw.default_delay_days == 14
    # An exception from the leader can't go below the floor, not even for one version.
    eff = effective(_cfg(), _bundle(exceptions=[{"ecosystem": "npm", "package": "axios", "version": "1.15.1",
                                                 "delay_days": 0}]))  # fmt: skip
    assert eff.delay_days_for("npm", "axios", "1.15.1") == 1
    assert eff.delay_days_for("npm", "axios", "1.15.2") == 7


def test_local_exceptions_keep_their_authority() -> None:
    local = _cfg({"exceptions": [{"ecosystem": "pypi", "package": "internal-lib", "delay_days": 0}]})
    eff = effective(local, _bundle(default_delay_days=7))
    assert eff.delay_days_for("pypi", "internal-lib") == 0
    # ... but a stricter rule from the leader for the same package still applies.
    eff = effective(local, _bundle(exceptions=[{"ecosystem": "pypi", "package": "Internal_Lib", "delay_days": 3}]))
    assert eff.delay_days_for("pypi", "internal-lib") == 3


def test_fail_open_needs_both_sides() -> None:
    assert effective(_cfg(), _bundle(fail_open=True)).fail_open_for("npm") is True
    assert effective(_cfg(), _bundle(fail_open=False)).fail_open_for("npm") is False
    assert effective(_cfg(), _bundle(fail_open_by_ecosystem={"maven": False})).fail_open_for("maven") is False
    local = _cfg({"fail_open": False}, explicit=frozenset({"fail_open"}))
    assert effective(local, _bundle(fail_open=True)).fail_open_for("pypi") is False
    local = _cfg({"upstreams": {"cargo": {"fail_open": False}}})
    assert effective(local, _bundle(fail_open=True)).fail_open_for("cargo") is False


def test_loosening_is_detected_and_the_tightest_applies() -> None:
    oci = config_mod.OciUpstream()
    old = _bundle(exceptions=[{"ecosystem": "npm", "package": "risky", "delay_days": 30}])
    stricter = _bundle(version=2, default_delay_days=10, exceptions=old.exceptions)
    assert not loosens(old, stricter, oci)
    dropped = _bundle(version=2)  # the 30-day exception is gone: risky falls back to 7 days
    assert loosens(old, dropped, oci) == ["npm/risky: 30 → 7 days"]
    assert loosens(old, _bundle(version=2, enforce_age_on_download=False, exceptions=old.exceptions), oci)
    t = tightest(old, _bundle(version=2, default_delay_days=3, fail_open=False), oci)
    assert (t.version, t.default_delay_days, t.fail_open) == (2, 7, False)
    assert _rules_delay(t, "npm", "risky") == 30


def _rules_delay(b: Bundle, eco: str, name: str) -> float:
    return effective(_cfg(), b).delay_days_for(eco, name)


# ---- the late-news rule -----------------------------------------------------------------------------------


@pytest.fixture
def conn(tmp_path: Path) -> sqlite3.Connection:
    path = tmp_path / "x.db"
    migrate(path)
    c = sqlite3.connect(path, isolation_level=None)
    c.executemany("INSERT INTO shieldwall_sync_log (ts, head) VALUES (?, ?)", [(NOW - 3600, 100), (NOW - 60, 120)])
    return c


def test_late_news_rule(conn: sqlite3.Connection) -> None:
    week = NOW - 7 * 86400
    # Before pairing (the bootstrap): taken as claimed.
    assert credited(conn, week, 90, NOW, boot_head=100) == week
    # Logged after the last sync that didn't have it: no further back than that sync, less the grace.
    assert credited(conn, week, 121, NOW, boot_head=100) == NOW - 60 - GRACE
    # A genuine recent observation keeps its time.
    assert credited(conn, NOW - 30, 121, NOW, boot_head=100) == NOW - 30
    # Logged during an outage that began an hour ago: back to the outage, never more than a day.
    assert credited(conn, week, 110, NOW, boot_head=100) == NOW - 3600 - GRACE
    conn.execute("DELETE FROM shieldwall_sync_log WHERE head = 120")
    assert credited(conn, week, 110, NOW + 3 * 86400, boot_head=100) == NOW + 3 * 86400 - MAX_OUTAGE_CREDIT
    # Never in the future.
    assert credited(conn, NOW + 999, 121, NOW, boot_head=100) == NOW
