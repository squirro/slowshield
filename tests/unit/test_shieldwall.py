"""Shield wall building blocks without a server: identities, signed messages, join strings, the policy merge and the
late-news rule."""

from __future__ import annotations

import json
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
    tail = "#" + "a" * 26 + "." + token + "." + secret
    for bad in ("", "ssj1:ftp://x" + tail, str(j).replace("ssj1", "ssj2"), "ssj1:http://hq.example.com" + tail):
        with pytest.raises(JoinStringError):
            JoinString.parse(bad)
    assert JoinString.parse("ssj1:http://localhost:8080" + tail).url == "http://localhost:8080"
    assert JoinString.parse("ssj1:http://[::1]:8080" + tail).url == "http://[::1]:8080"
    for plain in ("http://hq.example.com", "http://10.0.0.5:8080", "http://localhost.evil.example"):
        with pytest.raises(JoinStringError, match="must be https"):
            JoinString(plain, "a" * 26, token, secret)  # however it is made


def test_an_untrusted_leader_certificate_says_what_the_follower_needs() -> None:
    from pyreqwest.exceptions import ConnectError

    from slowshield.shieldwall.transport import failure

    url = "https://hq.example.com/_shieldwall/v1/sync"
    # As pyreqwest reports a certificate nothing here trusts (Caddy's internal CA on the leader).
    untrusted = ConnectError("connection error", {"causes": [
        {"message": f"error sending request for url ({url})"}, {"message": "client error (Connect)"},
        {"message": "invalid peer certificate: UnknownIssuer"},
    ]})  # fmt: skip
    msg = failure(url, untrusted, private_ca=False)
    assert "SLOWSHIELD_LEADER_CA_FILE" in msg and "leaderCaSecret" in msg and "LEADER_CA_SECRET_FILE" in msg
    assert len(msg) <= 300  # what the Shield wall page shows of an error
    assert "is that the CA that signed it" in failure(url, untrusted, private_ca=True)
    refused = ConnectError("connection error", {"causes": [{"message": "tcp connect error: Connection refused"}]})
    assert failure(url, refused, private_ca=False) == f"{url}: ConnectError"


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


def test_only_a_configured_role_replaces_the_stored_one(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SLOWSHIELD_SHIELDWALL_ROLE", "")  # an empty Compose placeholder
    cfg = _cfg()
    assert config_mod.keep_role(cfg, "follower") and cfg.raw.shieldwall.role == "follower"  # no join string needed
    assert not config_mod.keep_role(_cfg(), None) and not config_mod.keep_role(_cfg(), "standalone")
    monkeypatch.setenv("SLOWSHIELD_SHIELDWALL_ROLE", "standalone")
    assert not config_mod.keep_role(cfg := _cfg(), "leader") and cfg.raw.shieldwall.role == "standalone"
    monkeypatch.delenv("SLOWSHIELD_SHIELDWALL_ROLE")
    path = tmp_path / "config.toml"
    path.write_text('data_dir = "/tmp/unused"\n[shieldwall]\nrole = "standalone"\n')
    assert not config_mod.keep_role(config_mod.load(path), "leader")  # set in the file
    # A reload keeps the role the instance runs with, without a restart warning or a validation error.
    path.write_text('data_dir = "/tmp/unused"\n')
    cfg = config_mod.load(path)
    assert config_mod.keep_role(cfg, "follower")
    holder = config_mod.ConfigHolder(cfg)
    path.write_text('data_dir = "/tmp/unused"\ndefault_delay_days = 9\n')
    assert holder.maybe_reload()
    assert holder.current.raw.shieldwall.role == "follower" and holder.current.raw.default_delay_days == 9


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


def test_acknowledgements_never_reach_past_what_was_sent(
    conn: sqlite3.Connection, caplog: pytest.LogCaptureFixture
) -> None:
    from slowshield.shieldwall.apply import apply_sync

    conn.execute(
        "INSERT INTO shieldwall_leader (id, leader_id, url, pubkey, join_token, state, discovered) "
        "VALUES (1, 'sl', 'https://hq.test', x'00', 't', 'active', 0)"
    )
    conn.executemany(
        "INSERT INTO shieldwall_outbox (seq, created, kind, body) VALUES (?, 0, 'stats', '{}')", [(1,), (2,), (3,)]
    )

    def outbox() -> list[int]:
        return [r[0] for r in conn.execute("SELECT seq FROM shieldwall_outbox ORDER BY seq")]

    def last_error() -> str | None:
        return conn.execute("SELECT last_error FROM shieldwall_leader").fetchone()[0]

    # An acknowledgement past the last report the request carried is refused: every report stays, and it is shown.
    with caplog.at_level("ERROR", logger="slowshield.shieldwall.apply"):
        apply_sync(conn, _cfg(), {"ack": 999, "head": 0}, NOW, sent=1, me="sme")
    assert outbox() == [1, 2, 3]
    assert "never sent" in caplog.text
    assert "sent up to 1" in (last_error() or "")
    # With nothing sent there is nothing to delete; the leader's own mark is no error.
    apply_sync(conn, _cfg(), {"ack": 999, "head": 0}, NOW, sent=0, me="sme")
    assert outbox() == [1, 2, 3] and last_error() is None
    # A proper acknowledgement deletes what it names.
    apply_sync(conn, _cfg(), {"ack": 2, "head": 0}, NOW, sent=3, me="sme")
    assert outbox() == [3] and last_error() is None


def test_malformed_fingerprints_are_ignored() -> None:
    from slowshield.shieldwall.leader import _fingerprint

    good = ["pypi", "/packages/a.whl", "a" * 64, 1.0, "alpha", "1.0"]
    assert _fingerprint(good, NOW) is not None
    for bad in (
        good[:5],
        ["cobol", *good[1:]],
        [*good[:2], "nothex" * 8, *good[3:]],
        [*good[:4], "", "1.0"],
        [*good[:2], "A" * 64, *good[3:]],
        {"ecosystem": "pypi"},
        ["pypi", "/packages/a.whl\nsother", *good[2:]],  # a control character would split the change key
        [*good[:3], float("inf"), *good[4:]],
        [*good[:3], float("nan"), *good[4:]],
        [*good[:3], 10**400, *good[4:]],  # too large for a float: refused, not an OverflowError
        [*good[:3], NOW + 3600, *good[4:]],  # seen in the future
        [*good[:3], True, *good[4:]],
    ):
        assert _fingerprint(bad, NOW) is None


def test_numbers_from_another_instance_are_read_strictly(monkeypatch: pytest.MonkeyPatch) -> None:
    from slowshield.shieldwall import wire

    assert wire.loads(b'{"a": 9223372036854775807, "b": -1.5e300}') == {"a": 2**63 - 1, "b": -1.5e300}
    huge = b"[1" + b"0" * 400 + b"]"
    for bad in (b"[NaN]", b"[Infinity]", b"[-Infinity]", b"[1e999]", b"[9223372036854775808]", huge):
        with pytest.raises(ValueError, match=r"out of range|is not a number"):
            wire.loads(bad)

    # How deep JSON may nest before the parser gives up depends on the platform's stack; when it does, the message
    # is malformed like any other, not a RecursionError the caller doesn't expect.
    def too_deep(*args: object, **kwargs: object) -> None:
        raise RecursionError

    monkeypatch.setattr(json, "loads", too_deep)
    with pytest.raises(ValueError, match="nested too deeply"):
        wire.loads(b"[]")
    assert wire.seq(wire.MAX_SEQ) == wire.MAX_SEQ
    for value in (-1, wire.MAX_SEQ + 1, 1.0, True, "1", None):
        with pytest.raises(ValueError, match="not a sequence number"):
            wire.seq(value)


def test_a_report_that_cant_be_applied_is_passed_not_retried(conn: sqlite3.Connection) -> None:
    from slowshield.shieldwall.leader import apply_outbox

    entries = [
        # Its second row is too large for SQLite: the first row is undone with it.
        {"seq": 1, "kind": "stats", "body": f'{{"lookups":[[0,"npm","registry",1],[0,"npm","proxy",{2**64 - 1}]]}}'},
        {"seq": 2, "kind": "fingerprints", "body": f'[["pypi","/p/a.whl","{"a" * 64}",NaN,"a","1"]]'},
        {"seq": 3, "kind": "fingerprints", "body": f'[["pypi","/p/a.whl","{"a" * 64}",1{"0" * 400},"a","1"]]'},
        {"seq": 4, "kind": "fingerprints", "body": '{"not": "a list"}'},
        {"seq": 5, "kind": "stats", "body": '{"lookups":[[0,"pypi","registry",2]]}'},
    ]
    assert apply_outbox(conn, "sfollower", 0, entries, NOW) == 5
    assert conn.execute("SELECT ecosystem, source, instance, count FROM lookups_5min").fetchall() == [
        ("pypi", "registry", "sfollower", 2)
    ]
    assert conn.execute("SELECT count(*) FROM shieldwall_fingerprints").fetchone() == (0,)


def test_a_sync_is_held_open_only_for_a_number_of_seconds() -> None:
    from slowshield.shieldwall.leader import MAX_WAIT, _wait

    assert [_wait(t) for t in ("", "10", "-5", "99", "nan", "inf", "1e999", "soon")] == [
        0.0, 10.0, 0.0, MAX_WAIT, 0.0, 0.0, 0.0, 0.0,
    ]  # fmt: skip


def test_history_at_pairing_comes_in_small_entries_even_for_long_go_paths(conn: sqlite3.Connection) -> None:
    from slowshield import names
    from slowshield.ecosystems.go import module as go
    from slowshield.shieldwall.follower import BACKFILL_BYTES, _backfill
    from slowshield.shieldwall.leader import MAX_BODY, _fingerprint

    # The longest valid Go module path, all upper case: its artifact path doubles once `!`-escaped.
    count = 3000
    rows = []
    for i in range(count):
        module = f"example.com/M{i:04d}/" + "A" * (names.GO_MAX_LEN - 18)
        assert len(module) == names.GO_MAX_LEN and names.is_valid_go(module)
        version = "v1.0.0-RC"
        assert go.is_canonical(version)
        path = f"/{go.escape(module)}/@v/{go.escape(version)}.zip"
        rows.append(("go", path, module, version, "x.zip", f"{i:064x}", NOW, NOW))
    assert len(rows[0][1]) > 2048 and len(rows[0][2]) > 300  # past what the leader took before
    conn.executemany(
        "INSERT INTO artifacts (ecosystem, path, package, version, filename, sha256, first_seen, last_seen) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    _backfill(conn, NOW)
    bodies = [r[0] for r in conn.execute("SELECT body FROM shieldwall_outbox WHERE kind = 'fingerprints' ORDER BY seq")]
    # Once 5,000 rows to an entry: about 9 MB here, past the leader's 8 MB limit, and the sync stuck behind it.
    assert len(bodies) > 1
    assert all(len(b.encode()) <= BACKFILL_BYTES for b in bodies) and BACKFILL_BYTES * 8 < MAX_BODY
    sent = [item for b in bodies for item in json.loads(b)]
    assert len(sent) == count
    # And the leader takes every one of them: long Go module paths and package names are well formed.
    assert all(_fingerprint(item, NOW) is not None for item in sent)


def test_a_followers_fingerprint_is_evidence_about_that_follower_only(conn: sqlite3.Connection) -> None:
    from slowshield.shieldwall.leader import apply_outbox

    conn.execute(
        "INSERT INTO artifacts (ecosystem, path, package, version, filename, sha256, first_seen, last_seen) "
        "VALUES ('pypi', '/p/alpha.whl', 'alpha', '1.0', 'alpha.whl', ?, 0, 0)",
        ("a" * 64,),
    )
    conn.executemany("INSERT INTO shieldwall_members (id, pubkey, name, state, joined) VALUES (?, ?, ?, 'active', 0)",
                     [("sliar", b"1", "liar"), ("shonest", b"2", "honest")])  # fmt: skip

    def report(member: str, *rows: list[object]) -> None:
        apply_outbox(conn, member, 0, [{"seq": 1, "kind": "fingerprints", "body": json.dumps(rows)}], NOW)

    def events() -> list[tuple[str, str, str]]:
        return conn.execute("SELECT type, package, instance FROM events ORDER BY rowid").fetchall()

    # Other bytes than the leader's, for the package and version the leader has on record: refused on that
    # follower only (a change only it receives), never on the leader.
    report("sliar", ["pypi", "/p/alpha.whl", "b" * 64, NOW, "alpha", "1.0"])
    assert conn.execute("SELECT dataset, key FROM shieldwall_changes").fetchall() == [
        ("flag", "pypi\n/p/alpha.whl\nsliar")
    ]
    assert events() == [("tampered", "alpha", "sliar")]
    assert conn.execute("SELECT tampered FROM artifacts").fetchall() == [(0,)]
    # A fingerprint that names another package or version for a file the leader knows is refused outright.
    report("shonest", ["pypi", "/p/alpha.whl", "b" * 64, NOW, "beta", "1.0"])
    report("shonest", ["pypi", "/p/alpha.whl", "b" * 64, NOW, "alpha", "6.6.6"])
    assert conn.execute("SELECT count(*) FROM shieldwall_fingerprints WHERE instance = 'shonest'").fetchone() == (0,)
    assert len(events()) == 1
    # A file the leader has no record of: a liar who reports first can't put an event on an honest follower's
    # timeline. The disagreement is the leader's own finding, naming both, and refuses nothing.
    report("sliar", ["pypi", "/p/gamma.whl", "c" * 64, NOW, "gamma", "1.0"])
    report("shonest", ["pypi", "/p/gamma.whl", "d" * 64, NOW, "gamma", "1.0"])
    assert events()[1:] == [("integrity_mismatch", "gamma", "")]
    details = json.loads(conn.execute("SELECT details FROM events ORDER BY rowid DESC").fetchone()[0])
    assert details["problems"] == [f"honest: {'d' * 64}", f"liar: {'c' * 64}"]
    assert conn.execute("SELECT count(*) FROM shieldwall_changes").fetchone() == (1,)
