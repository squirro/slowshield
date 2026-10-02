"""Names, versions, ranges and the age policy — including property-based invariants."""

from __future__ import annotations

import itertools
import math

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from slowshield import names, policy, versions
from slowshield.ecosystems.npm.packument import recompute_tags
from slowshield.policy import DAY, Candidate, evaluate

# ---- names ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "norm"),
    [("Markdown_It.PY", "markdown-it-py"), ("a--b__c..d", "a-b-c-d"), ("simple", "simple"), ("X", "x")],
)
def test_pep503(raw: str, norm: str) -> None:
    assert names.normalize_pypi(raw) == norm


@pytest.mark.parametrize("name", ["requests", "Flask-SQLAlchemy", "a", "zope.interface", "x_1"])
def test_valid_pypi(name: str) -> None:
    assert names.is_valid_pypi(name)


@pytest.mark.parametrize("name", ["", "-a", "a-", "_a", "a b", "a/b", "x" * 201, "../etc"])
def test_invalid_pypi(name: str) -> None:
    assert not names.is_valid_pypi(name)


@pytest.mark.parametrize("name", ["lodash", "@babel/core", "JSONStream", "a.b-c_d~e", "@scope/x"])
def test_valid_npm(name: str) -> None:
    assert names.is_valid_npm(name)


@pytest.mark.parametrize(
    "name", ["", ".hidden", "_private", "@scope/.x", "node_modules", "favicon.ico", "a b", "@a/b/c", "x" * 215, "a?b"]
)
def test_invalid_npm(name: str) -> None:
    assert not names.is_valid_npm(name)


def test_npm_basename() -> None:
    assert names.npm_basename("@babel/core") == "core" and names.npm_basename("lodash") == "lodash"
    assert names.normalize_npm(" x ") == "x"


# ---- versions ---------------------------------------------------------------------------------


def test_semver_ordering() -> None:
    ordered = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
        "1.0.1",
        "1.10.0",
        "2.0.0",
    ]
    shuffled = sorted(ordered, key=lambda v: versions.sort_key("npm", v))
    assert shuffled == ordered
    a, b = versions.parse_semver("1.2.3"), versions.parse_semver("v1.2.4+build")
    assert a and b and a < b and b > a and a <= b and b >= a
    assert versions.parse_semver("1.2") is None and versions.parse_semver("01.2.3") is None
    assert versions.is_prerelease("npm", "1.0.0-rc.1") and not versions.is_prerelease("npm", "1.0.0")
    assert versions.sort_key("npm", "garbage") < versions.sort_key("npm", "0.0.1")


def test_pep440() -> None:
    assert versions.canonical("pypi", "1.0") == "1.0" and versions.canonical("pypi", "1.0.0.post0") == "1.0.0.post0"
    assert versions.canonical("pypi", "not a version ") == "not a version"
    assert versions.canonical("npm", "v1.2.3") == "1.2.3" and versions.canonical("npm", "latest ") == "latest"
    assert versions.is_prerelease("pypi", "2.0.0rc1") and versions.is_prerelease("pypi", "1.0.dev1")
    assert not versions.is_prerelease("pypi", "1.0") and not versions.is_prerelease("pypi", "garbage")
    assert versions.sort_key("pypi", "1.10") > versions.sort_key("pypi", "1.9") > versions.sort_key("pypi", "bad")


@pytest.mark.parametrize(
    ("eco", "version", "spec", "expected"),
    [
        ("npm", "1.14.1", "= 1.14.1", True),
        ("npm", "1.14.2", "= 1.14.1", False),
        ("npm", "1.5.0", ">= 1.0.0, < 2.0.0", True),
        ("npm", "2.0.0", ">= 1.0.0, < 2.0.0", False),
        ("npm", "0.3.2", "<= 0.3.2", True),
        ("npm", "0.3.3", "> 0.3.2", True),
        ("npm", "1.0.0", "!= 1.0.0", False),
        ("npm", "9.9.9", ">= 0", True),
        ("npm", "1.0.0", "== 1.0.0", True),
        ("pypi", "1.0.0", "= 1.0", True),
        ("pypi", "2.0", ">= 1.0, < 2.0", False),
        ("pypi", "1.5.post1", "> 1.5", True),
        ("npm", "weird", "= weird", True),
        ("npm", "weird", ">= 1.0.0", False),
        ("npm", "1.0.0", "", False),
        ("npm", "1.0.0", "~> 1.0", False),
        ("npm", "1.0.0", "= 1.0.0, garbage here", False),
    ],
)
def test_in_range(eco: str, version: str, spec: str, expected: bool) -> None:
    assert versions.in_range(eco, version, spec) is expected


def test_range_helpers() -> None:
    assert versions.range_is_everything(None) and versions.range_is_everything(">= 0")
    assert versions.range_is_everything(">=0.0.0") and versions.range_is_everything("")
    assert not versions.range_is_everything(">= 1.0")
    assert versions.exact_version("= 1.2.3") == "1.2.3" and versions.exact_version("== 2") == "2"
    assert versions.exact_version(">= 1") is None and versions.exact_version(None) is None
    assert versions.exact_version("= 1, = 2") is None


semver_strategy = st.builds(
    lambda a, b, c, pre: f"{a}.{b}.{c}" + (f"-{pre}" if pre else ""),
    st.integers(0, 30),
    st.integers(0, 30),
    st.integers(0, 30),
    st.sampled_from(["", "alpha", "beta.1", "rc.2", "0"]),
)


@given(st.lists(semver_strategy, min_size=1, max_size=40, unique=True))
def test_semver_sort_is_total_and_consistent(vs: list[str]) -> None:
    ordered = sorted(vs, key=lambda v: versions.sort_key("npm", v))
    for a, b in itertools.pairwise(ordered):
        pa, pb = versions.parse_semver(a), versions.parse_semver(b)
        assert pa is not None and pb is not None and pa <= pb


# ---- policy -------------------------------------------------------------------------------------

NOW = 1_800_000_000.0


def test_age_helpers() -> None:
    assert policy.is_old_enough(NOW - 7 * DAY, 7, NOW)  # boundary inclusive
    assert not policy.is_old_enough(NOW - 7 * DAY + 1, 7, NOW)
    assert not policy.is_old_enough(None, 7, NOW)
    assert policy.is_old_enough(None, 0, NOW) and not policy.is_old_enough(NOW + 10, 0, NOW)
    assert policy.retry_after(NOW - DAY, 7, NOW) == 6 * DAY
    assert policy.retry_after(None, 7, NOW) is None
    assert policy.retry_after(NOW - 30 * DAY, 7, NOW) == 0
    assert policy.age_seconds(NOW - 5, NOW) == 5 and policy.age_seconds(None, NOW) is None


def test_evaluate_basic_and_next_change() -> None:
    cands = [
        Candidate("old", "1.0", NOW - 30 * DAY),
        Candidate("new", "2.0", NOW - DAY),
        Candidate("bad", "1.5", NOW - 20 * DAY),
    ]
    ev = evaluate(cands, now=NOW, delay_for=lambda _v: 7, is_blocked=lambda v: v == "1.5", fail_open=True)
    assert [c.item for c in ev.allowed] == ["old"]
    assert [c.item for c in ev.held] == ["new"]
    assert [c.item for c in ev.blocked] == ["bad"]
    assert not ev.fail_open and ev.next_change == NOW + 6 * DAY
    assert not ev.everything_blocked


def test_everything_blocked() -> None:
    ev = evaluate(
        [Candidate("x", "1", NOW - 99 * DAY)],
        now=NOW,
        delay_for=lambda _v: 7,
        is_blocked=lambda _v: True,
        fail_open=True,
    )
    assert ev.everything_blocked and ev.next_change == math.inf


candidate_strategy = st.lists(
    st.tuples(
        st.sampled_from(["1.0.0", "1.1.0", "2.0.0", "2.1.0", "3.0.0-rc.1", None]),
        st.one_of(st.none(), st.floats(min_value=-30 * DAY, max_value=60 * DAY)),
        st.booleans(),
    ),
    max_size=25,
)


@settings(max_examples=300)
@given(candidate_strategy, st.floats(0, 14), st.booleans())
def test_policy_invariants(raw: list, delay: float, fail_open: bool) -> None:
    cands = [Candidate(i, v, None if age is None else NOW - age) for i, (v, age, _b) in enumerate(raw)]
    blocked_ids = {i for i, (_v, _a, b) in enumerate(raw) if b}
    ev = evaluate(cands, now=NOW, delay_for=lambda _v: delay, is_blocked=lambda _v: False, fail_open=fail_open)
    ev_b = evaluate(
        cands,
        now=NOW,
        delay_for=lambda _v: delay,
        is_blocked=lambda v: any(raw[i][0] == v for i in blocked_ids),
        fail_open=fail_open,
    )
    for e in (ev, ev_b):
        # never serve something too new unless failing open
        if not e.fail_open:
            assert all(policy.is_old_enough(c.published, delay, NOW) for c in e.allowed)
        else:
            assert fail_open and not any(policy.is_old_enough(c.published, delay, NOW) for c in e.allowed)
        assert len(e.allowed) + len(e.held) + len(e.blocked) == len(cands)
    # blocked versions are never served, even when failing open
    blocked_versions = {raw[i][0] for i in blocked_ids}
    assert not any(c.version in blocked_versions for c in ev_b.allowed)


@given(
    st.lists(semver_strategy, min_size=1, max_size=30, unique=True),
    st.dictionaries(st.sampled_from(["latest", "next", "beta"]), semver_strategy, max_size=3),
)
def test_dist_tags_point_at_served_versions(kept: list[str], original: dict[str, str]) -> None:
    tags = recompute_tags(original, kept)
    assert "latest" in tags
    assert set(tags.values()) <= set(kept)
    stable = [v for v in kept if not versions.is_prerelease("npm", v)]
    if original.get("latest") not in kept and stable:
        assert not versions.is_prerelease("npm", tags["latest"])


def test_recompute_tags_cases() -> None:
    assert recompute_tags({"latest": "2.0.0"}, []) == {}
    assert recompute_tags({"latest": "1.0.0", "next": "2.0.0"}, ["1.0.0", "2.0.0"]) == {
        "latest": "1.0.0",
        "next": "2.0.0",
    }
    assert recompute_tags({"latest": "2.0.0"}, ["1.0.0", "3.0.0"])["latest"] == "1.0.0"
    assert recompute_tags({"latest": "2.0.0"}, ["1.0.0-a", "1.0.0-b"])["latest"] == "1.0.0-b"
    assert recompute_tags({}, ["junk", "1.0.0"])["latest"] == "1.0.0"
