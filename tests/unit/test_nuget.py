"""NuGet: ids and versions in their canonical spellings, NuGet's version order (cases from NuGet.Versioning's own
tests), and the configuration."""

from __future__ import annotations

import msgspec
import pytest

from slowshield import config as C
from slowshield import names, versions
from slowshield.config import ExceptionRule, NugetUpstream, rule_tables
from slowshield.ecosystems import ECOSYSTEMS
from slowshield.ecosystems.nuget import version as NV
from slowshield.feeds import BlockSpec
from slowshield.shieldwall.leader import policy_body

# ---- spellings --------------------------------------------------------------------------------------------------

# Every spelling in a row names one key: the lower-case id, and the lower-case normalized version.
SPELLINGS = [
    (["Newtonsoft.Json", "newtonsoft.json", "NEWTONSOFT.JSON", " Newtonsoft.Json "], "newtonsoft.json"),
    (["Microsoft.Extensions.Logging", "microsoft.extensions.logging"], "microsoft.extensions.logging"),
    (["My_Package-1", "my_package-1"], "my_package-1"),
]
VERSION_SPELLINGS = [
    (["1", "1.0", "1.0.0", "1.0.0.0", "01.0", "1.00.0.0", "1.0.0+abc", "1.0+Build.5"], "1.0.0"),
    (["1.0.0.1", "1.0.0.01", "1.0.0.1+meta"], "1.0.0.1"),
    (["1.2.3-BETA", "1.2.3-beta", "1.2.3-Beta+x.y", "01.02.03-beta"], "1.2.3-beta"),
    (["2.0-RC.1", "2.0.0-rc.1", "2.0.0.0-Rc.1"], "2.0.0-rc.1"),
    (["1.0.0009.01-1.1+A"], "1.0.9.1-1.1"),
]


@pytest.mark.parametrize(("spellings", "key"), SPELLINGS)
def test_every_spelling_of_an_id_is_one_key(spellings: list[str], key: str) -> None:
    for s in spellings:
        assert names.normalize_nuget(s) == key, s
        assert ECOSYSTEMS["nuget"].normalize(s) == key, s


@pytest.mark.parametrize(("spellings", "key"), VERSION_SPELLINGS)
def test_every_spelling_of_a_version_is_one_key(spellings: list[str], key: str) -> None:
    for s in spellings:
        assert versions.canonical("nuget", s) == key, s
        assert NV.canonical(s) == key, s


def test_ids_as_nuget_org_accepts_them() -> None:
    for good in ("Newtonsoft.Json", "a", "x_y", "A-B.C_d", "1Password.Sdk", "a" * 100):
        assert names.is_valid_nuget(good), good
    for bad in ("", ".a", "a.", "a..b", "a-.b", "a/b", "a b", "ä", "a" * 101, "../x", "a%2fb"):
        assert not names.is_valid_nuget(bad), bad


def test_normalized_keeps_the_label_case_and_canonical_lowers_it() -> None:
    v = NV.parse("1.0.0009.01-1.1+A")  # NuGetVersionTest.ToStringReturnsNormalizedForSemVer2
    assert v is not None and v.normalized == "1.0.9.1-1.1" and v.metadata == "A"
    assert NV.parse("1.0+A").normalized == "1.0.0"  # type: ignore[union-attr]
    assert NV.parse("1.0-1.1+B.B").normalized == "1.0.0-1.1"  # type: ignore[union-attr]
    assert NV.parse("1.2.3-Beta").normalized == "1.2.3-Beta"  # type: ignore[union-attr]


# ---- NuGet.Versioning's own cases ------------------------------------------------------------------------------
# From NuGet.Client test/NuGet.Core.Tests/NuGet.Versioning.Test (VersionComparerTests.cs, NuGetVersionTest.cs).

EQUAL = [
    ("1.0.0", "1.0.0"),
    ("1.0.0-BETA", "1.0.0-beta"),
    ("1.0.0-BETA+AA", "1.0.0-beta+aa"),
    ("1.0.0-BETA.X.y.5.77.0+AA", "1.0.0-beta.x.y.5.77.0+aa"),
    ("1.0.0", "1.0.0+beta"),
    ("1.0", "1.0.0.0"),
    ("1.0+test", "1.0.0.0"),
    ("1.0.0.1-1.2.A", "1.0.0.1-1.2.a+A"),
    ("1.0.01", "1.0.1.0"),
    ("1.23.01", "1.23.1"),
    ("1.45.6", "1.45.6.0"),
    ("1.45.6-Alpha", "1.45.6-Alpha"),
    ("1.6.2-BeTa", "1.6.02-beta"),
    ("1.0", "1.0.0.0+beta"),
    ("1.0.0.0+beta.2", "1.0.0.0+beta.1"),
]
NOT_EQUAL = [
    ("1.0", "1.0.0.1"),
    ("1.0+test", "1.0.0.1"),
    ("1.0.0.1-1.2.A", "1.0.0.1-1.2.a.A+A"),
    ("1.0.01", "1.0.1.2"),
    ("0.0.0", "1.0.0"),
    ("1.1.0", "1.0.0"),
    ("1.0.1", "1.0.0"),
    ("1.0.0-BETA", "1.0.0-beta2"),
    ("1.0.0+AA", "1.0.0-beta+aa"),
    # Not ("1.0.0-BETA+AA", "1.0.0-beta"): that case of VersionComparisonDefaultNotEqual calls object.Equals on the
    # two strings. As versions they are equal, since the default comparer ignores metadata.
    ("1.0.0-BETA.X.y.5.77.0+AA", "1.0.0-beta.x.y.5.79.0+aa"),
]
LESS = [
    ("0.0.0", "1.0.0"),
    ("1.0.0", "1.1.0"),
    ("1.0.0", "1.0.1"),
    ("1.999.9999", "2.1.1"),
    ("1.0.0-BETA", "1.0.0-beta2"),
    ("1.0.0-beta+AA", "1.0.0+aa"),
    ("1.0.0-BETA", "1.0.0-beta.1+AA"),
    ("1.0.0-BETA.X.y.5.77.0+AA", "1.0.0-beta.x.y.5.79.0+aa"),
    ("1.0.0-BETA.X.y.5.79.0+AA", "1.0.0-beta.x.y.5.790.0+abc"),
    # NuGetVersionTest.SemVerLessThanAndGreaterThanOperatorsWorks
    ("1.0", "1.0.1"),
    ("1.23", "1.231"),
    ("1.4.5.6", "1.45.6"),
    ("1.4.5.6", "1.4.5.60"),
    ("1.01", "1.10"),
    ("1.01-alpha", "1.10-beta"),
    ("1.01.0-RC-1", "1.10.0-rc-2"),
    ("1.01-RC-1", "1.01"),
    ("1.01", "1.2-preview"),
    # SemVer 2.0's precedence example, which NuGet follows
    ("1.0.0-alpha", "1.0.0-alpha.1"),
    ("1.0.0-alpha.1", "1.0.0-alpha.beta"),
    ("1.0.0-alpha.beta", "1.0.0-beta"),
    ("1.0.0-beta", "1.0.0-beta.2"),
    ("1.0.0-beta.2", "1.0.0-beta.11"),
    ("1.0.0-beta.11", "1.0.0-rc.1"),
    ("1.0.0-rc.1", "1.0.0"),
    # the fourth number comes before the labels
    ("1.0.0", "1.0.0.1-alpha"),
    ("1.0.0.1-alpha", "1.0.0.1"),
]
VALID = [
    "1.0.0", "0.0.1", "1.2.3", "1.2.3-alpha", "1.2.3-X.y.3+Meta-2", "1.2.3-X.yZ.3.234.243.3242342+METADATA",
    "1.2.3-X.y3+0", "1.2.3-X+0", "1.2.3+0", "1.2.3-0", "2.3-alpha", "3.4.0.3-RC-3", "1.022", "23.2.3",
    "1.3.42.10133", "1.3.42.200930-RC-2", "  1.022-Beta", "23.2.3-Alpha  ", "19", "01.1.1.1", "1.1.1.01",
    "2147483647.1.1.1", "1.1.1.2147483647", "1.3.2-CTP-2-Refresh-Alpha",
]  # fmt: skip
INVALID = [
    "", "         ", "1beta", "1.2Av^c", "1.2..", "1.2.3.4.5", "1.2.3.Beta",
    "1.2.3.4This version is full of awesomeness!!", "So.is.this", "1.34.2Alpha", "1.34.2Release Candidate",
    "1.4.7-", "1.4.7-*", "1.4.7+*", "1.4.7-AA.01^", "1.4.7-AA.0A^", "1.4.7-A^A", "1.4.7+AA.01^",
    "1.2147483648", "1.1.2147483648", "1.1.1.2147483648", "1.1.1.1.2147483648",
    "10000000000000000000", "1..2", "....", "..1", "-1.1.1.1", "1.-1.1.1", "1.1.1.-1", "1.",
    "1.1.", "1.1.1.", "1.1.1.1.", "1     1.1.1.1", "1.1     1.1.1", " .1.1.1", "1. .1.1", "1.1.1. ", "1 .",
    "2147483648.2.3.4", "1.2.3.2147483648", "-1.2.3.4", "   1 9", "1.4.7+", "1.0.0-01", "v1.0.0",
]  # fmt: skip


@pytest.mark.parametrize(("a", "b"), EQUAL)
def test_equal(a: str, b: str) -> None:
    assert NV.compare(a, b) == 0 and NV.compare(b, a) == 0
    assert versions.canonical("nuget", a) == versions.canonical("nuget", b)
    assert versions.sort_key("nuget", a) == versions.sort_key("nuget", b)


@pytest.mark.parametrize(("a", "b"), NOT_EQUAL)
def test_not_equal(a: str, b: str) -> None:
    assert NV.compare(a, b) != 0
    assert versions.canonical("nuget", a) != versions.canonical("nuget", b)


@pytest.mark.parametrize(("a", "b"), LESS)
def test_less(a: str, b: str) -> None:
    assert NV.compare(a, b) == -1 and NV.compare(b, a) == 1
    assert versions.sort_key("nuget", a) < versions.sort_key("nuget", b)


@pytest.mark.parametrize("value", VALID)
def test_valid(value: str) -> None:
    assert NV.parse(value) is not None, value


@pytest.mark.parametrize("value", INVALID)
def test_invalid(value: str) -> None:
    assert NV.parse(value) is None, value
    assert NV.compare(value, "1.0.0") is None


def test_parsed_parts() -> None:
    # NuGetVersionTest.StringConstructorParsesValuesCorrectly and ParseReadsLegacyStyleVersionNumbers
    for value, parts, release, metadata in (
        ("1.0.0", (1, 0, 0, 0), (), ""),
        ("2.3-alpha", (2, 3, 0, 0), ("alpha",), ""),
        ("3.4.0.3-RC-3", (3, 4, 0, 3), ("RC-3",), ""),
        ("1.0.0-beta.x.y.5.79.0+AA", (1, 0, 0, 0), ("beta", "x", "y", "5", "79", "0"), "AA"),
        ("1.022", (1, 22, 0, 0), (), ""),
        ("1.3.42.10133", (1, 3, 42, 10133), (), ""),
    ):
        v = NV.parse(value)
        assert v is not None
        assert (v.major, v.minor, v.patch, v.revision) == parts and v.release == release and v.metadata == metadata


def test_sorting_a_real_version_list() -> None:
    # Newtonsoft.Json's flat container order on 2026-10-08 (excerpt): the order nuget.org itself writes.
    real = ["3.5.8", "4.0.1", "6.0.1-beta1", "6.0.1", "9.0.1-beta1", "9.0.1", "12.0.1-beta1", "12.0.1-beta2", "12.0.1",
            "13.0.1-beta1", "13.0.1", "13.0.5-beta1", "14.0.1-beta1", "14.0.1-beta2"]  # fmt: skip
    shuffled = sorted(real, key=lambda v: (len(v), v), reverse=True)
    assert sorted(shuffled, key=lambda v: versions.sort_key("nuget", v)) == real


def test_versions_helpers() -> None:
    assert versions.is_prerelease("nuget", "1.0.0-beta") and not versions.is_prerelease("nuget", "1.0.0+meta")
    assert versions.in_range("nuget", "1.0.0.1", ">= 1.0, < 1.0.1")
    assert not versions.in_range("nuget", "1.0.1-beta", "< 1.0.0")
    assert versions.in_range("nuget", "1.0.0-BETA", "= 1.0-beta")
    assert versions.sort_key("nuget", "not a version") < versions.sort_key("nuget", "0.0.0")


def test_advisory_versions_are_stored_in_canonical_form() -> None:
    assert BlockSpec("nuget", "x", version="1.0").version == "1.0.0"
    assert BlockSpec("nuget", "x", version="1.0.0-RC.1+abc").version == "1.0.0-rc.1"
    assert BlockSpec("npm", "x", version="1.0").version == "1.0"  # other ecosystems keep theirs


# ---- configuration ----------------------------------------------------------------------------------------------


def test_defaults_point_at_nuget_org() -> None:
    n = NugetUpstream()
    assert n.enabled and n.fail_open is False
    assert n.urls() == {
        "flat_container_url": "https://api.nuget.org/v3-flatcontainer/",
        "registration_url": "https://api.nuget.org/v3/registration5-gz-semver2/",
        "catalog_url": "https://api.nuget.org/v3/catalog0/",
        "vulnerability_url": "https://api.nuget.org/v3/vulnerabilities/index.json",
        "search_url": "https://azuresearch-usnc.nuget.org/query",
    }
    cfg = C.parse("")
    assert cfg.fail_open_for("nuget") is False
    assert "nuget" in C.ECOSYSTEMS


def test_enabled_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SLOWSHIELD_NUGET_ENABLED", "false")
    assert C.parse("").raw.upstreams.nuget.enabled is False


@pytest.mark.parametrize(
    "toml",
    [
        '[upstreams.nuget]\nregistration_url = "ftp://x/"',
        '[upstreams.nuget]\nflat_container_url = "https://x/flat"',
        '[upstreams.nuget]\ncatalog_url = "https://x/catalog0"',
        '[upstreams.nuget]\nsearch_url = "azuresearch-usnc.nuget.org/query"',
        '[upstreams.nuget]\nfeeds = ["https://x/"]',
    ],
)
def test_invalid_nuget_config(toml: str) -> None:
    with pytest.raises(C.ConfigError):
        C.parse(toml)


def test_upstream_urls_need_a_restart() -> None:
    old = C.parse("").raw
    new = C.parse('[upstreams.nuget]\nsearch_url = "https://azuresearch-ussc.nuget.org/query"').raw
    assert C.restart_only_changes(old, new) == ["upstreams.nuget.search_url"]
    off = C.parse("[upstreams.nuget]\nenabled = false").raw
    assert C.restart_only_changes(old, off) == ["upstreams.nuget.enabled"]


def test_version_exceptions_match_any_spelling() -> None:
    rules = [ExceptionRule("nuget", "Newtonsoft.Json", 0, version="13.0")]
    _, ver = rule_tables(rules, msgspec.convert({}, C.OciUpstream))
    assert ver == {("nuget", "newtonsoft.json", "13.0.0"): 0}
    cfg = C.parse('[[exceptions]]\necosystem = "nuget"\npackage = "Newtonsoft.Json"\nversion = "13.0"\ndelay_days = 0')
    assert cfg.delay_days_for("nuget", "newtonsoft.json", "13.0.0") == 0
    assert cfg.delay_days_for("nuget", "newtonsoft.json", "13.0.1") == 7


def test_the_leader_sends_every_ecosystem_s_fail_open() -> None:
    cfg = C.parse("[upstreams.nuget]\nfail_open = true")
    assert policy_body(cfg)["fail_open_by_ecosystem"]["nuget"] is True
    assert set(policy_body(C.parse(""))["fail_open_by_ecosystem"]) >= {"maven", "cargo", "nuget"}
