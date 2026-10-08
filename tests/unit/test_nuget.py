"""NuGet: ids and versions in their canonical spellings, NuGet's version order (cases from NuGet.Versioning's own
tests), the configuration, packageHash, registration snapshots, pages and URLs, and the publish-time rule."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

import msgspec
import pytest

from slowshield import config as C
from slowshield import names, versions
from slowshield.config import ExceptionRule, NugetUpstream, rule_tables
from slowshield.ecosystems import ECOSYSTEMS
from slowshield.ecosystems.nuget import registration as R
from slowshield.ecosystems.nuget import version as NV
from slowshield.ecosystems.nuget.service import plausible, publish_time
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


# ---- packageHash -----------------------------------------------------------------------------------------------

DIGEST = hashlib.sha512(b"package bytes").digest()


def _catalog(**fields: object) -> dict[str, object]:
    doc: dict[str, object] = {
        "id": "Newtonsoft.Json",
        "version": "13.0.1",
        "packageHash": base64.b64encode(DIGEST).decode(),
        "packageHashAlgorithm": "SHA512",
        "packageSize": 2065787,
    }
    doc.update(fields)
    return {k: v for k, v in doc.items() if v is not None}


def test_package_hash_from_a_catalog_leaf() -> None:
    assert R.package_hash(_catalog(), "newtonsoft.json", "13.0.1") == (DIGEST, 2065787)
    # Spellings don't matter, and the size is optional.
    lenient = _catalog(version="13.0.1.0", packageHashAlgorithm="sha512", packageSize=None)
    assert R.package_hash(lenient, "newtonsoft.json", "13.0.1") == (DIGEST, None)
    # The digest from the spike: Newtonsoft.Json 13.0.1 on 2026-10-08.
    real = "g3MbZi6vBTeaI/hEbvR7vBETSd1DWLe9i1E4P+nPY34v5i94zqUqDXvdWC3G+7tYN9SnsdU9zzegrnRz4h7nsQ=="
    got = R.package_hash(_catalog(packageHash=real), "newtonsoft.json", "13.0.1")
    assert isinstance(got, tuple) and got[0] == base64.b64decode(real) and len(got[0]) == 64


@pytest.mark.parametrize(
    ("fields", "problem"),
    [
        ({"id": "Other.Package"}, "names another package"),
        ({"version": "13.0.2"}, "names another package"),
        ({"packageHashAlgorithm": "SHA256"}, "no SHA512"),
        ({"packageHashAlgorithm": None}, "no SHA512"),
        ({"packageHash": "not base64!"}, "not base64"),
        ({"packageHash": base64.b64encode(b"short").decode()}, "not a SHA512"),
    ],
)
def test_unusable_catalog_leaves(fields: dict[str, object], problem: str) -> None:
    got = R.package_hash(_catalog(**fields), "newtonsoft.json", "13.0.1")
    assert isinstance(got, str) and problem in got
    assert R.package_hash(None, "newtonsoft.json", "13.0.1") == "no catalog entry"


# ---- snapshots, pages and URLs ---------------------------------------------------------------------------------

UP = "https://api.nuget.org/v3/registration5-gz-semver2/"
FLAT = "https://api.nuget.org/v3-flatcontainer/"
CAT = "https://api.nuget.org/v3/catalog0/data/2026.01.01.00.00.00/"
URLS = R.Urls(registration="https://ss.test/nuget/v3/registration/", flat="https://ss.test/nuget/v3/flatcontainer/")


def _leaf(version: str, listed: bool = True) -> dict[str, Any]:
    lv = version.lower()
    return {
        "@id": f"{UP}x.y/{lv}.json",
        "@type": "Package",
        "catalogEntry": {
            "@id": f"{CAT}x.y.{lv}.json",
            "id": "X.Y",
            "version": version,
            "listed": listed,
            "published": "2026-01-01T00:00:00+00:00",
            "packageContent": f"{FLAT}x.y/{lv}/x.y.{lv}.nupkg",
            "iconUrl": f"{FLAT}x.y/{lv}/icon",
        },
        "packageContent": f"{FLAT}x.y/{lv}/x.y.{lv}.nupkg",
        "registration": f"{UP}x.y/index.json",
    }


def _page(versions: list[str], *, inline: bool) -> dict[str, Any]:
    lo, hi = versions[0].lower(), versions[-1].lower()
    page: dict[str, Any] = {
        "@id": f"{UP}x.y/index.json#page/{lo}/{hi}" if inline else f"{UP}x.y/page/{lo}/{hi}.json",
        "@type": "catalog:CatalogPage",
        "count": len(versions),
        "lower": lo,
        "upper": hi,
    }
    if inline:
        page["items"] = [_leaf(v) for v in versions]
    return page


def _snapshot() -> R.Snapshot:
    pages = [["1.0.0-beta", "1.0.0", "1.9.0"], ["1.10.0", "2.0.0-RC.1"], ["2.0.0"]]
    items = [_page(pages[0], inline=True), _page(pages[1], inline=False), _page(pages[2], inline=False)]
    index = {"@id": f"{UP}x.y/index.json", "count": 3, "items": items}
    linked = {
        f"{UP}x.y/page/{p[0].lower()}/{p[-1].lower()}.json": {"items": [_leaf(v) for v in p], "@context": {"x": 1}}
        for p in pages[1:]
    }
    assert R.page_urls(index, UP) == list(linked)
    return R.parse("x.y", index, linked)


def test_a_snapshot_reads_inlined_and_linked_pages_in_version_order() -> None:
    snap = _snapshot()
    assert list(snap.versions) == ["1.0.0-beta", "1.0.0", "1.9.0", "1.10.0", "2.0.0-rc.1", "2.0.0"]
    assert snap.served({"1.9.0", "2.0.0"}) == ["1.0.0-beta", "1.0.0", "1.10.0", "2.0.0-rc.1"]
    assert snap.versions["1.0.0"].catalog_url == f"{CAT}x.y.1.0.0.json"


def test_pages_are_recomputed_and_empty_ones_dropped() -> None:
    doc = R.render_index(_snapshot(), {"1.0.0-beta", "1.10.0", "2.0.0"}, URLS)
    assert doc["@id"] == "https://ss.test/nuget/v3/registration/x.y/index.json" and doc["count"] == 2
    first, second = doc["items"]
    assert (first["count"], first["lower"], first["upper"]) == (2, "1.0.0", "1.9.0")
    assert first["@id"] == "https://ss.test/nuget/v3/registration/x.y/index.json#page/1.0.0/1.9.0"
    assert [i["catalogEntry"]["version"] for i in first["items"]] == ["1.0.0", "1.9.0"]
    assert (second["count"], second["lower"], second["upper"]) == (1, "2.0.0-rc.1", "2.0.0-rc.1")
    assert second["@id"] == "https://ss.test/nuget/v3/registration/x.y/page/2.0.0-rc.1/2.0.0-rc.1.json"
    assert "items" not in second  # linked pages stay linked
    # Nothing dropped: nuget.org's bounds.
    full = R.render_index(_snapshot(), set(), URLS)
    bounds = [(p["lower"], p["upper"], p["count"]) for p in full["items"]]
    assert bounds == [("1.0.0-beta", "1.9.0", 3), ("1.10.0", "2.0.0-rc.1", 2), ("2.0.0", "2.0.0", 1)]


def test_a_linked_page_by_its_bounds_and_by_bounds_that_changed() -> None:
    snap = _snapshot()
    page = R.render_page(snap, {"1.10.0"}, URLS, "2.0.0-rc.1", "2.0.0-rc.1")
    assert page["count"] == 1 and page["parent"] == URLS.index("x.y") and page["@context"] == {"x": 1}
    assert [i["catalogEntry"]["version"] for i in page["items"]] == ["2.0.0-RC.1"]
    # The client read an older index: no page has these bounds now, so the served versions within them.
    old = R.render_page(snap, {"1.10.0"}, URLS, "1.10.0", "2.0.0-rc.1")
    assert [i["catalogEntry"]["version"] for i in old["items"]] == ["2.0.0-RC.1"]
    assert (old["lower"], old["upper"], old["count"]) == ("1.10.0", "2.0.0-rc.1", 1)


def test_urls_clients_follow_point_at_slowshield_and_the_rest_stays() -> None:
    doc = R.render_index(_snapshot(), set(), URLS)
    leaf = doc["items"][0]["items"][1]
    assert leaf["@id"] == "https://ss.test/nuget/v3/registration/x.y/1.0.0.json"
    assert leaf["registration"] == "https://ss.test/nuget/v3/registration/x.y/index.json"
    nupkg = "https://ss.test/nuget/v3/flatcontainer/x.y/1.0.0/x.y.1.0.0.nupkg"
    assert leaf["packageContent"] == leaf["catalogEntry"]["packageContent"] == nupkg
    assert leaf["catalogEntry"]["@id"] == f"{CAT}x.y.1.0.0.json"  # the catalog isn't served: unchanged
    assert leaf["catalogEntry"]["iconUrl"].startswith(FLAT)
    assert doc["items"][0]["parent"] == URLS.index("x.y")
    single = R.render_leaf(_snapshot(), "2.0.0-rc.1", URLS)
    assert single["@id"] == URLS.leaf("x.y", "2.0.0-rc.1")
    assert single["packageContent"] == URLS.nupkg("x.y", "2.0.0-rc.1")


def test_registration_documents_slowshield_refuses() -> None:
    with pytest.raises(R.RegistrationError):
        R.page_urls({"items": [{"@id": "https://evil.example/x.y/page/1/2.json"}]}, UP)
    with pytest.raises(R.RegistrationError):
        R.page_urls({"items": [{"@id": f"{UP}x.y/page/1/2.json?x=1"}]}, UP)
    with pytest.raises(R.RegistrationError):
        R.page_urls({"items": [{"@id": f"{UP}../../v3-flatcontainer/x.json"}]}, UP)  # out of the hive
    with pytest.raises(R.RegistrationError):
        R.parse("x.y", {"items": [{"@id": f"{UP}x.y/page/1/2.json"}]}, {})  # a page missing from the snapshot
    with pytest.raises(R.RegistrationError):
        R.page_urls([], UP)
    # Entries for another package, or without a readable version, are left out; a second spelling too.
    odd = _leaf("1.0.0")
    odd["catalogEntry"] = {**odd["catalogEntry"], "id": "Other"}
    snap = R.parse("x.y", {"items": [{"items": [odd, _leaf("not-a-version"), _leaf("1.1.0"), _leaf("1.1")]}]}, {})
    assert list(snap.versions) == ["1.1.0"]


# ---- publish time --------------------------------------------------------------------------------------------

NOW = 1_790_000_000.0
DAY = 86400.0
UNLISTED = R.parse_time("1900-01-01T00:00:00+00:00")


def test_unlisted_versions_say_1900_which_is_not_a_publish_time() -> None:
    assert UNLISTED is not None and plausible(UNLISTED, NOW) is None
    assert plausible(R.parse_time("2026-09-21T10:12:19.923+00:00"), NOW) is not None
    assert plausible(R.parse_time("2009-12-31T00:00:00Z"), NOW) is None  # before nuget.org
    assert plausible(NOW + 3600, NOW) is None  # in the future
    assert R.parse_time("2026-09-21T10:12:19") is None  # without a time zone
    assert R.parse_time(None) is None and R.parse_time("yesterday") is None


def test_the_latest_clock_counts() -> None:
    old = NOW - 100 * DAY
    # Listed: its own `published`.
    assert publish_time(old, (), NOW) == old
    # Unlisted when first seen: from then (first_listed), whatever 1900 says.
    assert publish_time(UNLISTED, (None, NOW - DAY), NOW) == NOW - DAY
    # Relisted later with its original date: still from when SlowShield first listed it.
    assert publish_time(old, (old, NOW - DAY), NOW) == NOW - DAY
    # Never earlier: the registration now states an earlier time than the one stored first...
    assert publish_time(NOW - 30 * DAY, (NOW - 2 * DAY, None), NOW) == NOW - 2 * DAY
    # ...but a later one counts.
    assert publish_time(NOW - DAY, (NOW - 2 * DAY, None), NOW) == NOW - DAY
    # A future date isn't one: first listed.
    assert publish_time(NOW + 30 * DAY, (None, NOW - 3 * DAY), NOW) == NOW - 3 * DAY
    # Nothing known: now (too new).
    assert publish_time(None, (), NOW) == NOW
