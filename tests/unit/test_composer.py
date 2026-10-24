"""Composer: version normalization and order, the minified p2 format, filtering and dist rewriting, names, config."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import msgspec
import pytest

from slowshield import config as config_mod
from slowshield import names
from slowshield import versions as V
from slowshield.app import _route_label
from slowshield.ecosystems.composer import metadata as M
from slowshield.ecosystems.composer import version as C
from slowshield.ecosystems.composer.service import composer_error, plausible, zip_content


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("1.2", "1.2.0.0"),
        ("v1.2.3", "1.2.3.0"),
        ("V2.0", "2.0.0.0"),
        ("1.0-beta2", "1.0.0.0-beta2"),
        ("1.0.0-b2", "1.0.0.0-beta2"),
        ("1.0.0-RC1", "1.0.0.0-RC1"),
        ("1.0.0-rc.1", "1.0.0.0-RC1"),
        ("2.0.0-alpha", "2.0.0.0-alpha"),
        ("1.0.0-pl1", "1.0.0.0-patch1"),
        ("1.0.0-stable", "1.0.0.0"),
        ("1.0.0+build.5", "1.0.0.0"),
        ("1.0.0-beta.1-dev", "1.0.0.0-beta1-dev"),
        ("dev-main", "dev-main"),
        ("dev-feature/x", "dev-feature/x"),
        ("master", "dev-master"),
        ("2.x-dev", "2.9999999.9999999.9999999-dev"),
        ("1.0@dev", "1.0.0.0"),
        ("20240101", "20240101"),
        ("1.2.3.4.5", None),
        ("not a version", None),
    ],
)
def test_versions_normalize_as_composer_does(raw: str, normalized: str | None) -> None:
    assert C.normalize(raw) == normalized


def test_versions_order_as_php_version_compare() -> None:
    ordered = [
        "dev-main",
        "0.9",
        "v1.0.0-dev",
        "1.0.0-alpha",
        "1.0.0-beta2",
        "1.0.0-beta10",
        "1.0.0-RC1",
        "1.0.0",
        "1.0.0-patch1",
        "1.0.1",
        "1.10.0",
        "2.x-dev",
    ]
    assert sorted(ordered[5:] + ordered[:5], key=C.key) == ordered
    assert C.compare("v1.2", "1.2.0") == 0 and C.compare("1.10", "1.9") == 1
    assert C.is_prerelease("1.0.0-RC1") and C.is_prerelease("dev-main") and not C.is_prerelease("1.0.0-patch1")
    assert C.is_dev("2.x-dev") and not C.is_dev("2.0.0")


def test_advisory_ranges_and_exact_versions_match_any_spelling() -> None:
    assert V.canonical("composer", "v1.1") == V.canonical("composer", "1.1.0") == "1.1.0.0"
    assert V.in_range("composer", "v1.1.0", "= 1.1")
    assert V.in_range("composer", "1.0.0-RC1", ">= 0, < 1.0.0") and not V.in_range("composer", "1.0.0", "< 1.0.0")
    assert not V.in_range("composer", "not a version", "< 9")
    assert V.sort_key("composer", "1.2.0") > V.sort_key("composer", "v1.1.0")
    assert V.is_prerelease("composer", "1.0.0-beta1")


def test_names_are_packagists() -> None:
    for good in ("monolog/monolog", "symfony/http-kernel", "a/b", "vendor.name/pkg_name", "x/a--b"):
        assert names.is_valid_composer(good), good
    for bad in ("Monolog/Monolog", "monolog", "a/b/c", "-a/b", "a/b-", "a//b", "", "a/" + "b" * 300):
        assert not names.is_valid_composer(bad), bad
    assert names.normalize_composer(" Monolog/Monolog ") == "monolog/monolog"


# ---- the minified format ------------------------------------------------------------------------------------------


ENTRIES = [
    {"name": "v/p", "version": "2.0.0", "license": ["MIT"], "require": {"php": ">=8.1"}, "published-time": "T2"},
    {"name": "v/p", "version": "1.1.0", "license": ["MIT"], "require": {"php": ">=8.1"}, "published-time": "T2"},
    {"name": "v/p", "version": "1.0.0", "license": ["MIT"], "published-time": "T1"},
]


def test_minify_and_expand_round_trip() -> None:
    small = M.minify(ENTRIES)
    assert small[1] == {"version": "1.1.0"}  # only what differs from the entry before
    assert small[2] == {"version": "1.0.0", "published-time": "T1", "require": "__unset"}
    assert M.expand(small) == ENTRIES
    assert M.expand([]) == [] and M.minify([]) == []


def _p2(entries: list[dict], **extra: object) -> M.P2File:
    body = json.dumps({"minified": "composer/2.0", "packages": {"v/p": M.minify(entries)}, **extra}).encode()
    p2 = M.parse("v/p", False, body)
    assert p2 is not None
    return p2


def _entry(version: str, ref: str, *, published: str | None = "2026-09-01T00:00:00+00:00", **dist: object) -> dict:
    e: dict = {
        "name": "v/p",
        "version": version,
        "source": {"type": "git", "url": "https://github.com/v/p.git", "reference": ref},
        "dist": {"type": "zip", "url": f"https://api.github.com/repos/v/p/zipball/{ref}", "reference": ref,
                 "shasum": "", **dist},
        "time": "2001-01-01T00:00:00+00:00",
    }  # fmt: skip
    if published:
        e["published-time"] = published
    return e


def test_parse_reads_published_time_and_the_dist() -> None:
    p2 = _p2(
        [
            _entry("2.0.0", "b" * 40, shasum="A" * 40),
            _entry("1.0.0", "a" * 40, published=None),
            _entry("0.9.0", "../x"),
            {"version": 3},
        ],
        **{"security-advisories": [{"advisoryId": "PKSA-1"}]},
    )
    assert list(p2.versions) == ["2.0.0", "1.0.0", "0.9.0"]
    v2, v1, v09 = p2.versions.values()
    assert v2.published == 1788220800.0 and v2.shasum == "a" * 40 and v2.servable and v2.filename == "b" * 40 + ".zip"
    assert v1.published is None  # the minified entry dropped it (`__unset`); `time` is never read
    assert v09.reference is None and not v09.servable  # a reference that can't name a file in a URL
    assert p2.extra == {"security-advisories": [{"advisoryId": "PKSA-1"}]}
    for junk in (b"not json", b"[]", b'{"packages": []}', b'{"packages": {"v/p": {}}}'):
        assert M.parse("v/p", False, junk) is None
    assert M.parse("v/p", False, b'{"packages": {}}').versions == {}  # no tags (only branches)


def test_render_drops_versions_rewrites_dists_and_strips_mirrors() -> None:
    mirrored = _entry("1.0.0", "a" * 40, mirrors=[{"url": "https://mirror.example/x.zip", "preferred": True}])
    mirrored["source"]["mirrors"] = [{"url": "https://git.example/x.git", "preferred": True}]
    p2 = _p2([_entry("2.0.0", "b" * 40), mirrored], filter={"malware": []})
    body = M.render(p2, {"2.0.0"}, lambda v: f"https://s/composer/dists/v/p/{v.filename}", warning="careful")
    doc = msgspec.json.decode(body)
    assert doc["minified"] == "composer/2.0" and doc["filter"] == {"malware": []} and doc["warning"] == "careful"
    (only,) = M.expand(doc["packages"]["v/p"])
    assert only["version"] == "1.0.0"
    assert only["dist"] == {"type": "zip", "url": f"https://s/composer/dists/v/p/{'a' * 40}.zip",
                            "reference": "a" * 40, "shasum": ""}  # fmt: skip
    assert "mirrors" not in only["source"] and only["time"] == "2001-01-01T00:00:00+00:00"
    # Nothing dropped: the same entries as upstream, but for the dist URLs.
    full = M.expand(msgspec.json.decode(M.render(p2, (), lambda v: "X"))["packages"]["v/p"])
    assert [e["dist"]["url"] for e in full] == ["X", "X"]


def test_github_api_archives_are_fetched_from_codeload() -> None:
    ref = "d7059e4c691d05ea1222b5124bed0f961be46e15"
    assert M.fetch_url(f"https://api.github.com/repos/Seldaek/monolog/zipball/{ref}") == (
        f"https://codeload.github.com/Seldaek/monolog/legacy.zip/{ref}"
    )
    assert M.fetch_url(f"https://api.github.com/repos/o/r/tarball/{ref}").endswith(f"/o/r/legacy.tar.gz/{ref}")
    for other in (f"https://gitlab.com/api/v4/projects/1/repository/archive.zip?sha={ref}",
                  f"https://api.github.com/repos/o/r/zipball/{ref}/../x"):  # fmt: skip
        assert M.fetch_url(other) == other


def test_zip_content_ignores_how_the_zip_was_written(tmp_path: Path) -> None:
    def write(name: str, when: tuple[int, int, int, int, int, int], level: int) -> Path:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=level) as zf:
            for path, data in (("p-abc/composer.json", b"{}"), ("p-abc/src/A.php", b"<?php\n" * 50)):
                zf.writestr(zipfile.ZipInfo(path, date_time=when), data)
        (tmp_path / name).write_bytes(buf.getvalue())
        return tmp_path / name

    a, b = write("a.zip", (2020, 1, 1, 0, 0, 0), 9), write("b.zip", (2021, 2, 2, 0, 0, 0), 1)
    assert a.read_bytes() != b.read_bytes() and zip_content(a) == zip_content(b)
    assert (zip_content(a) or "").startswith("h1:")
    (tmp_path / "c.zip").write_bytes(b"not a zip")
    assert zip_content(tmp_path / "c.zip") is None


def test_errors_are_warnings_composer_prints() -> None:
    r = composer_error(451, "tamper_detected", artifact="/v/p/x.zip")
    assert r.status_code == 451 and r.headers["content-type"] == "application/json"
    assert json.loads(r.body)["warning"].startswith("slowshield: /v/p/x.zip changed upstream")
    r = composer_error(502, "upstream_error", detail="boom")
    assert r.status_code == 503 and r.headers["retry-after"] == "10"
    assert plausible(1.0, 2e9) is None and plausible(3e9, 2e9) is None and plausible(1.7e9, 2e9) == 1.7e9


def test_route_labels() -> None:
    assert _route_label("/composer/p2/monolog/monolog.json") == "/composer/p2/{package}.json"
    assert _route_label("/composer/p2/monolog/monolog~dev.json") == "/composer/p2/{package}~dev.json"
    assert _route_label("/composer/dists/monolog/monolog/abc.zip") == "/composer/dists/{package}/{file}"
    assert _route_label("/composer/packages.json") == "/composer/packages.json"
    assert _route_label("/composer/whatever") == "/composer/{path}"


def test_config() -> None:
    cfg = config_mod.Config()
    assert cfg.upstreams.composer.fail_open is False and cfg.upstreams.composer.repo_url == "https://repo.packagist.org"
    assert "codeload.github.com" in cfg.upstreams.composer.download_hosts
    for bad in ({"repo_url": "ftp://x"}, {"download_hosts": ["https://codeload.github.com"]}):
        raw = msgspec.convert({"upstreams": {"composer": bad}}, config_mod.Config)
        with pytest.raises(config_mod.ConfigError, match=r"upstreams\.composer"):
            config_mod.build(raw, path=None, warnings=[])
    old = config_mod.Config()
    new = msgspec.convert({"upstreams": {"composer": {"download_hosts": ["gitlab.com"]}}}, config_mod.Config)
    assert "upstreams.composer.download_hosts" in config_mod.restart_only_changes(old, new)
    rules = msgspec.convert(
        {"exceptions": [{"ecosystem": "composer", "package": "V/P", "version": "v1.2", "delay_days": 0}]},
        config_mod.Config,
    )
    loaded = config_mod.build(rules, path=None, warnings=[])
    assert loaded.delay_days_for("composer", "v/p", V.canonical("composer", "1.2.0")) == 0
