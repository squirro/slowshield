"""Cargo: index paths, line parsing and the yank rewrite, crate names, versions, RustSec advisories."""

from __future__ import annotations

import msgspec
import pytest

from slowshield import names, versions
from slowshield.ecosystems.cargo import index as I
from slowshield.feeds import BlockSpec
from slowshield.feeds.osv import OsvVuln, to_advisory
from slowshield.ui import snippets as S

CKSUM = "a" * 64


def _line(
    vers: str, *, name: str = "serde", yanked: bool = False, pubtime: str | None = "2026-01-02T03:04:05Z"
) -> bytes:
    deps = '[{"name":"yanked","req":"^1","features":[],"optional":false,"default_features":true,"target":null}]'
    out = f'{{"name":"{name}","vers":"{vers}","deps":{deps},"cksum":"{CKSUM}","features":{{}}'
    out += f',"yanked":{str(yanked).lower()}'
    if pubtime:
        out += f',"pubtime":"{pubtime}"'
    return (out + "}").encode()


@pytest.mark.parametrize(
    ("name", "path"),
    [("a", "1/a"), ("ab", "2/ab"), ("abc", "3/a/abc"), ("Serde_JSON", "se/rd/serde_json"), ("cargo", "ca/rg/cargo")],
)
def test_index_paths(name: str, path: str) -> None:
    assert I.path_of(name) == path
    assert I.name_of(path) == name.lower()


@pytest.mark.parametrize("path", ["se/rd/Serde", "xx/rd/serde", "serde", "3/b/abc", "se/rd/", "../../etc/passwd"])
def test_other_paths_name_no_crate(path: str) -> None:
    assert I.name_of(path) is None


def test_parse_keeps_raw_lines_and_drops_unusable_ones() -> None:
    body = b"\n".join(
        [
            _line("1.0.0"),
            b"not json",
            _line("1.0.0"),  # repeated
            _line("1.1.0", name="other"),  # another crate
            _line("1.2.0").replace(CKSUM.encode(), b"short"),
            _line("1.3.0", name="Serde", pubtime=None),
            _line("1.4.0", pubtime="2026-01-02T03:04:05"),  # no zone: not a usable time
        ]
    )
    idx = I.parse("serde", body + b"\n")
    assert list(idx.versions) == ["1.0.0", "1.3.0", "1.4.0"]
    assert idx.versions["1.0.0"].line == _line("1.0.0") and idx.versions["1.0.0"].pubtime == 1767323045.0
    assert idx.versions["1.3.0"].name == "Serde" and idx.versions["1.3.0"].pubtime is None
    assert idx.versions["1.4.0"].pubtime is None
    assert I.parse("serde", body).content_id != I.parse("serde", body + b" ").content_id


def test_render_marks_held_versions_as_yanked_and_nothing_else() -> None:
    body = b"\n".join([_line("1.0.0"), _line("1.1.0", yanked=True), _line("1.2.0")]) + b"\n"
    idx = I.parse("serde", body)
    assert I.render(idx, ()) == body
    out = I.render(idx, {"1.1.0", "1.2.0"})
    assert out == b"\n".join([_line("1.0.0"), _line("1.1.0", yanked=True), _line("1.2.0", yanked=True)]) + b"\n"
    # The deps entry named "yanked" stays as it is: only the top-level field changes.
    assert out.count(b'"yanked"') == 6


def test_a_line_that_cannot_be_marked_is_left_out() -> None:
    spaced = _line("2.0.0").replace(b'"yanked":false', b'"yanked": false')
    idx = I.parse("serde", _line("1.0.0") + b"\n" + spaced)
    assert I.yank(spaced) is None
    assert I.render(idx, {"2.0.0"}) == _line("1.0.0") + b"\n"
    assert I.render(idx, {"1.0.0", "2.0.0"}) == _line("1.0.0", yanked=True) + b"\n"
    assert I.render(I.parse("serde", b""), ()) == b""


def test_crate_names() -> None:
    assert names.normalize_cargo("Serde-JSON") == names.normalize_cargo("serde_json") == "serde_json"
    for good in ("a", "serde", "Inflector", "serde-json", "x_1", "a" * 64):
        assert names.is_valid_cargo(good), good
    for bad in ("", "-a", "_a", "a.b", "a/b", "a b", "a" * 65, "é"):
        assert not names.is_valid_cargo(bad), bad


def test_versions_ignore_build_metadata() -> None:
    assert versions.canonical("cargo", "1.0.0+abc") == "1.0.0"
    assert versions.in_range("cargo", "1.2.3", ">= 0.0.0-0")
    assert versions.sort_key("cargo", "1.0.0-alpha") < versions.sort_key("cargo", "1.0.0")


def _rustsec(extra: str, *, categories: str = '["malicious"]', aliases: str = "[]") -> OsvVuln:
    return msgspec.json.decode(
        b'{"id": "RUSTSEC-2026-0001", "summary": "malicious crate", "aliases": ' + aliases.encode() + b', "affected": '
        b'[{"package": {"ecosystem": "crates.io", "name": "Evil-Crate"}, ' + extra.encode() + b", "
        b'"database_specific": {"categories": ' + categories.encode() + b', "cvss": null}}]}',
        type=OsvVuln,
    )


def test_rustsec_malware_becomes_a_block() -> None:
    whole = '"ranges": [{"type": "SEMVER", "events": [{"introduced": "0.0.0-0"}]}]'
    adv = to_advisory(_rustsec(whole))
    assert adv is not None and not adv.withdrawn and adv.specs == [BlockSpec("cargo", "evil_crate")]
    closed = '"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.2"}]}]'
    adv = to_advisory(_rustsec(closed))
    assert adv is not None and adv.specs == [BlockSpec("cargo", "evil_crate", version_range=">= 1.0.0, < 1.0.2")]


@pytest.mark.parametrize(
    ("extra", "categories", "aliases"),
    [
        ('"ranges": [{"type": "SEMVER", "events": [{"introduced": "0.0.0-0"}]}]', '["memory-corruption"]', "[]"),
        ('"ranges": [{"type": "SEMVER", "events": [{"introduced": "0.0.0-0"}]}]', '["malicious"]', '["MAL-2026-1"]'),
        ('"ranges": [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}]}]', '["malicious"]', "[]"),
        ('"versions": []', '["malicious"]', "[]"),
    ],
    ids=["not-malware", "covered-by-mal", "open-ended", "no-versions"],
)
def test_other_rustsec_advisories_are_no_blocks(extra: str, categories: str, aliases: str) -> None:
    adv = to_advisory(_rustsec(extra, categories=categories, aliases=aliases))
    assert adv is not None and adv.withdrawn and adv.specs == []


def test_cargo_setup_snippets() -> None:
    tool = S.tools(
        "https://h/pypi/simple/", "https://h/npm/", "https://h/go", "https://h/maven", "http://localhost/cargo/"
    )
    cargo = next(t for t in tool if t.name == "Cargo")
    config, command = (code for _, code in cargo.snippets)
    assert config == (
        '[source.crates-io]\nreplace-with = "slowshield"\n\n[registries.slowshield]\nindex = "sparse+http://localhost/cargo/"'
    )
    assert command.startswith('mkdir -p "${CARGO_HOME:-$HOME/.cargo}" && printf ')
    with pytest.raises(ValueError, match="refusing"):
        S.tools("a", "b", "c", "d", "https://h/cargo/'$(id)'")
