"""RubyGems: Gem::Version order, info lines, file names, gem names, and the /versions copy (zeroed checksums,
appends, rebuilds, a crash between writes)."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from slowshield import names, versions
from slowshield.ecosystems.rubygems import index as I
from slowshield.ecosystems.rubygems import version as G
from slowshield.ecosystems.rubygems import versions_file as VF
from slowshield.upstream import FetchResult, UpstreamError

SHA = "a" * 64


@pytest.mark.parametrize(
    ("low", "high"),
    [
        ("1.0.a", "1.0"),
        ("1.0", "1.0.1"),
        ("1.9", "1.10"),
        ("2.0.0.rc1", "2.0.0"),
        ("1.0.0-beta", "1.0.0"),  # `-` reads as `.pre.`
        ("1.0.a", "1.0.0.rc1"),
        ("1.a.0.b", "1.a"),  # a missing segment counts as 0, and a number is above any text
        ("0.9", "1.0.a"),
    ],
)
def test_gem_version_order(low: str, high: str) -> None:
    assert G.compare(low, high) == -1 and G.compare(high, low) == 1
    assert versions.sort_key("rubygems", low) < versions.sort_key("rubygems", high)


def test_gem_versions_equal_in_order_stay_distinct_as_spelled() -> None:
    assert G.compare("1.0", "1.0.0") == 0 and G.compare("1.0.0.pre.beta", "1.0.0-beta") == 0
    assert versions.canonical("rubygems", " 1.0 ") == "1.0" != versions.canonical("rubygems", "1.0.0")
    assert versions.is_prerelease("rubygems", "2.0.0.rc1") and not versions.is_prerelease("rubygems", "2.0.0")
    assert G.parse("") is None and G.parse("a1") is None and G.compare("x", "1.0") is None
    assert versions.in_range("rubygems", "1.6.13", ">= 1.6.10, < 1.6.14")
    assert not versions.in_range("rubygems", "1.6.14.rc1", "< 1.6.14.a")


@pytest.mark.parametrize("name", ["rack", "RedCloth", "aws-sdk-core", "net_http.ext", "-", ".cat", "A" * 255])
def test_valid_gem_names(name: str) -> None:
    assert names.is_valid_rubygems(name) and names.normalize_rubygems(f" {name} ") == name


@pytest.mark.parametrize("name", ["", ".", "..", "a/b", "a b", "ä", "A" * 256, "x%2F"])
def test_invalid_gem_names(name: str) -> None:
    assert not names.is_valid_rubygems(name)


def _line(key: str, *, deps: str = "", created: str | None = "2026-01-02T03:04:05Z", sha: str = SHA) -> bytes:
    fields = f"checksum:{sha},ruby:>= 2.4.0"
    if created is not None:
        fields += f",created_at:{created}"
    return f"{key} {deps}|{fields}".encode()


def test_info_lines_are_parsed_and_kept_byte_for_byte() -> None:
    lines = [
        _line("1.19.4-x86_64-linux-gnu", deps="racc:~> 1.4,mini_portile2:~> 2.8.2&>= 2.8"),
        _line("1.19.4"),
        _line("1.19.4"),  # repeated: the first counts
        _line("2.0.0", sha="nope"),  # nothing a download could be checked against
        _line("2.0.1", created=None),
        _line("2.0.2", created="2026-01-02T03:04:05"),  # no time zone: not a usable time
        b"garbage",
    ]
    body = b"---\n" + b"\n".join(lines) + b"\n"
    info = I.parse("nokogiri", body)
    assert info.header == b"---\n"
    assert list(info.lines) == ["1.19.4-x86_64-linux-gnu", "1.19.4", "2.0.1", "2.0.2"]
    native = info.lines["1.19.4-x86_64-linux-gnu"]
    assert (native.version, native.platform, native.sha256, native.raw) == ("1.19.4", "x86_64-linux-gnu", SHA, lines[0])
    assert info.lines["1.19.4"].platform == "ruby" and info.lines["1.19.4"].created_at == 1767323045.0
    assert info.lines["2.0.1"].created_at is None and info.lines["2.0.2"].created_at is None
    assert I.parse_line(f"2.0.3 |checksum:{SHA}\n".encode()) is None  # `$` would match before the newline
    served = I.render(info, {"1.19.4-x86_64-linux-gnu"})
    assert served == b"---\n" + lines[1] + b"\n" + lines[4] + b"\n" + lines[5] + b"\n"
    assert I.render(info, set(info.lines)) == b"---\n"
    assert I.etag(served) == '"' + hashlib.md5(served, usedforsecurity=False).hexdigest() + '"'
    assert I.repr_digest(served) == "sha-256=:" + base64.b64encode(hashlib.sha256(served).digest()).decode() + ":"


# Info lines from rubygems.org (2026-10-25): gem, key, the line's `rubygems:` and `platform:` fields, and the number
# and platform rubygems.org's API (/api/v1/versions/<gem>.json) gives for the line's checksum.
LIVE_KEYS = [
    ("asciidoctor-reducer", "1.0.0-beta.1", "> 1.3.1", "", "1.0.0-beta.1", "ruby"),
    ("asciidoctor-reducer", "1.0.0-rc.1", "> 1.3.1", "", "1.0.0-rc.1", "ruby"),
    ("version_test", "1.1.1-1.1.1", "", "", "1.1.1", "1.1.1"),
    ("version_test", "1.1.2-1.1.1", "", "", "1.1.2", "1.1.1"),
    ("uuidtoolds", "0.0.2-do_not_install", "", "", "0.0.2", "do_not_install"),
    ("test1234567890", "0.1.0-1-2-3-4", "", "", "0.1.0", "1-2-3-4"),
    ("test1234567890", "0.1.0-java17", "", "", "0.1.0", "java17"),
    ("test1234567890", "1.0.0.pre.alpha-java17", "", "", "1.0.0.pre.alpha", "java17"),
    ("test1234567890", "1.0.0-java-17", "", "", "1.0.0", "java-17"),
    ("shattered_ogre", "0.4-windows", "", "", "0.4", "windows"),
    ("shattered_ogre", "0.3-i386-mswin32", "", "", "0.3", "i386-mswin32"),
    ("sqldroid", "0.2.1-android", "", "", "0.2.1", "android"),
    ("sqldroid", "0.0.2-java", "", "", "0.0.2", "java"),
    ("zen-engine-ruby", "0.0.1-amd64-windows", "", "", "0.0.1", "amd64-windows"),
    ("zen-engine-ruby", "0.0.1-amd64-linux", "", "", "0.0.1", "amd64-linux"),
    ("couchbase", "3.0.0.alpha.1-universal-darwin-19", "> 1.3.1", "", "3.0.0.alpha.1", "universal-darwin-19"),
    ("couchbase", "3.0.0.alpha.1-x86_64-darwin-19", "> 1.3.1", "", "3.0.0.alpha.1", "x86_64-darwin-19"),
    ("sass-embedded", "1.58.3-aarch64-linux-android", ">= 3.3.22", "", "1.58.3", "aarch64-linux-android"),
    ("sass-embedded", "1.74.1-riscv64-linux-musl", "", "", "1.74.1", "riscv64-linux-musl"),
    ("sass-embedded", "1.74.1-x86_64-cygwin", "", "", "1.74.1", "x86_64-cygwin"),
    ("sass-embedded", "1.58.0-arm-linux-musleabihf", ">= 3.3.22", "", "1.58.0", "arm-linux-musleabihf"),
    ("aikido-zen", "1.0.1.beta.3-arm64-linux-musl", "", "", "1.0.1.beta.3", "arm64-linux-musl"),
    ("aikido-zen", "0.1.0-x86_64-mingw-64", "", "", "0.1.0", "x86_64-mingw-64"),
    ("aikido-zen", "0.1.0-arm64-linux", "", "", "0.1.0", "arm64-linux"),
    ("beamer-rails", "0.1.0.beta4-arm64-linux-gnu", "", "", "0.1.0.beta4", "arm64-linux-gnu"),
    ("beamer-rails", "0.1.0.beta4-x86_64-linux-musl", "", "", "0.1.0.beta4", "x86_64-linux-musl"),
    ("rubydex", "0.4.2-04da877c", ">= 4.1.0.a", "x86_64-darwin", "0.4.2", "x86_64-darwin"),
    ("jenshenny-nokogiri", "1.19.4-86e5e59f", ">= 4.1.0.dev", "= arm64-darwin", "1.19.4", "arm64-darwin"),
    ("content_addressable_test", "0.1.0-a56253e0", ">= 4.1.0.beta1", "arm64-darwin", "0.1.0", "arm64-darwin"),
    ("flot-graph-rails", "1.0.0-Ruby", ">= 1.3.6", "", "1.0.0", "Ruby"),
    ("test-platform", "1.0-RubyMotion", "", "", "1.0", "RubyMotion"),
    ("ironbuildrake", "0.1.1-ironruby", "", "", "0.1.1", "ironruby"),
    ("mygem57", "1.0.0-ruby_2.6", "", "", "1.0.0", "ruby_2.6"),
    ("mygem57", "1.0.0-x86_64-darwin-19", "", "", "1.0.0", "x86_64-darwin-19"),
    ("libnotify", "0.5.6.pre-universal-rubinius-1.2", "> 1.3.1", "", "0.5.6.pre", "universal-rubinius-1.2"),
    ("example_gem", "0.0.1-dalvik10", "", "", "0.0.1", "dalvik10"),
    ("wxruby3", "0.9.0.pre.beta.1-x64-mingw-ucrt-3.2", "", "", "0.9.0.pre.beta.1", "x64-mingw-ucrt-3.2"),
    ("rubywmq", "0.3.0-i386-mswin32-mq5.3", "", "", "0.3.0", "i386-mswin32-mq5.3"),
    ("rubywmq", "0.3.0-sparc-solaris2.8-mq5.3", "", "", "0.3.0", "sparc-solaris2.8-mq5.3"),
    ("iron-term-ansicolor", "0.0.3-universal-.net-2.0", "", "", "0.0.3", "universal-.net-2.0"),
    ("unimidi", "0.1.4-x86_64-darwin10.7.0", ">= 1.3.6", "", "0.1.4", "x86_64-darwin10.7.0"),
    ("ibmi_db", "2.5.14-powerpc-aix-6", "", "", "2.5.14", "powerpc-aix-6"),
    ("iseq", "0.0.2-x86-mswin32-1.9.1", "", "", "0.0.2", "x86-mswin32-1.9.1"),
    ("ji2p", "0.0.3-jruby-java-universal-java-9", "", "", "0.0.3", "jruby-java-universal-java-9"),
    ("minio", "0.1.0-x86_64-windows", "", "", "0.1.0", "x86_64-windows"),
    ("rockbox_ffi", "0.1.0-x86_64-netbsd", "", "", "0.1.0", "x86_64-netbsd"),
    ("suzuna", "0.0.1-freebsd", "", "", "0.0.1", "freebsd"),
    ("libpng", "1.6.58.4-aarch64-linux-ohos", "", "", "1.6.58.4", "aarch64-linux-ohos"),
    ("cpr", "0.1.0-darwin", "", "", "0.1.0", "darwin"),
]


@pytest.mark.parametrize("case", LIVE_KEYS, ids=lambda case: f"{case[0]}-{case[1]}")
def test_keys_split_into_the_version_and_platform_rubygems_org_has(case: tuple[str, ...]) -> None:
    _gem, key, rubygems, platform, number, api_platform = case
    fields = f"checksum:{SHA},ruby:>= 2.4.0" + (f",rubygems:{rubygems}" if rubygems else "")
    fields += (f",platform:{platform}" if platform else "") + ",created_at:2026-01-02T03:04:05Z"
    line = I.parse_line(f"{key} |{fields}".encode())
    assert line is not None and line.key == key
    assert (line.version, line.platform) == (number, api_platform)


def test_a_version_with_a_dash_is_matched_and_ordered_as_itself() -> None:
    # The `> 1.3.1` mark makes the dash part of the version, unless the rest is a platform RubyGems knows.
    assert I.split_key("1.0.0-beta.1", prerelease=True) == ("1.0.0-beta.1", "ruby")
    assert I.split_key("1.0.0-arm64-darwin", prerelease=True) == ("1.0.0", "arm64-darwin")
    assert I.split_key("1.0.0-beta.1-x86_64-linux", prerelease=True) == ("1.0.0", "beta.1-x86_64-linux")
    assert I.split_key("1.0.0-do_not_install", prerelease=True) == ("1.0.0", "do_not_install")  # no version
    assert I.split_key("1.0.0-beta.1") == ("1.0.0", "beta.1")  # without the mark, as Bundler reads it
    assert I.split_key("0.4.2-04da877c") == ("0.4.2", "04da877c")  # a digest without a platform field
    assert I.split_key("1.0-") == ("1.0", "ruby")
    # Without the line (a file no longer listed), a key that can be either names both versions.
    assert I.readings("1.0.0-beta.1") == ["1.0.0", "1.0.0-beta.1"] and I.readings("1.0.0") == ["1.0.0"]
    assert I.readings("1.19.4-x86_64-linux-gnu") == ["1.19.4"]
    # Gem::Version reads `-` as `.pre.`: a prerelease, below 1.0.0 and above 1.0.0.beta.
    assert versions.is_prerelease("rubygems", "1.0.0-beta.1")
    assert versions.sort_key("rubygems", "1.0.0.beta") < versions.sort_key("rubygems", "1.0.0-beta.1")
    assert versions.sort_key("rubygems", "1.0.0-beta.1") < versions.sort_key("rubygems", "1.0.0-rc.1")
    assert versions.sort_key("rubygems", "1.0.0-rc.1") < versions.sort_key("rubygems", "1.0.0")
    assert versions.in_range("rubygems", "1.0.0-beta.1", "< 1.0.0")
    assert not versions.in_range("rubygems", "1.0.0-beta.1", "= 1.0.0")
    assert versions.in_range("rubygems", "1.0.0-beta.1", "= 1.0.0-beta.1")


def test_file_names_split_before_each_version() -> None:
    assert I.split_file("rack-3.1.8") == [("rack", "3.1.8")]
    assert I.split_file("nokogiri-1.19.4-x86_64-linux-gnu") == [("nokogiri", "1.19.4-x86_64-linux-gnu")]
    assert I.split_file("google-protobuf-4.31.1-x86_64-linux") == [("google-protobuf", "4.31.1-x86_64-linux")]
    assert I.split_file("fake-2fa-1.0.0") == [("fake", "2fa-1.0.0"), ("fake-2fa", "1.0.0")]
    assert I.split_file("rack") == [] and I.split_file("rack-") == []


def test_versions_lines_get_zeros_for_their_checksums() -> None:
    upstream = b"created_at: 2026-10-01T00:00:04Z\n---\nrack 1.0,2.0 " + b"f" * 32 + b"\n-A 0.0.0 " + b"0a" * 16 + b"\n"
    served = VF.zero_checksums(upstream)
    assert (
        served == b"created_at: 2026-10-01T00:00:04Z\n---\nrack 1.0,2.0 " + VF.ZEROS + b"\n-A 0.0.0 " + VF.ZEROS + b"\n"
    )
    assert len(served) == len(upstream)
    # Line by line: the result for a file is the result for its parts, split at line ends.
    cut = upstream.index(b"\n-A") + 1
    assert VF.zero_checksums(upstream[:cut]) + VF.zero_checksums(upstream[cut:]) == served
    assert VF.complete_lines(b"a 1 x\nb 2") == b"a 1 x\n" and VF.complete_lines(b"partial") == b""
    assert VF.parse_digest({"repr-digest": 'sha-256="abc="'}) == "abc="
    assert VF.parse_digest({"digest": "md5=:x:, sha-256=:def=:"}) == "def="
    assert VF.parse_digest({}) is None


class _Upstream:
    """rubygems.org's /versions: Range from an offset, If-None-Match, Repr-Digest of the whole file."""

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.requests: list[dict[str, str]] = []
        self.fail = False

    async def fetch(self, url: str, *, headers: dict[str, str], max_bytes: int) -> FetchResult:
        self.requests.append(dict(headers))
        if self.fail:
            raise UpstreamError(url, "down")
        tag = '"' + hashlib.md5(self.body, usedforsecurity=False).hexdigest() + '"'
        meta = {"etag": tag, "repr-digest": f'sha-256="{VF.sha256_b64(self.body)}"'}
        if headers.get("If-None-Match") == tag:
            return FetchResult(304, meta, b"", url, "HTTP/2")
        if rng := headers.get("Range"):
            start = int(rng.removeprefix("bytes=").rstrip("-"))
            meta["content-range"] = f"bytes {start}-{len(self.body) - 1}/{len(self.body)}"
            return FetchResult(206, meta, self.body[start:], url, "HTTP/2")
        return FetchResult(200, meta, self.body, url, "HTTP/2")


async def test_the_versions_copy_appends_rebuilds_and_survives_a_crash(tmp_path: Path) -> None:
    now = [1000.0]
    base = b"created_at: x\n---\na 1.0 " + b"1" * 32 + b"\n"
    up = _Upstream(base)
    vf = VF.VersionsFile(tmp_path, up, "https://index.example/versions", lambda: now[0])  # type: ignore[arg-type]
    snap = await vf.snapshot()
    assert (snap.generation, snap.size) == (1, len(base)) and up.requests[-1] == {"Accept-Encoding": "identity"}
    served = (tmp_path / "served.1").read_bytes()
    assert served == VF.zero_checksums(base) and snap.md5 == hashlib.md5(served, usedforsecurity=False).hexdigest()
    assert await vf.snapshot() == snap and len(up.requests) == 1  # fresh for a minute

    now[0] += 61
    up.body = base + b"b 2.0 " + b"2" * 32 + b"\n"
    snap = await vf.snapshot()
    assert up.requests[-1]["Range"] == f"bytes={len(base) - 1}-" and snap.generation == 1
    assert (tmp_path / "served.1").read_bytes() == VF.zero_checksums(up.body) and snap.size == len(up.body)

    now[0] += 61
    snap = await vf.snapshot()  # unchanged: a 304
    assert snap.size == len(up.body) and snap.checked == now[0]

    # A worker died after appending to the files but before writing the state: the next append cuts them back.
    with (tmp_path / "upstream.1").open("ab") as f:
        f.write(b"half a li")
    with (tmp_path / "served.1").open("ab") as f:
        f.write(b"half a li")
    now[0] += 61
    up.body += b"c 3.0 " + b"3" * 32 + b"\n"
    snap = await vf.snapshot()
    assert (tmp_path / "served.1").read_bytes() == VF.zero_checksums(up.body)
    assert (tmp_path / "upstream.1").read_bytes() == up.body

    # The monthly rebuild: no longer an append, so the whole file again, as a new generation.
    now[0] += 61
    up.body = b"created_at: y\n---\na 1.0 " + b"4" * 32 + b"\nb 2.0 " + b"5" * 32 + b"\n"
    snap = await vf.snapshot()
    assert snap.generation == 2 and (tmp_path / "served.2").read_bytes() == VF.zero_checksums(up.body)
    assert not (tmp_path / "served.1").exists() and not (tmp_path / "upstream.1").exists()
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["generation"] == 2 and state["size"] == len(up.body)

    # rubygems.org unreachable: the last copy.
    now[0] += 61
    up.fail = True
    assert (await vf.snapshot()).generation == 2


async def test_a_copy_that_cannot_be_written_leaves_the_last_one_served(tmp_path: Path) -> None:
    now = [1000.0]
    base = b"created_at: x\n---\na 1.0 " + b"1" * 32 + b"\n"
    up = _Upstream(base)
    vf = VF.VersionsFile(tmp_path, up, "https://index.example/versions", lambda: now[0])  # type: ignore[arg-type]
    good = await vf.snapshot()

    def full(*_args: object) -> None:
        raise OSError(28, "No space left on device")

    vf._write_append = full  # type: ignore[method-assign]
    vf._write_full = full  # type: ignore[method-assign]
    for body in (base + b"b 2.0 " + b"2" * 32 + b"\n", b"created_at: y\n---\n"):  # an append, then a rebuild
        now[0] += 61
        up.body = body
        assert await vf.snapshot() == good
        with vf.open(good) as f:
            assert f.read() == VF.zero_checksums(base)


async def test_without_a_copy_an_upstream_failure_is_an_error(tmp_path: Path) -> None:
    up = _Upstream(b"")
    up.fail = True
    vf = VF.VersionsFile(tmp_path, up, "https://index.example/versions", lambda: 0.0)  # type: ignore[arg-type]
    with pytest.raises(UpstreamError):
        await vf.snapshot()


async def test_a_versions_file_that_does_not_match_its_digest_is_refused(tmp_path: Path) -> None:
    class Wrong(_Upstream):
        async def fetch(self, url: str, **kw: Any) -> FetchResult:
            res = await super().fetch(url, **kw)
            res.headers["repr-digest"] = 'sha-256="AAAA"'
            return res

    vf = VF.VersionsFile(tmp_path, Wrong(b"a 1 " + b"0" * 32 + b"\n"), "u", lambda: 0.0)  # type: ignore[arg-type]
    with pytest.raises(UpstreamError, match="Repr-Digest"):
        await vf.snapshot()
