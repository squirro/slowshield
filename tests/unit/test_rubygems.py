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
    served = I.render(info, {"1.19.4-x86_64-linux-gnu"})
    assert served == b"---\n" + lines[1] + b"\n" + lines[4] + b"\n" + lines[5] + b"\n"
    assert I.render(info, set(info.lines)) == b"---\n"
    assert I.etag(served) == '"' + hashlib.md5(served, usedforsecurity=False).hexdigest() + '"'
    assert I.repr_digest(served) == "sha-256=:" + base64.b64encode(hashlib.sha256(served).digest()).decode() + ":"


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
