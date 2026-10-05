"""Maven version order (ComparableVersion), repository layout, and metadata filtering."""

from __future__ import annotations

import pytest

from slowshield.ecosystems.maven import layout as L
from slowshield.ecosystems.maven import metadata as MD
from slowshield.ecosystems.maven.version import compare

# Maven's own ComparableVersionTest orderings (oldest first).
QUALIFIERS = [
    "1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2", "1-beta123", "1-m2", "1-m11", "1-rc", "1-cr2",
    "1-rc123", "1-SNAPSHOT", "1", "1-sp", "1-sp2", "1-sp123", "1-abc", "1-def", "1-pom-1", "1-1-snapshot", "1-1",
    "1-2", "1-123",
]  # fmt: skip
NUMBERS = [
    "2.0", "2-1", "2.0.a", "2.0.0.a", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c", "2.1-1", "2.1.0.1",
    "2.2", "2.123", "11.a2", "11.a11", "11.b2", "11.b11", "11.m2", "11.m11", "11", "11.a", "11b", "11c", "11m",
]  # fmt: skip


@pytest.mark.parametrize("ordered", [QUALIFIERS, NUMBERS])
def test_version_order(ordered: list[str]) -> None:
    for i, older in enumerate(ordered):
        for newer in ordered[i + 1 :]:
            assert compare(older, newer) < 0, (older, newer)
            assert compare(newer, older) > 0, (newer, older)


@pytest.mark.parametrize(
    "same", [("1", "1.0", "1.0.0", "1-0", "1.0-0", "1-ga", "1-final", "1-release"), ("1-cr1", "1-rc1", "1-RC1"),
             ("1a1", "1-alpha-1", "1-a1")],
)  # fmt: skip
def test_equal_versions(same: tuple[str, ...]) -> None:
    assert all(compare(same[0], v) == 0 for v in same)


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("org/apache/commons/commons-lang3/3.21.0/commons-lang3-3.21.0.jar", "file"),
        ("org/apache/commons/commons-lang3/3.21.0/commons-lang3-3.21.0-sources.jar", "file"),
        ("org/apache/commons/commons-lang3/3.21.0/commons-lang3-3.21.0.jar.sha1", "checksum"),
        ("org/apache/commons/commons-lang3/maven-metadata.xml", "metadata"),
        ("org/apache/commons/commons-lang3/maven-metadata.xml.sha512", "metadata"),
        ("archetype-catalog.xml", "passthrough"),
        ("org/apache/commons/commons-lang3/3.21.0/unrelated.jar", None),  # not <artifactId>-<version>*
        ("org/apache/commons/commons-lang3/", None),  # no directory listings
        (".index/nexus-maven-repository-index.gz", None),
        ("org/../../etc/passwd", None),
        ("org/x/maven-metadata.xml.exe", None),
    ],
)
def test_layout(path: str, kind: str | None) -> None:
    parsed = L.parse(path)
    assert (parsed.kind if parsed else None) == kind


METADATA = b"""<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>org.x</groupId>
  <artifactId>y</artifactId>
  <versioning>
    <latest>1.2.0</latest>
    <release>1.2.0</release>
    <versions>
      <version>1.0.0</version>
      <version>1.1.0</version>
      <version>1.2.0</version>
    </versions>
    <lastUpdated>20261001120000</lastUpdated>
  </versioning>
</metadata>
"""


def test_metadata_render_changes_only_versions_latest_and_release() -> None:
    md = MD.parse(METADATA)
    assert md is not None and md.versions == ("1.0.0", "1.1.0", "1.2.0") and md.latest == "1.2.0"
    out = MD.render(md, {"1.0.0", "1.1.0"}, "1.1.0", "1.1.0")
    expected = METADATA.replace(b"      <version>1.2.0</version>\n", b"").replace(b"1.2.0</latest>", b"1.1.0</latest>")
    assert out == expected.replace(b"1.2.0</release>", b"1.1.0</release>")
    none = MD.render(md, set(), None, None)
    assert b"<latest>" not in none and b"<release>" not in none and b"<version>" not in none


@pytest.mark.parametrize(
    "attack",
    [
        b'<?xml version="1.0"?><!DOCTYPE m [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;">]>'
        b"<metadata><groupId>&b;</groupId><artifactId>y</artifactId><versioning><versions/></versioning></metadata>",
        b'<?xml version="1.0"?><!DOCTYPE m [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        b"<metadata><groupId>&x;</groupId><artifactId>y</artifactId><versioning><versions/></versioning></metadata>",
        b"<metadata><groupId>org.x</groupId>",  # truncated
    ],
)
def test_metadata_refuses_dtds_entities_and_broken_xml(attack: bytes) -> None:
    assert MD.parse(attack) is None
