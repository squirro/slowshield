"""Artifact-level `maven-metadata.xml`: read the version list, and write it back without the versions SlowShield
holds. Only the `<version>` entries and `<latest>`/`<release>` change; everything else stays byte for byte."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from defusedxml import DefusedXmlException
from defusedxml import ElementTree as SafeET

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

_VERSIONS = re.compile(r"<versions>(.*?)</versions>", re.S)
_VERSION = re.compile(r"[ \t]*<version>\s*([^<]*?)\s*</version>[ \t]*\r?\n?")


class MetadataError(ValueError):
    """A rewritten document that doesn't read back as intended: never served."""


@dataclass(frozen=True, slots=True)
class Metadata:
    group: str | None  # as the document says; SlowShield goes by the path
    artifact: str | None
    versions: tuple[str, ...]
    latest: str | None
    release: str | None
    raw: bytes


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(el: Element | None, name: str) -> Element | None:
    if el is None:
        return None
    return next((c for c in el if _local(c.tag) == name), None)


def _text(el: Element | None) -> str | None:
    return el.text.strip() if el is not None and el.text and el.text.strip() else None


def _root(body: bytes) -> Element | None:
    try:
        # defusedxml, and no DTD at all: Maven metadata never has one, so no entity can ever be expanded.
        root = SafeET.fromstring(body, forbid_dtd=True)
    except SafeET.ParseError, DefusedXmlException:
        return None
    return root if _local(root.tag) == "metadata" else None


def parse(body: bytes) -> Metadata | None:
    """An artifact's version list, or None for anything else: see kind()."""
    root = _root(body)
    versioning = _child(root, "versioning")
    versions_el = _child(versioning, "versions")
    if root is None or versions_el is None:
        return None
    group, artifact = _text(_child(root, "groupId")), _text(_child(root, "artifactId"))
    versions = tuple(dict.fromkeys(v for c in versions_el if _local(c.tag) == "version" if (v := _text(c))))
    return Metadata(
        group, artifact, versions, _text(_child(versioning, "latest")), _text(_child(versioning, "release")), body
    )


def kind(body: bytes) -> str | None:
    """`versions` (an artifact's version list), `snapshot` (one snapshot version's builds), `plugins` (a group's
    plugin prefixes), or None: unreadable, a DOCTYPE, or none of these."""
    root = _root(body)
    if root is None:
        return None
    versioning = _child(root, "versioning")
    if _child(versioning, "versions") is not None:
        return "versions"
    if _child(versioning, "snapshot") is not None or _child(versioning, "snapshotVersions") is not None:
        return "snapshot"
    return "plugins" if _child(root, "plugins") is not None else None


def _replace(text: str, tag: str, value: str | None) -> str:
    pattern = re.compile(rf"([ \t]*)<{tag}>[^<]*</{tag}>([ \t]*\r?\n?)")
    if value is None:
        return pattern.sub("", text, count=1)
    return pattern.sub(lambda m: f"{m.group(1)}<{tag}>{value}</{tag}>{m.group(2)}", text, count=1)


def render(md: Metadata, keep: set[str], latest: str | None, release: str | None) -> bytes:
    text = md.raw.decode("utf-8")

    def versions(m: re.Match[str]) -> str:
        inner = _VERSION.sub(lambda v: v.group(0) if v.group(1) in keep else "", m.group(1))
        return f"<versions>{inner}</versions>"

    text = _VERSIONS.sub(versions, text, count=1)
    text = _replace(text, "latest", latest)
    text = _replace(text, "release", release)
    out = text.encode("utf-8")
    # The edits are textual, so read the result back: a document they can't handle (prefixed tags, say) must not
    # go out with versions SlowShield meant to hold.
    back = parse(out)
    want = set(md.versions) & keep
    if back is None or set(back.versions) != want or back.latest != latest or back.release != release:
        raise MetadataError("the filtered maven-metadata.xml doesn't read back as intended")
    return out
