"""Artifact-level `maven-metadata.xml`: read the version list, and write it back without the versions SlowShield
holds. Only the `<version>` entries and `<latest>`/`<release>` change; everything else stays byte for byte."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET  # DOCTYPE is refused below, so no entities are ever expanded
from dataclasses import dataclass

_VERSIONS = re.compile(r"<versions>(.*?)</versions>", re.S)
_VERSION = re.compile(r"[ \t]*<version>\s*([^<]*?)\s*</version>[ \t]*\r?\n?")


@dataclass(frozen=True, slots=True)
class Metadata:
    group: str
    artifact: str
    versions: tuple[str, ...]
    latest: str | None
    release: str | None
    raw: bytes


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(el: ET.Element | None, name: str) -> ET.Element | None:
    if el is None:
        return None
    return next((c for c in el if _local(c.tag) == name), None)


def _text(el: ET.Element | None) -> str | None:
    return el.text.strip() if el is not None and el.text and el.text.strip() else None


def parse(body: bytes) -> Metadata | None:
    """The metadata of one artifact, or None for anything else (group-level plugin lists, snapshot metadata)."""
    if b"<!DOCTYPE" in body.upper() or b"<!ENTITY" in body.upper():
        return None
    try:
        root = ET.fromstring(body)  # noqa: S314 - no DOCTYPE, see above
    except ET.ParseError:
        return None
    versioning = _child(root, "versioning")
    versions_el = _child(versioning, "versions")
    group, artifact = _text(_child(root, "groupId")), _text(_child(root, "artifactId"))
    if group is None or artifact is None or versions_el is None:
        return None
    versions = tuple(dict.fromkeys(v for c in versions_el if _local(c.tag) == "version" if (v := _text(c))))
    return Metadata(
        group, artifact, versions, _text(_child(versioning, "latest")), _text(_child(versioning, "release")), body
    )


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
    return text.encode("utf-8")
