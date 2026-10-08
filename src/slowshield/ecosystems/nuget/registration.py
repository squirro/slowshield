"""NuGet registrations: one snapshot per package, rendered without the versions SlowShield holds back.

A registration index lists pages of versions (https://learn.microsoft.com/nuget/api/registration-base-url-resource).
nuget.org inlines the pages of a package with at most 128 versions and links the rest, 64 versions each, as separate
documents. A snapshot is the index plus every linked page, read together, so the registration, its pages and the flat
container list (built from the snapshot too) always agree.

Rendering removes the held and blocked versions, counts and bounds every page again in NuGet's version order, drops
pages left empty, and points the URLs a client follows (registration, pages, leaves, package downloads) at SlowShield.
Catalog, icon, licence and readme URLs stay as nuget.org wrote them. See docs/design/nuget.md.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import msgspec

from slowshield.ecosystems.nuget import version as NV

MAX_DOCUMENT_BYTES = 32 << 20
MAX_PAGES = 2000  # nuget.org's largest packages have a few hundred pages of 64 versions
_LEAF_CONTEXT = {
    "@vocab": "http://schema.nuget.org/schema#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "catalogEntry": {"@type": "@id"},
    "registration": {"@type": "@id"},
    "packageContent": {"@type": "@id"},
    "published": {"@type": "xsd:dateTime"},
}


class RegistrationError(ValueError):
    """A registration document SlowShield can't use."""


@dataclass(frozen=True, slots=True)
class Leaf:
    version: str  # canonical: lower-case normalized
    doc: dict[str, Any]  # the registration leaf as nuget.org wrote it
    listed: bool
    published: float | None  # as stated; None when missing or unreadable
    published_raw: str
    catalog_url: str | None
    key: tuple[Any, ...]  # NuGet's version order


@dataclass(frozen=True, slots=True)
class Page:
    doc: dict[str, Any]  # the page entry in the index, without `items`
    inlined: bool
    leaves: tuple[Leaf, ...]
    context: Any  # a linked page's own @context


@dataclass(frozen=True, slots=True)
class Snapshot:
    id: str  # lower case
    index: dict[str, Any]  # the index document, without its pages
    pages: tuple[Page, ...]
    versions: dict[str, Leaf]  # canonical version -> leaf, in NuGet's version order
    content_id: str
    weight: int  # approximate memory cost, for the metadata cache

    def served(self, drop: Collection[str]) -> list[str]:
        """The versions left after `drop`, in NuGet's version order (the flat container list)."""
        return [v for v in self.versions if v not in drop]


@dataclass(frozen=True, slots=True)
class Urls:
    """SlowShield's URLs for one package, as a client should see them."""

    registration: str  # <base>/nuget/v3/registration/
    flat: str  # <base>/nuget/v3/flatcontainer/

    def index(self, pid: str) -> str:
        return f"{self.registration}{pid}/index.json"

    def page(self, pid: str, lower: str, upper: str) -> str:
        return f"{self.registration}{pid}/page/{lower}/{upper}.json"

    def leaf(self, pid: str, ver: str) -> str:
        return f"{self.registration}{pid}/{ver}.json"

    def nupkg(self, pid: str, ver: str) -> str:
        return f"{self.flat}{pid}/{ver}/{pid}.{ver}.nupkg"


def parse_time(raw: Any) -> float | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return dt.timestamp() if dt.tzinfo is not None else None


def page_urls(index: Any, base: str) -> list[str]:
    """The pages of `index` that aren't inlined, which must be fetched too. Only URLs under `base` (the configured
    registration hive) are followed."""
    items = _items(index, "registration index")
    if len(items) > MAX_PAGES:
        raise RegistrationError(f"registration index lists {len(items)} pages")
    out: list[str] = []
    for page in items:
        if not isinstance(page, dict):
            raise RegistrationError("registration page entry is not an object")
        if "items" in page:
            continue
        url = page.get("@id")
        if not isinstance(url, str) or not url.startswith(base) or "?" in url or "#" in url:
            raise RegistrationError(f"registration page outside the configured hive: {url!r}")
        out.append(url)
    return out


def _items(doc: Any, what: str) -> list[Any]:
    if not isinstance(doc, dict):
        raise RegistrationError(f"{what} is not an object")
    items = doc.get("items", [])
    if not isinstance(items, list):
        raise RegistrationError(f"{what} items are not a list")
    return items


def _leaf(pid: str, doc: Any) -> Leaf | None:
    """A version of package `pid`, or None for an entry SlowShield won't serve (another package, no readable
    version)."""
    if not isinstance(doc, dict):
        return None
    entry = doc.get("catalogEntry")
    if not isinstance(entry, dict):
        return None
    name, raw_version = entry.get("id"), entry.get("version")
    if not isinstance(name, str) or name.lower() != pid or not isinstance(raw_version, str):
        return None
    parsed = NV.parse(raw_version)
    if parsed is None:
        return None
    catalog = entry.get("@id")
    published = entry.get("published")
    return Leaf(
        parsed.canonical,
        doc,
        entry.get("listed", True) is not False,
        parse_time(published),
        published if isinstance(published, str) else "",
        catalog if isinstance(catalog, str) else None,
        parsed.key,
    )


def parse(pid: str, index: Any, pages: dict[str, Any], raw_size: int = 0) -> Snapshot:
    """The snapshot of package `pid` (lower case) from its registration index and the linked pages, by URL."""
    items = _items(index, "registration index")
    out_pages: list[Page] = []
    versions: dict[str, Leaf] = {}
    for entry in items:
        if not isinstance(entry, dict):
            raise RegistrationError("registration page entry is not an object")
        inlined = "items" in entry
        if inlined:
            source, context = entry, None
        else:
            url = entry.get("@id")
            if not isinstance(url, str) or url not in pages:
                raise RegistrationError(f"registration page missing from the snapshot: {url!r}")
            source = pages[url]
            context = source.get("@context") if isinstance(source, dict) else None
        leaves: list[Leaf] = []
        for doc in _items(source, "registration page"):
            leaf = _leaf(pid, doc)
            if leaf is None or leaf.version in versions:
                continue
            versions[leaf.version] = leaf
            leaves.append(leaf)
        meta = {k: v for k, v in entry.items() if k != "items"}
        out_pages.append(Page(meta, inlined, tuple(leaves), context))
    ordered = dict(sorted(versions.items(), key=lambda kv: kv[1].key))
    body = msgspec.json.encode([index, sorted(pages.items())])
    content_id = hashlib.blake2b(body, digest_size=12).hexdigest()
    meta_index = {k: v for k, v in index.items() if k != "items"}
    return Snapshot(pid, meta_index, tuple(out_pages), ordered, content_id, 1024 + 3 * (raw_size or len(body)))


def package_hash(doc: Any, pid: str, version: str) -> tuple[bytes, int | None] | str:
    """The SHA512 and size a catalog leaf states for `pid` (lower case) `version` (canonical), or what is wrong with
    it. `packageHash` is base64, `packageHashAlgorithm` "SHA512"."""
    if not isinstance(doc, dict):
        return "no catalog entry"
    if str(doc.get("id", "")).lower() != pid or NV.canonical(str(doc.get("version", ""))) != version:
        return "the catalog entry names another package"
    if str(doc.get("packageHashAlgorithm", "")).upper() != "SHA512":
        return "the catalog entry has no SHA512 packageHash"
    try:
        digest = base64.b64decode(str(doc.get("packageHash", "")), validate=True)
    except ValueError:
        return "the catalog entry's packageHash is not base64"
    if len(digest) != 64:
        return "the catalog entry's packageHash is not a SHA512"
    size = doc.get("packageSize")
    return digest, size if isinstance(size, int) and not isinstance(size, bool) and size > 0 else None


# ---- rendering -----------------------------------------------------------------------------------------------


def _rewrite_leaf(pid: str, leaf: Leaf, urls: Urls) -> dict[str, Any]:
    doc = dict(leaf.doc)
    doc["@id"] = urls.leaf(pid, leaf.version)
    doc["registration"] = urls.index(pid)
    doc["packageContent"] = urls.nupkg(pid, leaf.version)
    entry = dict(doc["catalogEntry"])
    if "packageContent" in entry:
        entry["packageContent"] = urls.nupkg(pid, leaf.version)
    doc["catalogEntry"] = entry
    return doc


@dataclass(frozen=True, slots=True)
class RenderedPage:
    lower: str
    upper: str
    inlined: bool
    entry: dict[str, Any]  # as it appears in the index
    leaves: tuple[Leaf, ...]
    context: Any


def pages(snap: Snapshot, drop: Collection[str], urls: Urls) -> list[RenderedPage]:
    """The pages as served: without the versions in `drop`, bounded and counted again, and without empty ones."""
    out: list[RenderedPage] = []
    for page in snap.pages:
        leaves = tuple(sorted((leaf for leaf in page.leaves if leaf.version not in drop), key=lambda leaf: leaf.key))
        if not leaves:
            continue
        lower, upper = leaves[0].version, leaves[-1].version
        entry = dict(page.doc)
        entry["@id"] = (
            f"{urls.index(snap.id)}#page/{lower}/{upper}" if page.inlined else urls.page(snap.id, lower, upper)
        )
        entry["count"] = len(leaves)
        entry["lower"] = lower
        entry["upper"] = upper
        if page.inlined:
            entry["parent"] = urls.index(snap.id)
            entry["items"] = [_rewrite_leaf(snap.id, leaf, urls) for leaf in leaves]
        out.append(RenderedPage(lower, upper, page.inlined, entry, leaves, page.context))
    return out


def render_index(snap: Snapshot, drop: Collection[str], urls: Urls) -> dict[str, Any]:
    rendered = pages(snap, drop, urls)
    doc = dict(snap.index)
    doc["@id"] = urls.index(snap.id)
    doc["count"] = len(rendered)
    doc["items"] = [p.entry for p in rendered]
    return doc


def render_page(snap: Snapshot, drop: Collection[str], urls: Urls, lower: str, upper: str) -> dict[str, Any]:
    """A linked page by its bounds. When the snapshot changed since the client read the index and no page has these
    bounds any more, the served versions within them, so the client still gets a consistent answer."""
    rendered = pages(snap, drop, urls)
    page = next((p for p in rendered if not p.inlined and p.lower == lower and p.upper == upper), None)
    if page is not None:
        leaves, entry, context = page.leaves, page.entry, page.context
    else:
        lo, hi = NV.parse(lower), NV.parse(upper)
        if lo is None or hi is None:
            raise RegistrationError("page bounds are not versions")
        leaves = tuple(leaf for v, leaf in snap.versions.items() if v not in drop and lo.key <= leaf.key <= hi.key)
        entry, context = {"@type": "catalog:CatalogPage"}, None
    doc = {k: v for k, v in entry.items() if k != "items"}
    doc["@id"] = urls.page(snap.id, lower, upper)
    doc["count"] = len(leaves)
    doc["lower"] = lower
    doc["upper"] = upper
    doc["parent"] = urls.index(snap.id)
    doc["items"] = [_rewrite_leaf(snap.id, leaf, urls) for leaf in leaves]
    if context is not None:
        doc["@context"] = context
    return doc


def render_leaf(snap: Snapshot, version: str, urls: Urls) -> dict[str, Any]:
    """A registration leaf document for a served version (the form nuget.org serves at `<hive><id>/<ver>.json`)."""
    leaf = snap.versions[version]
    return {
        "@id": urls.leaf(snap.id, version),
        "@type": ["Package", "http://schema.nuget.org/catalog#Permalink"],
        "catalogEntry": leaf.catalog_url,
        "listed": leaf.listed,
        "packageContent": urls.nupkg(snap.id, version),
        "published": leaf.published_raw,
        "registration": urls.index(snap.id),
        "@context": _LEAF_CONTEXT,
    }
