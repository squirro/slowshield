"""Distribution filename parsing (wheels, sdists and legacy formats) -> (normalised name, version)."""

from __future__ import annotations

import re

from packaging.utils import InvalidSdistFilename, InvalidWheelFilename, parse_sdist_filename, parse_wheel_filename

from slowshield.names import normalize_pypi
from slowshield.versions import parse_pep440

_LEGACY_EXT = (".tar.bz2", ".tar.xz", ".tgz", ".tar", ".egg", ".exe", ".msi", ".rpm", ".dmg")
_EGG = re.compile(r"^(?P<name>.+?)-(?P<ver>[^-]+?)(-py\d+(\.\d+)?)?(-.+)?\.egg$")
# Path layout of files.pythonhosted.org: /packages/<2>/<2>/<60>/<filename>; the 64 hex = blake2b-256.
PACKAGES_PATH = re.compile(
    r"^/packages/([0-9a-f]{2})/([0-9a-f]{2})/([0-9a-f]{60})/([A-Za-z0-9][A-Za-z0-9._+!~-]{0,250})$"
)


def parse(
    filename: str, *, known_versions: list[str] | None = None, project: str | None = None
) -> tuple[str | None, str | None]:
    """Return (normalised project name, version) or (None, None) if the format is unknown.

    `known_versions` / `project` let legacy filenames (ambiguous dashes) be resolved against the index.
    """
    fast = _fast(filename)
    if fast is not None:
        return fast
    try:
        if filename.endswith(".whl"):
            name, ver, _build, _tags = parse_wheel_filename(filename)
            return str(name), str(ver)
        if filename.endswith((".tar.gz", ".zip")):
            name, ver = parse_sdist_filename(filename)
            return str(name), str(ver)
    except InvalidWheelFilename:
        return None, None  # the wheel naming spec is strict: never guess
    except InvalidSdistFilename:
        pass
    if filename.endswith(".egg"):
        m = _EGG.match(filename)
        if m:
            return normalize_pypi(m.group("name")), m.group("ver")
    return _guess(filename, known_versions or [], project)


def _fast(filename: str) -> tuple[str, str] | None:
    """Spec-shaped wheels and modern sdists without the (slow) tag parsing of `packaging`."""
    if filename.endswith(".whl"):
        parts = filename[:-4].split("-")
        if len(parts) in (5, 6) and parse_pep440(parts[1]) is not None:
            return normalize_pypi(parts[0]), parts[1]
        return None
    for ext in (".tar.gz", ".zip"):
        if filename.endswith(ext):
            name, sep, ver = filename[: -len(ext)].rpartition("-")
            if sep and name and parse_pep440(ver) is not None:
                return normalize_pypi(name), ver
            return None
    return None


def _guess(filename: str, versions: list[str], project: str | None) -> tuple[str | None, str | None]:
    stem = filename
    for ext in (".tar.gz", ".zip", ".whl", *_LEGACY_EXT):
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break
    norm = normalize_pypi(stem)
    if project:
        prefix = normalize_pypi(project) + "-"
        if norm.startswith(prefix):
            rest = norm[len(prefix) :]
            for v in sorted(versions, key=len, reverse=True):
                nv = normalize_pypi(v)
                if rest == nv or rest.startswith(nv + "-"):
                    return normalize_pypi(project), v
    if "-" in stem:
        name, _, ver = stem.rpartition("-")
        return normalize_pypi(name), ver or None
    return None, None
