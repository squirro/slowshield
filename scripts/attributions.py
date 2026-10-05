"""Regenerate ATTRIBUTIONS.md from the installed runtime dependency tree.

uv sync --no-dev && uv run python scripts/attributions.py > ATTRIBUTIONS.md
"""

from __future__ import annotations

import re
from importlib import metadata

ROOT = "slowshield"

DATA_SOURCES = """
## Threat-intelligence data

| Source | Used for | Terms |
|---|---|---|
| [OSV](https://osv.dev/) | Malicious-package advisories (`MAL-*`) for PyPI, npm and Go | [CC-BY-4.0](https://github.com/google/osv.dev/blob/master/LICENSE) |
| [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) | Origin of the `MAL-*` records OSV redistributes | [Apache-2.0](https://github.com/ossf/malicious-packages/blob/main/LICENSE) |
| [GitHub Advisory Database](https://github.com/advisories) | `malware` advisories via the REST API | [CC-BY-4.0](https://github.com/github/advisory-database/blob/main/LICENSE.md) |

## Bundled front-end assets

| Asset | License |
|---|---|
| [htmx](https://htmx.org/) 4.x (`ui/static/vendor/htmx.min.js`) | 0BSD |

## Container images

Built on [Amazon Linux 2023](https://aws.amazon.com/linux/amazon-linux-2023/) packages (see each RPM's license
in the image's RPM database), [python-build-standalone](https://github.com/astral-sh/python-build-standalone)
CPython 3.15 (PSF-2.0 and bundled third-party licenses) and [Caddy](https://caddyserver.com/) (Apache-2.0).
"""


def _license(dist: metadata.Distribution) -> str:
    meta = dist.metadata
    expr = meta.get("License-Expression")
    if expr:
        return expr
    classifiers = [c.split(" :: ")[-1] for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
    if classifiers:
        return ", ".join(sorted(set(classifiers)))
    lic = (meta.get("License") or "").strip()
    return lic.splitlines()[0][:60] if lic else "see project"


def _requirements(dist: metadata.Distribution) -> list[str]:
    out = []
    for req in dist.requires or []:
        if "extra ==" in req:
            continue
        name = re.split(r"[\s;<>=!~\[(]", req, maxsplit=1)[0]
        out.append(name)
    return out


def main() -> None:
    seen: dict[str, metadata.Distribution] = {}
    stack = [ROOT]
    while stack:
        name = stack.pop()
        key = name.lower().replace("_", "-")
        if key in seen:
            continue
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue
        seen[key] = dist
        stack.extend(_requirements(dist))
    seen.pop(ROOT, None)
    print("# Third-party attributions\n")
    print("SlowShield is built on these open-source projects. Thank you to their authors and maintainers.\n")
    print("## Python runtime dependencies\n")
    print("| Package | Version | License | Project |")
    print("|---|---|---|---|")
    for key in sorted(seen):
        dist = seen[key]
        urls = dist.metadata.get_all("Project-URL") or []
        home = next(
            (u.split(",", 1)[1].strip() for u in urls if u.lower().startswith(("source", "homepage", "repository"))), ""
        )
        home = home or dist.metadata.get("Home-page") or ""
        link = f"[link]({home})" if home.startswith("http") else ""
        print(f"| {dist.metadata['Name']} | {dist.version} | {_license(dist)} | {link} |")
    print(DATA_SOURCES)


if __name__ == "__main__":
    main()
