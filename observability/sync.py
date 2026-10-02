#!/usr/bin/env python3
"""Propagate the observability image pins and configs to every deployment variant (stdlib only).

    python3 observability/sync.py                 # rewrite the copies from the sources of truth
    python3 observability/sync.py --check         # exit 1 if any copy is stale (CI, via check.py)
    python3 observability/sync.py --from-compose  # adopt image bumps made in compose (Dependabot) first

Sources of truth and their copies:

* `observability/images.env` -> the `image:` lines in deploy/docker/compose.observability.yaml, the
  `Image=` lines of the Quadlet units in deploy/podman/observability/ and the `<component>.image`
  blocks in deploy/helm/slowshield-observability/values.yaml.
* `observability/{alloy,prometheus,loki,tempo,grafana}` -> deploy/helm/slowshield-observability/files/
  (Helm can only read files inside the chart). The Kubernetes Alloy config (config.k8s.alloy) is
  copied as files/alloy/config.alloy.

Dependabot bumps the compose file only; `--from-compose` copies those pins into images.env, then
everything else is re-synced from there.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
IMAGES_ENV = HERE / "images.env"
COMPOSE = ROOT / "deploy" / "docker" / "compose.observability.yaml"
QUADLET_DIR = ROOT / "deploy" / "podman" / "observability"
CHART = ROOT / "deploy" / "helm" / "slowshield-observability"
VALUES = CHART / "values.yaml"
CHART_FILES = CHART / "files"

# images.env key -> Helm values component.
COMPONENTS = {
    "ALLOY_IMAGE": "alloy",
    "PROMETHEUS_IMAGE": "prometheus",
    "LOKI_IMAGE": "loki",
    "TEMPO_IMAGE": "tempo",
    "GRAFANA_IMAGE": "grafana",
}

_REF = re.compile(r"(?P<repo>[a-z0-9.\-/]+):(?P<tag>[\w.\-]+)@(?P<digest>sha256:[0-9a-f]{64})")


@dataclass(frozen=True)
class Image:
    repo: str
    tag: str
    digest: str

    @property
    def ref(self) -> str:
        return f"{self.repo}:{self.tag}@{self.digest}"

    @classmethod
    def parse(cls, ref: str) -> Image:
        m = _REF.fullmatch(ref.strip())
        if not m:
            raise ValueError(f"not a repo:tag@sha256:digest reference: {ref!r}")
        return cls(m["repo"], m["tag"], m["digest"])


def read_images(text: str | None = None) -> dict[str, Image]:
    text = IMAGES_ENV.read_text() if text is None else text
    images: dict[str, Image] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            images[key.strip()] = Image.parse(value)
    missing = set(COMPONENTS) - set(images)
    if missing:
        raise ValueError(f"{IMAGES_ENV.name} lacks {', '.join(sorted(missing))}")
    return images


def _sub_refs(text: str, prefix: str, images: dict[str, Image]) -> str:
    """Replace `<prefix><repo>:<tag>@<digest>` for every pinned repository."""
    for img in images.values():
        pattern = re.compile(rf"(?m)^(?P<lead>{prefix}){re.escape(img.repo)}:[\w.\-]+@sha256:[0-9a-f]{{64}}")
        text = pattern.sub(lambda m, img=img: m["lead"] + img.ref, text)
    return text


def render_compose(text: str, images: dict[str, Image]) -> str:
    return _sub_refs(text, r"\s*image:\s*", images)


def render_quadlet(text: str, images: dict[str, Image]) -> str:
    return _sub_refs(text, r"Image=", images)


def render_values(text: str, images: dict[str, Image]) -> str:
    """Rewrite `repository: <repo>` / `tag:` / `digest:` triples (in that order) in values.yaml."""
    for img in images.values():
        pattern = re.compile(
            rf"(?m)^(?P<ind>[ \t]*)repository:[ \t]*\"?{re.escape(img.repo)}\"?[ \t]*\n"
            r"(?P=ind)tag:[^\n]*\n"
            r"(?P=ind)digest:[^\n]*$"
        )
        text = pattern.sub(
            lambda m, img=img: (
                f'{m["ind"]}repository: {img.repo}\n{m["ind"]}tag: "{img.tag}"\n{m["ind"]}digest: "{img.digest}"'
            ),
            text,
        )
    return text


def chart_file_map() -> dict[Path, Path]:
    """Chart copy -> canonical source."""
    files: dict[Path, Path] = {CHART_FILES / "alloy" / "config.alloy": HERE / "alloy" / "config.k8s.alloy"}
    for sub in ("prometheus", "loki", "tempo", "grafana"):
        for src in sorted((HERE / sub).rglob("*")):
            if src.is_file() and not src.name.startswith("."):
                files[CHART_FILES / src.relative_to(HERE)] = src
    return files


def compose_images(text: str) -> dict[str, Image]:
    """Pinned refs found in the compose file, keyed by images.env key (via the repository)."""
    by_repo = {img.repo: key for key, img in read_images().items()}
    found: dict[str, Image] = {}
    for m in re.finditer(r"(?m)^\s*image:\s*(\S+)", text):
        try:
            img = Image.parse(m[1])
        except ValueError:
            continue
        if img.repo in by_repo:
            found[by_repo[img.repo]] = img
    return found


def adopt_compose() -> list[str]:
    """Copy compose pins that differ from images.env into images.env; return the changed keys."""
    text = IMAGES_ENV.read_text()
    current = read_images(text)
    changed = []
    for key, img in compose_images(COMPOSE.read_text()).items():
        if current[key] != img:
            text = re.sub(rf"(?m)^{key}=.*$", f"{key}={img.ref}", text)
            changed.append(key)
    if changed:
        IMAGES_ENV.write_text(text)
    return changed


def planned() -> tuple[dict[Path, str | bytes], list[Path]]:
    """Desired content of every derived file, plus chart copies that no longer have a source."""
    images = read_images()
    want: dict[Path, str | bytes] = {COMPOSE: render_compose(COMPOSE.read_text(), images)}
    for unit in sorted(QUADLET_DIR.glob("*.container")):
        want[unit] = render_quadlet(unit.read_text(), images)
    want[VALUES] = render_values(VALUES.read_text(), images)
    copies = chart_file_map()
    want.update({dst: src.read_bytes() for dst, src in copies.items()})
    extra = [p for p in sorted(CHART_FILES.rglob("*")) if p.is_file() and p not in copies]
    return want, extra


def unpinned() -> list[str]:
    """Derived files that do not mention every image they should (a pin the regexes could not find)."""
    images = read_images()
    problems = []
    compose = COMPOSE.read_text()
    values = VALUES.read_text()
    for key, img in images.items():
        if f"image: {img.repo}:" not in compose:
            problems.append(f"{COMPOSE.relative_to(ROOT)}: no pinned image for {img.repo} ({key})")
        if not re.search(rf"(?m)^\s*repository:\s*\"?{re.escape(img.repo)}\"?\s*$", values):
            problems.append(f"{VALUES.relative_to(ROOT)}: no repository/tag/digest block for {img.repo} ({key})")
        if not any(f"Image={img.repo}:" in u.read_text() for u in QUADLET_DIR.glob("*.container")):
            problems.append(f"{QUADLET_DIR.relative_to(ROOT)}: no Quadlet unit uses {img.repo} ({key})")
    return problems


def main(argv: list[str]) -> int:
    check = "--check" in argv
    if "--from-compose" in argv:
        if check:
            print("--from-compose and --check are mutually exclusive")
            return 2
        for key in adopt_compose():
            print(f"images.env: adopted {key} from {COMPOSE.relative_to(ROOT)}")
    want, extra = planned()
    stale = []
    for path, body in want.items():
        current = path.read_bytes() if path.is_file() else None
        data = body.encode() if isinstance(body, str) else body
        if current != data:
            stale.append(path)
            if not check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                print("wrote", path.relative_to(ROOT))
    for path in extra:
        if not check:
            path.unlink()
            print("removed", path.relative_to(ROOT))
    problems = unpinned()
    for p in problems:
        print(p)
    if check and (stale or extra):
        for path in stale:
            print(f"stale: {path.relative_to(ROOT)}")
        for path in extra:
            print(f"no source for chart copy: {path.relative_to(ROOT)}")
        print("run: uv run python observability/sync.py   (after a Dependabot compose bump: --from-compose)")
    return 1 if problems or (check and (stale or extra)) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
