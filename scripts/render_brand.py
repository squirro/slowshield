"""Render the raster brand assets from the master SVGs in brand/ (dev-only tooling).

    uv run --no-project --with resvg-py --with pillow python scripts/render_brand.py

Writes brand/png/* and the UI copies under src/slowshield/ui/static/brand/. Run brand/build.py first.
"""

from __future__ import annotations

import io
import shutil
from pathlib import Path

import resvg_py
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / "brand"
PNG = BRAND / "png"
UI = ROOT / "src/slowshield/ui/static/brand"


def render(svg: Path, width: int, height: int | None = None) -> Image.Image:
    data = resvg_py.svg_to_bytes(svg_path=str(svg), width=width, height=height or width)
    return Image.open(io.BytesIO(bytes(data))).convert("RGBA")


def main() -> None:
    PNG.mkdir(exist_ok=True)
    UI.mkdir(parents=True, exist_ok=True)
    # The ICO carries the dedicated small drawings: 16 px from favicon.svg, 32 and 48 px from favicon-32.svg.
    icons = [
        render(BRAND / "favicon.svg", 16),
        render(BRAND / "favicon-32.svg", 32),
        render(BRAND / "favicon-32.svg", 48),
    ]
    icons[-1].save(PNG / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)], append_images=icons[:-1])
    render(BRAND / "favicon-32.svg", 32).save(PNG / "icon-32.png", optimize=True)
    for s in (180, 192, 512):  # touch and PWA icons: opaque night square
        render(BRAND / "app-icon.svg", s).save(PNG / f"icon-{s}.png", optimize=True)
    render(BRAND / "social-preview.svg", 1280, 640).save(PNG / "social-preview.png", optimize=True)
    render(BRAND / "readme-banner.svg", 1200, 280).save(PNG / "readme-banner.png", optimize=True)
    render(BRAND / "x-header.svg", 1500, 500).convert("RGB").save(PNG / "x-header.png", optimize=True)  # x.com header
    for name in ("mark.svg", "mark-dark.svg", "favicon.svg", "wordmark.svg", "wordmark-dark.svg"):
        shutil.copyfile(BRAND / name, UI / name)
    shutil.copyfile(PNG / "favicon.ico", UI / "favicon.ico")
    shutil.copyfile(PNG / "icon-180.png", UI / "apple-touch-icon.png")
    print("rendered:", ", ".join(sorted(p.name for p in PNG.iterdir())))


if __name__ == "__main__":
    main()
