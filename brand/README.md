# SlowShield brand — “Shell-Shield”

A geometric snail whose spiral shell is a shield. The spiral is time; the amber cube at its heart is the
release being held back. *Safety through patience.*

The name and logo are trademarks of Squirro AG and are not covered by the Apache-2.0 license
(see [TRADEMARKS.md](../TRADEMARKS.md)).

## Assets

| File | Use |
|---|---|
| `mark.svg` / `mark-dark.svg` | The mark on light / dark backgrounds (UI top bar, docs) |
| `mark-mono.svg` | Single colour (`currentColor`), for print, stamps, monochrome contexts |
| `favicon.svg` | Simplified cut for 16–32 px (shield + spiral + amber dot) |
| `lockup-horizontal.svg` / `lockup-horizontal-dark.svg` | Mark + wordmark |
| `lockup-stacked.svg` | Mark, wordmark and tagline |
| `readme-hero.svg` | README banner, follows `prefers-color-scheme` |
| `social-preview.svg` / `png/social-preview.png` | GitHub social preview (1280×640) |
| `png/favicon.ico`, `png/icon-*.png` | Raster renders (regenerate with `scripts/render_brand.py`) |
| `tokens.css` | Colour tokens, mirrored in the UI stylesheet and Grafana dashboards |
| `proposals/` | The three concepts that were evaluated, with their generator |

## Rules

* Keep clear space of at least ¼ of the mark's width around it; never put it on busy imagery.
* Don't recolour the amber cube — it carries the meaning ("held"). On single-colour media use `mark-mono.svg`.
* Below 32 px use `favicon.svg` (the full mark's antennae and spiral turns disappear at 16 px).
* Wordmark: "Slow" in ink, "Shield" in brand teal, system UI font stack; tagline in amber (`--hold-bright`) or muted.
* Colours: brand teal `#0f6e5d` / `#3cc4a6` (dark), amber `#d98a1c`, status colours only for status
  (held `#a44a07`, blocked `#c0262d`, tampered `#a21caf`, available `#137334`).

Regenerate rasters after editing an SVG:

```bash
uv run --with resvg-py --with pillow python scripts/render_brand.py
```
