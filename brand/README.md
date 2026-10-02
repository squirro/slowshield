# SlowShield brand

The full guide (mark, lockups, colour, type, motion, voice, downloads) is the website page
[`website/src/brand/index.html`](../website/src/brand/index.html), published at <https://slowshield.net/brand/>.
This file is the short version for people working in the repository.

## The idea

A shield that is **solid on the side where things arrive** and **open (dotted) on the other**. Fast things, like
a release published minutes ago or an attack, hit the solid side and stop there: the chevrons cut into it are
what got stopped. Patient, verified packages pass through the dotted side. Tagline: **Deflect, don't obstruct.**

## Files

| File | Use |
|---|---|
| `mark.svg`, `mark-dark.svg` | The mark on light / dark backgrounds (48 px and up) |
| `mark-mono.svg`, `mark-white.svg` | One colour (`currentColor`), white on brand blue or photos |
| `favicon.svg`, `favicon-32.svg` | The dedicated 16 px and 32 px drawings (the 16 px file follows the browser theme) |
| `app-icon.svg`, `png/icon-{180,192,512}.png` | Touch and app icons (opaque night square) |
| `lockup-horizontal(-dark).svg`, `lockup-stacked(-dark).svg`, `wordmark(-dark).svg` | Mark and name; all text outlined |
| `social-preview.svg`, `png/social-preview.png` | 1280 × 640 GitHub / Open Graph image |
| `readme-banner(-dark).svg` | The README header (light and dark `<picture>`) |
| `tokens.css` | Colours (light, dark, `.ss-light` / `.ss-dark` scopes), fonts, radii |
| `fonts/` | Schibsted Grotesk (SIL OFL 1.1): the variable TTF used to outline the wordmark, a Latin WOFF2 for the website |
| `palette.html` | Palette tables with measured contrast, included into the guide |
| `proposals/` | The round-2 exploration that led here (Inbound = `proposals/glance-shield/2d/inbound`) |

## Rebuilding

```sh
uv run --no-project --with fonttools --with uharfbuzz --with brotli python brand/build.py   # SVG masters, tokens, font
uv run --no-project --with resvg-py --with pillow python scripts/render_brand.py            # PNG / ICO, UI copies
```

Edit `brand/build.py`, never the generated files. The product UI (`src/slowshield/ui/static/app.css`), the website
(`website/src/assets/site.css`, which inlines `tokens.css` at build time) and the Grafana dashboards
(`observability/build_dashboards.py`) use the same palette.

## Rules of thumb

* The solid side faces left. Never mirror, recolour the halves, fill the dotted side or add objects.
* Below 48 px use the small drawings, never the scaled master. Minimum 16 px.
* Clear space: a quarter of the mark's height on every side.
* Brand blue is the only accent; status colours (available, held, blocked, tampered) mean exactly that.
* Never retype the wordmark: *Slow* is Schibsted Grotesk 500 in ink, *Shield* 750 in brand blue, outlined in the files.
