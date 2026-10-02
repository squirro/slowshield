"""Build SlowShield's brand masters: the Inbound mark, Night Field palette and Schibsted Grotesk wordmark.

    uv run --no-project --with fonttools --with uharfbuzz --with brotli python brand/build.py
    uv run --no-project --with resvg-py --with pillow python scripts/render_brand.py   # PNG / ICO renders

Dev-only tooling. Writes the SVG masters, `tokens.css` and the website font subset into brand/. All text in
the logos is outlined from the brand typeface (fonts/, SIL OFL 1.1), so they render identically everywhere.
The style guide is website/src/brand/index.html (https://slowshield.net/brand/).
"""

from __future__ import annotations

import io
import xml.dom.minidom
from functools import cache
from itertools import pairwise
from pathlib import Path

import uharfbuzz as hb
from fontTools import subset
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

HERE = Path(__file__).resolve().parent
FONT_VF = HERE / "fonts" / "SchibstedGrotesk-VF.ttf"
TAGLINE = "Safety through patience."

# ============================================================================ palette: Night Field
# Text and status colours clear WCAG AA (4.5:1) on surface, ground and their own badge tint (14% light, 22% dark).

LIGHT = {
    "ground": "#f2f4fb", "surface": "#ffffff", "line": "#dce1f0", "ink": "#0a0f24", "muted": "#56607f",
    "brand": "#2a4bff", "accent": "#8ea2ff",
    "available": "#107445", "held": "#6447d6", "blocked": "#c02238", "tampered": "#b4208c",
}  # fmt: skip
DARK = {
    "ground": "#060915", "surface": "#0d1222", "line": "#1f2742", "ink": "#e6eafb", "muted": "#98a2c4",
    "brand": "#7f95ff", "accent": "#b9c6ff",
    "available": "#4fd48a", "held": "#a99bff", "blocked": "#ff6f7e", "tampered": "#f27bd6",
}  # fmt: skip
ROLES = {
    "ground": "Page background",
    "surface": "Cards, tables, top bar",
    "line": "Borders and grid lines",
    "ink": "Text and headings",
    "muted": "Secondary text, captions, axes",
    "brand": "The mark, primary actions, links, focus",
    "accent": "Glows and decoration (never text)",
    "available": "Served, healthy",
    "held": "Held back: too new, fail-open",
    "blocked": "Known malware (HTTP 451)",
    "tampered": "Tampering and integrity failures",
}
STATUS = ("brand", "available", "held", "blocked", "tampered")
FONT_DISPLAY = '"Schibsted Grotesk", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif'
FONT_TEXT = 'system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'
FONT_MONO = 'ui-monospace, "SF Mono", "Cascadia Code", "JetBrains Mono", Menlo, Consolas, monospace'


def mix(a: str, b: str, t: float) -> str:
    """t of colour a over b."""
    ra = [int(a[i : i + 2], 16) for i in (1, 3, 5)]
    rb = [int(b[i : i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x * t + y * (1 - t)):02x}" for x, y in zip(ra, rb, strict=True))


def derived(p: dict[str, str], dark: bool) -> dict[str, str]:
    """Second surface and soft badge tints, derived so they always match the palette."""
    out = dict(p)
    out["surface-2"] = mix(p["line"], p["surface"], 0.45)
    for k in STATUS:
        out[f"{k}-soft"] = mix(p[k], p["surface"], 0.22 if dark else 0.14)
    return out


# ============================================================================ geometry (64-unit grid)


def f(n: float) -> str:
    s = f"{n:.2f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def shield_halves(cx: float = 32.0, top: float = 4.0, s: float = 1.0) -> tuple[str, str]:
    """(closed left half, open right edge) of the master shield (crown at (cx, top), 44 x 56 at s = 1)."""

    def P(x: float, y: float) -> str:
        return f"{f(cx + (x - 32) * s)} {f(top + (y - 4) * s)}"

    left = f"M{P(32, 4)} L{P(10, 11)} L{P(10, 30)} C{P(10, 45)} {P(19, 55)} {P(32, 60)} Z"
    right = f"M{P(32, 4)} L{P(54, 11)} L{P(54, 30)} C{P(54, 45)} {P(45, 55)} {P(32, 60)}"
    return left, right


def _cubic_pt(p0, p1, p2, p3, t):  # type: ignore[no-untyped-def]
    mt = 1 - t
    return (
        mt**3 * p0[0] + 3 * mt * mt * t * p1[0] + 3 * mt * t * t * p2[0] + t**3 * p3[0],
        mt**3 * p0[1] + 3 * mt * mt * t * p1[1] + 3 * mt * t * t * p2[1] + t**3 * p3[1],
    )


def edge_dots(cx: float, top: float, s: float, steps: int) -> list[tuple[float, float]]:
    """Points that divide the right edge into `steps` equal arc lengths, without the two ends.

    The ends (crown and point) are covered by the solid half's corners, so the first and last visible dots
    are mirror images. Explicit circles render identically everywhere (no dasharray or pathLength support needed).
    """

    def T(x: float, y: float) -> tuple[float, float]:
        return (cx + (x - 32) * s, top + (y - 4) * s)

    pts = [T(32 + 22 * i / 400, 4 + 7 * i / 400) for i in range(400)]
    pts += [T(54, 11 + 19 * i / 400) for i in range(400)]
    pts += [T(*_cubic_pt((54, 30), (54, 45), (45, 55), (32, 60), i / 2000)) for i in range(2001)]
    cum = [0.0]
    for a, b in pairwise(pts):
        cum.append(cum[-1] + ((b[0] - a[0]) ** 2 + (b[1] - a[1]) ** 2) ** 0.5)
    total, out, j = cum[-1], [], 0
    for k in range(1, steps):
        target = total * k / steps
        while cum[j + 1] < target:
            j += 1
        u = (target - cum[j]) / (cum[j + 1] - cum[j])
        out.append((pts[j][0] + (pts[j + 1][0] - pts[j][0]) * u, pts[j][1] + (pts[j + 1][1] - pts[j][1]) * u))
    return out


def chevron(x0: float, cy: float, w: float, h: float) -> str:
    return f"M{f(x0)} {f(cy - h)} L{f(x0 + w)} {f(cy)} L{f(x0)} {f(cy + h)}"


# The three drawings of the mark: large (48 px and up), 32 px and 16 px. Same idea, weights per size.
# Dots: the right edge is divided into `steps` equal parts (pathLength), so dots sit on the crown and the point
# (hidden under the solid half's corners) and the first and last visible dots are mirror images.
DRAWINGS = {
    "mark": {"shield": (32.0, 4.0, 1.0), "edge": 4.2, "dot": 4.2, "steps": 13,
             "chevrons": (14.2, 21.8), "cw": 6.4, "ch": 8.6, "csw": 3.4, "right": "dotted"},
    "fav32": {"shield": (32.0, 3.0, 1.06), "edge": 5.6, "dot": 5.6, "steps": 10,
              "chevrons": (14.5, 23.0), "cw": 6.6, "ch": 9.0, "csw": 4.6, "right": "dotted"},
    "fav16": {"shield": (32.0, 3.0, 1.06), "edge": 5.6, "dot": 6.0, "steps": 0,
              "chevrons": (18.5,), "cw": 7.5, "ch": 10.0, "csw": 6.0, "right": "faint"},
}  # fmt: skip


def mark_body(drawing: str, uid: str, *, fill: str = "", stroke_cls: str = "", fill_cls: str = "") -> str:
    """The Inbound mark: solid left half with chevrons cut into it, dotted (or faint) right edge.

    Colour comes either from `fill` (an attribute value, e.g. a hex or currentColor) or from CSS classes.
    """
    d = DRAWINGS[drawing]
    left, right = shield_halves(*d["shield"])
    cuts = "".join(
        f'<path d="{chevron(x0, 31, d["cw"], d["ch"])}" fill="none" stroke="#000" stroke-width="{f(d["csw"])}" '
        f'stroke-linecap="round" stroke-linejoin="round"/>'
        for x0 in d["chevrons"]
    )
    paint_f = f' class="{fill_cls}"' if fill_cls else f' fill="{fill}" stroke="{fill}"'
    paint_s = f' class="{stroke_cls}"' if stroke_cls else f' stroke="{fill}"'
    if d["right"] == "dotted":
        dot_paint = f' class="{fill_cls}"' if fill_cls else f' fill="{fill}"'
        r = d["dot"] / 2
        dots = "".join(f'<circle cx="{f(x)}" cy="{f(y)}" r="{f(r)}"/>' for x, y in edge_dots(*d["shield"], d["steps"]))
        right_el = f"<g{dot_paint}>{dots}</g>"
    else:  # dots blur into grey at 16 px: a faint solid line instead
        right_el = (
            f'<path d="{right}" fill="none"{paint_s} stroke-width="{f(d["dot"])}" stroke-linecap="round" '
            f'stroke-linejoin="round" opacity=".42"/>'
        )
    return (
        f'<defs><mask id="{uid}" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80">'
        f'<rect x="-8" y="-8" width="80" height="80" fill="#fff"/>{cuts}</mask></defs>'
        f'<path d="{left}"{paint_f} stroke-width="{f(d["edge"])}" stroke-linejoin="round" mask="url(#{uid})"/>'
        f"{right_el}"
    )


def svg(inner: str, w: float, h: float, label: str, extra: str = "") -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {f(w)} {f(h)}" width="{f(w)}" height="{f(h)}" '
        f'role="img" aria-label="{label}"{extra}><title>{label}</title>{inner}</svg>'
    )


# ============================================================================ type: outlined text


@cache
def _instance(wght: int) -> tuple[TTFont, bytes]:
    font = instantiateVariableFont(TTFont(FONT_VF), {"wght": wght})
    buf = io.BytesIO()
    font.save(buf)
    return font, buf.getvalue()


def text_path(text: str, wght: int, size: float, x: float, y: float, *, tracking: float = 0.0) -> tuple[str, float]:
    """SVG path data for `text` set in Schibsted Grotesk (shaped with HarfBuzz), baseline at y. Returns (d, width)."""
    font, data = _instance(wght)
    hbfont = hb.Font(hb.Face(data))
    upem = font["head"].unitsPerEm
    buf = hb.Buffer()
    buf.add_str(text)
    buf.guess_segment_properties()
    hb.shape(hbfont, buf, {"kern": True, "liga": True})
    glyphs, order = font.getGlyphSet(), font.getGlyphOrder()
    k, adv, parts = size / upem, 0.0, []
    for info, pos in zip(buf.glyph_infos, buf.glyph_positions, strict=True):
        pen = SVGPathPen(glyphs, ntos=f)
        glyphs[order[info.codepoint]].draw(TransformPen(pen, (k, 0, 0, -k, x + (adv + pos.x_offset) * k, y)))
        parts.append(pen.getCommands())
        adv += pos.x_advance + tracking * upem
    width = (adv - tracking * upem) * k
    return " ".join(p for p in parts if p), width


def text_el(text: str, wght: int, size: float, x: float, y: float, fill: str, *, anchor: str = "start",
            tracking: float = 0.0) -> tuple[str, float]:  # fmt: skip
    _, width = text_path(text, wght, size, 0, y, tracking=tracking)
    x0 = x - width / 2 if anchor == "middle" else x - width if anchor == "end" else x
    d, _ = text_path(text, wght, size, x0, y, tracking=tracking)
    return f'<path fill="{fill}" d="{d}"/>', width


def wordmark(x: float, y: float, size: float, p: dict[str, str], *, anchor: str = "start") -> tuple[str, float]:
    """`Slow` in ink at 500, `Shield` in brand blue at 750, set tight."""
    _, w1 = text_path("Slow", 500, size, 0, y)
    _, w2 = text_path("Shield", 750, size, 0, y)
    total = w1 + w2
    x0 = x - total / 2 if anchor == "middle" else x
    a, _ = text_path("Slow", 500, size, x0, y)
    b, _ = text_path("Shield", 750, size, x0 + w1, y)
    return f'<path fill="{p["ink"]}" d="{a}"/><path fill="{p["brand"]}" d="{b}"/>', total


# ============================================================================ assets


def mark_svg(p: dict[str, str] | None, drawing: str = "mark", label: str = "SlowShield") -> str:
    if p is None:  # one colour, inherits currentColor
        return svg(mark_body(drawing, "m", fill="currentColor"), 64, 64, label, ' color="#111111"')
    return svg(mark_body(drawing, "m", fill=p["brand"]), 64, 64, label)


def favicon_svg(drawing: str) -> str:
    """Adapts to the browser theme with a media query (supported for SVG favicons)."""
    style = (
        f"<style>.f{{fill:{LIGHT['brand']};stroke:{LIGHT['brand']}}}.s{{stroke:{LIGHT['brand']}}}"
        f"@media (prefers-color-scheme:dark){{.f{{fill:{DARK['brand']};stroke:{DARK['brand']}}}"
        f".s{{stroke:{DARK['brand']}}}}}circle{{stroke:none}}</style>"
    )
    return svg(style + mark_body(drawing, "m", fill_cls="f", stroke_cls="s"), 64, 64, "SlowShield")


def app_icon_svg() -> str:
    """Touch / PWA icon: the dark mark on a night square (platforms add their own corner rounding)."""
    inner = (
        f'<rect width="64" height="64" fill="{DARK["surface"]}"/>'
        f'<g transform="translate(9.6 9.6) scale(.7)">{mark_body("mark", "m", fill=DARK["brand"])}</g>'
    )
    return svg(inner, 64, 64, "SlowShield")


def lockup_horizontal(p: dict[str, str]) -> str:
    wm, width = wordmark(78, 43.5, 32, p)
    return svg(f"<g>{mark_body('mark', 'm', fill=p['brand'])}</g>{wm}", 78 + width + 4, 64, "SlowShield")


def lockup_stacked(p: dict[str, str]) -> str:
    w = 260
    wm, _ = wordmark(w / 2, 132, 36, p, anchor="middle")
    tag, _ = text_el(TAGLINE.upper(), 600, 11.5, w / 2, 158, p["muted"], anchor="middle", tracking=0.16)
    inner = f'<g transform="translate({f(w / 2 - 40)} 0) scale(1.25)">{mark_body("mark", "m", fill=p["brand"])}</g>{wm}{tag}'
    return svg(inner, w, 170, "SlowShield")


def wordmark_svg(p: dict[str, str]) -> str:
    wm, width = wordmark(2, 33, 40, p)
    return svg(wm, width + 4, 44, "SlowShield")


def chevron_stream(x: float, cy: float, n: int, step: float, w: float, h: float, sw: float, color: str) -> str:
    """Chevrons flowing towards the mark, fading with distance (decoration for banners)."""
    out = []
    for i in range(n):
        op = 0.12 + 0.7 * (i + 1) / n
        out.append(
            f'<path d="{chevron(x + i * step, cy, w, h)}" fill="none" stroke="{color}" stroke-width="{f(sw)}" '
            f'stroke-linecap="round" stroke-linejoin="round" opacity="{op:.2f}"/>'
        )
    return "".join(out)


def social_preview() -> str:
    p = DARK
    title, _ = wordmark(470, 250, 104, p)
    tag, _ = text_el(TAGLINE, 650, 42, 474, 318, p["brand"])
    l1, _ = text_el("Supply-chain shield for PyPI and npm.", 400, 30, 474, 392, p["ink"])
    l2, _ = text_el("Known-bad is blocked. Brand-new is held back.", 400, 30, 474, 436, p["muted"])
    foot, _ = text_el("slowshield.net  ·  open source, Apache-2.0", 500, 22, 474, 560, p["muted"])
    inner = (
        f'<defs><radialGradient id="g" cx="0.22" cy="0.45" r="0.55"><stop offset="0" stop-color="{p["brand"]}" '
        f'stop-opacity=".22"/><stop offset="1" stop-color="{p["brand"]}" stop-opacity="0"/></radialGradient></defs>'
        f'<rect width="1280" height="640" fill="{p["ground"]}"/><rect width="1280" height="640" fill="url(#g)"/>'
        + chevron_stream(28, 320, 3, 34, 20, 30, 9, p["brand"])
        + f'<g transform="translate(118 128) scale(5.6)">{mark_body("mark", "m", fill=p["brand"])}</g>'
        + title + tag + l1 + l2
        + f'<path d="M474 500 H1200" stroke="{p["line"]}" stroke-width="2"/>' + foot
    )  # fmt: skip
    return svg(inner, 1280, 640, "SlowShield: safety through patience")


def readme_banner(p: dict[str, str], dark: bool) -> str:
    x = 268
    title, _ = wordmark(x, 132, 64, p)
    tag, _ = text_el(TAGLINE, 650, 26, x + 2, 176, p["brand"])
    sub, _ = text_el(
        "A supply-chain shield for PyPI and npm: known-bad is blocked, brand-new is held back.",
        400,
        19,
        x + 2,
        214,
        p["muted"],
    )
    inner = (
        f'<rect width="1200" height="280" rx="20" fill="{p["surface"] if not dark else p["ground"]}"/>'
        + chevron_stream(18, 140, 3, 20, 11, 17, 5, p["brand"])
        + f'<g transform="translate(76 52) scale(2.75)">{mark_body("mark", "m", fill=p["brand"])}</g>'
        + title + tag + sub
    )  # fmt: skip
    return svg(inner, 1200, 280, "SlowShield: safety through patience")


def sprite_html() -> str:
    """The mark as an inline SVG <symbol> for the website (currentColor), included by website/build.py."""
    body = mark_body("mark", "ss-cut", fill="currentColor").replace('<defs><mask id="ss-cut"', '<mask id="ss-cut"', 1)
    mask_end = body.index("</mask></defs>") + len("</mask>")
    mask, rest = body[:mask_end], body[mask_end + len("</defs>") :]
    return (
        '<svg class="sprite" aria-hidden="true" focusable="false"><defs>'
        f'{mask}<symbol id="ss-mark" viewBox="0 0 64 64">{rest}</symbol></defs></svg>\n'
    )


def tokens_css() -> str:
    def block(p: dict[str, str], indent: str) -> str:
        return "\n".join(f"{indent}--ss-{k}: {v};" for k, v in p.items())

    light, dark = derived(LIGHT, False), derived(DARK, True)
    common = (
        f"  --ss-font-display: {FONT_DISPLAY};\n  --ss-font-text: {FONT_TEXT};\n  --ss-font-mono: {FONT_MONO};\n"
        "  --ss-radius-s: 6px;\n  --ss-radius-m: 10px;\n  --ss-radius-l: 18px;\n"
    )
    return (
        "/* SlowShield design tokens: Night Field. Generated by brand/build.py, edit there.\n"
        '   Light by default, dark with the OS setting or data-theme="dark"; .ss-light / .ss-dark pin a region. */\n'
        f":root {{\n{block(light, '  ')}\n{common}  color-scheme: light;\n}}\n"
        f'@media (prefers-color-scheme: dark) {{\n  :root:not([data-theme="light"]) {{\n{block(dark, "    ")}\n'
        "    color-scheme: dark;\n  }\n}\n"
        f':root[data-theme="dark"] {{\n{block(dark, "  ")}\n  color-scheme: dark;\n}}\n'
        f".ss-light {{\n{block(light, '  ')}\n  color-scheme: light;\n}}\n"
        f".ss-dark {{\n{block(dark, '  ')}\n  color-scheme: dark;\n}}\n"
    )


def _lum(h: str) -> float:
    def ch(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (int(h[i : i + 2], 16) / 255 for i in (1, 3, 5))
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((_lum(a), _lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def palette_html() -> str:
    """Palette tables for the style guide (included by website/build.py), with measured contrast."""
    rows = []
    for k, role in ROLES.items():
        cells = []
        for theme, p in (("light", LIGHT), ("dark", DARK)):
            ratio = "" if k in ("ground", "surface", "line", "accent") else f"{contrast(p[k], p['surface']):.1f}:1"
            cells.append(
                f'<td><span class="swatch sw-{k} ss-{theme}"></span><code>{p[k]}</code>'
                f"{f'<small>{ratio} on surface</small>' if ratio else ''}</td>"
            )
        rows.append(f'<tr><th scope="row"><code>--ss-{k}</code><span>{role}</span></th>{"".join(cells)}</tr>')
    return (
        '<table class="palette"><thead><tr><th scope="col">Token</th><th scope="col">Light</th>'
        f'<th scope="col">Dark</th></tr></thead><tbody>{"".join(rows)}</tbody></table>\n'
    )


def web_font() -> None:
    """Latin subset of the variable font as WOFF2 for the website (all weights 400 to 900)."""
    opts = subset.Options()
    opts.flavor = "woff2"
    opts.layout_features = ["kern", "liga", "calt", "tnum", "case"]
    font = TTFont(FONT_VF)
    sub = subset.Subsetter(opts)
    latin = [*range(0x20, 0x7F), *range(0xA0, 0x100), 0x152, 0x153, *range(0x2010, 0x2027), 0x2030, 0x2039, 0x203A,
             0x20AC, 0x2122, 0x2190, 0x2191, 0x2192, 0x2193, 0x2212, 0x2713]  # fmt: skip
    sub.populate(unicodes=latin)
    sub.subset(font)
    font.flavor = "woff2"
    font.save(HERE / "fonts" / "SchibstedGrotesk-latin.woff2")


def check(markup: str, name: str) -> None:
    try:
        xml.dom.minidom.parseString(markup)
    except Exception as exc:
        raise SystemExit(f"invalid SVG {name}: {exc}") from exc


def main() -> None:
    files = {
        "mark.svg": mark_svg(LIGHT),
        "mark-dark.svg": mark_svg(DARK),
        "mark-mono.svg": mark_svg(None),
        "mark-white.svg": mark_svg({"brand": "#ffffff"}),
        "favicon.svg": favicon_svg("fav16"),
        "favicon-32.svg": favicon_svg("fav32"),
        "app-icon.svg": app_icon_svg(),
        "lockup-horizontal.svg": lockup_horizontal(LIGHT),
        "lockup-horizontal-dark.svg": lockup_horizontal(DARK),
        "lockup-stacked.svg": lockup_stacked(LIGHT),
        "lockup-stacked-dark.svg": lockup_stacked(DARK),
        "wordmark.svg": wordmark_svg(LIGHT),
        "wordmark-dark.svg": wordmark_svg(DARK),
        "social-preview.svg": social_preview(),
        "readme-banner.svg": readme_banner(LIGHT, dark=False),
        "readme-banner-dark.svg": readme_banner(DARK, dark=True),
    }
    for name, markup in files.items():
        check(markup, name)
        (HERE / name).write_text(markup + "\n", encoding="utf-8")
    (HERE / "tokens.css").write_text(tokens_css(), encoding="utf-8")
    (HERE / "palette.html").write_text(palette_html(), encoding="utf-8")
    (HERE / "sprite.html").write_text(sprite_html(), encoding="utf-8")
    web_font()
    print(f"wrote {len(files)} SVG masters, tokens.css and fonts/SchibstedGrotesk-latin.woff2 to {HERE}")


if __name__ == "__main__":
    main()
