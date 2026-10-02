"""SlowShield brand proposals, round 2: "deflect, yet don't obstruct".

Regenerates every master asset in this directory:

    python3 brand/proposals/generate.py

Per concept (`<concept>/`): marks (light, dark, mono), favicons, horizontal and stacked lockups (light and
dark), a 1280x640 social banner, a standalone CSS motion study (`motion.html`) and design tokens (`tokens.css`).
Everything is hand-built SVG/CSS on a 64-unit grid: no raster images, no web fonts, no JavaScript.
"""

from __future__ import annotations

import colorsys
import math
import xml.dom.minidom
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
FONT = "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
MONO = "ui-monospace, 'SF Mono', 'Cascadia Code', Menlo, Consolas, monospace"
TAGLINE = "Deflect, don't obstruct."

# ============================================================================ colour maths


def _rgb(h: str) -> tuple[float, float, float]:
    h = h.lstrip("#")
    return tuple(int(h[i : i + 2], 16) / 255 for i in (0, 2, 4))  # type: ignore[return-value]


def _hex(rgb: tuple[float, float, float]) -> str:
    return "#" + "".join(f"{round(max(0, min(1, c)) * 255):02x}" for c in rgb)


def luminance(h: str) -> float:
    def f(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = _rgb(h)
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def contrast(a: str, b: str) -> float:
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def mix(a: str, b: str, t: float) -> str:
    """t of colour a over b."""
    ra, rb = _rgb(a), _rgb(b)
    return _hex(tuple(x * t + y * (1 - t) for x, y in zip(ra, rb, strict=True)))  # type: ignore[arg-type]


def shift_lightness(h: str, delta: float) -> str:
    r, g, b = _rgb(h)
    hh, ll, ss = colorsys.rgb_to_hls(r, g, b)
    return _hex(colorsys.hls_to_rgb(hh, max(0, min(1, ll + delta)), ss))


TINT_LIGHT = 0.14
TINT_DARK = 0.22


def tint(color: str, surface: str, dark: bool) -> str:
    return mix(color, surface, TINT_DARK if dark else TINT_LIGHT)


def tune(color: str, surface: str, ground: str, *, dark: bool, target: float = 4.6, badge: bool = True) -> str:
    """Nudge lightness until the colour clears AA on surface, ground and (if a badge colour) its own tint."""
    c = color
    for _ in range(80):
        checks = [contrast(c, surface), contrast(c, ground)]
        if badge:
            checks.append(contrast(c, tint(c, surface, dark)))
        if min(checks) >= target:
            return c
        c = shift_lightness(c, 0.01 if dark else -0.01)
    return c


# ============================================================================ palettes

TEXT_TOKENS = ("ink", "muted")
BADGE_TOKENS = ("brand", "available", "held", "blocked", "tampered")
TOKEN_USAGE = {
    "ground": "Page background",
    "surface": "Cards, tables, top bar",
    "line": "Borders, grid lines",
    "ink": "Body text, headings",
    "muted": "Secondary text, axes, captions",
    "brand": "Primary actions, links, active nav, wordmark accent",
    "accent": "Decorative glow / signature colour (not for text)",
    "available": "Available versions, healthy feeds",
    "held": "Held back (too new), fail-open",
    "blocked": "Known malware, HTTP 451",
    "tampered": "Tamper and integrity events",
}


@dataclass
class Palette:
    name: str
    light: dict[str, str]
    dark: dict[str, str]
    notes: str
    shimmer: list[str] = field(default_factory=list)

    def tuned(self) -> Palette:
        out = Palette(self.name, dict(self.light), dict(self.dark), self.notes, list(self.shimmer))
        for mode, dark in ((out.light, False), (out.dark, True)):
            for k in TEXT_TOKENS:
                mode[k] = tune(mode[k], mode["surface"], mode["ground"], dark=dark, badge=False)
            for k in BADGE_TOKENS:
                if k == "brand" and mode["brand"] == mode["ink"]:
                    continue
                mode[k] = tune(mode[k], mode["surface"], mode["ground"], dark=dark)
        return out


PALETTES: dict[str, Palette] = {
    "glance": Palette(
        name="Night Field",
        notes="Deep night ink with an electric field blue. Dark-first: the field glows against the night.",
        light={
            "ground": "#f2f4fb",
            "surface": "#ffffff",
            "line": "#dce1f0",
            "ink": "#0a0f24",
            "muted": "#56607f",
            "brand": "#2a4bff",
            "accent": "#8ea2ff",
            "available": "#13804e",
            "held": "#6447d6",
            "blocked": "#d0263c",
            "tampered": "#b8218f",
        },
        dark={
            "ground": "#060915",
            "surface": "#0d1222",
            "line": "#1f2742",
            "ink": "#e6eafb",
            "muted": "#98a2c4",
            "brand": "#7a91ff",
            "accent": "#b9c6ff",
            "available": "#4fd48a",
            "held": "#a99bff",
            "blocked": "#ff6f7e",
            "tampered": "#f27bd6",
        },
    ),
    "parting": Palette(
        name="Graphite Prism",
        notes="Graphite neutrals with an iridescent violet-to-rose shimmer. The shimmer is decoration only; text uses the solid iris.",
        shimmer=["#6a3ff2", "#a84ee6", "#e45ba6", "#ff8f8a"],
        light={
            "ground": "#f4f4f6",
            "surface": "#ffffff",
            "line": "#e1e1e7",
            "ink": "#16171b",
            "muted": "#5f616b",
            "brand": "#6a3ff2",
            "accent": "#e45ba6",
            "available": "#17804a",
            "held": "#1f6db5",
            "blocked": "#cc2a36",
            "tampered": "#b5206f",
        },
        dark={
            "ground": "#101114",
            "surface": "#191a1f",
            "line": "#2a2c34",
            "ink": "#ececf2",
            "muted": "#a0a2ad",
            "brand": "#a48bff",
            "accent": "#ff8fc4",
            "available": "#57d18e",
            "held": "#79b7ff",
            "blocked": "#ff737d",
            "tampered": "#ff7fbf",
        },
    ),
    "dotfield": Palette(
        name="Sand & Cobalt",
        notes="Warm sand paper with deep cobalt ink, like a printed technical manual. Light-first.",
        light={
            "ground": "#f3ecdf",
            "surface": "#fffaf2",
            "line": "#e3d8c5",
            "ink": "#1c1914",
            "muted": "#6b6252",
            "brand": "#1d44c4",
            "accent": "#c9b48d",
            "available": "#2b7840",
            "held": "#7c4aa0",
            "blocked": "#b8292b",
            "tampered": "#a8197a",
        },
        dark={
            "ground": "#15130f",
            "surface": "#1f1c17",
            "line": "#35302a",
            "ink": "#f1eadc",
            "muted": "#b3a993",
            "brand": "#86a0ff",
            "accent": "#8a7a5d",
            "available": "#74c98a",
            "held": "#c59df0",
            "blocked": "#ff7c70",
            "tampered": "#f17cc8",
        },
    ),
    "slow-s": Palette(
        name="Mono & Signal Pink",
        notes="Pure black and white with one vivid signal pink, reserved for the patient package.",
        light={
            "ground": "#f5f5f5",
            "surface": "#ffffff",
            "line": "#e2e2e2",
            "ink": "#0a0a0a",
            "muted": "#5c5c5c",
            "brand": "#0a0a0a",
            "accent": "#e6007a",
            "available": "#18804a",
            "held": "#3f4bd1",
            "blocked": "#d1242f",
            "tampered": "#8a2bd6",
        },
        dark={
            "ground": "#090909",
            "surface": "#141414",
            "line": "#262626",
            "ink": "#f5f5f5",
            "muted": "#a3a3a3",
            "brand": "#f5f5f5",
            "accent": "#ff4fa6",
            "available": "#5ad38f",
            "held": "#8f99ff",
            "blocked": "#ff6e6e",
            "tampered": "#c38bff",
        },
    ),
}
PALETTES = {k: v.tuned() for k, v in PALETTES.items()}

# ============================================================================ svg helpers


def f(n: float) -> str:
    s = f"{n:.2f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def paint(prop: str, color: str) -> str:
    return f'style="{prop}:{color}"' if color.startswith("var(") else f'{prop}="{color}"'


def stop(offset: str, color: str, opacity: float | None = None) -> str:
    op = "" if opacity is None else f";stop-opacity:{opacity}"
    return f'<stop offset="{offset}" style="stop-color:{color}{op}"/>'


def svg(inner: str, w: float, h: float, *, label: str = "SlowShield", extra: str = "") -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {f(w)} {f(h)}" role="img" aria-label="{label}"{extra}>'
        f"{inner}</svg>"
    )


def uniq(markup: str, suffix: str) -> str:
    return markup.replace("UID", f"u{suffix}")


def taper(p0: tuple[float, float], p1: tuple[float, float], w0: float, w1: float) -> str:
    """Tapered streak from tail p0 (width w0) to head p1 (width w1), with a round head."""
    dx, dy = p1[0] - p0[0], p1[1] - p0[1]
    length = math.hypot(dx, dy)
    nx, ny = -dy / length, dx / length
    a = (p0[0] + nx * w0 / 2, p0[1] + ny * w0 / 2)
    b = (p1[0] + nx * w1 / 2, p1[1] + ny * w1 / 2)
    c = (p1[0] - nx * w1 / 2, p1[1] - ny * w1 / 2)
    d = (p0[0] - nx * w0 / 2, p0[1] - ny * w0 / 2)
    r = w1 / 2
    return f"M{f(a[0])} {f(a[1])} L{f(b[0])} {f(b[1])} A{f(r)} {f(r)} 0 0 1 {f(c[0])} {f(c[1])} L{f(d[0])} {f(d[1])} Z"


def streak(
    uid: str,
    p0: tuple[float, float],
    p1: tuple[float, float],
    color: str,
    width: float,
    a0: float = 0.0,
    a1: float = 1.0,
) -> str:
    """A motion line from p0 to p1 whose opacity ramps from a0 to a1 (round cap at the opaque end)."""
    grad = (
        f'<linearGradient id="{uid}" gradientUnits="userSpaceOnUse" x1="{f(p0[0])}" y1="{f(p0[1])}" '
        f'x2="{f(p1[0])}" y2="{f(p1[1])}">{stop("0", color, a0)}{stop("1", color, a1)}</linearGradient>'
    )
    return (
        f"<defs>{grad}</defs>"
        f'<path d="M{f(p0[0])} {f(p0[1])} L{f(p1[0])} {f(p1[1])}" fill="none" stroke="url(#{uid})" '
        f'stroke-width="{f(width)}" stroke-linecap="round"/>'
    )


def reflect(d: tuple[float, float], n: tuple[float, float]) -> tuple[float, float]:
    dot = d[0] * n[0] + d[1] * n[1]
    return (d[0] - 2 * dot * n[0], d[1] - 2 * dot * n[1])


def on_circle(cx: float, cy: float, r: float, deg: float) -> tuple[float, float]:
    a = math.radians(deg)
    return (cx + r * math.cos(a), cy + r * math.sin(a))


SHIELD = "M32 4 L54 11 V30 C54 45 45 55 32 60 C19 55 10 45 10 30 V11 Z"

# ============================================================================ concept 1: Glance
# A field arc. A fast streak glances off it; a slow dot has already passed through and rests inside.

G_C, G_R = (40.0, 32.0), 22.0


def glance_mark(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    cx, cy = G_C
    brand = "currentColor" if mono else p["brand"]
    ink = "currentColor" if mono else p["ink"]
    dot = "currentColor" if mono else p["brand"]
    span = (238, 122) if fav else (232, 128)
    a0, a1 = on_circle(cx, cy, G_R, span[0]), on_circle(cx, cy, G_R, span[1])
    arc = f"M{f(a0[0])} {f(a0[1])} A{f(G_R)} {f(G_R)} 0 0 0 {f(a1[0])} {f(a1[1])}"
    ang = 203
    n = (math.cos(math.radians(ang)), math.sin(math.radians(ang)))
    impact = on_circle(cx, cy, G_R + (4.2 if fav else 3.4), ang)
    tail = (2, 6) if not fav else (4, 7)
    r = reflect((impact[0] - tail[0], impact[1] - tail[1]), n)
    rl = math.hypot(*r)
    out_end = (impact[0] + r[0] / rl * (13 if not fav else 12), impact[1] + r[1] / rl * (13 if not fav else 12))
    parts = []
    if not mono:
        parts.append(
            f'<defs><linearGradient id="UID-zone" gradientUnits="userSpaceOnUse" x1="{f(cx - G_R)}" y1="0" x2="{f(cx + 2)}" y2="0">'
            f"{stop('0', p['brand'], 0.3)}{stop('1', p['brand'], 0)}</linearGradient></defs>"
            f'<circle cx="{f(cx)}" cy="{f(cy)}" r="{f(G_R)}" fill="url(#UID-zone)"/>'
        )
    sw = 6.4 if fav else 4.6
    parts.append(f'<path d="{arc}" fill="none" {paint("stroke", brand)} stroke-width="{sw}" stroke-linecap="round"/>')
    if fav:
        parts.append(
            f'<path d="M{f(tail[0])} {f(tail[1])} L{f(impact[0])} {f(impact[1])} L{f(out_end[0])} {f(out_end[1])}" '
            f'fill="none" {paint("stroke", ink)} stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>'
            f'<circle cx="35.5" cy="38" r="7.2" {paint("fill", dot)}/>'
        )
        return "".join(parts)
    parts.append(streak("UID-in", tail, impact, ink, 3.2, 0.0, 1.0))
    parts.append(streak("UID-out", impact, out_end, ink, 2.2, 0.75, 0.0))
    parts.append(
        f'<circle cx="14.2" cy="43.6" r="1.5" {paint("fill", dot)} opacity=".35"/>'
        f'<circle cx="24.4" cy="41.8" r="2.2" {paint("fill", dot)} opacity=".6"/>'
        f'<circle cx="33.8" cy="39.6" r="4.8" {paint("fill", dot)}/>'
    )
    return "".join(parts)


# ============================================================================ concept 2: Parting
# A shield made of field lines; the lines part around a slow orb travelling through.

P_LINES = [
    "M2 13 H20 C25 13 26 10 32 10 C38 10 39 13 44 13 H62",
    "M2 22 H18 C24 22 25 16 32 16 C39 16 40 22 46 22 H62",
    "M2 31 H23.4",
    "M40.6 31 H62",
    "M2 40 H18 C24 40 25 46 32 46 C39 46 40 40 46 40 H62",
    "M2 49 H20 C25 49 26 52 32 52 C38 52 39 49 44 49 H62",
]
P_FAV = [
    "M2 17 H18 C24 17 25 12.5 32 12.5 C39 12.5 40 17 46 17 H62",
    "M2 32 H22.3",
    "M41.7 32 H62",
    "M2 47 H18 C24 47 25 51.5 32 51.5 C39 51.5 40 47 46 47 H62",
]


def parting_mark(p: dict[str, str], *, mono: bool = False, fav: bool = False, shimmer: list[str] | None = None) -> str:
    shimmer = shimmer or PALETTES["parting"].shimmer
    lines = P_FAV if fav else P_LINES
    sw = 6.2 if fav else 3.8
    defs = f'<clipPath id="UID-clip"><path d="{SHIELD}"/></clipPath>'
    if mono:
        stroke = 'stroke="currentColor"'
        orb = 'fill="currentColor"'
    else:
        stops = "".join(stop(f"{i / (len(shimmer) - 1):.2f}", c) for i, c in enumerate(shimmer))
        defs += f'<linearGradient id="UID-sh" gradientUnits="userSpaceOnUse" x1="10" y1="6" x2="54" y2="58">{stops}</linearGradient>'
        stroke = 'stroke="url(#UID-sh)"'
        orb = paint("fill", p["ink"])
    body = "".join(f'<path d="{d}"/>' for d in lines)
    r = 7.2 if fav else 5.3
    cy = 32 if fav else 31
    return (
        f"<defs>{defs}</defs>"
        f'<g clip-path="url(#UID-clip)" fill="none" {stroke} stroke-width="{sw}" stroke-linecap="round">{body}</g>'
        f'<circle cx="32" cy="{cy}" r="{r}" {orb}/>'
    )


# ============================================================================ concept 3: Dot Field
# A halftone shield made of packages. Fast impacts ripple through the field as rings of smaller dots;
# the patient package simply joins the grid.


def _shield_polygon(steps: int = 24) -> list[tuple[float, float]]:
    def cubic(p0, p1, p2, p3):  # type: ignore[no-untyped-def]
        return [
            (
                (1 - t) ** 3 * p0[0] + 3 * (1 - t) ** 2 * t * p1[0] + 3 * (1 - t) * t * t * p2[0] + t**3 * p3[0],
                (1 - t) ** 3 * p0[1] + 3 * (1 - t) ** 2 * t * p1[1] + 3 * (1 - t) * t * t * p2[1] + t**3 * p3[1],
            )
            for t in (i / steps for i in range(1, steps + 1))
        ]

    pts = [(32.0, 4.0), (54.0, 11.0), (54.0, 30.0)]
    pts += cubic((54, 30), (54, 45), (45, 55), (32, 60))
    pts += cubic((32, 60), (19, 55), (10, 45), (10, 30))
    pts += [(10.0, 11.0)]
    return pts


_POLY = _shield_polygon()


def inside_shield(x: float, y: float, inset: float = 0.0) -> bool:
    inside = False
    n = len(_POLY)
    for i in range(n):
        x1, y1 = _POLY[i]
        x2, y2 = _POLY[(i + 1) % n]
        if (y1 > y) != (y2 > y) and x < (x2 - x1) * (y - y1) / (y2 - y1) + x1:
            inside = not inside
    if not inside or inset <= 0:
        return inside
    return all(math.hypot(x - px, y - py) >= inset for px, py in _POLY)


D_IMPACT = (9.0, 19.0)


def dotfield_mark(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    dots = "currentColor" if mono else p["brand"]
    special = "currentColor" if mono else p["ink"]
    if fav:
        step, base, rings = 9.6, 3.55, []
        cols, rows, y0 = range(-3, 4), range(7), 6.8
        slot, special_r = (41.6, 45.2), 4.6
    else:
        step, base = 5.4, 2.2
        cols, rows, y0 = range(-5, 6), range(11), 5.3
        rings = [(10.5, 0.92), (21.5, 0.7), (32.5, 0.42)]
        slot, special_r = (42.8, 42.5), 3.2
    out = []
    for j in rows:
        for k in cols:
            x, y = 32 + k * step, y0 + j * step
            # keep dots whose disc touches the shield; the clip path gives the crisp silhouette
            if not inside_shield(x, y) and min(math.hypot(x - px, y - py) for px, py in _POLY) > base:
                continue
            if abs(x - slot[0]) < 0.1 and abs(y - slot[1]) < 0.1:
                continue
            r = base
            if rings:
                d = math.hypot(x - D_IMPACT[0], y - D_IMPACT[1])
                dent = max(w * math.exp(-((d - R) ** 2) / (2 * 2.4**2)) for R, w in rings)
                r = base * (1 - 0.78 * dent)
            if r > 0.25:
                out.append(f'<circle cx="{f(x)}" cy="{f(y)}" r="{f(r)}"/>')
    body = (
        f'<defs><clipPath id="UID-c"><path d="{SHIELD}"/></clipPath></defs>'
        f'<g clip-path="url(#UID-c)" {paint("fill", dots)}>{"".join(out)}</g>'
        f'<circle cx="{f(slot[0])}" cy="{f(slot[1])}" r="{f(special_r)}" {paint("fill", special)}/>'
    )
    if not fav:
        ink = "currentColor" if mono else p["ink"]
        hit = (6.6, 19.0)
        body += streak("UID-in", (0.6, 6.0), hit, ink, 2.5, 0.0, 1.0)
        body += streak("UID-out", hit, (0.6, 31.0), ink, 1.7, 0.7, 0.0)
    return body


# ============================================================================ concept 4: Slow S
# The S of SlowShield is a single field line. A fast streak bounces off its shoulder; a pink dot passes
# through the middle of the spine, where the line opens to let it through.

S_PATH = (
    "M47 15.5 C44 10 38.5 7.5 32 7.5 C23.5 7.5 17 12 17 19.5 C17 27 23.5 29.5 32 32 "
    "C40.5 34.5 47.5 37 47.5 44.5 C47.5 52 41 56.5 32 56.5 C25 56.5 19.5 54 16.5 48.5"
)
S_APEX = (44.6, 3.7)


def slow_s_mark(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    ink = "currentColor" if mono else p["brand"]
    pink = "currentColor" if mono else p["accent"]
    sw = 9.4 if fav else 7.4
    gap = 9.2 if fav else 8.4
    dot_r = 5.6 if fav else 4.7
    mask = (
        f'<mask id="UID-m" maskUnits="userSpaceOnUse" x="0" y="0" width="64" height="64">'
        f'<rect width="64" height="64" fill="#fff"/><circle cx="32" cy="32" r="{gap}" fill="#000"/></mask>'
    )
    out = (
        f"<defs>{mask}</defs>"
        f'<path d="{S_PATH}" fill="none" {paint("stroke", ink)} stroke-width="{sw}" stroke-linecap="round" mask="url(#UID-m)"/>'
        f'<circle cx="32" cy="32" r="{dot_r}" {paint("fill", pink)}/>'
    )
    if not fav:
        tail = (63.5, 2.6)
        n = (0.42, -0.907)
        r = reflect((S_APEX[0] - tail[0], S_APEX[1] - tail[1]), n)
        k = (S_APEX[1] - 0.6) / -r[1]
        end = (S_APEX[0] + r[0] * k, S_APEX[1] + r[1] * k)
        out += streak("UID-in", tail, S_APEX, ink, 2.8, 0.0, 1.0)
        out += streak("UID-out", S_APEX, end, ink, 2.0, 0.7, 0.0)
    return out


# ============================================================================ registry


@dataclass
class Concept:
    key: str
    title: str
    tagline: str
    mark: object
    wordmark: object


def wm_glance(x: float, y: float, size: float, p: dict[str, str], anchor: str = "start") -> str:
    return (
        f'<text x="{f(x)}" y="{f(y)}" font-family="{FONT}" font-size="{f(size)}" letter-spacing="-0.5" text-anchor="{anchor}">'
        f'<tspan {paint("fill", p["ink"])} font-weight="500">Slow</tspan>'
        f'<tspan {paint("fill", p["brand"])} font-weight="750">Shield</tspan></text>'
    )


def wm_parting(x: float, y: float, size: float, p: dict[str, str], anchor: str = "start") -> str:
    return (
        f'<text x="{f(x)}" y="{f(y)}" font-family="{FONT}" font-size="{f(size)}" letter-spacing="0.4" text-anchor="{anchor}">'
        f'<tspan {paint("fill", p["muted"])} font-weight="400">slow</tspan>'
        f'<tspan {paint("fill", p["ink"])} font-weight="650">shield</tspan></text>'
    )


def wm_dotfield(x: float, y: float, size: float, p: dict[str, str], anchor: str = "start") -> str:
    s = size * 0.82
    return (
        f'<text x="{f(x)}" y="{f(y)}" font-family="{FONT}" font-size="{f(s)}" letter-spacing="{f(s * 0.16)}" '
        f'font-weight="760" text-anchor="{anchor}">'
        f"<tspan {paint('fill', p['ink'])}>SLOW</tspan><tspan {paint('fill', p['brand'])}>SHIELD</tspan></text>"
    )


def wm_slow_s(x: float, y: float, size: float, p: dict[str, str], anchor: str = "start") -> str:
    return (
        f'<text x="{f(x)}" y="{f(y)}" font-family="{FONT}" font-size="{f(size)}" letter-spacing="-1" font-weight="800" '
        f'text-anchor="{anchor}"><tspan {paint("fill", p["ink"])}>slowshield</tspan>'
        f"<tspan {paint('fill', p['accent'])}>.</tspan></text>"
    )


CONCEPTS: dict[str, Concept] = {
    "glance": Concept(
        "glance", "Glance", "Fast things glance off; patient things are already inside.", glance_mark, wm_glance
    ),
    "parting": Concept(
        "parting", "Parting", "The field parts for whatever moves slowly enough.", parting_mark, wm_parting
    ),
    "dotfield": Concept(
        "dotfield",
        "Dot Field",
        "Impacts ripple through the field; the patient package simply joins it.",
        dotfield_mark,
        wm_dotfield,
    ),
    "slow-s": Concept(
        "slow-s", "Slow S", "The S is the field line itself, and it opens for the slow dot.", slow_s_mark, wm_slow_s
    ),
}
WM_WIDTH = {"glance": 0.585, "parting": 0.56, "dotfield": 0.86, "slow-s": 0.56}
WM_CHARS = {"glance": 10, "parting": 10, "dotfield": 10, "slow-s": 11}


def mark_svg(key: str, p: dict[str, str], *, mono: bool = False, fav: bool = False, suffix: str = "a") -> str:
    inner = CONCEPTS[key].mark(p, mono=mono, fav=fav)  # type: ignore[operator]
    extra = ' color="#111111"' if mono else ""
    return uniq(svg(inner, 64, 64, extra=extra), suffix)


def lockup_h(key: str, p: dict[str, str], suffix: str = "a") -> str:
    c = CONCEPTS[key]
    size = 30
    width = 78 + WM_CHARS[key] * size * WM_WIDTH[key] + 6
    inner = f"<g>{c.mark(p)}</g>" + c.wordmark(78, 43, size, p)  # type: ignore[operator]
    return uniq(svg(inner, width, 64, label="SlowShield logo"), suffix)


def lockup_s(key: str, p: dict[str, str], suffix: str = "a") -> str:
    c = CONCEPTS[key]
    inner = (
        f'<g transform="translate(84 2) scale(1.125)">{c.mark(p)}</g>'  # type: ignore[operator]
        + c.wordmark(120, 120, 34, p, "middle")  # type: ignore[operator]
        + f'<text x="120" y="146" font-family="{FONT}" font-size="11.5" font-weight="600" letter-spacing="2.4" '
        f'text-anchor="middle" {paint("fill", p["muted"])}>{TAGLINE.upper()}</text>'
    )
    return uniq(svg(inner, 240, 158, label="SlowShield logo"), suffix)


# ============================================================================ social banner


def social(key: str, suffix: str = "a") -> str:
    c = CONCEPTS[key]
    pal = PALETTES[key]
    p = pal.light if key == "dotfield" else pal.dark
    bg = p["ground"]
    glow = p["brand"] if key != "slow-s" else p["accent"]
    rows = [
        ("$ pip install granian", "held · unlocks in 5 d 14 h", p["held"], "2.8.4 waits; 2.8.3 is served"),
        ("$ npm install axios@1.14.1", "deflected · HTTP 451", p["blocked"], "MAL-2026-2307"),
    ]
    row_svg = ""
    for i, (cmd, state, col, note) in enumerate(rows):
        y = 512 + i * 54
        w = 26 + 13.2 * len(state)
        row_svg += (
            f'<text x="104" y="{y}" font-family="{MONO}" font-size="24" fill="{p["muted"]}">{cmd}</text>'
            f'<rect x="560" y="{y - 25}" rx="16" width="{f(w)}" height="35" fill="{tint(col, bg, key != "dotfield")}"/>'
            f'<text x="574" y="{y}" font-family="{MONO}" font-size="21" fill="{col}">{state}</text>'
            f'<text x="{f(576 + w)}" y="{y}" font-family="{FONT}" font-size="22" fill="{p["muted"]}">{note}</text>'
        )
    mark = c.mark(p)  # type: ignore[operator]
    inner = (
        f'<defs><radialGradient id="UID-glow" cx="0.2" cy="0.4" r="0.6">{stop("0", glow, 0.22 if key != "dotfield" else 0.12)}'
        f"{stop('1', glow, 0)}</radialGradient></defs>"
        f'<rect width="1280" height="640" fill="{bg}"/><rect width="1280" height="640" fill="url(#UID-glow)"/>'
        f'<path d="M64 452 H1216" stroke="{p["line"]}" stroke-width="2"/>'
        f'<g transform="translate(92 70) scale(4.9)">{mark}</g>'
        + c.wordmark(476, 214, 100, p)  # type: ignore[operator]
        + f'<text x="480" y="276" font-family="{FONT}" font-size="36" font-weight="650" '
        f'fill="{p["brand"] if key != "slow-s" else p["accent"]}">{TAGLINE}</text>'
        f'<text x="480" y="336" font-family="{FONT}" font-size="29" fill="{p["ink"]}" opacity=".86">'
        "Supply-chain defence proxy for PyPI and npm.</text>"
        f'<text x="480" y="378" font-family="{FONT}" font-size="29" fill="{p["ink"]}" opacity=".86">'
        "New releases wait 7 days. Malware is turned away.</text>" + row_svg
    )
    return uniq(svg(inner, 1280, 640, label="SlowShield social preview"), suffix)


# ============================================================================ motion studies (CSS only)
# Each study is a 320x180 stage. Fast things are deflected; the slow thing passes without resistance.
# Under prefers-reduced-motion the stage shows one composed still frame instead.


def _streak_keys(
    name: str,
    start: tuple[float, float],
    impact: tuple[float, float],
    normal: tuple[float, float],
    out_len: float,
    hit: float = 22.0,
) -> tuple[str, float, float, tuple[float, float]]:
    d = (impact[0] - start[0], impact[1] - start[1])
    r = reflect(d, normal)
    rl = math.hypot(*r)
    out = (impact[0] + r[0] / rl * out_len, impact[1] + r[1] / rl * out_len)
    a_in = math.degrees(math.atan2(d[1], d[0]))
    a_out = math.degrees(math.atan2(r[1], r[0]))

    def tf(pt: tuple[float, float], a: float) -> str:
        return f"transform:translate({f(pt[0])}px,{f(pt[1])}px) rotate({f(a)}deg)"

    keys = (
        f"@keyframes {name}{{0%{{{tf(start, a_in)};opacity:0}}3%{{opacity:1}}"
        f"{f(hit)}%{{{tf(impact, a_in)};opacity:1}}{f(hit + 0.01)}%{{{tf(impact, a_out)}}}"
        f"{f(hit + 16)}%{{{tf(out, a_out)};opacity:0}}100%{{{tf(out, a_out)};opacity:0}}}}"
    )
    mid = (impact[0] + (out[0] - impact[0]) * 0.35, impact[1] + (out[1] - impact[1]) * 0.35)
    return keys, a_in, a_out, mid


def _flash_keys(name: str, hit: float = 22.0) -> str:
    return (
        f"@keyframes {name}{{0%,{f(hit - 0.5)}%{{opacity:0;transform:translate(-50%,-50%) scale(.2)}}"
        f"{f(hit + 1)}%{{opacity:.95;transform:translate(-50%,-50%) scale(.7)}}"
        f"{f(hit + 18)}%,100%{{opacity:0;transform:translate(-50%,-50%) scale(2.4)}}}}"
    )


MOTION_BASE = """
.ms{--ms-size:1;position:relative;width:320px;height:180px;overflow:hidden;border-radius:14px;background:var(--m-bg);
  border:1px solid var(--m-line);flex:none}
.ms svg.stage-bg{position:absolute;inset:0;width:320px;height:180px}
.ms .streak{position:absolute;left:-46px;top:-1.5px;width:46px;height:3px;border-radius:2px;transform-origin:100% 50%;
  background:linear-gradient(90deg,transparent,var(--m-fast));opacity:0}
.ms .flash{position:absolute;left:0;top:0;width:30px;height:30px;border-radius:50%;opacity:0;
  background:radial-gradient(circle,var(--m-field) 0,transparent 70%)}
.ms .slow{position:absolute;left:0;top:0;width:14px;height:14px;margin:-7px 0 0 -7px;border-radius:50%;
  background:var(--m-slow);box-shadow:0 0 0 3px var(--m-halo),0 0 18px var(--m-slow)}
.ms .trail{position:absolute;left:0;top:0;width:6px;height:6px;margin:-3px 0 0 -3px;border-radius:50%;background:var(--m-slow);opacity:.4}
@media (prefers-reduced-motion: reduce){.ms *{animation:none!important}}
"""


def motion_glance(prefix: str) -> tuple[str, str]:
    cx, cy, r = 300.0, 90.0, 118.0
    a0, a1 = on_circle(cx, cy, r, 226), on_circle(cx, cy, r, 134)
    css, html = [], []
    streaks = [(-10, 22, 204, "0s"), (-10, 150, 166, "1.1s"), (-10, 78, 188, "2.05s")]
    stills = []
    for i, (sx, sy, ang, delay) in enumerate(streaks):
        imp = on_circle(cx, cy, r + 3, ang)
        n = (math.cos(math.radians(ang)), math.sin(math.radians(ang)))
        keys, _ai, ao, mid = _streak_keys(f"{prefix}-s{i}", (sx, sy), imp, n, 120)
        css.append(keys + _flash_keys(f"{prefix}-f{i}"))
        css.append(
            f".{prefix} .s{i}{{animation:{prefix}-s{i} 3.1s linear {delay} infinite;"
            f"transform:translate({f(mid[0])}px,{f(mid[1])}px) rotate({f(ao)}deg);opacity:{1 if i == 0 else 0}}}"
            f".{prefix} .f{i}{{left:{f(imp[0])}px;top:{f(imp[1])}px;animation:{prefix}-f{i} 3.1s linear {delay} infinite}}"
        )
        stills.append(i)
        html.append(f'<i class="streak s{i}"></i><i class="flash f{i}"></i>')
    css.append(
        f"@keyframes {prefix}-slow{{0%{{transform:translate(-20px,122px);opacity:0}}8%{{opacity:1}}"
        f"88%{{transform:translate(258px,104px);opacity:1}}100%{{transform:translate(272px,103px);opacity:0}}}}"
        f".{prefix} .slow,.{prefix} .trail{{animation:{prefix}-slow 9s cubic-bezier(.45,.05,.55,.95) infinite;"
        f"transform:translate(196px,108px)}}"
        f".{prefix} .t1{{animation-delay:-.35s}}.{prefix} .t2{{animation-delay:-.7s;opacity:.22}}"
        f"@media (prefers-reduced-motion: reduce){{.{prefix} .t1{{transform:translate(181px,110px)}}"
        f".{prefix} .t2{{transform:translate(166px,112px)}}}}"
    )
    bg = (
        f'<svg class="stage-bg" viewBox="0 0 320 180" aria-hidden="true"><defs><linearGradient id="{prefix}-z" x1="180" x2="320" '
        f'y1="0" y2="0" gradientUnits="userSpaceOnUse">{stop("0", "var(--m-field)", 0.22)}{stop("1", "var(--m-field)", 0)}'
        f'</linearGradient></defs><circle cx="{f(cx)}" cy="{f(cy)}" r="{f(r)}" fill="url(#{prefix}-z)"/>'
        f'<path d="M{f(a0[0])} {f(a0[1])} A{f(r)} {f(r)} 0 0 0 {f(a1[0])} {f(a1[1])}" fill="none" '
        f'style="stroke:var(--m-field)" stroke-width="4" stroke-linecap="round"/></svg>'
    )
    html = [bg, *html, '<i class="trail t2"></i><i class="trail t1"></i><i class="slow"></i>']
    return "".join(css), "".join(html)


def motion_parting(prefix: str) -> tuple[str, str]:
    xs = [150, 166, 182, 198, 214, 230]
    lines = "".join(f'<path d="M{x} 6 V174"/>' for x in xs)
    shimmer = PALETTES["parting"].shimmer
    stops = "".join(stop(f"{i / (len(shimmer) - 1):.2f}", c) for i, c in enumerate(shimmer))
    bg = (
        f'<svg class="stage-bg" viewBox="0 0 320 180" aria-hidden="true"><defs>'
        f'<linearGradient id="{prefix}-g" gradientUnits="userSpaceOnUse" x1="140" y1="0" x2="240" y2="180">{stops}</linearGradient>'
        f'<mask id="{prefix}-m" maskUnits="userSpaceOnUse" x="0" y="0" width="320" height="180"><rect width="320" height="180" fill="#fff"/>'
        f'<ellipse class="gap" cx="0" cy="0" rx="13" ry="22" fill="#000"/></mask></defs>'
        f'<g class="curtain" mask="url(#{prefix}-m)" fill="none" stroke="url(#{prefix}-g)" stroke-width="3" stroke-linecap="round">{lines}</g>'
        f"</svg>"
    )
    css = [
        f"@keyframes {prefix}-slow{{0%{{transform:translate(-20px,92px);opacity:0}}6%{{opacity:1}}"
        f"94%{{transform:translate(340px,92px);opacity:1}}100%{{transform:translate(352px,92px);opacity:0}}}}"
        f".{prefix} .slow,.{prefix} .gap{{animation:{prefix}-slow 10s cubic-bezier(.4,0,.6,1) infinite;transform:translate(190px,92px)}}"
        f".{prefix} .slow{{width:16px;height:16px;margin:-8px 0 0 -8px}}"
        f"@keyframes {prefix}-pulse{{0%,21%{{opacity:.85}}23%{{opacity:1}}40%,100%{{opacity:.85}}}}"
        f".{prefix} .curtain{{opacity:.85;animation:{prefix}-pulse 2.6s linear infinite}}"
    ]
    html = [bg]
    for i, (sy, ty, delay) in enumerate([(28, 60, "0s"), (168, 132, "1.3s")]):
        imp = (147.0, float(ty))
        keys, _ai, ao, mid = _streak_keys(f"{prefix}-s{i}", (-10, sy), imp, (-1, 0), 110)
        css.append(keys + _flash_keys(f"{prefix}-f{i}"))
        css.append(
            f".{prefix} .s{i}{{animation:{prefix}-s{i} 2.6s linear {delay} infinite;"
            f"transform:translate({f(mid[0])}px,{f(mid[1])}px) rotate({f(ao)}deg);opacity:{1 if i == 0 else 0}}}"
            f".{prefix} .f{i}{{left:{f(imp[0])}px;top:{f(imp[1])}px;animation:{prefix}-f{i} 2.6s linear {delay} infinite}}"
        )
        html.append(f'<i class="streak s{i}"></i><i class="flash f{i}"></i>')
    html.append('<i class="slow"></i>')
    return "".join(css), "".join(html)


def motion_dotfield(prefix: str) -> tuple[str, str]:
    tx, ty, sc = 150.0, 8.0, 2.6
    shield_d = (
        f"M{f(tx + 32 * sc)} {f(ty + 4 * sc)} L{f(tx + 54 * sc)} {f(ty + 11 * sc)} V{f(ty + 30 * sc)} "
        f"C{f(tx + 54 * sc)} {f(ty + 45 * sc)} {f(tx + 45 * sc)} {f(ty + 55 * sc)} {f(tx + 32 * sc)} {f(ty + 60 * sc)} "
        f"C{f(tx + 19 * sc)} {f(ty + 55 * sc)} {f(tx + 10 * sc)} {f(ty + 45 * sc)} {f(tx + 10 * sc)} {f(ty + 30 * sc)} "
        f"V{f(ty + 11 * sc)} Z"
    )
    cx0 = tx + 32 * sc
    pitch = 12.0
    slot = (cx0 + pitch, 18 + 7 * pitch)
    edge_x = tx + 10 * sc
    impacts = [(edge_x, 46.0, (-10.0, 12.0), "0s"), (edge_x, 104.0, (-10.0, 156.0), "1.4s")]
    rings = "".join(
        f'<circle class="rp r{i}" cx="{f(ix)}" cy="{f(iy)}" r="80" fill="none" stroke="#000" stroke-width="14"/>'
        for i, (ix, iy, _st, _d) in enumerate(impacts)
    )
    bg = (
        f'<svg class="stage-bg" viewBox="0 0 320 180" aria-hidden="true"><defs>'
        f'<pattern id="{prefix}-p" patternUnits="userSpaceOnUse" x="{f(cx0 - pitch / 2)}" y="12" width="{f(pitch)}" height="{f(pitch)}">'
        f'<circle cx="{f(pitch / 2)}" cy="{f(pitch / 2)}" r="3.6" style="fill:var(--m-field)"/></pattern>'
        f'<mask id="{prefix}-m" maskUnits="userSpaceOnUse" x="0" y="0" width="320" height="180">'
        f'<rect width="320" height="180" fill="#fff"/>{rings}</mask></defs>'
        f'<path d="{shield_d}" fill="url(#{prefix}-p)" mask="url(#{prefix}-m)"/></svg>'
    )
    css: list[str] = []
    html = [bg]
    for i, (ix, iy, start, delay) in enumerate(impacts):
        imp = (ix - 4, iy)
        keys, _ai, ao, mid = _streak_keys(f"{prefix}-s{i}", start, imp, (-1, 0), 110)
        css.append(keys)
        css.append(
            f".{prefix} .s{i}{{animation:{prefix}-s{i} 2.8s linear {delay} infinite;"
            f"transform:translate({f(mid[0])}px,{f(mid[1])}px) rotate({f(ao)}deg);opacity:{1 if i == 0 else 0}}}"
            f"@keyframes {prefix}-r{i}{{0%,21.5%{{transform:scale(.01);opacity:0}}23%{{opacity:.85}}"
            f"75%,100%{{transform:scale(1);opacity:0}}}}"
            f".{prefix} .r{i}{{transform-box:fill-box;transform-origin:center;transform:scale({'.45' if i == 0 else '.01'});"
            f"opacity:{'.6' if i == 0 else '0'};animation:{prefix}-r{i} 2.8s cubic-bezier(.2,.6,.3,1) {delay} infinite}}"
        )
        html.append(f'<i class="streak s{i}"></i>')
    css.append(
        f"@keyframes {prefix}-slow{{0%{{transform:translate(-20px,128px);opacity:0}}6%{{opacity:1}}"
        f"62%{{transform:translate({f(slot[0])}px,{f(slot[1])}px)}}90%{{transform:translate({f(slot[0])}px,{f(slot[1])}px);opacity:1}}"
        f"100%{{transform:translate({f(slot[0])}px,{f(slot[1])}px);opacity:0}}}}"
        f".{prefix} .slow{{width:12px;height:12px;margin:-6px 0 0 -6px;"
        f"animation:{prefix}-slow 11s cubic-bezier(.45,.05,.55,.95) infinite;transform:translate({f(slot[0])}px,{f(slot[1])}px)}}"
    )
    html.append('<i class="slow"></i>')
    return "".join(css), "".join(html)


def _cubic(p0, p1, p2, p3, t):  # type: ignore[no-untyped-def]
    mt = 1 - t
    x = mt**3 * p0[0] + 3 * mt * mt * t * p1[0] + 3 * mt * t * t * p2[0] + t**3 * p3[0]
    y = mt**3 * p0[1] + 3 * mt * mt * t * p1[1] + 3 * mt * t * t * p2[1] + t**3 * p3[1]
    dx = 3 * mt * mt * (p1[0] - p0[0]) + 6 * mt * t * (p2[0] - p1[0]) + 3 * t * t * (p3[0] - p2[0])
    dy = 3 * mt * mt * (p1[1] - p0[1]) + 6 * mt * t * (p2[1] - p1[1]) + 3 * t * t * (p3[1] - p2[1])
    return (x, y), (dx, dy)


S_SEGMENTS = [
    ((47, 15.5), (44, 10), (38.5, 7.5), (32, 7.5)),
    ((32, 7.5), (23.5, 7.5), (17, 12), (17, 19.5)),
    ((17, 19.5), (17, 27), (23.5, 29.5), (32, 32)),
    ((32, 32), (40.5, 34.5), (47.5, 37), (47.5, 44.5)),
    ((47.5, 44.5), (47.5, 52), (41, 56.5), (32, 56.5)),
    ((32, 56.5), (25, 56.5), (19.5, 54), (16.5, 48.5)),
]


def motion_slow_s(prefix: str) -> tuple[str, str]:
    tx, ty, sc = 104.0, 2.0, 2.6

    def T(pt: tuple[float, float]) -> str:
        return f"{f(tx + pt[0] * sc)} {f(ty + pt[1] * sc)}"

    path = f"M{T(S_SEGMENTS[0][0])} " + " ".join(f"C{T(a)} {T(b)} {T(c)}" for _, a, b, c in S_SEGMENTS)
    bg = (
        f'<svg class="stage-bg" viewBox="0 0 320 180" aria-hidden="true"><path d="{path}" fill="none" '
        f'style="stroke:var(--m-field)" stroke-width="{f(7.4 * sc)}" stroke-linecap="round"/></svg>'
    )
    css = [
        f"@keyframes {prefix}-ride{{0%{{offset-distance:0%;opacity:0}}8%{{opacity:1}}92%{{opacity:1}}100%{{offset-distance:100%;opacity:0}}}}"
        f".{prefix} .slow{{offset-path:path('{path}');offset-rotate:0deg;offset-distance:50%;margin:0;left:-8px;top:-8px;"
        f"width:16px;height:16px;animation:{prefix}-ride 9s cubic-bezier(.45,.05,.55,.95) infinite}}"
    ]
    html = [bg]
    hits = [(0, 0.35, (330, 6), "0s"), (4, 0.3, (330, 160), "1.4s"), (2, 0.25, (-10, 96), "0.7s")]
    for i, (seg, t, start, delay) in enumerate(hits):
        (px, py), (dx, dy) = _cubic(*S_SEGMENTS[seg], t)
        ln = math.hypot(dx, dy)
        nx, ny = -dy / ln, dx / ln
        sp = (tx + px * sc, ty + py * sc)
        # choose the normal that faces the incoming streak
        if (start[0] - sp[0]) * nx + (start[1] - sp[1]) * ny < 0:
            nx, ny = -nx, -ny
        imp = (sp[0] + nx * 7.4 * sc / 2 + nx * 2, sp[1] + ny * 7.4 * sc / 2 + ny * 2)
        keys, _ai, ao, mid = _streak_keys(f"{prefix}-s{i}", start, imp, (nx, ny), 100)
        css.append(keys + _flash_keys(f"{prefix}-f{i}"))
        css.append(
            f".{prefix} .s{i}{{animation:{prefix}-s{i} 2.8s linear {delay} infinite;"
            f"transform:translate({f(mid[0])}px,{f(mid[1])}px) rotate({f(ao)}deg);opacity:{1 if i == 0 else 0}}}"
            f".{prefix} .f{i}{{left:{f(imp[0])}px;top:{f(imp[1])}px;animation:{prefix}-f{i} 2.8s linear {delay} infinite}}"
        )
        html.append(f'<i class="streak s{i}"></i><i class="flash f{i}"></i>')
    html.append('<i class="slow"></i>')
    return "".join(css), "".join(html)


MOTIONS = {"glance": motion_glance, "parting": motion_parting, "dotfield": motion_dotfield, "slow-s": motion_slow_s}


def motion_vars(key: str, mode: str) -> dict[str, str]:
    pal = PALETTES[key]
    p = pal.dark if mode == "dark" else pal.light
    if key == "glance":
        return {
            "bg": p["ground"],
            "line": p["line"],
            "field": p["brand"],
            "fast": p["ink"],
            "slow": p["accent"] if mode == "dark" else p["brand"],
            "halo": p["ground"],
            "ripple": p["surface"],
        }
    if key == "parting":
        return {
            "bg": p["ground"],
            "line": p["line"],
            "field": p["accent"],
            "fast": p["ink"],
            "slow": p["ink"],
            "halo": p["ground"],
            "ripple": p["surface"],
        }
    if key == "dotfield":
        return {
            "bg": p["ground"],
            "line": p["line"],
            "field": p["brand"],
            "fast": p["ink"],
            "slow": p["ink"],
            "halo": p["ground"],
            "ripple": p["surface"],
        }
    return {
        "bg": p["surface"],
        "line": p["line"],
        "field": p["ink"],
        "fast": p["ink"],
        "slow": p["accent"],
        "halo": p["surface"],
        "ripple": p["surface"],
    }


def motion_html(key: str) -> str:
    prefix = f"ms-{key}"
    css, body = MOTIONS[key](prefix)
    light = ";".join(f"--m-{k}:{v}" for k, v in motion_vars(key, "light").items())
    dark = ";".join(f"--m-{k}:{v}" for k, v in motion_vars(key, "dark").items())
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>SlowShield motion study: {CONCEPTS[key].title}</title><style>"
        f"body{{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--m-bg)}}"
        f":root{{{light}}}@media (prefers-color-scheme: dark){{:root{{{dark}}}}}"
        f"{MOTION_BASE}{css}</style></head><body>"
        f'<div class="ms {prefix}" role="img" aria-label="Fast streaks deflect off the field; a slow dot passes through">{body}</div>'
        "</body></html>"
    )


# ============================================================================ tokens


def tokens_css(key: str) -> str:
    pal = PALETTES[key]

    def block(p: dict[str, str]) -> str:
        return "\n".join(f"  --ss-{k}: {v};" for k, v in p.items())

    shimmer = ""
    if pal.shimmer:
        shimmer = f"\n  --ss-shimmer: linear-gradient(135deg, {', '.join(pal.shimmer)});"
    return (
        f"/* SlowShield round-2 proposal: {CONCEPTS[key].title} / {pal.name}. Generated by generate.py. */\n"
        f":root {{\n{block(pal.light)}{shimmer}\n}}\n"
        f'@media (prefers-color-scheme: dark) {{\n  :root:not([data-theme="light"]) {{\n'
        + "\n".join(f"    --ss-{k}: {v};" for k, v in pal.dark.items())
        + "\n    color-scheme: dark;\n  }\n}\n"
        f':root[data-theme="dark"] {{\n{block(pal.dark)}\n  color-scheme: dark;\n}}\n'
    )


# ============================================================================ output


def check(markup: str, name: str) -> None:
    try:
        xml.dom.minidom.parseString(markup)
    except Exception as exc:
        raise SystemExit(f"invalid SVG {name}: {exc}") from exc


def write_files() -> None:
    for key in CONCEPTS:
        pal = PALETTES[key]
        d = HERE / key
        d.mkdir(parents=True, exist_ok=True)
        files = {
            "mark.svg": mark_svg(key, pal.light),
            "mark-dark.svg": mark_svg(key, pal.dark),
            "mark-mono.svg": mark_svg(key, pal.light, mono=True),
            "favicon.svg": mark_svg(key, pal.light, fav=True),
            "favicon-dark.svg": mark_svg(key, pal.dark, fav=True),
            "lockup-horizontal.svg": lockup_h(key, pal.light),
            "lockup-horizontal-dark.svg": lockup_h(key, pal.dark),
            "lockup-stacked.svg": lockup_s(key, pal.light),
            "lockup-stacked-dark.svg": lockup_s(key, pal.dark),
            "social-preview.svg": social(key),
        }
        for name, markup in files.items():
            check(markup, f"{key}/{name}")
            (d / name).write_text(markup + "\n", encoding="utf-8")
        (d / "motion.html").write_text(motion_html(key) + "\n", encoding="utf-8")
        (d / "tokens.css").write_text(tokens_css(key), encoding="utf-8")


if __name__ == "__main__":
    write_files()
    print("round-2 brand proposals written to", HERE)
