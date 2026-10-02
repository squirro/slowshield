"""SlowShield brand round 2b: variations of Glance and Dot Field.

    python3 brand/proposals/variations.py

Builds on generate.py (same grid, helpers, palettes and AA tuning). Writes `variations/<variant>/` with marks
(light, dark, mono), favicons, horizontal and stacked lockups (light and dark) and tokens.css. Shape variants use
their family's palette; palette variants apply an alternative palette to the family's "Clear" shape so form and
colour can be judged separately. Motion studies stay per family (glance/, dotfield/).
"""

from __future__ import annotations

import importlib.util
import math
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("ss_generate", HERE / "generate.py")
if _spec is None or _spec.loader is None:
    raise SystemExit("cannot load generate.py")
G = importlib.util.module_from_spec(_spec)
sys.modules["ss_generate"] = G
_spec.loader.exec_module(G)

f, paint, stop, streak, reflect, on_circle = G.f, G.paint, G.stop, G.streak, G.reflect, G.on_circle
OUT = HERE / "variations"


def col(p: dict[str, str], key: str, mono: bool, fallback: str) -> str:
    """A palette colour (or currentColor for the one-colour mark), with an optional palette override key."""
    return "currentColor" if mono else p.get(key, p[fallback])


def deflect(
    tail: tuple[float, float], impact: tuple[float, float], normal_deg: float, length: float
) -> tuple[float, float]:
    n = (math.cos(math.radians(normal_deg)), math.sin(math.radians(normal_deg)))
    r = reflect((impact[0] - tail[0], impact[1] - tail[1]), n)
    rl = math.hypot(*r)
    return (impact[0] + r[0] / rl * length, impact[1] + r[1] / rl * length)


# ============================================================================ Glance variants


def glance_clear(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    """The original arc, streak and resting dot with heavier weights; the favicon keeps only arc + dot."""
    field, ink, dot = col(p, "field", mono, "brand"), col(p, "fast", mono, "ink"), col(p, "signal", mono, "brand")
    if fav:
        cx, cy, r = 39.0, 32.0, 22.0
        a0, a1 = on_circle(cx, cy, r, 236), on_circle(cx, cy, r, 124)
        return (
            f'<path d="M{f(a0[0])} {f(a0[1])} A{f(r)} {f(r)} 0 0 0 {f(a1[0])} {f(a1[1])}" fill="none" '
            f'{paint("stroke", field)} stroke-width="9" stroke-linecap="round"/>'
            f'<circle cx="35" cy="37" r="9" {paint("fill", dot)}/>'
        )
    cx, cy, r = 40.0, 32.0, 22.0
    a0, a1 = on_circle(cx, cy, r, 230), on_circle(cx, cy, r, 130)
    impact = on_circle(cx, cy, r + 3.8, 203)
    tail = (2.0, 5.5)
    out = deflect(tail, impact, 203, 13)
    parts = []
    if not mono:
        parts.append(
            f'<defs><linearGradient id="UID-zone" gradientUnits="userSpaceOnUse" x1="{f(cx - r)}" y1="0" x2="{f(cx + 2)}" y2="0">'
            f"{stop('0', p.get('field', p['brand']), 0.28)}{stop('1', p.get('field', p['brand']), 0)}</linearGradient></defs>"
            f'<circle cx="{f(cx)}" cy="{f(cy)}" r="{f(r)}" fill="url(#UID-zone)"/>'
        )
    parts.append(
        f'<path d="M{f(a0[0])} {f(a0[1])} A{f(r)} {f(r)} 0 0 0 {f(a1[0])} {f(a1[1])}" fill="none" '
        f'{paint("stroke", field)} stroke-width="5.6" stroke-linecap="round"/>'
    )
    parts.append(streak("UID-in", tail, impact, ink, 3.8, 0.0, 1.0))
    parts.append(streak("UID-out", impact, out, ink, 2.6, 0.75, 0.0))
    parts.append(
        f'<circle cx="16" cy="44.2" r="1.7" {paint("fill", dot)} opacity=".35"/>'
        f'<circle cx="25.4" cy="42.2" r="2.6" {paint("fill", dot)} opacity=".6"/>'
        f'<circle cx="35" cy="39.4" r="5.8" {paint("fill", dot)}/>'
    )
    return "".join(parts)


def glance_ring(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    """The field closes into a ring. The fast streak grazes its outside; the slow dot came in through the opening."""
    field, ink, dot = col(p, "field", mono, "brand"), col(p, "fast", mono, "ink"), col(p, "signal", mono, "brand")
    cx, cy = 33.0, 32.0
    r = 20.5 if fav else 21.0
    g0, g1 = (48, 352) if fav else (52, 348)  # opening on the lower right, around 20 degrees
    a0, a1 = on_circle(cx, cy, r, g0), on_circle(cx, cy, r, g1)
    sw = 8.4 if fav else 5.2
    ring = (
        f'<path d="M{f(a0[0])} {f(a0[1])} A{f(r)} {f(r)} 0 1 1 {f(a1[0])} {f(a1[1])}" fill="none" '
        f'{paint("stroke", field)} stroke-width="{f(sw)}" stroke-linecap="round"/>'
    )
    if fav:
        return ring + f'<circle cx="{f(cx + 1)}" cy="{f(cy + 1)}" r="8.4" {paint("fill", dot)}/>'
    impact = on_circle(cx, cy, r + 3.6, 222)
    tail = (impact[0] - 15.5, impact[1] + 12.5)
    out = deflect(tail, impact, 222, 15)
    trail = on_circle(cx, cy, r, 20)
    return (
        ring
        + streak("UID-in", tail, impact, ink, 3.6, 0.0, 1.0)
        + streak("UID-out", impact, out, ink, 2.5, 0.75, 0.0)
        + f'<circle cx="{f(trail[0] + 8.6)}" cy="{f(trail[1] + 3.4)}" r="1.6" {paint("fill", dot)} opacity=".35"/>'
        f'<circle cx="{f(trail[0])}" cy="{f(trail[1])}" r="2.5" {paint("fill", dot)} opacity=".6"/>'
        f'<circle cx="{f(cx + 2.5)}" cy="{f(cy + 2)}" r="6.2" {paint("fill", dot)}/>'
    )


# The shield's left half, drawn as one field line from the crown down to the point.
SHIELD_LEFT = "M32 4 L10 11 V30 C10 45 19 55 32 60"
SHIELD_RIGHT = "M32 4 L54 11 V30 C54 45 45 55 32 60"


def glance_shield(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    """The field is the shield's own edge: solid where the streak glances off, fading away on the far side."""
    field, ink, dot = col(p, "field", mono, "brand"), col(p, "fast", mono, "ink"), col(p, "signal", mono, "brand")
    sw = 8.0 if fav else 5.2
    left = f'<path d="{SHIELD_LEFT}" fill="none" {paint("stroke", field)} stroke-width="{f(sw)}" stroke-linecap="round" stroke-linejoin="round"/>'
    if fav:
        right = f'<path d="{SHIELD_RIGHT}" fill="none" {paint("stroke", field)} stroke-width="{f(sw)}" stroke-linecap="round" stroke-linejoin="round" opacity=".38"/>'
        return right + left + f'<circle cx="34" cy="33" r="8.6" {paint("fill", dot)}/>'
    fade = (
        f'<defs><linearGradient id="UID-fade" gradientUnits="userSpaceOnUse" x1="30" y1="0" x2="56" y2="0">'
        f"{stop('0', p.get('field', p['brand']) if not mono else '#111111', 0.55)}"
        f"{stop('1', p.get('field', p['brand']) if not mono else '#111111', 0.04)}</linearGradient></defs>"
    )
    right = (
        f'<path d="{SHIELD_RIGHT}" fill="none" stroke="url(#UID-fade)" stroke-width="{f(sw)}" stroke-linecap="round" stroke-linejoin="round"/>'
        if not mono
        else f'<path d="{SHIELD_RIGHT}" fill="none" stroke="currentColor" stroke-width="{f(sw * 0.6)}" stroke-linecap="round" stroke-linejoin="round" stroke-dasharray="0.1 6.2"/>'
    )
    impact = (10 - 3.6, 19.0)
    tail = (impact[0] - 4.5, impact[1] - 15.5)
    out = (impact[0] - 6.0, impact[1] + 13.5)
    return (
        fade
        + right
        + left
        + streak("UID-in", tail, impact, ink, 3.4, 0.0, 1.0)
        + streak("UID-out", impact, out, ink, 2.4, 0.75, 0.0)
        + f'<circle cx="21.5" cy="44.5" r="1.6" {paint("fill", dot)} opacity=".35"/>'
        f'<circle cx="27" cy="40.8" r="2.4" {paint("fill", dot)} opacity=".6"/>'
        f'<circle cx="35" cy="35.5" r="5.8" {paint("fill", dot)}/>'
    )


# ============================================================================ Dot Field variants

D_IMPACT = (9.0, 19.0)
RINGS = [(10.5, 0.92), (21.5, 0.7), (32.5, 0.42)]


def _touches_shield(x: float, y: float, reach: float) -> bool:
    return G.inside_shield(x, y) or min(math.hypot(x - px, y - py) for px, py in G._POLY) <= reach


def _dot_grid(
    *, step: float, cols: range, rows: range, x0: float, y0: float, reach: float
) -> list[tuple[float, float]]:
    pts = []
    for j in rows:
        for k in cols:
            x, y = x0 + k * step, y0 + j * step
            if _touches_shield(x, y, reach):
                pts.append((x, y))
    return pts


def _streak_dot(mono: bool, p: dict[str, str]) -> str:
    ink = col(p, "fast", mono, "ink")
    hit = (6.6, 19.0)
    return streak("UID-in", (0.6, 6.0), hit, ink, 2.6, 0.0, 1.0) + streak(
        "UID-out", hit, (0.6, 31.0), ink, 1.8, 0.7, 0.0
    )


def _shield_clip(inner: str, fill: str) -> str:
    return (
        f'<defs><clipPath id="UID-c"><path d="{G.SHIELD}"/></clipPath></defs>'
        f'<g clip-path="url(#UID-c)" {paint("fill", fill)}>{inner}</g>'
    )


def _fav_dots(dots: str, special: str, scale) -> str:  # type: ignore[no-untyped-def]
    """Three columns of big dots in a shield outline; the patient package (ink) sits low on the right."""
    pos = {(k, j): (32 + k * 18.0, 9 + j * 16.0) for k, j in FAV_DOTS}
    grid = "".join(
        f'<circle cx="{f(x)}" cy="{f(y)}" r="{f(7.0 * scale(*kj))}"/>'
        for kj, (x, y) in pos.items()
        if kj != FAV_DOT_SLOT
    )
    sx, sy = pos[FAV_DOT_SLOT]
    return (
        f"<g {paint('fill', dots)}>{grid}</g>" + f'<circle cx="{f(sx)}" cy="{f(sy)}" r="7.4" {paint("fill", special)}/>'
    )


def dotfield_clear(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    """The original halftone shield; the patient package is larger and in ink, and the favicon uses a 5-column grid."""
    dots, special = col(p, "dots", mono, "brand"), col(p, "signal", mono, "ink")
    if fav:
        return _fav_dots(dots, special, lambda k, j: 1.0)
    step, base, slot = 5.4, 2.2, (42.8, 42.5)
    pts = _dot_grid(step=step, cols=range(-5, 6), rows=range(11), x0=32, y0=5.3, reach=base)
    circles = []
    for x, y in pts:
        if math.hypot(x - slot[0], y - slot[1]) < 0.1:
            continue
        d = math.hypot(x - D_IMPACT[0], y - D_IMPACT[1])
        dent = max(w * math.exp(-((d - R) ** 2) / (2 * 2.4**2)) for R, w in RINGS)
        r = _halo(math.hypot(x - slot[0], y - slot[1]), base * (1 - 0.78 * dent), 3.6)
        if r > 0.25:
            circles.append(f'<circle cx="{f(x)}" cy="{f(y)}" r="{f(r)}"/>')
    return (
        _shield_clip("".join(circles), dots)
        + f'<circle cx="{f(slot[0])}" cy="{f(slot[1])}" r="3.6" {paint("fill", special)}/>'
        + _streak_dot(mono, p)
    )


# Favicon patterns: whole elements on a coarse grid, no clipping, so nothing lands on half pixels.
# Crates: 12-unit pitch, 8-unit crates = 3 px pitch and 2 px crates at 16 px (4/2 px... at 32 px).
FAV_CRATES = [
    (-2, 0),
    (-1, 0),
    (0, 0),
    (1, 0),
    (2, 0),
    (-2, 1),
    (-1, 1),
    (0, 1),
    (1, 1),
    (2, 1),
    (-2, 2),
    (-1, 2),
    (0, 2),
    (1, 2),
    (2, 2),
    (-1, 3),
    (0, 3),
    (1, 3),
    (0, 4),
]
FAV_CRATE_SLOT = (1, 3)
# Dots: three columns of big dots (about 3.5 px at 16 px) still read as a halftone shield.
FAV_DOTS = [(-1, 0), (0, 0), (1, 0), (-1, 1), (0, 1), (1, 1), (-1, 2), (0, 2), (1, 2), (0, 3)]
FAV_DOT_SLOT = (1, 2)


def _halo(d: float, size: float, special: float, gap: float = 1.0) -> float:
    """Shrink a grid element next to the patient package so a clear ring separates them (also in one colour)."""
    return min(size, max(0.0, d - special - gap))


def _crate(x: float, y: float, side: float) -> str:
    return f'<rect x="{f(x - side / 2)}" y="{f(y - side / 2)}" width="{f(side)}" height="{f(side)}" rx="{f(side * 0.24)}"/>'


def dotfield_crates(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    """Packages as small crates. Squares sit on the pixel grid, so the favicon stays crisp at 16 and 32 px."""
    dots, special = col(p, "dots", mono, "brand"), col(p, "signal", mono, "ink")
    if fav:
        pos = {(k, j): (32 + k * 12.0, 8 + j * 12.0) for k, j in FAV_CRATES}
        crates = "".join(_crate(x, y, 8.0) for kj, (x, y) in pos.items() if kj != FAV_CRATE_SLOT)
        return (
            f"<g {paint('fill', dots)}>{crates}</g><g {paint('fill', special)}>{_crate(*pos[FAV_CRATE_SLOT], 8.0)}</g>"
        )
    step, side, slot = 5.6, 4.0, (43.2, 41.6)
    pts = _dot_grid(step=step, cols=range(-5, 6), rows=range(11), x0=32, y0=5.2, reach=side / 2)
    crates = []
    for x, y in pts:
        if math.hypot(x - slot[0], y - slot[1]) < 0.1:
            continue
        d = math.hypot(x - D_IMPACT[0], y - D_IMPACT[1])
        dent = max(w * math.exp(-((d - R) ** 2) / (2 * 2.4**2)) for R, w in RINGS)
        s = 2 * _halo(math.hypot(x - slot[0], y - slot[1]), side * (1 - 0.8 * dent) / 2, 2.7 * 1.2, 0.9)
        if s > 0.5:
            crates.append(_crate(x, y, s))
    return (
        _shield_clip("".join(crates), dots)
        + f"<g {paint('fill', special)}>{_crate(*slot, 5.4)}</g>"
        + _streak_dot(mono, p)
    )


def dotfield_wave(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    """The impact becomes the image: dots thin out towards the struck shoulder like a printed gradient."""
    dots, special = col(p, "dots", mono, "brand"), col(p, "signal", mono, "ink")
    if fav:
        # The struck (top-left) dot shrinks; the rest stay full so the shape still reads at 16 px.
        return _fav_dots(
            dots, special, lambda k, j: 0.55 if (k, j) == (-1, 0) else 0.8 if (k, j) in ((0, 0), (-1, 1)) else 1.0
        )
    step, base, slot = 4.6, 2.05, (42.2, 42.3)
    pts = _dot_grid(step=step, cols=range(-6, 7), rows=range(13), x0=32, y0=5.0, reach=base)
    circles = []
    for x, y in pts:
        if math.hypot(x - slot[0], y - slot[1]) < 2.3:
            continue
        d = math.hypot(x - D_IMPACT[0], y - D_IMPACT[1])
        t = min(1.0, max(0.0, (d - 3) / 40))
        r = _halo(math.hypot(x - slot[0], y - slot[1]), base * (0.12 + 0.88 * t**0.8), 3.8)
        if r > 0.3:
            circles.append(f'<circle cx="{f(x)}" cy="{f(y)}" r="{f(r)}"/>')
    return (
        _shield_clip("".join(circles), dots)
        + f'<circle cx="{f(slot[0])}" cy="{f(slot[1])}" r="3.8" {paint("fill", special)}/>'
        + _streak_dot(mono, p)
    )


# ============================================================================ palettes

NIGHT_FIELD = G.PALETTES["glance"]
SAND_COBALT = G.PALETTES["dotfield"]

ALT_PALETTES = {
    "ultraviolet": G.Palette(
        name="Ultraviolet",
        notes="Night ink with a violet field. Held moves to blue so it never reads as the brand.",
        light={
            "ground": "#f4f2fb",
            "surface": "#ffffff",
            "line": "#e2ddf2",
            "ink": "#120c26",
            "muted": "#5d5779",
            "brand": "#5b2ff0",
            "accent": "#a58cff",
            "available": "#13804e",
            "held": "#1f6db5",
            "blocked": "#d0263c",
            "tampered": "#b8218f",
        },
        dark={
            "ground": "#0a0716",
            "surface": "#120e22",
            "line": "#262043",
            "ink": "#ece8fb",
            "muted": "#a39cc2",
            "brand": "#9a82ff",
            "accent": "#c7b8ff",
            "available": "#4fd48a",
            "held": "#79b7ff",
            "blocked": "#ff6f7e",
            "tampered": "#f27bd6",
        },
    ).tuned(),
    "graphite-signal": G.Palette(
        name="Graphite & Signal Blue",
        notes="The field and streak in graphite; only the patient package carries colour.",
        light={
            "ground": "#f3f4f5",
            "surface": "#ffffff",
            "line": "#dfe1e4",
            "ink": "#121417",
            "muted": "#5b6068",
            "brand": "#1f4fe0",
            "accent": "#7d9cff",
            "available": "#13804e",
            "held": "#6447d6",
            "blocked": "#d0263c",
            "tampered": "#b8218f",
            "field": "#121417",
            "signal": "#1f4fe0",
        },
        dark={
            "ground": "#0c0d0f",
            "surface": "#16181b",
            "line": "#2a2d32",
            "ink": "#eceef1",
            "muted": "#a0a5ad",
            "brand": "#7b9bff",
            "accent": "#a9bcff",
            "available": "#4fd48a",
            "held": "#a99bff",
            "blocked": "#ff6f7e",
            "tampered": "#f27bd6",
            "field": "#eceef1",
            "signal": "#7b9bff",
        },
    ).tuned(),
    "paper-ink": G.Palette(
        name="Paper & Ink",
        notes="A newspaper halftone: ink dots on white paper; the patient package is the only cobalt.",
        light={
            "ground": "#f4f4f1",
            "surface": "#ffffff",
            "line": "#e1e1dc",
            "ink": "#151515",
            "muted": "#5f5f5a",
            "brand": "#1d44c4",
            "accent": "#cfcfc8",
            "available": "#2b7840",
            "held": "#7c4aa0",
            "blocked": "#b8292b",
            "tampered": "#a8197a",
            "dots": "#151515",
            "signal": "#1d44c4",
        },
        dark={
            "ground": "#0f0f0e",
            "surface": "#191918",
            "line": "#2d2d2b",
            "ink": "#efefea",
            "muted": "#a9a9a2",
            "brand": "#86a0ff",
            "accent": "#4f4f4b",
            "available": "#74c98a",
            "held": "#c59df0",
            "blocked": "#ff7c70",
            "tampered": "#f17cc8",
            "dots": "#efefea",
            "signal": "#86a0ff",
        },
    ).tuned(),
    "blueprint": G.Palette(
        name="Blueprint",
        notes="Cool drafting paper and cobalt by day, deep navy by night: the technical-manual idea without the sand.",
        light={
            "ground": "#eef2f8",
            "surface": "#fbfcfe",
            "line": "#d6deeb",
            "ink": "#0f1830",
            "muted": "#53607a",
            "brand": "#1d44c4",
            "accent": "#9db0e6",
            "available": "#2b7840",
            "held": "#7c4aa0",
            "blocked": "#b8292b",
            "tampered": "#a8197a",
        },
        dark={
            "ground": "#08101f",
            "surface": "#0e182b",
            "line": "#1f2c45",
            "ink": "#e6ecf7",
            "muted": "#9aa8c2",
            "brand": "#7f9cff",
            "accent": "#33476e",
            "available": "#74c98a",
            "held": "#c59df0",
            "blocked": "#ff7c70",
            "tampered": "#f17cc8",
            "signal": "#ffffff",
        },
    ).tuned(),
}


# ============================================================================ registry


@dataclass
class Variant:
    key: str
    family: str  # glance | dotfield (wordmark, motion)
    name: str
    kind: str  # shape | palette
    mark: object
    palette: object
    idea: str


VARIANTS = [
    Variant(
        "glance-clear",
        "glance",
        "Clear",
        "shape",
        glance_clear,
        NIGHT_FIELD,
        "The original, with heavier strokes. The favicon keeps only arc and dot, so it survives 16 px.",
    ),
    Variant(
        "glance-ring",
        "glance",
        "Ring",
        "shape",
        glance_ring,
        NIGHT_FIELD,
        "The field closes into a ring. The streak grazes its outside; the slow dot came in through the opening.",
    ),
    Variant(
        "glance-shield",
        "glance",
        "Shield",
        "shape",
        glance_shield,
        NIGHT_FIELD,
        "The field is the shield's own edge: solid where the streak glances off, fading on the far side.",
    ),
    Variant(
        "glance-clear-ultraviolet",
        "glance",
        "Clear · Ultraviolet",
        "palette",
        glance_clear,
        ALT_PALETTES["ultraviolet"],
        "Night ink with a violet field instead of blue. Held moves to blue so it never reads as the brand.",
    ),
    Variant(
        "glance-clear-graphite",
        "glance",
        "Clear · Graphite & Signal Blue",
        "palette",
        glance_clear,
        ALT_PALETTES["graphite-signal"],
        "Field and streak in graphite; only the patient dot is blue. Calmer, and the one colour means something.",
    ),
    Variant(
        "dotfield-clear",
        "dotfield",
        "Clear",
        "shape",
        dotfield_clear,
        SAND_COBALT,
        "The original halftone. The patient package is larger and in ink; the favicon uses a 5-column grid.",
    ),
    Variant(
        "dotfield-crates",
        "dotfield",
        "Crates",
        "shape",
        dotfield_crates,
        SAND_COBALT,
        "Packages as small crates. They sit on whole pixels, so the favicon stays crisp at 16 and 32 px.",
    ),
    Variant(
        "dotfield-wave",
        "dotfield",
        "Wave",
        "shape",
        dotfield_wave,
        SAND_COBALT,
        "The impact becomes the image: dots thin out towards the struck shoulder like a printed gradient.",
    ),
    Variant(
        "dotfield-clear-paper",
        "dotfield",
        "Clear · Paper & Ink",
        "palette",
        dotfield_clear,
        ALT_PALETTES["paper-ink"],
        "A newspaper halftone: ink dots on white paper, and the patient package is the only cobalt.",
    ),
    Variant(
        "dotfield-clear-blueprint",
        "dotfield",
        "Clear · Blueprint",
        "palette",
        dotfield_clear,
        ALT_PALETTES["blueprint"],
        "Cool drafting paper and cobalt by day, deep navy by night: the technical-manual idea without the sand.",
    ),
]

for v in VARIANTS:
    base = G.CONCEPTS[v.family]
    G.CONCEPTS[v.key] = G.Concept(v.key, f"{base.title} · {v.name}", base.tagline, v.mark, base.wordmark)
    G.WM_WIDTH[v.key] = G.WM_WIDTH[v.family]
    G.WM_CHARS[v.key] = G.WM_CHARS[v.family]
    G.PALETTES[v.key] = v.palette


def write_files() -> None:
    for v in VARIANTS:
        pal = v.palette
        d = OUT / v.key
        d.mkdir(parents=True, exist_ok=True)
        files = {
            "mark.svg": G.mark_svg(v.key, pal.light),
            "mark-dark.svg": G.mark_svg(v.key, pal.dark),
            "mark-mono.svg": G.mark_svg(v.key, pal.light, mono=True),
            "favicon.svg": G.mark_svg(v.key, pal.light, fav=True),
            "favicon-dark.svg": G.mark_svg(v.key, pal.dark, fav=True),
            "lockup-horizontal.svg": G.lockup_h(v.key, pal.light),
            "lockup-horizontal-dark.svg": G.lockup_h(v.key, pal.dark),
            "lockup-stacked.svg": G.lockup_s(v.key, pal.light),
            "lockup-stacked-dark.svg": G.lockup_s(v.key, pal.dark),
        }
        for name, markup in files.items():
            G.check(markup, f"{v.key}/{name}")
            (d / name).write_text(markup + "\n", encoding="utf-8")
        (d / "tokens.css").write_text(
            G.tokens_css(v.key)
            .replace("round-2 proposal", "round-2b variation")
            .replace("generate.py", "variations.py"),
            encoding="utf-8",
        )


if __name__ == "__main__":
    write_files()
    print(f"{len(VARIANTS)} variations written to", OUT)
