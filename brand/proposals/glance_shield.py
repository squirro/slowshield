"""SlowShield brand round 2c: Glance · Shield, reworked.

    python3 brand/proposals/glance_shield.py

Writes `glance-shield/`:
* `<treatment>/` for four ways of drawing the glance (mark, mark-dark, mark-mono, lockups).
* `favicons/<idea>(-dark).svg` for five small-size ideas, each drawn for 16 and 32 px rather than scaled down.

Changes against the round-2b Shield: the shield sits right of centre so the glance has room; its edge is one
gradient stroke (solid on the struck side, soft on the far side) with no seams; the slow dot comes in through
the soft side, which is the point of the field.
"""

from __future__ import annotations

import importlib.util
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("ss_variations", HERE / "variations.py")
if _spec is None or _spec.loader is None:
    raise SystemExit("cannot load variations.py")
VM = importlib.util.module_from_spec(_spec)
sys.modules["ss_variations"] = VM
_spec.loader.exec_module(VM)
G = VM.G
f, paint, stop, streak, reflect = G.f, G.paint, G.stop, G.streak, G.reflect
OUT = HERE / "glance-shield"
PAL = VM.NIGHT_FIELD

# ============================================================================ geometry

CX, TOP, SCALE = 37.0, 7.5, 0.86  # crown of the shield; the left 15 units stay free for the glance


def pt(x: float, y: float, cx: float = CX, top: float = TOP, s: float = SCALE) -> tuple[float, float]:
    """Map a point of the 64-unit master shield (generate.SHIELD) into this composition."""
    return (cx + (x - 32) * s, top + (y - 4) * s)


def shield_d(cx: float = CX, top: float = TOP, s: float = SCALE, *, half: str = "") -> str:
    def P(x: float, y: float) -> str:
        a, b = pt(x, y, cx, top, s)
        return f"{f(a)} {f(b)}"

    if half == "left":
        return f"M{P(32, 4)} L{P(10, 11)} L{P(10, 30)} C{P(10, 45)} {P(19, 55)} {P(32, 60)}"
    if half == "right":
        return f"M{P(32, 4)} L{P(54, 11)} L{P(54, 30)} C{P(54, 45)} {P(45, 55)} {P(32, 60)}"
    return (
        f"M{P(32, 4)} L{P(54, 11)} L{P(54, 30)} C{P(54, 45)} {P(45, 55)} {P(32, 60)} "
        f"C{P(19, 55)} {P(10, 45)} {P(10, 30)} L{P(10, 11)} Z"
    )


def unit(v: tuple[float, float]) -> tuple[float, float]:
    n = math.hypot(*v)
    return (v[0] / n, v[1] / n)


SW = 5.2  # edge stroke
LEFT_X = pt(10, 0)[0]
CROWN, SHOULDER = pt(32, 4), pt(10, 11)
TOP_EDGE = unit((CROWN[0] - SHOULDER[0], CROWN[1] - SHOULDER[1]))
TOP_NORMAL = (TOP_EDGE[1], -TOP_EDGE[0])  # outward (up and to the left)
DOT = (42.5, 34.0)


def edge(p: dict[str, str], mono: bool) -> str:
    """The shield edge: one stroke, solid on the struck (left) side, soft on the far side."""
    if mono:
        return (
            f'<path d="{shield_d(half="right")}" fill="none" stroke="currentColor" stroke-width="{f(SW * 0.62)}" '
            f'stroke-linecap="round" stroke-dasharray="0.1 6" stroke-linejoin="round"/>'
            f'<path d="{shield_d(half="left")}" fill="none" stroke="currentColor" stroke-width="{f(SW)}" '
            f'stroke-linecap="round" stroke-linejoin="round"/>'
        )
    x0, x1 = LEFT_X - SW / 2, pt(54, 0)[0] + SW / 2
    c = p["brand"]
    return (
        f'<defs><linearGradient id="UID-edge" gradientUnits="userSpaceOnUse" x1="{f(x0)}" y1="0" x2="{f(x1)}" y2="0">'
        f"{stop('0', c, 1)}{stop('0.42', c, 1)}{stop('0.78', c, 0.38)}{stop('1', c, 0.14)}</linearGradient></defs>"
        f'<path d="{shield_d()}" fill="none" stroke="url(#UID-edge)" stroke-width="{f(SW)}" stroke-linejoin="round"/>'
    )


def slow_dot(p: dict[str, str], mono: bool, r: float = 5.6) -> str:
    """The patient package, with a short trail that came in through the soft side."""
    c = "currentColor" if mono else p["brand"]
    return (
        f'<circle cx="62.2" cy="39.6" r="1.4" {paint("fill", c)} opacity=".3"/>'
        f'<circle cx="54.6" cy="37.4" r="2.2" {paint("fill", c)} opacity=".55"/>'
        f'<circle cx="{f(DOT[0])}" cy="{f(DOT[1])}" r="{f(r)}" {paint("fill", c)}/>'
    )


def comet(uid: str, tail: tuple[float, float], head: tuple[float, float], color: str, w0: float, w1: float) -> str:
    """A tapered streak: thin and transparent at the tail, full width and opaque at the head."""
    return (
        f'<defs><linearGradient id="{uid}" gradientUnits="userSpaceOnUse" x1="{f(tail[0])}" y1="{f(tail[1])}" '
        f'x2="{f(head[0])}" y2="{f(head[1])}">{stop("0", color, 0)}{stop("0.55", color, 0.55)}{stop("1", color, 1)}'
        f'</linearGradient></defs><path d="{G.taper(tail, head, w0, w1)}" fill="url(#{uid})"/>'
    )


def bounce(
    uid: str,
    color: str,
    impact: tuple[float, float],
    d_in: tuple[float, float],
    normal: tuple[float, float],
    l_in: float,
    l_out: float,
    w: float = 3.4,
) -> str:
    d_in = unit(d_in)
    tail = (impact[0] - d_in[0] * l_in, impact[1] - d_in[1] * l_in)
    r = unit(reflect(d_in, normal))
    out = (impact[0] + r[0] * l_out, impact[1] + r[1] * l_out)
    return comet(f"{uid}-in", tail, impact, color, 0.4, w) + streak(
        f"{uid}-out", impact, out, color, w * 0.66, 0.8, 0.0
    )


def on_top_edge(t: float, gap: float = 1.2) -> tuple[float, float]:
    """A point just outside the top-left edge, t of the way from shoulder to crown."""
    x = SHOULDER[0] + (CROWN[0] - SHOULDER[0]) * t
    y = SHOULDER[1] + (CROWN[1] - SHOULDER[1]) * t
    k = SW / 2 + gap
    return (x + TOP_NORMAL[0] * k, y + TOP_NORMAL[1] * k)


def on_left_edge(y: float, gap: float = 1.2) -> tuple[float, float]:
    return (LEFT_X - SW / 2 - gap, y)


# ============================================================================ glance treatments


def t_ricochet(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    """A true glance: the streak skims in, touches the top edge at a shallow angle and skips off over the crown."""
    ink = "currentColor" if mono else p["ink"]
    hit = on_top_edge(0.3)
    return edge(p, mono) + bounce("UID-g", ink, hit, (1.0, 0.2), TOP_NORMAL, 22, 13) + slow_dot(p, mono)


def t_ripple(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    """The field shows itself where it is hit: two ripples spread from the impact on the left side."""
    ink = "currentColor" if mono else p["ink"]
    field = "currentColor" if mono else p["brand"]
    cy = 24.0
    hit = on_left_edge(cy, 1.0)
    ripples = ""
    for r, op in ((6.4, 0.55), (10.2, 0.28)):
        a0, a1 = math.radians(148), math.radians(212)
        s = (LEFT_X + r * math.cos(a0), cy + r * math.sin(a0))
        e = (LEFT_X + r * math.cos(a1), cy + r * math.sin(a1))
        ripples += (
            f'<path d="M{f(s[0])} {f(s[1])} A{f(r)} {f(r)} 0 0 0 {f(e[0])} {f(e[1])}" fill="none" '
            f'{paint("stroke", field)} stroke-width="1.7" stroke-linecap="round" opacity="{op}"/>'
        )
    return edge(p, mono) + ripples + bounce("UID-g", ink, hit, (0.42, -1.0), (-1, 0), 17, 12) + slow_dot(p, mono)


def t_sparks(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    """The streak strikes the shoulder and breaks into sparks; nothing of it gets through."""
    ink = "currentColor" if mono else p["ink"]
    hit = (SHOULDER[0] - 2.6, SHOULDER[1] + 1.2)
    d_in = unit((1.0, 0.62))
    tail = (hit[0] - d_in[0] * 15, hit[1] - d_in[1] * 15)
    sparks = ""
    for i, (ang, ln, w) in enumerate(((198, 8.5, 1.7), (222, 7.0, 1.5), (176, 6.0, 1.3), (246, 5.0, 1.2))):
        a = math.radians(ang)
        s0 = (hit[0] + math.cos(a) * 1.6, hit[1] + math.sin(a) * 1.6)
        s1 = (hit[0] + math.cos(a) * (1.6 + ln), hit[1] + math.sin(a) * (1.6 + ln))
        sparks += streak(f"UID-sp{i}", s0, s1, ink, w, 0.9, 0.0)
    return edge(p, mono) + comet("UID-in", tail, hit, ink, 0.4, 3.4) + sparks + slow_dot(p, mono)


def t_volley(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    """Three streaks glance off at different heights; only the slow dot is inside."""
    ink = "currentColor" if mono else p["ink"]
    out = edge(p, mono)
    for i, (t, l_in, l_out, w) in enumerate(((0.32, 20, 12, 3.2),)):
        out += bounce(f"UID-v{i}", ink, on_top_edge(t), (1.0, 0.24), TOP_NORMAL, l_in, l_out, w)
    for i, (y, l_in, l_out, w, op) in enumerate(((27.0, 15, 10, 2.6, 0.8), (40.0, 11, 8, 2.1, 0.55)), start=1):
        g = (
            f'<g opacity="{op}">'
            + bounce(f"UID-v{i}", ink, on_left_edge(y, 1.0), (0.45, -1.0), (-1, 0), l_in, l_out, w)
            + "</g>"
        )
        out += g
    return out + slow_dot(p, mono)


TREATMENTS = {
    "ricochet": (
        "Ricochet",
        t_ricochet,
        "The streak skims in, touches the top edge at a shallow angle and skips off over the crown: a real glance, not a bounce.",
    ),
    "ripple": (
        "Ripple",
        t_ripple,
        "The field shows itself where it is hit: two ripples spread from the impact while the streak slides off.",
    ),
    "sparks": (
        "Sparks",
        t_sparks,
        "The streak strikes the shoulder and breaks into sparks. Nothing of it gets through.",
    ),
    "volley": (
        "Volley",
        t_volley,
        "Three streaks glance off at different heights; the only thing inside is the slow dot.",
    ),
}

# ============================================================================ small sizes (favicons)
# Drawn on the full 64-unit canvas (no room needed for a glance) at weights that survive 16 px.

FS = 1.06  # favicon shield scale, centred
FCX, FTOP = 32.0, 2.8


def fav_shield(*, half: str = "") -> str:
    return shield_d(FCX, FTOP, FS, half=half)


def fpt(x: float, y: float) -> tuple[float, float]:
    return pt(x, y, FCX, FTOP, FS)


def f_bold(p: dict[str, str]) -> str:
    """Even, heavy outline and a big dot. No fade: at 16 px a fade only looks blurry."""
    c = p["brand"]
    return (
        f'<path d="{fav_shield()}" fill="none" {paint("stroke", c)} stroke-width="7.6" stroke-linejoin="round"/>'
        f'<circle cx="32" cy="31.5" r="8.6" {paint("fill", c)}/>'
    )


def f_solid(p: dict[str, str]) -> str:
    """A filled shield with the patient package punched out: the strongest shape a tab can show."""
    return (
        f'<defs><mask id="UID-m" maskUnits="userSpaceOnUse" x="0" y="0" width="64" height="64">'
        f'<rect width="64" height="64" fill="#fff"/><circle cx="32" cy="30" r="8.2" fill="#000"/></mask></defs>'
        f'<path d="{fav_shield()}" {paint("fill", p["brand"])} mask="url(#UID-m)"/>'
    )


def f_split(p: dict[str, str]) -> str:
    """The struck half is solid, the far half only an outline, and the dot sits in the open half."""
    c = p["brand"]
    top, mid_bottom = fpt(32, 4), fpt(32, 60)
    left_fill = fav_shield(half="left") + f" L{f(mid_bottom[0])} {f(mid_bottom[1])} L{f(top[0])} {f(top[1])} Z"
    return (
        f'<path d="{fav_shield(half="right")}" fill="none" {paint("stroke", c)} stroke-width="5" '
        f'stroke-linejoin="round" stroke-linecap="round" opacity=".5"/>'
        f'<path d="{left_fill}" {paint("fill", c)}/>'
        f'<circle cx="41" cy="31" r="7" {paint("fill", c)}/>'
    )


def f_slice(p: dict[str, str]) -> str:
    """A filled shield whose struck corner is cut away by the glance; the dot is punched out."""
    # Centre line of the cut in master coordinates: 7 units inside the shoulder corner, at 45 degrees.
    a, b = fpt(2, 25.4), fpt(26.4, 1)
    k = 2.6  # half width of the cut
    n = unit((b[1] - a[1], -(b[0] - a[0])))
    # n points outwards (up and left): drop everything beyond the inner edge of the cut, so no splinter
    # of the corner is left to blur at 16 px.
    far = 40.0
    cut = (
        f"M{f(a[0] - n[0] * k)} {f(a[1] - n[1] * k)} L{f(b[0] - n[0] * k)} {f(b[1] - n[1] * k)} "
        f"L{f(b[0] + n[0] * far)} {f(b[1] + n[1] * far)} L{f(a[0] + n[0] * far)} {f(a[1] + n[1] * far)} Z"
    )
    return (
        f'<defs><mask id="UID-m" maskUnits="userSpaceOnUse" x="0" y="0" width="64" height="64">'
        f'<rect width="64" height="64" fill="#fff"/><path d="{cut}" fill="#000"/>'
        f'<circle cx="35" cy="34" r="7.6" fill="#000"/></mask></defs>'
        f'<path d="{fav_shield()}" {paint("fill", p["brand"])} mask="url(#UID-m)"/>'
    )


def f_glance(p: dict[str, str]) -> str:
    """The full idea, simplified: heavy outline, big dot, one bold streak skipping off the top edge."""
    c, ink = p["brand"], p["ink"]
    cx, top, s = 37.5, 11.0, 0.8
    sh, cr = pt(10, 11, cx, top, s), pt(32, 4, cx, top, s)
    e = unit((cr[0] - sh[0], cr[1] - sh[1]))
    nrm = (e[1], -e[0])
    t = 0.3
    hit = (sh[0] + (cr[0] - sh[0]) * t + nrm[0] * 5.6, sh[1] + (cr[1] - sh[1]) * t + nrm[1] * 5.6)
    d_in = unit((1.0, 0.22))
    tail = (hit[0] - d_in[0] * 14, hit[1] - d_in[1] * 14)
    r = unit(reflect(d_in, nrm))
    out = (hit[0] + r[0] * 6.5, hit[1] + r[1] * 6.5)  # stays on the canvas
    return (
        f'<path d="{shield_d(cx, top, s)}" fill="none" {paint("stroke", c)} stroke-width="7" stroke-linejoin="round"/>'
        f'<circle cx="{f(cx + 2)}" cy="34" r="7.4" {paint("fill", c)}/>'
        f'<path d="M{f(tail[0])} {f(tail[1])} L{f(hit[0])} {f(hit[1])} L{f(out[0])} {f(out[1])}" fill="none" '
        f'{paint("stroke", ink)} stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>'
    )


FAVICONS = {
    "bold": (
        "Bold outline",
        f_bold,
        "Even, heavy outline and a big dot. No fade, because at 16 px a fade only looks blurry.",
    ),
    "solid": (
        "Solid",
        f_solid,
        "A filled shield with the patient package punched out. The strongest silhouette a browser tab can show.",
    ),
    "split": (
        "Split",
        f_split,
        "The struck half is solid, the far half only an outline; the dot sits in the open half.",
    ),
    "slice": (
        "Chamfer",
        f_slice,
        "A filled shield whose struck corner is cut away, as if the glance took it; the dot is punched out.",
    ),
    "glance": (
        "Mini glance",
        f_glance,
        "The whole idea, simplified: heavy outline, big dot and one bold streak skipping off the top edge. For 32 px and up.",
    ),
}

# ============================================================================ output


def write_files() -> None:
    for key, (title, fn, _idea) in TREATMENTS.items():
        vkey = f"glance-shield-{key}"
        G.CONCEPTS[vkey] = G.Concept(vkey, f"Glance Shield · {title}", G.CONCEPTS["glance"].tagline, fn, G.wm_glance)
        G.WM_WIDTH[vkey], G.WM_CHARS[vkey] = G.WM_WIDTH["glance"], G.WM_CHARS["glance"]
        d = OUT / key
        d.mkdir(parents=True, exist_ok=True)
        files = {
            "mark.svg": G.mark_svg(vkey, PAL.light),
            "mark-dark.svg": G.mark_svg(vkey, PAL.dark),
            "mark-mono.svg": G.mark_svg(vkey, PAL.light, mono=True),
            "lockup-horizontal.svg": G.lockup_h(vkey, PAL.light),
            "lockup-horizontal-dark.svg": G.lockup_h(vkey, PAL.dark),
            "lockup-stacked.svg": G.lockup_s(vkey, PAL.light),
            "lockup-stacked-dark.svg": G.lockup_s(vkey, PAL.dark),
        }
        for name, markup in files.items():
            G.check(markup, f"{key}/{name}")
            (d / name).write_text(markup + "\n", encoding="utf-8")
    fd = OUT / "favicons"
    fd.mkdir(parents=True, exist_ok=True)
    for key, (_title, fn, _idea) in FAVICONS.items():
        for suf, p in (("", PAL.light), ("-dark", PAL.dark)):
            markup = G.uniq(G.svg(fn(p), 64, 64), f"f{key}")
            G.check(markup, f"favicons/{key}{suf}.svg")
            (fd / f"{key}{suf}.svg").write_text(markup + "\n", encoding="utf-8")
    (OUT / "tokens.css").write_text(
        G.tokens_css("glance").replace("round-2 proposal", "round-2c Glance Shield"), encoding="utf-8"
    )


if __name__ == "__main__":
    write_files()
    print(f"{len(TREATMENTS)} treatments and {len(FAVICONS)} favicon ideas written to", OUT)
