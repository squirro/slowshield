"""SlowShield brand round 2d: the half-solid shield.

    python3 brand/proposals/glance_shield_2d.py

From the round-2c feedback: Ripple direction, reset. The shield is solid on the struck (left) side and only a
dotted outline on the far side; the glance moves into the solid side as chevrons that show motion into the
shield; no dot. Writes `glance-shield/2d/<variant>/` (marks, lockups, and favicons drawn separately for 16 and
32 px).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("ss_glance_shield", HERE / "glance_shield.py")
if _spec is None or _spec.loader is None:
    raise SystemExit("cannot load glance_shield.py")
GS = importlib.util.module_from_spec(_spec)
sys.modules["ss_glance_shield"] = GS
_spec.loader.exec_module(GS)
G = GS.G
f, paint = G.f, G.paint
PAL = GS.PAL
OUT = HERE / "glance-shield" / "2d"


def left_half(cx: float, top: float, s: float) -> str:
    """The left half of the shield as a closed area (edge plus the centre line)."""
    return GS.shield_d(cx, top, s, half="left") + " Z"


def dotted_right(c: str, cx: float, top: float, s: float, *, width: float, gap: float, opacity: float = 1.0) -> str:
    op = "" if opacity == 1 else f' opacity="{opacity}"'
    return (
        f'<path d="{GS.shield_d(cx, top, s, half="right")}" fill="none" {paint("stroke", c)} stroke-width="{f(width)}" '
        f'stroke-linecap="round" stroke-linejoin="round" stroke-dasharray="0.1 {f(gap)}"{op}/>'
    )


def faint_right(c: str, cx: float, top: float, s: float, width: float) -> str:
    """At 16 px dots blur into grey, so the far side becomes a faint solid line instead."""
    return (
        f'<path d="{GS.shield_d(cx, top, s, half="right")}" fill="none" {paint("stroke", c)} stroke-width="{f(width)}" '
        f'stroke-linecap="round" stroke-linejoin="round" opacity=".42"/>'
    )


def solid_left(c: str, cx: float, top: float, s: float, width: float, mask: str = "") -> str:
    """Filled left half; the stroke of the same colour makes it as wide as the dotted side."""
    m = f' mask="url(#{mask})"' if mask else ""
    return (
        f'<path d="{left_half(cx, top, s)}" {paint("fill", c)} {paint("stroke", c)} stroke-width="{f(width)}" '
        f'stroke-linejoin="round"{m}/>'
    )


def chevron(x0: float, cy: float, w: float, h: float) -> str:
    return f"M{f(x0)} {f(cy - h)} L{f(x0 + w)} {f(cy)} L{f(x0)} {f(cy + h)}"


def chevrons(c: str, items: list[tuple[float, float]], cy: float, w: float, h: float, width: float) -> str:
    """Chevrons pointing right (into the shield); items = (x0, opacity), farthest first."""
    return "".join(
        f'<path d="{chevron(x0, cy, w, h)}" fill="none" {paint("stroke", c)} stroke-width="{f(width)}" '
        f'stroke-linecap="round" stroke-linejoin="round" opacity="{op}"/>'
        for x0, op in items
    )


def cut_mask(uid: str, cuts: str) -> str:
    return (
        f'<defs><mask id="{uid}" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80">'
        f'<rect x="-8" y="-8" width="80" height="80" fill="#fff"/>{cuts}</mask></defs>'
    )


def scaled_left_edge(cx: float, cy: float, k: float, base: tuple[float, float, float] = (32.0, 4.0, 1.0)) -> str:
    """The left edge of the `base` shield scaled by k around (cx, cy): one ripple line inside the solid half."""
    top = cy + (base[1] - cy) * k
    return GS.shield_d(cx, top, base[2] * k, half="left")


# ============================================================================ variants (64-unit marks)
# Centred shield: crown (32, 4), scale 1. Shifted shield (room on the left): crown (37, 7.5), scale 0.86.

C1 = (32.0, 4.0, 1.0)
C2 = (37.0, 7.5, 0.86)


def v_inbound(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    """Two chevrons cut into the solid half, pointing into the shield: fast things go in and stop there."""
    c = "currentColor" if mono else p["brand"]
    cuts = "".join(
        f'<path d="{chevron(x0, 31, 6.4, 8.6)}" fill="none" stroke="#000" stroke-width="3.4" stroke-linecap="round" '
        f'stroke-linejoin="round"/>'
        for x0 in (14.2, 21.8)
    )
    return cut_mask("UID-m", cuts) + solid_left(c, *C1, 4.2, "UID-m") + dotted_right(c, *C1, width=4.2, gap=6.4)


def v_approach(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    """Chevrons fly in from the left, fading with distance, and stop at the solid side."""
    c = "currentColor" if mono else p["brand"]
    return (
        chevrons(c, [(0.8, 0.28), (6.0, 0.55), (11.2, 1.0)], 30.5, 4.6, 6.6, 2.9)
        + solid_left(c, *C2, 3.8)
        + dotted_right(c, *C2, width=3.8, gap=5.8)
    )


def v_ripple(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    """The reset Ripple: the impact runs through the solid half as rings, from the edge inwards."""
    c = "currentColor" if mono else p["brand"]
    cuts = "".join(
        f'<path d="{scaled_left_edge(33.0, 32.0, k)}" fill="none" stroke="#000" stroke-width="{f(w)}" '
        f'stroke-linecap="round" stroke-linejoin="round"/>'
        for k, w in ((0.76, 2.8), (0.52, 2.4))
    )
    return cut_mask("UID-m", cuts) + solid_left(c, *C1, 4.2, "UID-m") + dotted_right(c, *C1, width=4.2, gap=6.4)


def v_ripple_approach(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    """Ripple and Approach together: chevrons arrive from the left and their impact rings through the solid half."""
    c = "currentColor" if mono else p["brand"]
    cy = C2[1] + (32 - 4) * C2[2]
    cuts = "".join(
        f'<path d="{scaled_left_edge(C2[0] + 1, cy, k, C2)}" fill="none" stroke="#000" stroke-width="{f(w)}" '
        f'stroke-linecap="round" stroke-linejoin="round"/>'
        for k, w in ((0.74, 2.5), (0.48, 2.1))
    )
    return (
        cut_mask("UID-m", cuts)
        + chevrons(c, [(0.8, 0.28), (6.0, 0.55), (11.2, 1.0)], 30.5, 4.6, 6.6, 2.9)
        + solid_left(c, *C2, 3.8, "UID-m")
        + dotted_right(c, *C2, width=3.8, gap=5.8)
    )


def v_line(p: dict[str, str], *, mono: bool = False, fav: bool = False) -> str:
    """The stroke reading of "solid": a solid left edge, dotted right edge, chevrons approaching."""
    c = "currentColor" if mono else p["brand"]
    return (
        chevrons(c, [(0.8, 0.28), (6.0, 0.55), (11.2, 1.0)], 30.5, 4.6, 6.6, 2.9)
        + f'<path d="{GS.shield_d(*C2, half="left")}" fill="none" {paint("stroke", c)} stroke-width="5.2" '
        f'stroke-linecap="round" stroke-linejoin="round"/>' + dotted_right(c, *C2, width=4.0, gap=5.8)
    )


VARIANTS = {
    "inbound": (
        "Inbound",
        v_inbound,
        "Two chevrons cut into the solid half point into the shield: fast things go in and stop there.",
    ),
    "approach": (
        "Approach",
        v_approach,
        "Chevrons fly in from the left, fading with distance, and stop at the solid side.",
    ),
    "ripple": ("Ripple, reset", v_ripple, "The impact runs through the solid half as rings, from the edge inwards."),
    "ripple-approach": (
        "Ripple + Approach",
        v_ripple_approach,
        "Both together: chevrons arrive from the left and their impact rings through the solid half.",
    ),
    "line": (
        "Line",
        v_line,
        "The other reading of “solid”: a solid edge on the left, dotted on the right, chevrons approaching.",
    ),
}


# ============================================================================ favicons (16 and 32 px drawings)
# Full-size shield on the 64-unit canvas; no thin lines at 16 px, dots only from 32 px.

FB = (32.0, 3.0, 1.06)


def fav(key: str, p: dict[str, str], size: int) -> str:
    c = p["brand"]
    small = size <= 16
    right = faint_right(c, *FB, 6.0) if small else dotted_right(c, *FB, width=5.6, gap=8.6)
    if key == "inbound":
        xs = (18.5,) if small else (14.5, 23.0)
        sw = 6.0 if small else 4.6
        cuts = "".join(
            f'<path d="{chevron(x0, 31, 7.5 if small else 6.6, 10 if small else 9)}" fill="none" stroke="#000" '
            f'stroke-width="{f(sw)}" stroke-linecap="round" stroke-linejoin="round"/>'
            for x0 in xs
        )
        return cut_mask("UID-m", cuts) + solid_left(c, *FB, 5.6, "UID-m") + right
    if key == "approach":
        cs = (24.0, 3.5, 0.86) if small else C2
        chev = [(5.0, 1.0)] if small else [(2.0, 0.45), (9.5, 1.0)]
        return (
            chevrons(c, chev, 31, 6.4 if small else 5.6, 9.5 if small else 8.0, 5.6 if small else 4.2)
            + solid_left(c, (40.0 if small else cs[0]), cs[1], cs[2], 5.6)
            + (faint_right(c, 40.0, cs[1], cs[2], 6.0) if small else dotted_right(c, *cs, width=5.4, gap=8.2))
        )
    if key in ("ripple", "ripple-approach"):
        rings = ((0.62, 4.6),) if small else ((0.74, 3.8), (0.46, 3.2))
        cuts = "".join(
            f'<path d="{scaled_left_edge(33.0, 32.0, k)}" fill="none" stroke="#000" stroke-width="{f(w)}" '
            f'stroke-linecap="round" stroke-linejoin="round"/>'
            for k, w in rings
        )
        return cut_mask("UID-m", cuts) + solid_left(c, *FB, 5.6, "UID-m") + right
    # line
    return (
        f'<path d="{GS.shield_d(*FB, half="left")}" fill="none" {paint("stroke", c)} stroke-width="{f(8 if small else 7)}" '
        f'stroke-linecap="round" stroke-linejoin="round"/>' + right
    )


# ============================================================================ output


def write_files() -> None:
    for key, (title, fn, _idea) in VARIANTS.items():
        vkey = f"glance-shield-2d-{key}"
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
        }
        for size in (16, 32):
            for suf, p in (("", PAL.light), ("-dark", PAL.dark)):
                files[f"favicon-{size}{suf}.svg"] = G.uniq(G.svg(fav(key, p, size), 64, 64), f"f{size}")
        for name, markup in files.items():
            G.check(markup, f"2d/{key}/{name}")
            (d / name).write_text(markup + "\n", encoding="utf-8")


if __name__ == "__main__":
    write_files()
    print(f"{len(VARIANTS)} round-2d variants written to", OUT)
