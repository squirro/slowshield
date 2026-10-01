"""Tiny server-side SVG charts: no JavaScript, no chart library, CSP-safe (colours come from CSS classes)."""

from __future__ import annotations

from datetime import UTC, datetime
from html import escape

from markupsafe import Markup


def _fmt_bucket(ts: int, step: int) -> str:
    dt = datetime.fromtimestamp(ts, UTC)
    return dt.strftime("%H:%M" if step < 86400 else "%b %d")


def sparkline(values: list[float], *, width: int = 120, height: int = 28, cls: str = "spark") -> Markup:
    if not values or max(values) <= 0:
        return Markup(
            f'<svg class="{cls} empty" viewBox="0 0 {width} {height}" width="{width}" height="{height}" aria-hidden="true">'
            f'<line x1="0" y1="{height - 1}" x2="{width}" y2="{height - 1}"/></svg>'
        )
    peak = max(values)
    n = len(values)
    dx = width / max(1, n - 1)
    pts = [(i * dx, height - 2 - (v / peak) * (height - 4)) for i, v in enumerate(values)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    area = f"0,{height} {line} {width:.1f},{height}"
    return Markup(
        f'<svg class="{cls}" viewBox="0 0 {width} {height}" width="{width}" height="{height}" aria-hidden="true">'
        f'<polygon class="area" points="{area}"/><polyline class="line" points="{line}"/></svg>'
    )


def stacked_bars(
    buckets: list[int],
    series: dict[str, dict[int, int]],
    *,
    step: int,
    order: list[str],
    labels: dict[str, str] | None = None,
    width: int = 900,
    height: int = 220,
    title: str = "",
) -> Markup:
    """Stacked column chart. Each series gets CSS class `s-<name>`; hovering a column shows a tooltip."""
    labels = labels or {}
    pad_l, pad_b, pad_t = 44, 22, 8
    plot_w, plot_h = width - pad_l - 4, height - pad_b - pad_t
    n = max(1, len(buckets))
    totals = [sum(series.get(s, {}).get(b, 0) for s in order) for b in buckets]
    peak = max(totals) if totals and max(totals) > 0 else 1
    bw = plot_w / n
    parts = [
        f'<svg class="chart" viewBox="0 0 {width} {height}" preserveAspectRatio="none" role="img" aria-label="{escape(title)}">'
    ]
    for frac in (0.25, 0.5, 0.75, 1.0):
        y = pad_t + plot_h - frac * plot_h
        parts.append(f'<line class="grid" x1="{pad_l}" y1="{y:.1f}" x2="{width - 4}" y2="{y:.1f}"/>')
        parts.append(
            f'<text class="axis" x="{pad_l - 6}" y="{y + 4:.1f}" text-anchor="end">{_short(peak * frac)}</text>'
        )
    label_every = max(1, n // 8)
    for i, b in enumerate(buckets):
        x = pad_l + i * bw
        y = pad_t + plot_h
        tip = [_fmt_bucket(b, step)]
        for s in order:
            v = series.get(s, {}).get(b, 0)
            if v <= 0:
                continue
            h = v / peak * plot_h
            y -= h
            parts.append(
                f'<rect class="s-{escape(s)}" x="{x + bw * 0.1:.1f}" y="{y:.1f}" width="{max(1.0, bw * 0.8):.1f}" height="{h:.1f}"/>'
            )
            tip.append(f"{labels.get(s, s)}: {v:,}")
        parts.append(
            f'<rect class="hover" x="{x:.1f}" y="{pad_t}" width="{bw:.1f}" height="{plot_h}"><title>{escape(chr(10).join(tip))}</title></rect>'
        )
        if i % label_every == 0:
            parts.append(
                f'<text class="axis" x="{x + bw / 2:.1f}" y="{height - 6}" text-anchor="middle">{_fmt_bucket(b, step)}</text>'
            )
    parts.append("</svg>")
    return Markup("".join(parts))


def hbar(value: float, peak: float, *, width: int = 160, height: int = 10, cls: str = "hbar") -> Markup:
    w = 0 if peak <= 0 else max(1.0, value / peak * width)
    return Markup(
        f'<svg class="{cls}" viewBox="0 0 {width} {height}" width="{width}" height="{height}" aria-hidden="true">'
        f'<rect class="track" width="{width}" height="{height}" rx="3"/><rect class="fill" width="{w:.1f}" height="{height}" rx="3"/></svg>'
    )


def _short(v: float) -> str:
    for unit, div in (("M", 1e6), ("k", 1e3)):
        if v >= div:
            return f"{v / div:.1f}{unit}".replace(".0", "")
    return f"{v:.0f}"
