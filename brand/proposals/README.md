# SlowShield brand proposals, round 2: "Deflect, yet don't obstruct"

A shield that stops anything moving too fast but lets slow things pass. That is what SlowShield does to
packages: fresh releases and attacks are turned away at the edge; patient, verified versions pass calmly into
builds. Round 1 (Shell-Shield, Hourglass Gate, Quarantine Crate; teal, moss and amber) was rejected and removed.
Only the concept is used here, with no imagery or naming from any film or book. Everything is ownable by Squirro AG.

| Concept | Palette | Idea |
|---|---|---|
| **Glance** | Night Field: night ink + electric field blue | A field arc. The fast streak glances off; the slow dot has already walked through and rests inside. |
| **Parting** (recommended) | Graphite Prism: graphite + iridescent violet-to-rose shimmer | A shield made of field lines that part around the slow orb travelling through them. |
| **Dot Field** (the unexpected one) | Sand & Cobalt: warm sand paper + deep cobalt | A halftone shield made of packages. Impacts ripple through as rings of smaller dots; the patient package simply joins the grid. |
| **Slow S** | Mono & Signal Pink: black and white + one signal pink | The S of SlowShield is one field line. A streak bounces off its shoulder; the line opens for the pink dot. |

## Files per concept (`<concept>/`)

| File | Use |
|---|---|
| `mark.svg`, `mark-dark.svg`, `mark-mono.svg` | Mark for light and dark backgrounds; single colour (`currentColor`) |
| `favicon.svg`, `favicon-dark.svg` | Simplified cut for 16–32 px |
| `lockup-horizontal(-dark).svg`, `lockup-stacked(-dark).svg` | Mark + wordmark (+ tagline “Deflect, don't obstruct.”) |
| `social-preview.svg` | 1280×640 GitHub social preview / Open Graph image |
| `motion.html` | CSS-only motion study (fast deflects, slow passes); respects `prefers-reduced-motion` |
| `tokens.css` | Light and dark UI tokens incl. semantic status colours, `--ss-*` custom properties |

Regenerate everything with `python3 brand/proposals/generate.py`. Text and status colours are tuned by the
generator so they clear WCAG AA (4.5:1) on the surface, the page ground and their own badge tint (14% light,
22% dark). Decorative tokens (`accent`, `--ss-shimmer`) are never used for text.

The wordmarks are live text in the system UI stack (no web fonts, strict CSP intact); outline the chosen
wordmark before production.

## Recommendation

**Parting on Graphite Prism.** It is the only concept where the shield itself makes way: the field lines
bend around the slow orb instead of opening a gate. It has the most ownable silhouette, still reads at 16 px
(three lines and a dot), the mono version is just lines, and the iridescent stroke gives SlowShield a signature
no security brand uses while the graphite UI stays calm. **Slow S** is the strong second if a typographic
identity is preferred. Glance is the most literal but sits in the crowded blue security space; Dot Field is the
most surprising but weakest at favicon size.

## Review (2026-10-02)

Checked against the brief: all four express the shield idea, use no film or book names or imagery, avoid teal,
moss and amber as primary colours, and every text and status token clears 4.5:1 (lowest: Slow S, 4.60:1).
Two findings:

* **Parting:** the rose accent and the *tampered* status share a hue; in dark mode they are almost identical
  (`#ff8fc4` / `#ff7fbf`). If Parting is chosen, move tampered to burnt orange (`#a6470b` light, `#ff9e66` dark;
  4.84:1 and 5.45:1 on surface and badge).
* **16 px:** Slow S reads best; Parting keeps lines and dot but loses the shield outline; Glance and Dot Field
  blur at 16 px and are fine from 32 px.

Open decisions: the concept, the tagline ("Deflect, don't obstruct." or the earlier "Safety through patience."),
and whether *held* stays blue/violet or goes back to amber as a status colour only.
