# Gaugery brand

<img src="static/icon.svg" width="96" alt="Gaugery icon">

**Gaugery** (an old English word for *the gauge-keeper's office*) keeps an eye on your
servers' gauges. Write it with a capital G in sentences, `gaugery` in code, paths and
container names. Never "GaugeRy", "Gauge-ry" or "GAUGERY" in running text.

## The mark

A ring gauge drawn as a **G**:

- **The arc** is the gauge's reading. It runs from the top right, around the left, to the
  right middle, which is also the curve of the G.
- **The faint track** is the unread part of the dial, so the mark still reads as a gauge.
- **The amber needle** points from the centre to the arc's end, and is also the bar of the G.

It's drawn on a 64 × 64 grid with a 19-unit ring radius and 6-unit strokes, which stays
legible at 16 px in a browser tab. The file is [`static/icon.svg`](static/icon.svg).

- Use the mark on its rounded dark tile, as in the file. Don't place the bare ring on light
  backgrounds.
- Keep clear space around the tile of at least a quarter of its width.
- Don't recolour, rotate, stretch or add effects. Don't separate the needle from the ring.

**Lockup:** the tile followed by the name in IBM Plex Sans SemiBold, with the gap equal to a
quarter of the tile's width and the type's cap height at about half the tile's height. In the
app, the headers and the sign-in page are the lockup.

## Colours

| Role | Hex | Use |
|---|---|---|
| Ink | `#0B1118` → `#1A2633` | The tile, as a top-to-bottom gradient from `#1A2633` to `#0B1118`; also the dark backgrounds |
| Teal | `#35D0BA` | Start of the reading arc; the app's default accent |
| Sky | `#4FA8FF` | End of the reading arc |
| Amber | `#F5B942` | The needle. Use it sparingly as the signature colour, never for large areas |
| Paper | `#F4F6F9` | Light backgrounds |

The status colours (ok, warning, critical) belong to the interface, not to the brand. Keep
them out of brand material.

## Type

**IBM Plex Sans** for everything, and **IBM Plex Mono** for numbers in tables and code. Both
ship with the app under the SIL Open Font License (`static/fonts/`). Headings are SemiBold
(600), text Regular (400), and labels Medium (500).

## Voice

Plain, calm and specific: say what's happening and what to do next. "/data is 92% full",
not "Storage threshold exceeded!".
