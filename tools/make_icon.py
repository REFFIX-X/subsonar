"""Generate the square subsonar app icon — the reticle + radar-graph mark.

Run with the venv Python:  ``.venv/Scripts/python.exe tools/make_icon.py``
Writes ``assets/icon.png`` (Monokai dark) and ``assets/icon-light.png``.  Both
are 512x512 rounded tiles with transparent corners, usable as an app icon or the
GitHub "Social preview" image.
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
SIZE = 512
SS = 4  # supersample factor for smooth edges

DARK = {
    "bg": "#2d2a2e", "ring": "#403e41", "pink": "#ff61ef",
    "green": "#a9dc76", "orange": "#fc9867", "yellow": "#ffd866", "cyan": "#78dce8",
}
LIGHT = {
    "bg": "#f7f7f5", "ring": "#d7d5d3", "pink": "#e040cf",
    "green": "#5f9e2f", "orange": "#e0703f", "yellow": "#d9a800", "cyan": "#2aa6bf",
}


def _rgb(hex_colour: str) -> tuple[int, int, int]:
    return tuple(int(hex_colour[i : i + 2], 16) for i in (1, 3, 5))  # type: ignore[return-value]


def draw_icon(theme: dict[str, str], out: Path) -> None:
    s = SIZE * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Rounded-square tile (transparent corners).
    draw.rounded_rectangle((0, 0, s - 1, s - 1), radius=int(0.22 * s), fill=theme["bg"])

    cx = cy = s // 2
    rings = (0.13, 0.26, 0.39)
    r_out = int(rings[-1] * s)

    # Radar sweep wedge, blended over the tile.
    sweep = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    ImageDraw.Draw(sweep).pieslice(
        (cx - r_out, cy - r_out, cx + r_out, cy + r_out), -28, 32,
        fill=_rgb(theme["cyan"]) + (72,),
    )
    img = Image.alpha_composite(img, sweep)
    draw = ImageDraw.Draw(img)

    # Reticle: concentric rings.
    width = max(2, int(0.011 * s))
    for frac in rings:
        r = int(frac * s)
        draw.ellipse((cx - r, cy - r, cx + r, cy + r), outline=theme["ring"], width=width)

    # Crosshair.
    draw.line((cx - r_out, cy, cx + r_out, cy), fill=theme["ring"], width=width)
    draw.line((cx, cy - r_out, cx, cy + r_out), fill=theme["ring"], width=width)

    # Contact blips on the rings.
    dot = int(0.019 * s)
    for frac, deg, colour in (
        (0.26, 25, theme["green"]),
        (0.39, -60, theme["orange"]),
        (0.39, -112, theme["pink"]),
        (0.19, 72, theme["yellow"]),
    ):
        r = frac * s
        theta = math.radians(deg)
        x = cx + r * math.cos(theta)
        y = cy - r * math.sin(theta)
        draw.ellipse((x - dot, y - dot, x + dot, y + dot), fill=colour)

    # Centre emitter.
    cdot = int(0.027 * s)
    draw.ellipse((cx - cdot, cy - cdot, cx + cdot, cy + cdot), fill=theme["pink"])

    img.resize((SIZE, SIZE), Image.LANCZOS).save(out)
    print(f"wrote {out} ({SIZE}x{SIZE})")


if __name__ == "__main__":
    (ROOT / "assets").mkdir(parents=True, exist_ok=True)
    draw_icon(DARK, ROOT / "assets" / "icon.png")
    draw_icon(LIGHT, ROOT / "assets" / "icon-light.png")
