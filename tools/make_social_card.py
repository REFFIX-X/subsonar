"""Generate the 1280x640 GitHub social-preview card.

Run with the venv Python:  ``.venv/Scripts/python.exe tools/make_social_card.py``
Writes ``assets/social-card.png`` — the reticle mark on the left, the subsonar
wordmark on the right, in the Monokai Pro Dark palette.  GitHub's social preview
box is 2:1, so this fills it edge to edge (unlike the square icon).
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets" / "social-card.png"
FONTS = Path("C:/Windows/Fonts")

W, H = 1280, 640

BG = "#2d2a2e"
RING = "#403e41"
TEXT = "#fcfcfa"
PINK = "#ff61ef"
CYAN = "#78dce8"
GREEN = "#a9dc76"
ORANGE = "#fc9867"
YELLOW = "#ffd866"


def _rgb(hex_colour: str) -> tuple[int, int, int]:
    return tuple(int(hex_colour[i : i + 2], 16) for i in (1, 3, 5))  # type: ignore[return-value]


def _reticle(cx: int, cy: int, r_out: int) -> Image.Image:
    """The radar/reticle mark as a transparent RGBA layer."""
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)

    sweep = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(sweep).pieslice(
        (cx - r_out, cy - r_out, cx + r_out, cy + r_out), -28, 32,
        fill=_rgb(CYAN) + (64,),
    )
    layer = Image.alpha_composite(layer, sweep)
    draw = ImageDraw.Draw(layer)

    width = max(2, int(r_out * 0.020))
    for frac in (0.34, 0.67, 1.0):
        r = int(frac * r_out)
        draw.ellipse((cx - r, cy - r, cx + r, cy + r), outline=RING, width=width)
    draw.line((cx - r_out, cy, cx + r_out, cy), fill=RING, width=width)
    draw.line((cx, cy - r_out, cx, cy + r_out), fill=RING, width=width)

    dot = int(r_out * 0.042)
    for frac, deg, colour in (
        (0.34, 25, GREEN),
        (0.67, -60, ORANGE),
        (1.0, -112, PINK),
        (0.5, 72, YELLOW),
    ):
        r = frac * r_out
        theta = math.radians(deg)
        x = cx + r * math.cos(theta)
        y = cy - r * math.sin(theta)
        draw.ellipse((x - dot, y - dot, x + dot, y + dot), fill=colour)

    cdot = int(r_out * 0.058)
    draw.ellipse((cx - cdot, cy - cdot, cx + cdot, cy + cdot), fill=PINK)
    return layer


def main() -> None:
    img = Image.new("RGBA", (W, H), BG)
    img = Image.alpha_composite(img, _reticle(cx=300, cy=H // 2, r_out=214))
    draw = ImageDraw.Draw(img)

    # Divider between mark and wordmark.
    draw.line((572, 150, 572, H - 150), fill=RING, width=2)

    word_font = ImageFont.truetype(str(FONTS / "InconsolataGoNerdFont-Bold.ttf"), 116)
    x, y = 640, 194
    draw.text((x, y), "sub", font=word_font, fill=TEXT)
    x += draw.textlength("sub", font=word_font)
    draw.text((x, y), "sonar", font=word_font, fill=PINK)

    tag_font = ImageFont.truetype(str(FONTS / "CascadiaCode.ttf"), 22)
    draw.text((644, 352), "asynchronous subdomain & web-interface sonar", font=tag_font, fill=CYAN)

    bx, by = 644, 432
    draw.rectangle((bx, by, bx + 360, by + 5), fill=PINK)
    draw.rectangle((bx + 368, by, bx + 448, by + 5), fill=ORANGE)
    draw.rectangle((bx + 456, by, bx + 484, by + 5), fill=YELLOW)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    img.convert("RGB").save(OUT)
    print(f"wrote {OUT} ({W}x{H})")


if __name__ == "__main__":
    main()
