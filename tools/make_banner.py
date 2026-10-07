"""Generate the Monokai Pro Dark ``subsonar`` banner used at the top of the README.

Run with the venv Python:  ``.venv/Scripts/python.exe tools/make_banner.py``
Writes ``assets/banner.png`` (reproducible from the committed source).
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets" / "banner.png"
FONTS = Path("C:/Windows/Fonts")

# Monokai Pro Dark (single source of truth: subsonar/core/theme.py)
BG = "#2d2a2e"
SURFACE_ALT = "#403e41"
TEXT = "#fcfcfa"
MUTED = "#727072"
PINK = "#ff61ef"
GREEN = "#a9dc76"
ORANGE = "#fc9867"
YELLOW = "#ffd866"
CYAN = "#78dce8"

W, H = 1600, 400


def _font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONTS / name), size)


def _radar(draw: ImageDraw.ImageDraw, cx: int, cy: int, rmax: int) -> None:
    for r in range(40, rmax + 1, 40):
        draw.ellipse((cx - r, cy - r, cx + r, cy + r), outline=SURFACE_ALT, width=2)
    draw.line((cx - rmax, cy, cx + rmax, cy), fill=SURFACE_ALT, width=2)
    draw.line((cx, cy - rmax, cx, cy + rmax), fill=SURFACE_ALT, width=2)


def _blip(draw: ImageDraw.ImageDraw, cx: int, cy: int, r: int, deg: int, colour: str, size: int = 9) -> None:
    theta = math.radians(deg)
    x = cx + r * math.cos(theta)
    y = cy - r * math.sin(theta)
    draw.ellipse((x - size / 2, y - size / 2, x + size / 2, y + size / 2), fill=colour)


def main() -> None:
    base = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(base)

    # Sweep wedge, drawn semi-transparent so the rings stay visible underneath.
    cx, cy, rmax = 250, 200, 180
    sweep = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    sweep_draw = ImageDraw.Draw(sweep)
    sweep_draw.pieslice(
        (cx - rmax, cy - rmax, cx + rmax, cy + rmax), -20, 40, fill=(120, 220, 232, 70)
    )
    base = Image.alpha_composite(base.convert("RGBA"), sweep).convert("RGB")
    draw = ImageDraw.Draw(base)

    _radar(draw, cx, cy, rmax)
    _blip(draw, cx, cy, 60, 25, GREEN)
    _blip(draw, cx, cy, 120, -60, ORANGE)
    _blip(draw, cx, cy, 150, -110, PINK)
    _blip(draw, cx, cy, 90, 70, YELLOW, size=7)
    draw.ellipse((cx - 5, cy - 5, cx + 5, cy + 5), fill=PINK)

    # Two-tone wordmark: "sub" white, "sonar" pink.
    word_font = _font("InconsolataGoNerdFont-Bold.ttf", 132)
    sub = "sub"
    sonar = "sonar"
    x = 520
    y = 78
    draw.text((x, y), sub, font=word_font, fill=TEXT)
    x += draw.textlength(sub, font=word_font)
    draw.text((x, y), sonar, font=word_font, fill=PINK)

    # Tagline + accent bar.
    tag_font = _font("CascadiaCode.ttf", 30)
    draw.text((526, 258), "asynchronous subdomain & web-interface sonar", font=tag_font, fill=CYAN)

    draw.rectangle((526, 340, 526 + 460, 344), fill=PINK)
    draw.rectangle((526 + 460 + 8, 340, 526 + 460 + 8 + 90, 344), fill=ORANGE)
    draw.rectangle((526 + 460 + 8 + 90 + 8, 340, 526 + 460 + 8 + 90 + 8 + 30, 344), fill=YELLOW)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    base.save(OUT)
    print(f"wrote {OUT} ({W}x{H})")


if __name__ == "__main__":
    main()
