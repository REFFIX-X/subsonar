"""Monokai Pro Dark visual identity for subsonar.

Single source of truth for the colour palette, the ASCII-art logo and every
severity/category → colour mapping used by the Textual TUI, the console
renderer and the Streamlit dashboard.
"""

from __future__ import annotations

from typing import Final

# --------------------------------------------------------------------------- #
# Palette
# --------------------------------------------------------------------------- #


class Palette:
    """Monokai Pro Dark palette — hex codes used verbatim across all UIs."""

    BACKGROUND: Final = "#2d2a2e"    # Dark Charcoal / Charcoal Black
    SURFACE: Final = "#221f22"       # deeper charcoal for nested panels
    SURFACE_ALT: Final = "#403e41"   # selection, borders, scrollbars
    TEXT: Final = "#fcfcfa"          # Crisp White
    MUTED: Final = "#727072"         # Muted Gray
    PINK: Final = "#ff61ef"          # accent 1 — functions / keywords
    GREEN: Final = "#a9dc76"         # accent 2 — strings / success
    ORANGE: Final = "#fc9867"        # accent 3 — numbers / stats
    YELLOW: Final = "#ffd866"        # accent 4 — classes / URIs
    CYAN: Final = "#78dce8"          # accent 5 — operators / IPs
    RED: Final = "#ff6188"           # errors / critical

    #: Severity & category → colour.  Shared by every interface.
    SEVERITY: Final[dict[str, str]] = {
        "trace": MUTED,
        "debug": MUTED,
        "info": TEXT,
        "notice": CYAN,
        "success": GREEN,
        "warn": ORANGE,
        "warning": ORANGE,
        "error": RED,
        "critical": RED,
        "dns": CYAN,
        "osint": PINK,
        "port": YELLOW,
        "http": GREEN,
        "probe": GREEN,
        "filter": MUTED,
        "wildcard": ORANGE,
        "stat": ORANGE,
        "phase": PINK,
        "target": YELLOW,
        "wordlist": CYAN,
        "done": GREEN,
    }

    #: Category → short glyph tag rendered in the live console.
    GLYPH: Final[dict[str, str]] = {
        "phase": "▸",
        "target": "◈",
        "wildcard": "⁂",
        "osint": "☁",
        "wordlist": "≡",
        "dns": "⌁",
        "port": "⇄",
        "http": "↯",
        "probe": "✔",
        "filter": "⊘",
        "stat": "∑",
        "error": "✖",
        "warn": "!",
        "done": "★",
        "info": "·",
    }

    @classmethod
    def for_event(cls, severity: str, category: str = "") -> str:
        """Resolve the hex colour for an event, preferring its category."""
        if category and category in cls.SEVERITY:
            return cls.SEVERITY[category]
        return cls.SEVERITY.get(severity, cls.TEXT)


# --------------------------------------------------------------------------- #
# ASCII-art logo
# --------------------------------------------------------------------------- #

#: Wide radio-themed wordmark, used when the terminal is ≥ 80 columns.
LOGO_FULL: Final = r"""
   ███████╗██╗   ██╗██████╗ ███████╗ ██████╗ ███╗   ██╗ █████╗ ██████╗
   ██╔════╝██║   ██║██╔══██╗██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔══██╗
   ███████╗██║   ██║██████╔╝███████╗██║   ██║██╔██╗ ██║███████║██████╔╝
   ╚════██║██║   ██║██╔══██╗╚════██║██║   ██║██║╚██╗██║██╔══██║██╔══██╗
   ███████║╚██████╔╝██████╔╝███████║╚██████╔╝██║ ╚████║██║  ██║██║  ██║
   ╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝
"""

#: Narrow wordmark for small terminals / the web dashboard sidebar.
LOGO_COMPACT: Final = r"""
  ___ _   _ ___ ___  ___  _  _   _ ___
 / __| | | / __/ _ \/ _ \| \| | /_\ | _ \
 \__ \ |_| \__ \ (_) | (_) | .` |/ _ \|   /
 |___/\__,_|___/\___/ \___/|_|\_/_/ \_\_|_\
"""

#: Radar-ring motif rendered beside the compact logo.
SONAR_RINGS: Final = (
    "        .  *  .        ",
    "     .    ___    .     ",
    "   *    ,'   ',    *   ",
    "  .    /  ,-.  \\    .  ",
    "   *   | (   ) |   *   ",
    "  .    \\  `-'  /    .  ",
    "   *    ',___,'    *   ",
    "     .    ---    .     ",
    "        .  *  .        ",
)


def logo_block(*, compact: bool = False, width: int = 100) -> str:
    """Return the banner appropriate for the available width."""
    if compact or width < 80:
        return LOGO_COMPACT.strip("\n")
    return LOGO_FULL.strip("\n")


def banner_lines(width: int = 100) -> list[str]:
    """Logo lines followed by the strapline."""
    lines = logo_block(width=width).splitlines()
    lines.append("")
    lines.append("   » asynchronous subdomain & web-interface sonar «")
    lines.append("   » anonymous resolver pool · no Google · no Cloudflare «")
    return lines


# --------------------------------------------------------------------------- #
# ANSI helpers (used by the headless console renderer)
# --------------------------------------------------------------------------- #


def hex_to_rgb(value: str) -> tuple[int, int, int]:
    value = value.lstrip("#")
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def fg(hex_color: str) -> str:
    r, g, b = hex_to_rgb(hex_color)
    return f"\x1b[38;2;{r};{g};{b}m"


def bg(hex_color: str) -> str:
    r, g, b = hex_to_rgb(hex_color)
    return f"\x1b[48;2;{r};{g};{b}m"


RESET: Final = "\x1b[0m"
BOLD: Final = "\x1b[1m"
DIM: Final = "\x1b[2m"
