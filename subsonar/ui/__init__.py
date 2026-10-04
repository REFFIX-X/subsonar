"""subsonar user-interface package — Textual TUI, Streamlit dashboard, console.

:mod:`subsonar.ui.render` holds the palette-aware rendering helpers shared by
every interface.
"""

from .render import (
    GLYPHS,
    STAT_COLORS,
    STAT_LABELS,
    clickable,
    event_color,
    event_glyph,
    finding_line,
    findings_to_rows,
    progress_bar,
    rich_line,
    stat_pairs,
    summary_markup,
)

__all__ = [
    "GLYPHS",
    "STAT_COLORS",
    "STAT_LABELS",
    "clickable",
    "event_color",
    "event_glyph",
    "finding_line",
    "findings_to_rows",
    "progress_bar",
    "rich_line",
    "stat_pairs",
    "summary_markup",
]
