"""Palette-aware rendering helpers shared by the TUI, dashboard and console."""

from __future__ import annotations

from typing import Any, Sequence

from ..core.engine import Finding, ScanResult
from ..core.events import ScanEvent
from ..core.theme import Palette

#: Statistic key → display label, in panel order.
STAT_LABELS: tuple[tuple[str, str], ...] = (
    ("phase", "PHASE"),
    ("elapsed", "ELAPSED"),
    ("candidates", "CANDIDATES"),
    ("dns_queries", "DNS QUERIES"),
    ("dns_resolved", "DNS RESOLVED"),
    ("dns_failed", "DNS FAILED"),
    ("dns_cache_hits", "DNS CACHE HITS"),
    ("ports_probed", "PORTS PROBED"),
    ("ports_open", "PORTS OPEN"),
    ("http_probes", "HTTP PROBES"),
    ("findings", "WEB FOUND"),
    ("filtered_no_web", "FILTERED"),
    ("wildcard_filtered", "WC FILTERED"),
    ("provider_skipped", "3RD-PARTY SKIP"),
    ("errors", "ERRORS"),
    ("timeouts", "TIMEOUTS"),
    ("rate", "RATE/s"),
)

STAT_COLORS: dict[str, str] = {
    "phase": Palette.PINK,
    "elapsed": Palette.YELLOW,
    "candidates": Palette.ORANGE,
    "dns_queries": Palette.CYAN,
    "dns_resolved": Palette.GREEN,
    "dns_failed": Palette.RED,
    "dns_cache_hits": Palette.GREEN,
    "ports_probed": Palette.ORANGE,
    "ports_open": Palette.YELLOW,
    "http_probes": Palette.GREEN,
    "findings": Palette.GREEN,
    "filtered_no_web": Palette.MUTED,
    "wildcard_filtered": Palette.ORANGE,
    "provider_skipped": Palette.CYAN,
    "errors": Palette.RED,
    "timeouts": Palette.ORANGE,
    "rate": Palette.CYAN,
}

#: Category → glyph, sourced from the theme so every UI agrees.
GLYPHS = Palette.GLYPH


def event_color(event: ScanEvent) -> str:
    return Palette.for_event(event.severity, event.category)


def event_glyph(event: ScanEvent) -> str:
    return GLYPHS.get(event.category) or GLYPHS.get(event.severity) or "·"


def rich_line(event: ScanEvent) -> str:
    """Complete Rich-markup line for the live scanning console."""
    from rich.markup import escape

    colour = event_color(event)
    clock = escape(event.clock)
    glyph = escape(event_glyph(event))
    tag = escape(f"{event.category or event.severity:<9}")
    target = ""
    if event.host:
        target = f" [bold {Palette.CYAN}]{escape(event.host)}"
        if event.port:
            target += f"[{Palette.ORANGE}]:{event.port}[bold {Palette.CYAN}]"
        target += f"[/bold {Palette.CYAN}]"
    return (
        f"[{Palette.MUTED}]{clock}[/{Palette.MUTED}] "
        f"[{colour}]{glyph} {tag}[/{colour}]{target} "
        f"[{colour}]{escape(event.message)}[/{colour}]"
    )


def stat_pairs(snapshot: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Return ``(label, value, colour)`` triples for the statistics panel."""
    out: list[tuple[str, str, str]] = []
    for key, label in STAT_LABELS:
        value = snapshot.get(key)
        if isinstance(value, float):
            rendered = f"{value:.1f}"
        elif isinstance(value, int):
            rendered = f"{value:,}"
        else:
            rendered = str(value)
        out.append((label, rendered, STAT_COLORS.get(key, Palette.TEXT)))
    return out


def progress_bar(fraction: float, width: int = 30) -> str:
    fraction = max(0.0, min(1.0, fraction))
    filled = int(round(fraction * width))
    return "█" * filled + "░" * (width - filled)


def clickable(finding: Finding) -> str:
    """Rich hyperlink markup — clickable in modern terminals."""
    from rich.markup import escape

    return (
        f"[link={finding.link}][{Palette.YELLOW} underline]{escape(finding.link)}"
        f"[/{Palette.YELLOW} underline][/link]"
    )


def finding_line(finding: Finding, index: int | None = None) -> str:
    """Compact one-line summary of a finding."""
    from rich.markup import escape

    prefix = f"{index:>4}. " if index is not None else ""
    status = finding.status or 0
    status_colour = (
        Palette.GREEN if status < 300 else Palette.YELLOW if status < 400 else Palette.ORANGE
    )
    return (
        f"[{Palette.MUTED}]{prefix}[/{Palette.MUTED}]"
        f"[bold {Palette.CYAN}]{escape(finding.subdomain)}[/bold {Palette.CYAN}]"
        f"[{Palette.ORANGE}]:{finding.port}[/{Palette.ORANGE}] "
        f"[{status_colour}]{finding.status or '-'}[/{status_colour}] "
        f"[{Palette.MUTED}]{escape(finding.ip)}[/{Palette.MUTED}]"
        f"{(f' [{Palette.GREEN}]{finding.flag or finding.country_code}[/{Palette.GREEN}]' if finding.country_code else '')} "
        f"[{Palette.TEXT}]{escape((finding.title or 'no title')[:56])}[/{Palette.TEXT}] "
        f"[link={finding.link}][{Palette.YELLOW}]{escape(finding.link)}"
        f"[/{Palette.YELLOW}][/link]"
    )


def summary_markup(result: ScanResult) -> str:
    lines = []
    for line in result.summary_lines():
        key, _, value = line.partition(":")
        lines.append(
            f"[{Palette.MUTED}]{key.strip():<18}[/{Palette.MUTED}]"
            f"[{Palette.ORANGE}]{value.strip()}[/{Palette.ORANGE}]"
        )
    return "\n".join(lines)


def findings_to_rows(findings: Sequence[Finding]) -> list[list[str]]:
    rows: list[list[str]] = []
    for finding in findings:
        rows.append(
            [
                finding.subdomain,
                finding.ip,
                str(finding.port),
                str(finding.status if finding.status is not None else "-"),
                (finding.title or "")[:70],
                finding.url,
            ]
        )
    return rows
