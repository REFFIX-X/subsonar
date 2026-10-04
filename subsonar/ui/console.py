"""Headless console renderer — Rich-powered live log with live statistics.

This is the interface used when no TTY is available (CI, piping, the sandbox
self-test) and when ``--no-tui`` is passed.  It implements the same Monokai Pro
palette and the same granular live log as the Textual TUI.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core.config import ScanConfig
from ..core.engine import Finding, ScanEngine, ScanResult
from ..core.events import BUS, EventBus
from ..core.profiles import Profile, get_profile
from ..core.theme import Palette, banner_lines
from .render import progress_bar, rich_line, stat_pairs


def build_logo_panel(subtitle: str = "") -> Panel:
    text = Text()
    for index, line in enumerate(banner_lines(width=100)):
        style = Palette.PINK if index < 7 else Palette.MUTED
        text.append(line + "\n", style=style)
    if subtitle:
        text.append(subtitle, style=f"bold {Palette.CYAN}")
    return Panel(
        text,
        border_style=Palette.SURFACE_ALT,
        title=f"[{Palette.YELLOW}]subsonar[/{Palette.YELLOW}]",
        subtitle=f"[{Palette.MUTED}]anonymous DNS · Monokai Pro[/{Palette.MUTED}]",
    )


def stats_panel(snapshot: dict[str, Any]) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="left", style=Palette.MUTED, no_wrap=True)
    table.add_column(justify="right", no_wrap=True)
    pairs = stat_pairs(snapshot)
    half = (len(pairs) + 1) // 2
    left, right = pairs[:half], pairs[half:]
    for index in range(half):
        label, value, colour = left[index]
        table.add_row(label, Text(value, style=colour))
        if index < len(right):
            label2, value2, colour2 = right[index]
            table.add_row(label2, Text(value2, style=colour2))
    fraction = float(snapshot.get("progress") or 0.0)
    bar = Text()
    bar.append(progress_bar(fraction, 40), style=Palette.PINK)
    bar.append(f" {fraction * 100:5.1f}%", style=Palette.ORANGE)
    group = Group(table, bar)
    return Panel(
        group,
        title=f"[{Palette.YELLOW}]live statistics[/{Palette.YELLOW}]",
        border_style=Palette.SURFACE_ALT,
    )


def findings_table(findings: list[Finding], *, title: str = "web interfaces") -> Table:
    """Monokai-styled table. Rich emits the URL column as an OSC-8 hyperlink."""
    table = Table(
        title=f"[{Palette.PINK}]{title}[/{Palette.PINK}]",
        border_style=Palette.SURFACE_ALT,
        header_style=f"bold {Palette.YELLOW}",
        expand=True,
        show_lines=False,
    )
    table.add_column("#", justify="right", style=Palette.MUTED, width=3, no_wrap=True)
    table.add_column("Subdomain", style=Palette.CYAN, no_wrap=True, max_width=28, overflow="ellipsis")
    table.add_column("IP", style=Palette.GREEN, no_wrap=True, max_width=15, overflow="ellipsis")
    show_geo = any(finding.country_code for finding in findings)
    if show_geo:
        table.add_column("Geo", no_wrap=True, max_width=16, overflow="ellipsis")
    table.add_column("Port", justify="right", style=Palette.ORANGE, width=5, no_wrap=True)
    table.add_column("Code", justify="right", style=Palette.YELLOW, width=4, no_wrap=True)
    show_titles = any(finding.title for finding in findings)
    if show_titles:
        table.add_column("Title", style=Palette.TEXT, overflow="ellipsis", max_width=24)
    table.add_column("URL (clickable)", overflow="ellipsis", no_wrap=True)
    for index, finding in enumerate(findings, start=1):
        link = Text(finding.link, style=f"underline {Palette.YELLOW}")
        link.stylize(f"link {finding.link}")
        row = [str(index), finding.subdomain, finding.ip]
        if show_geo:
            geo = finding.geo_label
            if finding.as_org:
                geo = f"{geo} {finding.as_org[:10]}".strip()
            row.append(geo)
        row.extend(
            [
                str(finding.port),
                str(finding.status if finding.status is not None else "-"),
            ]
        )
        if show_titles:
            row.append(finding.title or "")
        row.append(link)
        table.add_row(*row)
    if not findings:
        filler = ["-"] * (5 + (1 if show_geo else 0) + (1 if show_titles else 0))
        table.add_row(*filler)
    return table


class ConsoleRenderer:
    """Streams the live log and statistics to a Rich console."""

    def __init__(
        self,
        *,
        bus: EventBus | None = None,
        console: Console | None = None,
        show_debug: bool = True,
        refresh: float = 8.0,
    ) -> None:
        self.bus = bus or BUS
        self.console = console or Console(
            highlight=False, soft_wrap=False, emoji=False
        )
        self.show_debug = show_debug
        self.refresh = refresh
        self._live: Live | None = None
        self._stats_task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()

    # -- rendering --------------------------------------------------------- #
    def _emit(self, markup: str) -> None:
        self.console.print(markup, highlight=False)

    def _should_show(self, event: Any) -> bool:
        if self.show_debug:
            return True
        if event.severity in ("trace", "debug"):
            return False
        return event.category not in ("filter",)

    async def _stats_loop(self) -> None:
        assert self._live is not None
        while not self._stop.is_set():
            self._live.update(stats_panel(self.bus.snapshot()), refresh=True)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.refresh)
            except asyncio.TimeoutError:
                continue

    # -- main -------------------------------------------------------------- #
    async def run(
        self,
        config: ScanConfig,
        profile: Profile | int | str | None = None,
        *,
        stop_event: asyncio.Event | None = None,
    ) -> ScanResult:
        prof = (
            profile
            if isinstance(profile, Profile)
            else get_profile(profile if profile is not None else config.profile_id)
        )
        self.console.print(build_logo_panel(f"target: {config.domain}   profile: {prof.id}. {prof.name}"))
        # Drop debug/trace events at the source when the caller does not want
        # them — they are the majority of the port phase (one per refused port)
        # and would otherwise be allocated and buffered for nothing.
        self.bus.set_verbosity("debug" if self.show_debug else "info")
        engine = ScanEngine(config, profile=prof, bus=self.bus)
        self._live = Live(
            stats_panel(self.bus.snapshot()),
            console=self.console,
            refresh_per_second=4,
            transient=True,
            vertical_overflow="visible",
        )
        self._live.start()
        self._stats_task = asyncio.create_task(self._stats_loop())
        task = asyncio.create_task(engine.run())
        try:
            # Consume events while the engine runs.
            while not task.done():
                for event in self.bus.drain(limit=500):
                    if event.category == "__eof__":
                        continue
                    if self._should_show(event):
                        self._live.console.print(rich_line(event), highlight=False)
                if stop_event is not None and stop_event.is_set():
                    engine.stop()
                await asyncio.sleep(0.12)
            result = task.result()
        finally:
            self._stop.set()
            if self._stats_task is not None:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await asyncio.wait_for(self._stats_task, timeout=2)
            self._live.stop()
        # Flush whatever remains in the buffer.
        for event in self.bus.drain(limit=10_000):
            if event.category == "__eof__":
                continue
            if self._should_show(event):
                self.console.print(rich_line(event), highlight=False)
        self.render_result(result)
        return result

    def render_result(self, result: ScanResult) -> None:
        self.console.print()
        summary = Table.grid(padding=(0, 2))
        summary.add_column(style=Palette.MUTED, justify="left")
        summary.add_column(style=Palette.ORANGE)
        for line in result.summary_lines():
            key, _, value = line.partition(":")
            summary.add_row(key.strip(), value.strip())
        if result.wildcard and result.wildcard.wildcard:
            summary.add_row(
                Text("wildcard DNS", style=Palette.RED),
                Text(", ".join(sorted(result.wildcard.ips)), style=Palette.RED),
            )
        self.console.print(
            Panel(
                summary,
                title=f"[{Palette.PINK}]scan summary[/{Palette.PINK}]",
                border_style=Palette.SURFACE_ALT,
            )
        )
        self.console.print(findings_table(result.findings))
        if result.findings:
            self.console.print(
                f"[{Palette.MUTED}]tip: URLs render as OSC-8 hyperlinks in modern "
                f"terminals — click to open the host browser.[/{Palette.MUTED}]"
            )


async def run_console(
    config: ScanConfig,
    profile: Profile | int | str | None = None,
    *,
    bus: EventBus | None = None,
    show_debug: bool = True,
    stop_event: asyncio.Event | None = None,
) -> ScanResult:
    """Run a scan in the headless console renderer."""
    renderer = ConsoleRenderer(bus=bus, show_debug=show_debug)
    return await renderer.run(config, profile, stop_event=stop_event)
