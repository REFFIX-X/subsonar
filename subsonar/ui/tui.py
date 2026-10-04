"""Textual Terminal User Interface — Monokai Pro Dark.

Layout
------
``┌ subsonar ─────────────────────── profile · target · elapsed ┐``
``│ ASCII logo + live progress bar                              │``
``├ statistics ──────────────┬ live scanning log ───────────────┤``
``│ DNS / PORT / HTTP / FIND │ granular event stream            │``
``├ findings ────────────────┴──────────────────────────────────┤``
``│ clickable http(s)://domain:port in the URL column           │``
``└ F1 help · F2 open URL · F3 export · F4 filter · F5 stop ────┘``
"""

from __future__ import annotations

import webbrowser
from pathlib import Path
from typing import Any

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    ListItem,
    ListView,
    ProgressBar,
    RichLog,
    Static,
    Switch,
)

from ..core.config import PORT_MATRIX, PORT_MATRIX_EXTENDED, ScanConfig
from ..core.engine import Finding, ScanResult
from ..core.events import BUS, EventBus
from ..core.profiles import PROFILES, Profile, get_profile
from ..core.theme import Palette, logo_block
from ..reporters import write_reports
from ..runner import ScanRunner
from .render import finding_line, progress_bar, rich_line, stat_pairs

THEME_CSS = f"""
Screen {{
    background: {Palette.BACKGROUND};
    color: {Palette.TEXT};
}}
Header {{
    background: {Palette.SURFACE};
    color: {Palette.PINK};
}}
Footer {{
    background: {Palette.SURFACE};
    color: {Palette.MUTED};
}}
Footer > .footer--key {{
    background: {Palette.SURFACE_ALT};
    color: {Palette.YELLOW};
}}
Footer > .footer--description {{
    color: {Palette.MUTED};
}}
#logo {{
    color: {Palette.PINK};
    text-style: bold;
    padding: 0 1;
    width: 1fr;
}}
#tagline {{
    color: {Palette.MUTED};
    padding: 0 1;
}}
#statusline {{
    color: {Palette.CYAN};
    padding: 0 1;
}}
.panel {{
    border: round {Palette.SURFACE_ALT};
    background: {Palette.SURFACE};
    padding: 0 1;
}}
.panel-title {{
    color: {Palette.YELLOW};
    text-style: bold;
}}
#stats-panel {{
    width: 42;
    min-width: 34;
    border: round {Palette.SURFACE_ALT};
    background: {Palette.SURFACE};
    padding: 0 1;
}}
#log-panel {{
    width: 1fr;
    border: round {Palette.SURFACE_ALT};
    background: {Palette.SURFACE};
    padding: 0 1;
}}
#progress {{
    width: 1fr;
    padding: 0 1;
}}
ProgressBar > .bar--bar {{
    color: {Palette.PINK};
    background: {Palette.SURFACE_ALT};
}}
ProgressBar > .bar--complete {{
    color: {Palette.GREEN};
}}
#findings-table {{
    height: 1fr;
    background: {Palette.SURFACE};
}}
DataTable > .datatable--header {{
    background: {Palette.SURFACE_ALT};
    color: {Palette.YELLOW};
    text-style: bold;
}}
DataTable > .datatable--cursor {{
    background: {Palette.PINK};
    color: {Palette.BACKGROUND};
}}
DataTable > .datatable--hover {{
    background: {Palette.SURFACE_ALT};
}}
#url-detail {{
    height: auto;
    max-height: 8;
    padding: 0 1;
    border: round {Palette.SURFACE_ALT};
    background: {Palette.SURFACE};
}}
#setup-form {{
    width: 1fr;
    padding: 1 2;
    border: round {Palette.SURFACE_ALT};
    background: {Palette.SURFACE};
}}
#profile-list {{
    height: 1fr;
    border: round {Palette.SURFACE_ALT};
    background: {Palette.SURFACE};
}}
ListView > ListItem.--highlight {{
    background: {Palette.PINK};
    color: {Palette.BACKGROUND};
}}
Input {{
    background: {Palette.BACKGROUND};
    color: {Palette.CYAN};
    border: tall {Palette.SURFACE_ALT};
}}
Input:focus {{
    border: tall {Palette.PINK};
}}
Button {{
    background: {Palette.SURFACE_ALT};
    color: {Palette.TEXT};
}}
Button.-primary {{
    background: {Palette.PINK};
    color: {Palette.BACKGROUND};
    text-style: bold;
}}
Switch > .switch--slider {{
    color: {Palette.PINK};
}}
TabbedContent ContentSwitcher {{
    background: {Palette.SURFACE};
}}
Tabs {{
    background: {Palette.SURFACE};
}}
Tab {{
    color: {Palette.MUTED};
}}
Tab.-active {{
    color: {Palette.PINK};
}}
#summary-text {{
    color: {Palette.TEXT};
    padding: 0 1;
}}
#hint {{
    color: {Palette.MUTED};
    padding: 0 1;
}}
"""


def open_in_browser(url: str) -> bool:
    """Open *url* in the host's default browser."""
    try:
        return webbrowser.open(url, new=2, autoraise=True)
    except Exception:
        return False


class BannerWidget(Static):
    """ASCII-art logo block."""

    def __init__(self, *, compact: bool = False, **kwargs: Any) -> None:
        super().__init__(logo_block(compact=compact), **kwargs)


class StatsPanel(VerticalScroll):
    """Live statistics with Monokai-coloured counters and a progress bar."""

    def compose(self) -> ComposeResult:
        yield Static("live statistics", classes="panel-title", id="stats-title")
        yield Static("", id="stats-body")
        yield Static("", id="progress-bar")
        yield ProgressBar(total=100, show_eta=False, id="progress")

    def refresh_stats(self, snapshot: dict[str, Any]) -> None:
        lines = []
        for label, value, colour in stat_pairs(snapshot):
            lines.append(f"[{Palette.MUTED}]{label:<14}[/{Palette.MUTED}] [{colour}]{value}[/{colour}]")
        body = self.query("#stats-body")
        if body:
            body.first(Static).update("\n".join(lines))
        bar = self.query("#progress-bar")
        if bar:
            fraction = float(snapshot.get("progress") or 0.0)
            bar.first(Static).update(
                f"[{Palette.MUTED}]{progress_bar(fraction)}[/{Palette.MUTED}] "
                f"[{Palette.ORANGE}]{fraction * 100:5.1f}%[/{Palette.ORANGE}] "
                f"[{Palette.MUTED}]dns[/{Palette.MUTED}]"
            )
        progress = self.query("#progress")
        if progress:
            widget = progress.first(ProgressBar)
            widget.update(progress=min(100.0, float(snapshot.get("progress") or 0.0) * 100))


class SetupScreen(Container):
    """Target + profile selection screen."""

    def compose(self) -> ComposeResult:
        with Vertical(id="setup-form"):
            yield Static(
                f"[{Palette.YELLOW}]target domain[/{Palette.YELLOW}]  "
                f"[{Palette.MUTED}](e.g. example.com — scheme and path are stripped)[/{Palette.MUTED}]"
            )
            yield Input(placeholder="example.com", id="domain-input")
            yield Static(
                f"[{Palette.YELLOW}]scan profile[/{Palette.YELLOW}]  "
                f"[{Palette.MUTED}]↑/↓ to choose, Enter to start[/{Palette.MUTED}]"
            )
            yield ListView(id="profile-list")
            with Horizontal():
                yield Static(f"[{Palette.MUTED}]offline (cache only)[/{Palette.MUTED}] ", classes="panel-title")
                yield Switch(value=False, id="offline-switch")
                yield Static(f"[{Palette.MUTED}]   quiet log[/{Palette.MUTED}] ", classes="panel-title")
                yield Switch(value=False, id="quiet-switch")
            with Horizontal():
                yield Button("Start scan", variant="primary", id="start-button")
                yield Button("Quit", id="quit-button")


class ScanScreen(Container):
    """Main scanning dashboard with the live console and findings table."""

    def compose(self) -> ComposeResult:
        with Vertical():
            with Horizontal(id="top"):
                yield BannerWidget(id="logo")
                with Vertical(id="stats-panel"):
                    yield StatsPanel()
            with Horizontal(id="mid"):
                with Vertical(id="log-panel"):
                    yield Static("live scanning log", classes="panel-title")
                    yield RichLog(
                        id="live-log",
                        highlight=False,
                        markup=True,
                        wrap=True,
                        max_lines=8000,
                        auto_scroll=True,
                    )
            with Vertical(id="bottom"):
                yield Static("findings — click a URL cell to open it", classes="panel-title")
                yield DataTable(id="findings-table", zebra_stripes=True, cursor_type="row")
                yield Static("", id="url-detail")
                yield Static(
                    f"[{Palette.MUTED}]Enter/F2 opens the selected URL · F3 exports · "
                    f"F4 toggles the debug filter · F5 stops the scan[/{Palette.MUTED}]",
                    id="hint",
                )


class SubsonarApp(App):
    """The subsonar Textual application."""

    CSS = THEME_CSS
    TITLE = "subsonar"
    SUB_TITLE = "asynchronous subdomain & web-interface sonar"

    BINDINGS = [
        Binding("f1", "help", "Help"),
        Binding("f2", "open_url", "Open URL"),
        Binding("f3", "export", "Export"),
        Binding("f4", "toggle_filter", "Log filter"),
        Binding("f5", "stop", "Stop"),
        Binding("f9", "new_scan", "New scan"),
        Binding("ctrl+q", "quit", "Quit"),
    ]

    phase: reactive[str] = reactive("setup")
    findings_count: reactive[int] = reactive(0)

    def __init__(
        self,
        domain: str | None = None,
        profile_id: int = 3,
        *,
        bus: EventBus | None = None,
        auto_start: bool = False,
        offline: bool = False,
        quiet: bool = False,
    ) -> None:
        super().__init__()
        self.bus = bus or BUS
        self.initial_domain = domain or ""
        self.initial_profile = profile_id
        self.auto_start = auto_start
        self.offline = offline
        self.quiet = quiet
        self.runner: ScanRunner | None = None
        self.selected_profile: Profile = get_profile(profile_id)
        self._log_filter_debug = not quiet
        self._exported: list[Path] = []
        self._last_snapshot: dict[str, Any] = {}
        self._drain_cursor = 0
        #: Column key of the clickable URL column (set by :meth:`_prepare_table`).
        self._url_column: Any = None

    # -- composition ------------------------------------------------------- #
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield SetupScreen(id="setup-screen")
        yield ScanScreen(id="scan-screen")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#scan-screen").display = False
        profile_list = self.query_one("#profile-list", ListView)
        for profile in PROFILES:
            profile_list.append(
                ListItem(
                    Static(
                        f"[bold {Palette.PINK}]{profile.id}. {profile.name}"
                        f"[/bold {Palette.PINK}]  "
                        f"[{Palette.MUTED}]wordlist={profile.wordlist_size or 0} · "
                        f"ports={len(profile.port_numbers())} · "
                        f"{profile.packet_profile}[/{Palette.MUTED}]\n"
                        f"[{Palette.TEXT}]{profile.description}[/{Palette.TEXT}]"
                    )
                )
            )
        profile_list.index = max(0, min(len(PROFILES) - 1, self.initial_profile - 1))
        domain_input = self.query_one("#domain-input", Input)
        if self.initial_domain:
            domain_input.value = self.initial_domain
        self.query_one("#offline-switch", Switch).value = self.offline
        self.query_one("#quiet-switch", Switch).value = self.quiet
        self._prepare_table()
        self.set_interval(0.15, self._tick)
        self._banner_log()
        if self.auto_start and self.initial_domain:
            self.call_after_refresh(self._start_scan)

    def _banner_log(self) -> None:
        log = self.query_one("#live-log", RichLog)
        for line in logo_block(width=200).splitlines():
            log.write(f"[{Palette.PINK}]{line}[/{Palette.PINK}]")
        log.write(
            f"[{Palette.MUTED}]asynchronous subdomain & web-interface sonar · "
            f"anonymous resolver pool ({len(self.bus.stats.sources) or 18} nodes, "
            f"no Google · no Cloudflare) · Top-{len(PORT_MATRIX)} core / "
            f"{len(PORT_MATRIX_EXTENDED)} extended ports[/{Palette.MUTED}]"
        )

    def _prepare_table(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.clear(columns=True)
        table.add_column("#", width=4)
        table.add_column("Subdomain", width=28)
        table.add_column("Resolved IP", width=16)
        table.add_column("Geo", width=14)
        table.add_column("Port", width=6)
        table.add_column("Code", width=5)
        table.add_column("Conf", width=6)
        table.add_column("Kind", width=12)
        table.add_column("Title", width=24)
        # Keep the returned key: the URL column is resolved by key, never by a
        # hard-coded index (which silently points elsewhere once a column is
        # added, and by label lookup, which Textual does not support).
        self._url_column = table.add_column("URL", width=38)

    def _url_column_index(self) -> int:
        """Index of the URL column, or ``-1`` when it cannot be resolved."""
        key = self._url_column
        if key is None:
            return -1
        try:
            return self.query_one("#findings-table", DataTable).get_column_index(key)
        except Exception:  # pragma: no cover - widget/column not mounted yet
            return -1

    # -- setup interactions ------------------------------------------------ #
    @on(ListView.Highlighted, "#profile-list")
    def _profile_highlighted(self, event: ListView.Highlighted) -> None:
        index = self.query_one("#profile-list", ListView).index
        if index is None:
            return
        index = max(0, min(len(PROFILES) - 1, int(index)))
        self.selected_profile = PROFILES[index]

    @on(Input.Submitted, "#domain-input")
    def _domain_submitted(self, _: Input.Submitted) -> None:
        self._start_scan()

    @on(Button.Pressed, "#start-button")
    def _start_pressed(self, _: Button.Pressed) -> None:
        self._start_scan()

    @on(Button.Pressed, "#quit-button")
    def _quit_pressed(self, _: Button.Pressed) -> None:
        self.exit()

    def _start_scan(self) -> None:
        if self.runner is not None and self.runner.running:
            self.notify("a scan is already running", severity="warning")
            return
        domain = self.query_one("#domain-input", Input).value.strip()
        if not domain or "." not in domain:
            self.notify("enter a valid target domain, e.g. example.com", severity="error")
            return
        try:
            config = ScanConfig(
                domain=domain,
                profile_id=self.selected_profile.id,
                offline=self.query_one("#offline-switch", Switch).value,
            )
        except ValueError as exc:
            self.notify(str(exc), severity="error")
            return
        self._log_filter_debug = not self.query_one("#quiet-switch", Switch).value
        self.query_one("#setup-screen").display = False
        self.query_one("#scan-screen").display = True
        self._prepare_table()
        self._exported.clear()
        self.bus.clear()
        log = self.query_one("#live-log", RichLog)
        log.clear()
        self._banner_log()
        self.phase = "running"
        self.runner = ScanRunner(config, profile=self.selected_profile, bus=self.bus)
        self.runner.start()
        self.notify(
            f"scan started — {self.selected_profile.name} on {config.domain}",
            severity="information",
        )

    # -- live ticking ------------------------------------------------------ #
    def _tick(self) -> None:
        if self.runner is None:
            return
        snapshot = self.bus.snapshot()
        self._last_snapshot = snapshot
        if self.query_one("#scan-screen").display:
            try:
                self.query_one(StatsPanel).refresh_stats(snapshot)
            except Exception:  # pragma: no cover - widget not mounted yet
                pass
            self._drain_events()
        if self.runner.finished and self.phase == "running":
            self.phase = "finished"
            self._on_scan_finished()

    def _drain_events(self) -> None:
        events = self.bus.drain(limit=400)
        if not events:
            return
        log = self.query_one("#live-log", RichLog)
        for event in events:
            if not self._log_filter_debug and event.category in ("filter", "stat", "dns") and event.severity in ("debug", "trace"):
                continue
            if event.category in ("__eof__", "phase") and event.message in ("eof",):
                continue
            log.write(rich_line(event))
        self._refresh_findings()

    def _refresh_findings(self) -> None:
        runner = self.runner
        # ``live_result`` is populated while the engine thread still runs;
        # ``runner.result`` stays ``None`` until it returns, which left the table
        # empty for the entire scan.
        result = runner.live_result if runner is not None else None
        if result is None:
            return
        table = self.query_one("#findings-table", DataTable)
        if table.row_count == len(result.findings):
            return
        table.clear()
        for index, finding in enumerate(result.findings, start=1):
            port_text = str(finding.port)
            if finding.aliases:
                port_text += " +"
            table.add_row(
                str(index),
                finding.subdomain,
                finding.ip,
                finding.geo_label or "-",
                port_text,
                str(finding.status if finding.status is not None else "-"),
                f"{finding.confidence} {finding.confidence_label[:4]}",
                finding.kind,
                (finding.title or "")[:24],
                finding.url,
                key=str(index),
            )
        self.findings_count = len(result.findings)

    def _on_scan_finished(self) -> None:
        runner = self.runner
        assert runner is not None
        log = self.query_one("#live-log", RichLog)
        if runner.error is not None:
            log.write(
                f"[{Palette.RED}]✖ scan aborted — "
                f"{runner.error.__class__.__name__}: {runner.error}[/{Palette.RED}]"
            )
            self.notify("scan aborted — see the live log", severity="error")
            return
        result = runner.result
        if result is None:
            return
        self._refresh_findings()
        log.write("")
        for line in result.summary_lines():
            key, _, value = line.partition(":")
            log.write(
                f"[{Palette.MUTED}]{key.strip():<18}[/{Palette.MUTED}]"
                f"[{Palette.ORANGE}]{value.strip()}[/{Palette.ORANGE}]"
            )
        for index, finding in enumerate(result.findings, 1):
            log.write(finding_line(finding, index))
        self._auto_export(result)
        self.notify(
            f"scan finished — {len(result.findings)} web interface(s) confirmed",
            severity="information",
        )

    def _auto_export(self, result: ScanResult) -> None:
        try:
            written = write_reports(
                result,
                result.config.output_dir,
                formats=("json", "csv", "md", "html", "txt"),
            )
            self._exported = list(written.values())
            log = self.query_one("#live-log", RichLog)
            for fmt, path in written.items():
                log.write(
                    f"[{Palette.GREEN}]✔ {fmt:<4}[/{Palette.GREEN}] "
                    f"[{Palette.MUTED}]{path}[/{Palette.MUTED}]"
                )
        except Exception as exc:  # pragma: no cover - defensive
            self.notify(f"export failed: {exc}", severity="error")

    # -- actions ----------------------------------------------------------- #
    def _finding_for_row(self, row_key: Any) -> Finding | None:
        """Row keys are the 1-based index into ``result.findings``."""
        runner = self.runner
        result = runner.live_result if runner is not None else None
        if result is None:
            return None
        try:
            index = int(str(row_key)) - 1
        except (TypeError, ValueError):
            return None
        findings = result.findings
        if 0 <= index < len(findings):
            return findings[index]
        return None

    def _selected_finding(self) -> Finding | None:
        runner = self.runner
        result = runner.live_result if runner is not None else None
        if result is None:
            return None
        table = self.query_one("#findings-table", DataTable)
        if table.row_count == 0:
            return None
        try:
            row = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        except Exception:
            return None
        return self._finding_for_row(row)

    def action_open_url(self) -> None:
        finding = self._selected_finding()
        if finding is None:
            self.notify("no finding selected", severity="warning")
            return
        opened = open_in_browser(finding.link)
        self.notify(
            f"{'opened' if opened else 'could not open'} {finding.link}",
            severity="information" if opened else "error",
        )

    def action_export(self) -> None:
        runner = self.runner
        if runner is None or runner.result is None:
            self.notify("nothing to export yet", severity="warning")
            return
        written = write_reports(
            runner.result, runner.result.config.output_dir,
            formats=("json", "csv", "md", "html", "txt"),
        )
        self._exported = list(written.values())
        self.notify(
            f"exported {len(written)} report(s) to {runner.result.config.output_dir}",
            severity="information",
        )

    def action_toggle_filter(self) -> None:
        self._log_filter_debug = not self._log_filter_debug
        self.notify(
            f"debug/filter events {'shown' if self._log_filter_debug else 'hidden'}",
            severity="information",
        )

    def action_stop(self) -> None:
        if self.runner is None or not self.runner.running:
            self.notify("no scan running", severity="warning")
            return
        self.runner.stop()
        self.notify("stop requested — finishing in-flight probes", severity="warning")

    def action_new_scan(self) -> None:
        if self.runner is not None and self.runner.running:
            self.notify("stop the current scan first (F5)", severity="warning")
            return
        self.phase = "setup"
        self.query_one("#scan-screen").display = False
        self.query_one("#setup-screen").display = True
        self.query_one("#domain-input", Input).focus()

    def action_help(self) -> None:
        self.notify(
            "F2 opens the selected URL · F3 exports · F4 toggles log detail · "
            "F5 stops · F9 new scan · click a URL cell to open it in your browser",
            title="subsonar help",
            timeout=12,
            severity="information",
        )

    # -- table interactions ------------------------------------------------ #
    @on(DataTable.CellSelected, "#findings-table")
    def _cell_selected(self, event: DataTable.CellSelected) -> None:
        finding = self._finding_for_row(str(event.cell_key.row_key.value))
        if finding is None:
            return
        detail = self.query_one("#url-detail", Static)
        detail.update(
            f"[{Palette.MUTED}]selected:[/{Palette.MUTED}] "
            f"[underline {Palette.YELLOW}]{finding.link}[/underline {Palette.YELLOW}] "
            f"[{Palette.MUTED}]· {finding.port_label} · {finding.ip} · "
            f"{finding.server or 'no server header'} · "
            f"{'TLS ' + (finding.tls_version or '') if finding.tls else 'cleartext'}"
            f" · F2 opens it in your browser[/{Palette.MUTED}]"
        )
        # Clicking the URL column itself opens the host browser.
        if event.coordinate.column == self._url_column_index():
            opened = open_in_browser(finding.link)
            self.notify(
                f"{'opened' if opened else 'could not open'} {finding.link}",
                severity="information" if opened else "error",
            )

    def _finding_by_key(self, key: str) -> Finding | None:
        """Backwards-compatible alias for :meth:`_finding_for_row`."""
        return self._finding_for_row(key)


def run_tui(
    domain: str | None = None,
    profile_id: int = 3,
    *,
    offline: bool = False,
    quiet: bool = False,
) -> None:
    """Launch the Textual interface."""
    app = SubsonarApp(
        domain=domain,
        profile_id=profile_id,
        auto_start=bool(domain),
        offline=offline,
        quiet=quiet,
    )
    app.run()
