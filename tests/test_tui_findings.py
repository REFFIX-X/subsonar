"""Verify the findings table and its clickable URL column."""

from __future__ import annotations

import time

import pytest

from subsonar.core.config import ScanConfig
from subsonar.core.engine import Finding, ScanResult
from subsonar.core.events import EventBus
from subsonar.core.profiles import get_profile
from subsonar.ui.tui import SubsonarApp


def _synthetic_runner():
    class _Runner:
        running = False
        finished = True
        error = None
        config = ScanConfig(domain="example.com")
        profile = get_profile(3)

        def __init__(self) -> None:
            self.result = ScanResult(self.config, self.profile)
            self.result.findings = [
                Finding(
                    subdomain="portal.example.com",
                    ip="203.0.113.9",
                    port=8443,
                    scheme="https",
                    url="https://portal.example.com:8443",
                    status=200,
                    title="Admin Portal",
                    server="nginx",
                    tls=True,
                    tls_version="TLSv1.3",
                    port_label="HTTPS-Alt",
                ),
                Finding(
                    subdomain="dev.example.com",
                    ip="203.0.113.10",
                    port=8080,
                    scheme="http",
                    url="http://dev.example.com:8080",
                    status=200,
                    title="Dev Server",
                    port_label="HTTP-Alt",
                ),
            ]
            self.result.finished_at = time.time()

        @property
        def live_result(self):
            # Mirrors ScanRunner.live_result, which the TUI reads during a scan.
            return self.result

    return _Runner()


@pytest.mark.asyncio
async def test_findings_table_lists_clickable_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[str] = []
    monkeypatch.setattr("subsonar.ui.tui.open_in_browser", lambda url: opened.append(url) or True)

    app = SubsonarApp(bus=EventBus())
    app.runner = _synthetic_runner()  # type: ignore[assignment]
    async with app.run_test(size=(150, 50)) as pilot:
        await pilot.pause()
        app.query_one("#setup-screen").display = False
        app.query_one("#scan-screen").display = True
        app._refresh_findings()
        await pilot.pause()

        from textual.widgets import DataTable, Static

        table = app.query_one("#findings-table", DataTable)
        assert table.row_count == 2
        from textual.coordinate import Coordinate

        url_cell = Coordinate(0, app._url_column_index())
        assert table.get_cell_at(url_cell) == "https://portal.example.com:8443"

        # Simulate a click on the URL cell of row 0.
        app._cell_selected(
            DataTable.CellSelected(
                data_table=table,
                cell_key=table.coordinate_to_cell_key(url_cell),
                coordinate=url_cell,
                value=table.get_cell_at(url_cell),
            )
        )
        await pilot.pause()
        assert opened == ["https://portal.example.com:8443"]
        detail = str(app.query_one("#url-detail", Static).render())
        assert "portal.example.com" in detail
        assert "F2 opens it" in detail


@pytest.mark.asyncio
async def test_action_open_url_uses_selected_row(monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[str] = []
    monkeypatch.setattr("subsonar.ui.tui.open_in_browser", lambda url: opened.append(url) or True)

    app = SubsonarApp(bus=EventBus())
    app.runner = _synthetic_runner()  # type: ignore[assignment]
    async with app.run_test(size=(150, 50)) as pilot:
        await pilot.pause()
        app.query_one("#setup-screen").display = False
        app.query_one("#scan-screen").display = True
        app._refresh_findings()
        await pilot.pause()
        from textual.widgets import DataTable, Static

        app.query_one("#findings-table", DataTable).move_cursor(row=1)
        app.action_open_url()
        assert opened == ["http://dev.example.com:8080"]
