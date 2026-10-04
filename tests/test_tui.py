"""Headless rendering verification for the Textual TUI."""

from __future__ import annotations

import asyncio

import pytest

from subsonar.core.events import EventBus
from subsonar.ui.tui import SubsonarApp, open_in_browser


@pytest.mark.asyncio
async def test_tui_mounts_and_renders_setup_screen() -> None:
    app = SubsonarApp(bus=EventBus())
    async with app.run_test(size=(140, 48)) as pilot:
        await pilot.pause()
        assert app.query_one("#setup-screen").display is True
        assert app.query_one("#scan-screen").display is False
        # Eight profiles must be listed.
        assert app.selected_profile.id in range(1, 9)
        from textual.widgets import ListView

        assert len(app.query_one("#profile-list", ListView).children) == 8


@pytest.mark.asyncio
async def test_tui_switches_screens_and_streams_events() -> None:
    bus = EventBus()
    app = SubsonarApp(domain="example.com", bus=bus)
    async with app.run_test(size=(140, 48)) as pilot:
        await pilot.pause()
        await pilot.click("#start-button")
        await pilot.pause()
        assert app.query_one("#scan-screen").display is True
        assert app.runner is not None
        # Inject synthetic events and confirm they reach the live log panel.
        from textual.widgets import RichLog

        for index in range(5):
            bus.emit(
                f"DNS Request (A) sent to [9.9.9.10] for ://h{index}.example.com",
                "info",
                "dns",
                host=f"h{index}.example.com",
            )
        bus.emit("Checking wildcard status for target example.com...", "warn", "wildcard")
        await pilot.pause()
        app._drain_events()
        await pilot.pause()
        log = app.query_one("#live-log", RichLog)
        assert len(log.lines) >= 5
        app.runner.stop()
        app.runner.join(timeout=10)


@pytest.mark.asyncio
async def test_tui_help_and_filter_actions() -> None:
    bus = EventBus()
    app = SubsonarApp(bus=bus)
    async with app.run_test(size=(140, 48)) as pilot:
        await pilot.pause()
        app.action_toggle_filter()
        assert app._log_filter_debug is False
        app.action_toggle_filter()
        assert app._log_filter_debug is True
        app.action_new_scan()
        assert app.phase == "setup"


def test_open_in_browser_handles_bad_urls() -> None:
    # Must never raise, regardless of the host environment.
    assert open_in_browser("http://127.0.0.1:1/") in (True, False)
